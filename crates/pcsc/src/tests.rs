use super::*;
use std::os::unix::net::UnixListener;
use std::thread::JoinHandle;

const YK: &str = "Yubico YubiKey OTP+FIDO+CCID 00 00";
const EMPTY_READER: &str = "Other Reader 01 00";
const CONTEXT: u32 = 0x1234;
const HANDLE: u32 = 77;

// Plays pcscd 2.3.x (protocol 4.5) for one client and logs the commands it saw.
fn fake_pcscd(name: &str, readers: &'static [&'static str]) -> (PathBuf, JoinHandle<Vec<u32>>) {
    let path = std::env::temp_dir().join(format!("pcsc-{}-{name}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut log = Vec::new();
        let mut begins = 0;
        loop {
            let mut header = [0u8; 8];
            if s.read_exact(&mut header).is_err() {
                return log;
            }
            let (size, cmd) = (word(&header, 0) as usize, word(&header, 1));
            log.push(cmd);
            let b = recv(&mut s, size).unwrap();
            let reply = match cmd {
                VERSION if word(&b, 1) == 5 => words(&[4, 5, SUCCESS]),
                VERSION => words(&[4, 5, SERVICE_STOPPED]),
                ESTABLISH_CONTEXT => words(&[word(&b, 0), CONTEXT, SUCCESS]),
                RELEASE_CONTEXT => words(&[word(&b, 0), SUCCESS]),
                GET_READERS_STATE => {
                    let mut states = vec![0u8; MAX_READERS * READER_STATE_LEN];
                    for (i, r) in readers.iter().enumerate() {
                        // Leave slot 1 empty, as after an unplug.
                        let at = if i == 0 { 0 } else { (i + 1) * READER_STATE_LEN };
                        states[at..at + r.len()].copy_from_slice(r.as_bytes());
                    }
                    states
                }
                CONNECT => {
                    assert_eq!(word(&b, 0), CONTEXT);
                    let name = &b[4..4 + MAX_READERNAME];
                    let name = &name[..name.iter().position(|&c| c == 0).unwrap()];
                    let mut r = b.clone();
                    let f = 4 + MAX_READERNAME;
                    if name == YK.as_bytes() {
                        r[f + 8..f + 20].copy_from_slice(&words(&[HANDLE, 2, SUCCESS]));
                    } else {
                        r[f + 16..f + 20].copy_from_slice(&words(&[Error::NoSmartcard as u32]));
                    }
                    r
                }
                BEGIN_TRANSACTION => {
                    begins += 1;
                    let rv = if begins == 1 { SHARING_VIOLATION } else { SUCCESS };
                    words(&[word(&b, 0), rv])
                }
                TRANSMIT => {
                    assert_eq!((word(&b, 0), word(&b, 1)), (HANDLE, 2));
                    let mut data = recv(&mut s, word(&b, 3) as usize).unwrap();
                    data.reverse();
                    data.extend_from_slice(&[0x90, 0x00]);
                    let rv = if data.len() > word(&b, 6) as usize {
                        Error::InsufficientBuffer as u32
                    } else {
                        SUCCESS
                    };
                    let mut r = b[..24].to_vec();
                    r.extend(words(&[data.len() as u32, rv]));
                    if rv == SUCCESS {
                        r.extend_from_slice(&data);
                    }
                    r
                }
                CONTROL => {
                    assert_eq!(word(&b, 1), ctl_code(3400) as u32);
                    recv(&mut s, word(&b, 2) as usize).unwrap();
                    let mut r = b[..16].to_vec();
                    r.extend(words(&[3, SUCCESS]));
                    r.extend_from_slice(&[1, 2, 3]);
                    r
                }
                END_TRANSACTION | DISCONNECT => {
                    log.push(word(&b, 1));
                    words(&[word(&b, 0), word(&b, 1), SUCCESS])
                }
                other => panic!("unexpected command {other:#x}"),
            };
            s.write_all(&reply).unwrap();
        }
    });
    (path, server)
}

#[test]
fn session_against_fake_pcscd() {
    let (path, server) = fake_pcscd("session", &[YK, EMPTY_READER]);
    let ctx = Context::establish_at(&path, Scope::System).unwrap();

    let len = ctx.list_readers_len().unwrap();
    assert_eq!(len, YK.len() + 1 + EMPTY_READER.len() + 1 + 1);
    let mut small = vec![0u8; len - 1];
    assert_eq!(
        ctx.list_readers(&mut small).err(),
        Some(Error::InsufficientBuffer)
    );
    let mut buf = vec![0u8; len];
    let names: Vec<&CStr> = ctx.list_readers(&mut buf).unwrap().collect();
    assert_eq!(names.len(), 2);
    assert_eq!(names[0].to_bytes(), YK.as_bytes());
    assert_eq!(names[1].to_bytes(), EMPTY_READER.as_bytes());

    assert_eq!(
        ctx.connect(names[1], ShareMode::Shared, Protocols::ANY).err(),
        Some(Error::NoSmartcard)
    );
    let mut card = ctx.connect(names[0], ShareMode::Shared, Protocols::T1).unwrap();
    {
        let tx = card.transaction().unwrap();
        let mut resp = [0u8; 16];
        assert_eq!(
            tx.transmit(&[1, 2, 3], &mut resp).unwrap(),
            &[3, 2, 1, 0x90, 0x00]
        );
        let mut tiny = [0u8; 2];
        assert_eq!(
            tx.transmit(&[1, 2, 3], &mut tiny).err(),
            Some(Error::InsufficientBuffer)
        );
        let mut ctl = [0u8; 8];
        assert_eq!(
            tx.control(ctl_code(3400), &[], &mut ctl).unwrap(),
            &[1, 2, 3]
        );
    }
    card.disconnect(Disposition::LeaveCard).map_err(|(_, e)| e).unwrap();
    drop(ctx);

    let log = server.join().unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        log,
        [
            VERSION,
            VERSION,
            ESTABLISH_CONTEXT,
            GET_READERS_STATE,
            GET_READERS_STATE,
            GET_READERS_STATE,
            CONNECT,
            CONNECT,
            BEGIN_TRANSACTION,
            BEGIN_TRANSACTION,
            TRANSMIT,
            TRANSMIT,
            CONTROL,
            END_TRANSACTION,
            Disposition::LeaveCard as u32,
            DISCONNECT,
            Disposition::LeaveCard as u32,
            RELEASE_CONTEXT,
        ]
    );
}

#[test]
fn no_readers() {
    let (path, server) = fake_pcscd("empty", &[]);
    let ctx = Context::establish_at(&path, Scope::User).unwrap();
    assert_eq!(ctx.list_readers_len().unwrap(), 0);
    assert_eq!(ctx.list_readers(&mut []).unwrap().count(), 0);
    drop(ctx);
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn no_daemon() {
    let path = std::env::temp_dir().join(format!("pcsc-{}-missing.sock", std::process::id()));
    assert_eq!(
        Context::establish_at(&path, Scope::User).err(),
        Some(Error::NoService)
    );
}

#[test]
fn reader_state_layout() {
    assert_eq!(READER_STATE_LEN, 184);
}
