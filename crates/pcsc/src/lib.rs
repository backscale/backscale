//! A PC/SC client that speaks pcscd's socket protocol directly instead of
//! linking libpcsclite. It mirrors the subset of the `pcsc` crate's API that
//! `yubikey` and `card-backend-pcsc` use.
//!
//! The wire format is pcsc-lite's `winscard_msg.h`: a `{size, command}` header
//! followed by a fixed struct of 32-bit fields in native byte order. Replies are
//! the same struct with results filled in, plus any variable-length data.

#![forbid(unsafe_code)]

use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::ops::Deref;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[allow(clippy::upper_case_acronyms)]
pub type DWORD = std::os::raw::c_ulong;

pub const MAX_ATR_SIZE: usize = 33;
pub const MAX_BUFFER_SIZE: usize = 264;
pub const MAX_BUFFER_SIZE_EXTENDED: usize = 4 + 3 + (1 << 16) + 3 + 2;

const DEFAULT_SOCKET: &str = "/run/pcscd/pcscd.comm";
const PROTOCOL_MAJOR: u32 = 4;
// 4.4 is the oldest minor current pcscd accepts; 4.5 only adds a command we
// don't use, and pcscd 2.3.x accepts nothing but its own 4.5.
const PROTOCOL_MINOR: u32 = 4;
const PROTOCOL_MINOR_ALT: u32 = 5;
const MAX_READERNAME: usize = 128;
// Protocols up to 4.5 always return this many reader slots.
const MAX_READERS: usize = 16;
// struct pubReaderState: name, three u32, ATR, padding to 4, two u32.
const READER_STATE_LEN: usize = MAX_READERNAME + 12 + MAX_ATR_SIZE + 3 + 8;
const LOCK_POLL: Duration = Duration::from_millis(100);
// Long enough for a card waiting on a touch.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

const SUCCESS: u32 = 0;
const SHARING_VIOLATION: u32 = Error::SharingViolation as u32;
const SERVICE_STOPPED: u32 = Error::ServiceStopped as u32;

const ESTABLISH_CONTEXT: u32 = 0x01;
const RELEASE_CONTEXT: u32 = 0x02;
const CONNECT: u32 = 0x04;
const RECONNECT: u32 = 0x05;
const DISCONNECT: u32 = 0x06;
const BEGIN_TRANSACTION: u32 = 0x07;
const END_TRANSACTION: u32 = 0x08;
const TRANSMIT: u32 = 0x09;
const CONTROL: u32 = 0x0A;
const VERSION: u32 = 0x11;
const GET_READERS_STATE: u32 = 0x12;

macro_rules! errors {
    ($($name:ident = $code:literal, $desc:literal;)*) => {
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Error {
            $($name = $code,)*
        }

        impl Error {
            fn from_raw(raw: u32) -> Error {
                match raw {
                    $($code => Error::$name,)*
                    _ => Error::UnknownError,
                }
            }

            fn text(self) -> &'static str {
                match self {
                    $(Error::$name => $desc,)*
                }
            }
        }
    };
}

errors! {
    InternalError = 0x80100001, "An internal consistency check failed";
    Cancelled = 0x80100002, "The action was cancelled by an SCardCancel request";
    InvalidHandle = 0x80100003, "The supplied handle was invalid";
    InvalidParameter = 0x80100004, "One or more of the supplied parameters could not be properly interpreted";
    InvalidTarget = 0x80100005, "Registry startup information is missing or invalid";
    NoMemory = 0x80100006, "Not enough memory available to complete this command";
    WaitedTooLong = 0x80100007, "An internal consistency timer has expired";
    InsufficientBuffer = 0x80100008, "The data buffer to receive returned data is too small for the returned data";
    UnknownReader = 0x80100009, "The specified reader name is not recognized";
    Timeout = 0x8010000A, "The user-specified timeout value has expired";
    SharingViolation = 0x8010000B, "The smart card cannot be accessed because of other connections outstanding";
    NoSmartcard = 0x8010000C, "The operation requires a Smart Card, but no Smart Card is currently in the device";
    UnknownCard = 0x8010000D, "The specified smart card name is not recognized";
    CantDispose = 0x8010000E, "The system could not dispose of the media in the requested manner";
    ProtoMismatch = 0x8010000F, "The requested protocols are incompatible with the protocol currently in use with the smart card";
    NotReady = 0x80100010, "The reader or smart card is not ready to accept commands";
    InvalidValue = 0x80100011, "One or more of the supplied parameters values could not be properly interpreted";
    SystemCancelled = 0x80100012, "The action was cancelled by the system, presumably to log off or shut down";
    CommError = 0x80100013, "An internal communications error has been detected";
    UnknownError = 0x80100014, "An internal error has been detected, but the source is unknown";
    InvalidAtr = 0x80100015, "An ATR obtained from the registry is not a valid ATR string";
    NotTransacted = 0x80100016, "An attempt was made to end a non-existent transaction";
    ReaderUnavailable = 0x80100017, "The specified reader is not currently available for use";
    Shutdown = 0x80100018, "The operation has been aborted to allow the server application to exit";
    PciTooSmall = 0x80100019, "The PCI Receive buffer was too small";
    ReaderUnsupported = 0x8010001A, "The reader driver does not meet minimal requirements for support";
    DuplicateReader = 0x8010001B, "The reader driver did not produce a unique reader name";
    CardUnsupported = 0x8010001C, "The smart card does not meet minimal requirements for support";
    NoService = 0x8010001D, "The Smart card resource manager is not running";
    ServiceStopped = 0x8010001E, "The Smart card resource manager has shut down";
    IccInstallation = 0x80100020, "No primary provider can be found for the smart card";
    IccCreateorder = 0x80100021, "The requested order of object creation is not supported";
    UnsupportedFeature = 0x80100022, "This smart card does not support the requested feature";
    DirNotFound = 0x80100023, "The identified directory does not exist in the smart card";
    FileNotFound = 0x80100024, "The identified file does not exist in the smart card";
    NoDir = 0x80100025, "The supplied path does not represent a smart card directory";
    NoFile = 0x80100026, "The supplied path does not represent a smart card file";
    NoAccess = 0x80100027, "Access is denied to this file";
    WriteTooMany = 0x80100028, "The smart card does not have enough memory to store the information";
    BadSeek = 0x80100029, "There was an error trying to set the smart card file object pointer";
    InvalidChv = 0x8010002A, "The supplied PIN is incorrect";
    UnknownResMng = 0x8010002B, "An unrecognized error code was returned from a layered component";
    NoSuchCertificate = 0x8010002C, "The requested certificate does not exist";
    CertificateUnavailable = 0x8010002D, "The requested certificate could not be obtained";
    NoReadersAvailable = 0x8010002E, "Cannot find a smart card reader";
    CommDataLost = 0x8010002F, "A communications error with the smart card has been detected. Retry the operation";
    NoKeyContainer = 0x80100030, "The requested key container does not exist on the smart card";
    ServerTooBusy = 0x80100031, "The smart card resource manager is too busy to complete this operation";
    UnsupportedCard = 0x80100065, "The reader cannot communicate with the card, due to ATR string configuration conflicts";
    UnresponsiveCard = 0x80100066, "The smart card is not responding to a reset";
    UnpoweredCard = 0x80100067, "Power has been removed from the smart card, so that further communication is not possible";
    ResetCard = 0x80100068, "The smart card has been reset, so any shared state information is invalid";
    RemovedCard = 0x80100069, "The smart card has been removed, so further communication is not possible";
    SecurityViolation = 0x8010006A, "Access was denied because of a security violation";
    WrongChv = 0x8010006B, "The card cannot be accessed because the wrong PIN was presented";
    ChvBlocked = 0x8010006C, "The card cannot be accessed because the maximum number of PIN entry attempts has been reached";
    Eof = 0x8010006D, "The end of the smart card file has been reached";
    CancelledByUser = 0x8010006E, r#"The user pressed "Cancel" on a Smart Card Selection Dialog"#;
    CardNotAuthenticated = 0x8010006F, "No PIN was presented to the smart card";
    CacheItemNotFound = 0x80100070, "The requested item could not be found in the cache";
    CacheItemStale = 0x80100071, "The requested cache item is too old and was deleted from the cache";
    CacheItemTooBig = 0x80100072, "The new cache item exceeds the maximum per-item size defined for the cache";
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error {
        Error::CommError
    }
}

fn check(rv: u32) -> Result<(), Error> {
    if rv == SUCCESS {
        Ok(())
    } else {
        Err(Error::from_raw(rv))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    User = 0,
    Terminal = 1,
    System = 2,
    Global = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShareMode {
    Exclusive = 1,
    Shared = 2,
    Direct = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    LeaveCard = 0,
    ResetCard = 1,
    UnpowerCard = 2,
    EjectCard = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Protocols(DWORD);

impl Protocols {
    pub const UNDEFINED: Protocols = Protocols(0);
    pub const T0: Protocols = Protocols(1);
    pub const T1: Protocols = Protocols(2);
    pub const RAW: Protocols = Protocols(4);
    pub const ANY: Protocols = Protocols(1 | 2);

    pub fn bits(&self) -> DWORD {
        self.0
    }
}

pub const fn ctl_code(code: DWORD) -> DWORD {
    0x42000000 + code
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

fn word(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}

fn send(s: &mut UnixStream, command: u32, body: &[u8]) -> io::Result<()> {
    let mut msg = words(&[body.len() as u32, command]);
    msg.extend_from_slice(body);
    s.write_all(&msg)
}

fn recv(s: &mut UnixStream, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn exchange(s: &mut UnixStream, command: u32, body: &[u8]) -> io::Result<Vec<u8>> {
    send(s, command, body)?;
    recv(s, body.len())
}

// One connection to pcscd per context; every request and its reply happen
// under the lock so concurrent users don't interleave.
struct Conn {
    stream: Mutex<UnixStream>,
    context: u32,
}

impl Conn {
    fn with<T>(&self, f: impl FnOnce(&mut UnixStream) -> io::Result<T>) -> Result<T, Error> {
        let mut s = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&mut s)?)
    }

    fn call(&self, command: u32, body: &[u32]) -> Result<Vec<u8>, Error> {
        self.with(|s| exchange(s, command, &words(body)))
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let s = self.stream.get_mut().unwrap_or_else(|e| e.into_inner());
        let _ = exchange(s, RELEASE_CONTEXT, &words(&[self.context, 0]));
    }
}

pub struct Context {
    conn: Arc<Conn>,
}

#[derive(Clone, Debug)]
pub struct ReaderNames<'buf> {
    buf: &'buf [u8],
    pos: usize,
}

impl<'buf> Iterator for ReaderNames<'buf> {
    type Item = &'buf CStr;

    fn next(&mut self) -> Option<&'buf CStr> {
        let len = self.buf[self.pos..].iter().position(|&c| c == 0)?;
        if len == 0 {
            return None;
        }
        let start = self.pos;
        self.pos += len + 1;
        CStr::from_bytes_with_nul(&self.buf[start..self.pos]).ok()
    }
}

impl Context {
    pub fn establish(scope: Scope) -> Result<Context, Error> {
        let path = std::env::var_os("PCSCLITE_CSOCK_NAME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
        Self::establish_at(&path, scope)
    }

    fn establish_at(path: &Path, scope: Scope) -> Result<Context, Error> {
        let mut s = UnixStream::connect(path).map_err(|_| Error::NoService)?;
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut minor = PROTOCOL_MINOR;
        loop {
            let r = exchange(&mut s, VERSION, &words(&[PROTOCOL_MAJOR, minor, 0]))?;
            let (major, server_minor, rv) = (word(&r, 0), word(&r, 1), word(&r, 2));
            if rv == SERVICE_STOPPED
                && major == PROTOCOL_MAJOR
                && server_minor == PROTOCOL_MINOR_ALT
                && minor != PROTOCOL_MINOR_ALT
            {
                minor = PROTOCOL_MINOR_ALT;
                continue;
            }
            check(rv)?;
            break;
        }
        let r = exchange(&mut s, ESTABLISH_CONTEXT, &words(&[scope as u32, 0, 0]))?;
        check(word(&r, 2))?;
        Ok(Context {
            conn: Arc::new(Conn {
                stream: Mutex::new(s),
                context: word(&r, 1),
            }),
        })
    }

    pub fn is_valid(&self) -> Result<(), Error> {
        Ok(())
    }

    fn reader_names(&self) -> Result<Vec<Vec<u8>>, Error> {
        let states = self.conn.with(|s| {
            send(s, GET_READERS_STATE, &[])?;
            recv(s, MAX_READERS * READER_STATE_LEN)
        })?;
        Ok(states
            .chunks(READER_STATE_LEN)
            .map(|st| {
                let name = &st[..MAX_READERNAME];
                name[..name.iter().position(|&c| c == 0).unwrap_or(MAX_READERNAME)].to_vec()
            })
            .filter(|n| !n.is_empty())
            .collect())
    }

    // The multi-string size: each name and its NUL, then a final NUL.
    fn names_len(names: &[Vec<u8>]) -> usize {
        names.iter().map(|n| n.len() + 1).sum::<usize>() + 1
    }

    pub fn list_readers_len(&self) -> Result<usize, Error> {
        let names = self.reader_names()?;
        Ok(if names.is_empty() {
            0
        } else {
            Self::names_len(&names)
        })
    }

    pub fn list_readers<'buf>(&self, buffer: &'buf mut [u8]) -> Result<ReaderNames<'buf>, Error> {
        let names = self.reader_names()?;
        if names.is_empty() {
            return Ok(ReaderNames { buf: b"\0", pos: 0 });
        }
        let need = Self::names_len(&names);
        if buffer.len() < need {
            return Err(Error::InsufficientBuffer);
        }
        let mut at = 0;
        for n in &names {
            buffer[at..at + n.len()].copy_from_slice(n);
            buffer[at + n.len()] = 0;
            at += n.len() + 1;
        }
        buffer[at] = 0;
        Ok(ReaderNames {
            buf: &buffer[..need],
            pos: 0,
        })
    }

    pub fn connect(
        &self,
        reader: &CStr,
        share_mode: ShareMode,
        preferred_protocols: Protocols,
    ) -> Result<Card, Error> {
        let name = reader.to_bytes();
        if name.len() >= MAX_READERNAME {
            return Err(Error::InvalidValue);
        }
        let mut body = words(&[self.conn.context]);
        let mut field = [0u8; MAX_READERNAME];
        field[..name.len()].copy_from_slice(name);
        body.extend_from_slice(&field);
        body.extend(words(&[
            share_mode as u32,
            preferred_protocols.0 as u32,
            0,
            0,
            0,
        ]));
        let r = self.conn.with(|s| exchange(s, CONNECT, &body))?;
        let fields = &r[4 + MAX_READERNAME..];
        check(word(fields, 4))?;
        Ok(Card {
            conn: self.conn.clone(),
            handle: word(fields, 2),
            protocol: word(fields, 3),
            connected: true,
        })
    }
}

pub struct Card {
    conn: Arc<Conn>,
    handle: u32,
    protocol: u32,
    connected: bool,
}

impl Card {
    fn begin(&self) -> Result<(), Error> {
        loop {
            let r = self.conn.call(BEGIN_TRANSACTION, &[self.handle, 0])?;
            match word(&r, 1) {
                SHARING_VIOLATION => std::thread::sleep(LOCK_POLL),
                rv => return check(rv),
            }
        }
    }

    fn end(&self, disposition: Disposition) -> Result<(), Error> {
        let r = self
            .conn
            .call(END_TRANSACTION, &[self.handle, disposition as u32, 0])?;
        check(word(&r, 2))
    }

    fn disconnect_raw(&self, disposition: Disposition) -> Result<(), Error> {
        let r = self
            .conn
            .call(DISCONNECT, &[self.handle, disposition as u32, 0])?;
        check(word(&r, 2))
    }

    pub fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        self.begin()?;
        Ok(Transaction {
            card: self,
            active: true,
        })
    }

    pub fn transaction2(&mut self) -> Result<Transaction<'_>, (&mut Self, Error)> {
        match self.begin() {
            Ok(()) => Ok(Transaction {
                card: self,
                active: true,
            }),
            Err(e) => Err((self, e)),
        }
    }

    pub fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocols: Protocols,
        initialization: Disposition,
    ) -> Result<(), Error> {
        loop {
            let r = self.conn.call(
                RECONNECT,
                &[
                    self.handle,
                    share_mode as u32,
                    preferred_protocols.0 as u32,
                    initialization as u32,
                    self.protocol,
                    0,
                ],
            )?;
            match word(&r, 5) {
                SHARING_VIOLATION => std::thread::sleep(LOCK_POLL),
                rv => {
                    check(rv)?;
                    self.protocol = word(&r, 4);
                    return Ok(());
                }
            }
        }
    }

    pub fn disconnect(mut self, disposition: Disposition) -> Result<(), (Card, Error)> {
        match self.disconnect_raw(disposition) {
            Ok(()) => {
                self.connected = false;
                Ok(())
            }
            Err(e) => Err((self, e)),
        }
    }

    pub fn transmit<'buf>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'buf mut [u8],
    ) -> Result<&'buf [u8], Error> {
        if send_buffer.len() > MAX_BUFFER_SIZE_EXTENDED {
            return Err(Error::InsufficientBuffer);
        }
        // sizeof(SCARD_IO_REQUEST): two unsigned longs.
        let pci_len = 2 * std::mem::size_of::<DWORD>() as u32;
        let recv_cap = receive_buffer.len().min(u32::MAX as usize) as u32;
        let body = words(&[
            self.handle,
            self.protocol,
            pci_len,
            send_buffer.len() as u32,
            Protocols::ANY.0 as u32,
            pci_len,
            recv_cap,
            0,
        ]);
        loop {
            let (rv, len) = self.conn.with(|s| {
                send(s, TRANSMIT, &body)?;
                s.write_all(send_buffer)?;
                let r = recv(s, body.len())?;
                let (rv, len) = (word(&r, 7), word(&r, 6) as usize);
                if rv == SUCCESS {
                    read_payload(s, len, receive_buffer)?;
                }
                Ok((rv, len))
            })?;
            match rv {
                SHARING_VIOLATION => std::thread::sleep(LOCK_POLL),
                rv => {
                    check(rv)?;
                    return payload(receive_buffer, len);
                }
            }
        }
    }

    pub fn control<'buf>(
        &self,
        control_code: DWORD,
        send_buffer: &[u8],
        receive_buffer: &'buf mut [u8],
    ) -> Result<&'buf [u8], Error> {
        if send_buffer.len() > MAX_BUFFER_SIZE_EXTENDED {
            return Err(Error::InsufficientBuffer);
        }
        let recv_cap = receive_buffer.len().min(u32::MAX as usize) as u32;
        let body = words(&[
            self.handle,
            control_code as u32,
            send_buffer.len() as u32,
            recv_cap,
            0,
            0,
        ]);
        let (rv, len) = self.conn.with(|s| {
            send(s, CONTROL, &body)?;
            s.write_all(send_buffer)?;
            let r = recv(s, body.len())?;
            let (rv, len) = (word(&r, 5), word(&r, 4) as usize);
            if rv == SUCCESS {
                read_payload(s, len, receive_buffer)?;
            }
            Ok((rv, len))
        })?;
        check(rv)?;
        payload(receive_buffer, len)
    }
}

// Reads a reply's data. If it can't fit (pcscd shouldn't send that), it's
// still consumed so the stream stays in step; `payload` reports the error.
fn read_payload(s: &mut UnixStream, len: usize, buf: &mut [u8]) -> io::Result<()> {
    if len <= buf.len() {
        s.read_exact(&mut buf[..len])
    } else {
        io::copy(&mut s.take(len as u64), &mut io::sink()).map(|_| ())
    }
}

fn payload(buf: &[u8], len: usize) -> Result<&[u8], Error> {
    buf.get(..len).ok_or(Error::InsufficientBuffer)
}

impl Drop for Card {
    fn drop(&mut self) {
        if self.connected {
            let _ = self.disconnect_raw(Disposition::ResetCard);
        }
    }
}

pub struct Transaction<'tx> {
    card: &'tx mut Card,
    active: bool,
}

impl<'tx> Transaction<'tx> {
    pub fn end(mut self, disposition: Disposition) -> Result<(), (Transaction<'tx>, Error)> {
        match self.card.end(disposition) {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err(e) => Err((self, e)),
        }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.card.end(Disposition::LeaveCard);
        }
    }
}

impl Deref for Transaction<'_> {
    type Target = Card;

    fn deref(&self) -> &Card {
        self.card
    }
}

#[cfg(test)]
mod tests;
