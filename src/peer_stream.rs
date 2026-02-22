use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::mse::CipherState;
use crate::utp::UtpStream;

pub enum PeerStreamInner {
    Tcp(TcpStream),
    Utp(UtpStream),
}

pub struct PeerStream {
    inner: PeerStreamInner,
    cipher: Option<CipherState>,
}

impl PeerStream {
    pub fn tcp(stream: TcpStream) -> Self {
        Self {
            inner: PeerStreamInner::Tcp(stream),
            cipher: None,
        }
    }

    pub fn utp(stream: UtpStream) -> Self {
        Self {
            inner: PeerStreamInner::Utp(stream),
            cipher: None,
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match &self.inner {
            PeerStreamInner::Tcp(stream) => stream.peer_addr().ok(),
            PeerStreamInner::Utp(stream) => Some(stream.peer_addr()),
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.set_read_timeout(timeout),
            PeerStreamInner::Utp(stream) => {
                stream.set_read_timeout(timeout);
                Ok(())
            }
        }
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.set_write_timeout(timeout),
            PeerStreamInner::Utp(stream) => {
                stream.set_write_timeout(timeout);
                Ok(())
            }
        }
    }

    pub fn enable_encryption(&mut self, cipher: CipherState) {
        self.cipher = Some(cipher);
    }

    #[allow(dead_code)]
    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }
}

impl Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.read(buf)?,
            PeerStreamInner::Utp(stream) => stream.read(buf)?,
        };
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.decrypt(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(cipher) = self.cipher.as_mut() {
            let mut tmp = buf.to_vec();
            cipher.encrypt(&mut tmp);
            match &mut self.inner {
                PeerStreamInner::Tcp(stream) => stream.write(&tmp),
                PeerStreamInner::Utp(stream) => stream.write(&tmp),
            }
        } else {
            match &mut self.inner {
                PeerStreamInner::Tcp(stream) => stream.write(buf),
                PeerStreamInner::Utp(stream) => stream.write(buf),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.flush(),
            PeerStreamInner::Utp(stream) => stream.flush(),
        }
    }
}
