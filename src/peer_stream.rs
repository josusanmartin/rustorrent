use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::mse::CipherState;
use crate::utp::UtpStream;

const MAX_REUSED_WRITE_BUFFER: usize = 64 * 1024;

pub enum PeerStreamInner {
    Tcp(TcpStream),
    Utp(UtpStream),
}

pub struct PeerStream {
    inner: PeerStreamInner,
    cipher: Option<CipherState>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl PeerStream {
    pub fn tcp(stream: TcpStream) -> Self {
        Self {
            inner: PeerStreamInner::Tcp(stream),
            cipher: None,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    pub fn utp(stream: UtpStream) -> Self {
        Self {
            inner: PeerStreamInner::Utp(stream),
            cipher: None,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
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

    pub fn tcp_stream(&self) -> Option<&TcpStream> {
        match &self.inner {
            PeerStreamInner::Tcp(stream) => Some(stream),
            _ => None,
        }
    }

    pub fn enable_encryption(&mut self, cipher: CipherState) {
        self.cipher = Some(cipher);
    }

    pub fn prepend_read_buffer(&mut self, mut data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        if !self.read_buf.is_empty() {
            data.extend_from_slice(&self.read_buf);
        }
        self.read_buf = data;
    }

    #[allow(dead_code)]
    pub fn is_utp(&self) -> bool {
        matches!(self.inner, PeerStreamInner::Utp(_))
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }
}

impl Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.read_buf.is_empty() {
            // Serve bytes buffered during the handshake without touching the
            // socket: a further blocking read here could stall the caller for
            // a whole timeout while it already has data to process.
            let copied = buf.len().min(self.read_buf.len());
            buf[..copied].copy_from_slice(&self.read_buf[..copied]);
            self.read_buf.drain(..copied);
            return Ok(copied);
        }
        let n = match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.read(buf),
            PeerStreamInner::Utp(stream) => stream.read(buf),
        }?;
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.decrypt(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(cipher) = self.cipher.as_mut() else {
            return match &mut self.inner {
                PeerStreamInner::Tcp(stream) => stream.write(buf),
                PeerStreamInner::Utp(stream) => stream.write(buf),
            };
        };
        // Encrypt into a reused scratch buffer with a copy of the cipher, so
        // the keystream only advances by what the socket actually accepted.
        let mut scratch = std::mem::take(&mut self.write_buf);
        scratch.clear();
        scratch.extend_from_slice(buf);
        let mut preview = cipher.clone();
        preview.encrypt(&mut scratch);
        let result = match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.write(&scratch),
            PeerStreamInner::Utp(stream) => stream.write(&scratch),
        };
        if let Ok(written) = result {
            if written == scratch.len() {
                *cipher = preview;
            } else {
                // Re-encrypting any `written` bytes from the old state
                // advances it by exactly that amount.
                cipher.encrypt(&mut scratch[..written]);
            }
        }
        if scratch.capacity() <= MAX_REUSED_WRITE_BUFFER {
            self.write_buf = scratch;
        }
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            PeerStreamInner::Tcp(stream) => stream.flush(),
            PeerStreamInner::Utp(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server_stream, _) = listener.accept().unwrap();
        let client_stream = client.join().unwrap();
        (client_stream, server_stream)
    }

    #[test]
    fn peer_stream_plaintext_roundtrip() {
        let (client, server) = tcp_pair();
        let mut writer = PeerStream::tcp(client);
        let mut reader = PeerStream::tcp(server);
        assert!(writer.peer_addr().is_some());
        assert!(!writer.is_encrypted());

        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn peer_stream_encryption_roundtrip() {
        let (client, server) = tcp_pair();
        let mut writer = PeerStream::tcp(client);
        let mut reader = PeerStream::tcp(server);
        writer.enable_encryption(CipherState::new(b"key", b"key"));
        reader.enable_encryption(CipherState::new(b"key", b"key"));
        assert!(writer.is_encrypted());
        assert!(reader.is_encrypted());

        writer.write_all(b"encrypted").unwrap();
        writer.flush().unwrap();

        let mut buf = [0u8; 9];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"encrypted");
    }

    #[test]
    fn buffered_read_returns_progress_before_would_block() {
        let (client, _server) = tcp_pair();
        let mut reader = PeerStream::tcp(client);
        reader.prepend_read_buffer(vec![b'a']);
        reader.tcp_stream().unwrap().set_nonblocking(true).unwrap();

        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'a');
    }

    #[test]
    fn buffered_read_does_not_wait_for_the_socket() {
        let (client, _server) = tcp_pair();
        let mut reader = PeerStream::tcp(client);
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        reader.prepend_read_buffer(vec![b'a', b'b']);
        let started = std::time::Instant::now();
        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"ab");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn partial_encrypted_writes_keep_the_keystream_in_sync() {
        let (client, server) = tcp_pair();
        let mut writer = PeerStream::tcp(client);
        let mut reader = PeerStream::tcp(server);
        writer.enable_encryption(CipherState::new(b"k1", b"k2"));
        reader.enable_encryption(CipherState::new(b"k2", b"k1"));
        let payload: Vec<u8> = (0..32 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let reader_thread = thread::spawn(move || {
            // Let the sender fill the socket buffers before draining them.
            thread::sleep(std::time::Duration::from_millis(100));
            let mut received = vec![0u8; expected.len()];
            reader.read_exact(&mut received).unwrap();
            assert!(received == expected);
        });

        // Nonblocking writes accept only what fits in the socket buffers, so
        // some are partial or refused. (Windows may buffer a whole send.)
        writer.tcp_stream().unwrap().set_nonblocking(true).unwrap();
        let mut offset = 0;
        let mut short_writes = 0;
        while offset < payload.len() {
            match writer.write(&payload[offset..]) {
                Ok(written) => {
                    if written < payload.len() - offset {
                        short_writes += 1;
                    }
                    offset += written;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    short_writes += 1;
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(err) => panic!("{err}"),
            }
        }
        #[cfg(unix)]
        assert!(short_writes > 0);
        let _ = short_writes;
        reader_thread.join().unwrap();
    }
}
