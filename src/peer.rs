use std::fmt;
use std::io::{Read, Write};

const PSTR: &str = "BitTorrent protocol";
const PSTR_LEN: usize = 19;
const HANDSHAKE_LEN: usize = 49 + PSTR_LEN;
const MAX_MESSAGE_LEN: usize = 2 * 1024 * 1024;
const EXTENSION_PROTOCOL_BIT: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    pub fn supports_extensions(&self) -> bool {
        self.reserved[5] & EXTENSION_PROTOCOL_BIT != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
    Extended {
        ext_id: u8,
        payload: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidHandshake,
    InvalidProtocol,
    InvalidMessage,
    InvalidLength,
    UnsupportedMessage(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io error: {err}"),
            Error::InvalidHandshake => write!(f, "invalid handshake"),
            Error::InvalidProtocol => write!(f, "invalid protocol string"),
            Error::InvalidMessage => write!(f, "invalid message"),
            Error::InvalidLength => write!(f, "invalid message length"),
            Error::UnsupportedMessage(id) => write!(f, "unsupported message id {id}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

pub fn build_handshake(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    extensions: bool,
) -> [u8; HANDSHAKE_LEN] {
    let mut out = [0u8; HANDSHAKE_LEN];
    out[0] = PSTR_LEN as u8;
    out[1..1 + PSTR_LEN].copy_from_slice(PSTR.as_bytes());
    let reserved_start = 1 + PSTR_LEN;
    if extensions {
        out[reserved_start + 5] |= EXTENSION_PROTOCOL_BIT;
    }
    let info_start = reserved_start + 8;
    let peer_start = info_start + 20;
    out[info_start..peer_start].copy_from_slice(&info_hash);
    out[peer_start..peer_start + 20].copy_from_slice(&peer_id);
    out
}

pub fn parse_handshake(bytes: &[u8]) -> Result<Handshake, Error> {
    if bytes.len() != HANDSHAKE_LEN {
        return Err(Error::InvalidHandshake);
    }
    if bytes[0] as usize != PSTR_LEN {
        return Err(Error::InvalidHandshake);
    }
    if &bytes[1..1 + PSTR_LEN] != PSTR.as_bytes() {
        return Err(Error::InvalidProtocol);
    }
    let reserved_start = 1 + PSTR_LEN;
    let info_start = reserved_start + 8;
    let peer_start = info_start + 20;

    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&bytes[reserved_start..info_start]);
    let mut info_hash = [0u8; 20];
    info_hash.copy_from_slice(&bytes[info_start..peer_start]);
    let mut peer_id = [0u8; 20];
    peer_id.copy_from_slice(&bytes[peer_start..peer_start + 20]);

    Ok(Handshake {
        reserved,
        info_hash,
        peer_id,
    })
}

pub fn write_handshake<W: Write>(
    writer: &mut W,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    extensions: bool,
) -> Result<(), Error> {
    let data = build_handshake(info_hash, peer_id, extensions);
    writer.write_all(&data)?;
    Ok(())
}

pub fn read_handshake<R: Read>(reader: &mut R) -> Result<Handshake, Error> {
    let mut buf = [0u8; HANDSHAKE_LEN];
    reader.read_exact(&mut buf)?;
    parse_handshake(&buf)
}

pub fn write_message<W: Write>(writer: &mut W, message: &Message) -> Result<(), Error> {
    let data = encode_message(message);
    writer.write_all(&data)?;
    Ok(())
}

#[allow(dead_code)]
pub fn read_message<R: Read>(reader: &mut R) -> Result<Message, Error> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Message::KeepAlive);
    }
    if len > MAX_MESSAGE_LEN {
        return Err(Error::InvalidLength);
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    decode_message(&payload)
}

pub struct MessageReader {
    buf: Vec<u8>,
    start: usize,
}

impl MessageReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64 * 1024),
            start: 0,
        }
    }

    pub fn read_message<R: Read>(&mut self, reader: &mut R) -> Result<Option<Message>, Error> {
        loop {
            if let Some(message) = self.try_parse()? {
                return Ok(Some(message));
            }

            let mut tmp = [0u8; 4096];
            match reader.read(&mut tmp) {
                Ok(0) => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection",
                    )));
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(Error::Io(err)),
            }
        }
    }

    fn try_parse(&mut self) -> Result<Option<Message>, Error> {
        if self.available() < 4 {
            return Ok(None);
        }
        let header = &self.buf[self.start..self.start + 4];
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(Error::InvalidLength);
        }
        let total = 4 + len;
        if self.available() < total {
            return Ok(None);
        }
        if len == 0 {
            self.consume(4);
            return Ok(Some(Message::KeepAlive));
        }
        let payload_start = self.start + 4;
        let payload_end = payload_start + len;
        let payload = self.buf[payload_start..payload_end].to_vec();
        self.consume(total);
        Ok(Some(decode_message(&payload)?))
    }

    fn available(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }

    fn consume(&mut self, amount: usize) {
        self.start = self.start.saturating_add(amount);
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= 64 * 1024 {
            let remaining = self.buf.len() - self.start;
            self.buf.copy_within(self.start.., 0);
            self.buf.truncate(remaining);
            self.start = 0;
        }
    }
}

pub fn encode_message(message: &Message) -> Vec<u8> {
    match message {
        Message::KeepAlive => vec![0, 0, 0, 0],
        Message::Choke => encode_simple(0),
        Message::Unchoke => encode_simple(1),
        Message::Interested => encode_simple(2),
        Message::NotInterested => encode_simple(3),
        Message::Have(index) => {
            let mut payload = Vec::with_capacity(5);
            payload.push(4);
            payload.extend_from_slice(&index.to_be_bytes());
            with_len_prefix(payload)
        }
        Message::Bitfield(bits) => {
            let mut payload = Vec::with_capacity(1 + bits.len());
            payload.push(5);
            payload.extend_from_slice(bits);
            with_len_prefix(payload)
        }
        Message::Request {
            index,
            begin,
            length,
        } => encode_triple(6, *index, *begin, *length),
        Message::Piece {
            index,
            begin,
            block,
        } => {
            let mut payload = Vec::with_capacity(9 + block.len());
            payload.push(7);
            payload.extend_from_slice(&index.to_be_bytes());
            payload.extend_from_slice(&begin.to_be_bytes());
            payload.extend_from_slice(block);
            with_len_prefix(payload)
        }
        Message::Cancel {
            index,
            begin,
            length,
        } => encode_triple(8, *index, *begin, *length),
        Message::Port(port) => {
            let mut payload = Vec::with_capacity(3);
            payload.push(9);
            payload.extend_from_slice(&port.to_be_bytes());
            with_len_prefix(payload)
        }
        Message::Extended { ext_id, payload } => {
            let mut buf = Vec::with_capacity(2 + payload.len());
            buf.push(20);
            buf.push(*ext_id);
            buf.extend_from_slice(payload);
            with_len_prefix(buf)
        }
    }
}

pub fn decode_message(payload: &[u8]) -> Result<Message, Error> {
    if payload.is_empty() {
        return Err(Error::InvalidMessage);
    }
    let id = payload[0];
    let data = &payload[1..];
    match id {
        0 => expect_empty(data, Message::Choke),
        1 => expect_empty(data, Message::Unchoke),
        2 => expect_empty(data, Message::Interested),
        3 => expect_empty(data, Message::NotInterested),
        4 => {
            if data.len() != 4 {
                return Err(Error::InvalidMessage);
            }
            Ok(Message::Have(read_u32(data)?))
        }
        5 => Ok(Message::Bitfield(data.to_vec())),
        6 => decode_triple(data, |index, begin, length| Message::Request {
            index,
            begin,
            length,
        }),
        7 => {
            if data.len() < 8 {
                return Err(Error::InvalidMessage);
            }
            let index = read_u32(&data[0..4])?;
            let begin = read_u32(&data[4..8])?;
            let block = data[8..].to_vec();
            Ok(Message::Piece {
                index,
                begin,
                block,
            })
        }
        8 => decode_triple(data, |index, begin, length| Message::Cancel {
            index,
            begin,
            length,
        }),
        9 => {
            if data.len() != 2 {
                return Err(Error::InvalidMessage);
            }
            Ok(Message::Port(u16::from_be_bytes([data[0], data[1]])))
        }
        20 => {
            if data.is_empty() {
                return Err(Error::InvalidMessage);
            }
            Ok(Message::Extended {
                ext_id: data[0],
                payload: data[1..].to_vec(),
            })
        }
        other => Err(Error::UnsupportedMessage(other)),
    }
}

fn encode_simple(id: u8) -> Vec<u8> {
    with_len_prefix(vec![id])
}

fn encode_triple(id: u8, first: u32, second: u32, third: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(13);
    payload.push(id);
    payload.extend_from_slice(&first.to_be_bytes());
    payload.extend_from_slice(&second.to_be_bytes());
    payload.extend_from_slice(&third.to_be_bytes());
    with_len_prefix(payload)
}

fn with_len_prefix(mut payload: Vec<u8>) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&len.to_be_bytes());
    out.append(&mut payload);
    out
}

fn expect_empty(data: &[u8], msg: Message) -> Result<Message, Error> {
    if !data.is_empty() {
        return Err(Error::InvalidMessage);
    }
    Ok(msg)
}

fn decode_triple<F>(data: &[u8], build: F) -> Result<Message, Error>
where
    F: Fn(u32, u32, u32) -> Message,
{
    if data.len() != 12 {
        return Err(Error::InvalidMessage);
    }
    let first = read_u32(&data[0..4])?;
    let second = read_u32(&data[4..8])?;
    let third = read_u32(&data[8..12])?;
    Ok(build(first, second, third))
}

fn read_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() != 4 {
        return Err(Error::InvalidMessage);
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn handshake_roundtrip() {
        let info_hash = [1u8; 20];
        let peer_id = [2u8; 20];
        let bytes = build_handshake(info_hash, peer_id, true);
        let parsed = parse_handshake(&bytes).unwrap();
        assert_eq!(parsed.info_hash, info_hash);
        assert_eq!(parsed.peer_id, peer_id);
    }

    #[test]
    fn message_roundtrip() {
        let messages = vec![
            Message::KeepAlive,
            Message::Choke,
            Message::Interested,
            Message::Have(42),
            Message::Request {
                index: 1,
                begin: 2,
                length: 3,
            },
            Message::Piece {
                index: 4,
                begin: 8,
                block: vec![1, 2, 3, 4],
            },
            Message::Extended {
                ext_id: 2,
                payload: b"hello".to_vec(),
            },
        ];

        for msg in messages {
            let data = encode_message(&msg);
            let mut cursor = Cursor::new(data);
            let decoded = read_message(&mut cursor).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn parse_handshake_rejects_wrong_protocol() {
        let mut bytes = build_handshake([1u8; 20], [2u8; 20], false);
        bytes[1] = b'X';
        assert!(matches!(
            parse_handshake(&bytes),
            Err(Error::InvalidProtocol)
        ));
    }

    #[test]
    fn read_message_rejects_oversized_length() {
        let len = (MAX_MESSAGE_LEN as u32).saturating_add(1);
        let data = len.to_be_bytes();
        let mut cursor = Cursor::new(data);
        assert!(matches!(
            read_message(&mut cursor),
            Err(Error::InvalidLength)
        ));
    }

    #[test]
    fn decode_message_rejects_unsupported_id() {
        assert!(matches!(
            decode_message(&[99]),
            Err(Error::UnsupportedMessage(99))
        ));
    }

    #[test]
    fn message_reader_parses_incremental_frames() {
        let mut reader = MessageReader::new();
        reader
            .buf
            .extend_from_slice(&encode_message(&Message::KeepAlive));
        reader
            .buf
            .extend_from_slice(&encode_message(&Message::Have(7)));

        let first = reader.try_parse().unwrap();
        let second = reader.try_parse().unwrap();
        let third = reader.try_parse().unwrap();

        assert_eq!(first, Some(Message::KeepAlive));
        assert_eq!(second, Some(Message::Have(7)));
        assert_eq!(third, None);
    }
}
