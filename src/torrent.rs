use std::fmt;

use crate::bencode::{self, Value};
use crate::sha1;

#[derive(Debug)]
pub struct TorrentMeta {
    pub announce: Option<Vec<u8>>,
    pub announce_list: Vec<Vec<u8>>,
    #[cfg_attr(not(feature = "webseed"), allow(dead_code))]
    pub url_list: Vec<Vec<u8>>,
    #[cfg_attr(not(feature = "webseed"), allow(dead_code))]
    pub httpseeds: Vec<Vec<u8>>,
    pub info: InfoDict,
    pub info_hash: [u8; 20],
}

#[derive(Debug)]
pub struct InfoDict {
    pub name: Vec<u8>,
    pub piece_length: u64,
    pub pieces: Vec<[u8; 20]>,
    pub length: Option<u64>,
    pub files: Vec<FileInfo>,
    pub private: bool,
}

#[derive(Debug)]
pub struct FileInfo {
    pub length: u64,
    pub path: Vec<Vec<u8>>,
}

impl InfoDict {
    pub fn total_length(&self) -> u64 {
        if let Some(length) = self.length {
            length
        } else {
            self.files.iter().map(|file| file.length).sum()
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Bencode(bencode::Error),
    MissingField(&'static str),
    InvalidField(&'static str),
    InvalidType(&'static str),
    InvalidPiecesLength,
    TrailingData,
    InvalidAnnounceList,
    InvalidUrlList,
    InvalidHttpSeeds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bencode(err) => write!(f, "bencode error: {err}"),
            Error::MissingField(field) => write!(f, "missing field: {field}"),
            Error::InvalidField(field) => write!(f, "invalid field: {field}"),
            Error::InvalidType(field) => write!(f, "invalid type for {field}"),
            Error::InvalidPiecesLength => write!(f, "pieces length is not a multiple of 20"),
            Error::TrailingData => write!(f, "trailing data after torrent dictionary"),
            Error::InvalidAnnounceList => write!(f, "invalid announce-list"),
            Error::InvalidUrlList => write!(f, "invalid url-list"),
            Error::InvalidHttpSeeds => write!(f, "invalid httpseeds"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bencode::Error> for Error {
    fn from(err: bencode::Error) -> Self {
        Error::Bencode(err)
    }
}

pub fn parse_torrent(data: &[u8]) -> Result<TorrentMeta, Error> {
    let (top_dict, info_span) = parse_top_dict(data)?;
    let info_span = info_span.ok_or(Error::MissingField("info"))?;
    let announce = dict_get_bytes(&top_dict, b"announce");
    let announce_list = match dict_get(&top_dict, b"announce-list") {
        Some(value) => parse_announce_list(value)?,
        None => Vec::new(),
    };
    let url_list = match dict_get(&top_dict, b"url-list") {
        Some(value) => parse_url_list(value)?,
        None => Vec::new(),
    };
    let httpseeds = match dict_get(&top_dict, b"httpseeds") {
        Some(value) => parse_httpseeds(value)?,
        None => Vec::new(),
    };
    let info_value = dict_get(&top_dict, b"info").ok_or(Error::MissingField("info"))?;
    let info = parse_info_dict(info_value)?;
    let info_hash = sha1::sha1(&data[info_span.0..info_span.1]);

    Ok(TorrentMeta {
        announce,
        announce_list,
        url_list,
        httpseeds,
        info,
        info_hash,
    })
}

fn parse_top_dict(data: &[u8]) -> Result<(Vec<(Vec<u8>, Value)>, Option<(usize, usize)>), Error> {
    if data.first() != Some(&b'd') {
        return Err(Error::InvalidType("top-level dictionary"));
    }

    let mut dict = Vec::new();
    let mut pos = 1;
    let mut info_span = None;

    while pos < data.len() {
        if data[pos] == b'e' {
            pos += 1;
            break;
        }
        let (key_value, next) = bencode::parse_value(data, pos)?;
        let key = match key_value {
            Value::Bytes(bytes) => bytes,
            _ => return Err(Error::InvalidType("dictionary key")),
        };
        pos = next;
        let value_start = pos;
        let (value, next) = bencode::parse_value(data, pos)?;
        pos = next;
        if key == b"info" {
            info_span = Some((value_start, pos));
        }
        dict.push((key, value));
    }

    if pos != data.len() {
        return Err(Error::TrailingData);
    }

    Ok((dict, info_span))
}

fn parse_info_dict(value: &Value) -> Result<InfoDict, Error> {
    let dict = as_dict(value)?;
    let name = dict_get_bytes(dict, b"name").ok_or(Error::MissingField("name"))?;
    let piece_length =
        dict_get_int(dict, b"piece length").ok_or(Error::MissingField("piece length"))?;
    let pieces_bytes = dict_get_bytes(dict, b"pieces").ok_or(Error::MissingField("pieces"))?;

    if pieces_bytes.len() % 20 != 0 {
        return Err(Error::InvalidPiecesLength);
    }
    let mut pieces = Vec::with_capacity(pieces_bytes.len() / 20);
    for chunk in pieces_bytes.chunks_exact(20) {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(chunk);
        pieces.push(hash);
    }

    let length = dict_get_int(dict, b"length");
    let files_value = dict_get(dict, b"files");
    let files = if let Some(files_value) = files_value {
        parse_files(files_value)?
    } else {
        Vec::new()
    };
    let private = dict_get_int(dict, b"private")
        .map(|value| value != 0)
        .unwrap_or(false);

    if length.is_some() && !files.is_empty() {
        return Err(Error::InvalidField("length/files"));
    }

    Ok(InfoDict {
        name,
        piece_length,
        pieces,
        length,
        files,
        private,
    })
}

fn parse_files(value: &Value) -> Result<Vec<FileInfo>, Error> {
    let list = as_list(value)?;
    let mut files = Vec::with_capacity(list.len());

    for entry in list {
        let dict = as_dict(entry)?;
        let length = dict_get_int(dict, b"length").ok_or(Error::MissingField("length"))?;
        let path_value = dict_get(dict, b"path").ok_or(Error::MissingField("path"))?;
        let path_list = as_list(path_value)?;
        let mut path = Vec::with_capacity(path_list.len());
        for segment in path_list {
            match segment {
                Value::Bytes(bytes) => path.push(bytes.clone()),
                _ => return Err(Error::InvalidType("path segment")),
            }
        }
        files.push(FileInfo { length, path });
    }

    Ok(files)
}

fn parse_announce_list(value: &Value) -> Result<Vec<Vec<u8>>, Error> {
    let list = match value {
        Value::List(items) => items,
        _ => return Err(Error::InvalidAnnounceList),
    };
    let mut urls = Vec::new();
    for tier in list {
        let tier_list = match tier {
            Value::List(items) => items,
            _ => return Err(Error::InvalidAnnounceList),
        };
        for entry in tier_list {
            match entry {
                Value::Bytes(bytes) => urls.push(bytes.clone()),
                _ => return Err(Error::InvalidAnnounceList),
            }
        }
    }
    Ok(urls)
}

fn parse_url_list(value: &Value) -> Result<Vec<Vec<u8>>, Error> {
    match value {
        Value::Bytes(bytes) => Ok(vec![bytes.clone()]),
        Value::List(items) => {
            let mut urls = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Bytes(bytes) => urls.push(bytes.clone()),
                    _ => return Err(Error::InvalidUrlList),
                }
            }
            Ok(urls)
        }
        _ => Err(Error::InvalidUrlList),
    }
}

fn parse_httpseeds(value: &Value) -> Result<Vec<Vec<u8>>, Error> {
    let list = match value {
        Value::List(items) => items,
        _ => return Err(Error::InvalidHttpSeeds),
    };
    let mut urls = Vec::with_capacity(list.len());
    for item in list {
        match item {
            Value::Bytes(bytes) => urls.push(bytes.clone()),
            _ => return Err(Error::InvalidHttpSeeds),
        }
    }
    Ok(urls)
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

fn dict_get_bytes(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<Vec<u8>> {
    dict_get(dict, key).and_then(|value| match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    })
}

fn dict_get_int(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<u64> {
    dict_get(dict, key).and_then(|value| match value {
        Value::Int(num) if *num >= 0 => Some(*num as u64),
        _ => None,
    })
}

fn as_dict(value: &Value) -> Result<&[(Vec<u8>, Value)], Error> {
    match value {
        Value::Dict(items) => Ok(items),
        _ => Err(Error::InvalidType("dictionary")),
    }
}

fn as_list(value: &Value) -> Result<&[Value], Error> {
    match value {
        Value::List(items) => Ok(items),
        _ => Err(Error::InvalidType("list")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_info_dict() -> Value {
        Value::Dict(vec![
            (b"name".to_vec(), Value::Bytes(b"sample".to_vec())),
            (b"piece length".to_vec(), Value::Int(16)),
            (b"pieces".to_vec(), Value::Bytes(vec![7u8; 20])),
            (b"length".to_vec(), Value::Int(16)),
        ])
    }

    #[test]
    fn parse_torrent_extracts_fields_and_info_hash() {
        let info = valid_info_dict();
        let top = Value::Dict(vec![
            (
                b"announce".to_vec(),
                Value::Bytes(b"http://tracker/a".to_vec()),
            ),
            (
                b"announce-list".to_vec(),
                Value::List(vec![
                    Value::List(vec![Value::Bytes(b"http://tracker/a".to_vec())]),
                    Value::List(vec![
                        Value::Bytes(b"http://tracker/b".to_vec()),
                        Value::Bytes(b"http://tracker/c".to_vec()),
                    ]),
                ]),
            ),
            (
                b"url-list".to_vec(),
                Value::List(vec![
                    Value::Bytes(b"http://seed/one".to_vec()),
                    Value::Bytes(b"http://seed/two".to_vec()),
                ]),
            ),
            (
                b"httpseeds".to_vec(),
                Value::List(vec![Value::Bytes(b"http://legacy-seed".to_vec())]),
            ),
            (b"info".to_vec(), info),
        ]);
        let data = bencode::encode(&top);
        let (_, span) = parse_top_dict(&data).unwrap();
        let (start, end) = span.unwrap();
        let expected_hash = sha1::sha1(&data[start..end]);

        let meta = parse_torrent(&data).unwrap();
        assert_eq!(meta.announce, Some(b"http://tracker/a".to_vec()));
        assert_eq!(
            meta.announce_list,
            vec![
                b"http://tracker/a".to_vec(),
                b"http://tracker/b".to_vec(),
                b"http://tracker/c".to_vec()
            ]
        );
        assert_eq!(
            meta.url_list,
            vec![b"http://seed/one".to_vec(), b"http://seed/two".to_vec()]
        );
        assert_eq!(meta.httpseeds, vec![b"http://legacy-seed".to_vec()]);
        assert_eq!(meta.info_hash, expected_hash);
        assert_eq!(meta.info.total_length(), 16);
    }

    #[test]
    fn parse_torrent_rejects_missing_info() {
        let data = bencode::encode(&Value::Dict(vec![(
            b"announce".to_vec(),
            Value::Bytes(b"http://tracker".to_vec()),
        )]));
        assert!(matches!(
            parse_torrent(&data),
            Err(Error::MissingField("info"))
        ));
    }

    #[test]
    fn parse_torrent_rejects_invalid_pieces_len() {
        let info = Value::Dict(vec![
            (b"name".to_vec(), Value::Bytes(b"x".to_vec())),
            (b"piece length".to_vec(), Value::Int(4)),
            (b"pieces".to_vec(), Value::Bytes(vec![1u8; 19])),
            (b"length".to_vec(), Value::Int(4)),
        ]);
        let data = bencode::encode(&Value::Dict(vec![(b"info".to_vec(), info)]));
        assert!(matches!(
            parse_torrent(&data),
            Err(Error::InvalidPiecesLength)
        ));
    }

    #[test]
    fn parse_torrent_rejects_length_and_files_together() {
        let info = Value::Dict(vec![
            (b"name".to_vec(), Value::Bytes(b"root".to_vec())),
            (b"piece length".to_vec(), Value::Int(16)),
            (b"pieces".to_vec(), Value::Bytes(vec![9u8; 20])),
            (b"length".to_vec(), Value::Int(16)),
            (
                b"files".to_vec(),
                Value::List(vec![Value::Dict(vec![
                    (b"length".to_vec(), Value::Int(16)),
                    (
                        b"path".to_vec(),
                        Value::List(vec![Value::Bytes(b"a.bin".to_vec())]),
                    ),
                ])]),
            ),
        ]);
        let data = bencode::encode(&Value::Dict(vec![(b"info".to_vec(), info)]));
        assert!(matches!(
            parse_torrent(&data),
            Err(Error::InvalidField("length/files"))
        ));
    }

    #[test]
    fn parse_torrent_rejects_invalid_announce_list_type() {
        let info = valid_info_dict();
        let top = Value::Dict(vec![
            (b"info".to_vec(), info),
            (b"announce-list".to_vec(), Value::List(vec![Value::Int(1)])),
        ]);
        let data = bencode::encode(&top);
        assert!(matches!(
            parse_torrent(&data),
            Err(Error::InvalidAnnounceList)
        ));
    }

    #[test]
    fn parse_torrent_rejects_trailing_data() {
        let info = valid_info_dict();
        let mut data = bencode::encode(&Value::Dict(vec![(b"info".to_vec(), info)]));
        data.extend_from_slice(b"junk");
        assert!(matches!(parse_torrent(&data), Err(Error::TrailingData)));
    }
}
