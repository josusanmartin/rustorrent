use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(Vec<(Vec<u8>, Value)>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    UnexpectedEof,
    InvalidPrefix(u8),
    InvalidInt,
    InvalidLen,
    TrailingData,
    InvalidDictKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of input"),
            Error::InvalidPrefix(b) => write!(f, "invalid prefix byte: 0x{b:02x}"),
            Error::InvalidInt => write!(f, "invalid integer"),
            Error::InvalidLen => write!(f, "invalid byte string length"),
            Error::TrailingData => write!(f, "trailing data"),
            Error::InvalidDictKey => write!(f, "invalid dict key"),
        }
    }
}

impl std::error::Error for Error {}

pub fn parse(data: &[u8]) -> Result<Value, Error> {
    let (value, pos) = parse_value(data, 0)?;
    if pos != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(num) => {
            out.push(b'i');
            out.extend_from_slice(num.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(bytes) => {
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(bytes);
        }
        Value::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Value::Dict(items) => {
            out.push(b'd');
            let mut sorted = items.iter().collect::<Vec<_>>();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in sorted {
                out.extend_from_slice(key.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(key);
                encode_into(value, out);
            }
            out.push(b'e');
        }
    }
}

pub fn parse_value(data: &[u8], pos: usize) -> Result<(Value, usize), Error> {
    if pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    match data[pos] {
        b'i' => {
            let (value, next) = parse_int(data, pos)?;
            Ok((Value::Int(value), next))
        }
        b'l' => {
            let mut items = Vec::new();
            let mut i = pos + 1;
            while i < data.len() && data[i] != b'e' {
                let (value, next) = parse_value(data, i)?;
                items.push(value);
                i = next;
            }
            if i >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            Ok((Value::List(items), i + 1))
        }
        b'd' => {
            let mut items = Vec::new();
            let mut i = pos + 1;
            while i < data.len() && data[i] != b'e' {
                let (key_value, next) = parse_value(data, i)?;
                let key = match key_value {
                    Value::Bytes(bytes) => bytes,
                    _ => return Err(Error::InvalidDictKey),
                };
                let (value, next) = parse_value(data, next)?;
                items.push((key, value));
                i = next;
            }
            if i >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            Ok((Value::Dict(items), i + 1))
        }
        b'0'..=b'9' => {
            let (bytes, next) = parse_bytes(data, pos)?;
            Ok((Value::Bytes(bytes), next))
        }
        other => Err(Error::InvalidPrefix(other)),
    }
}

fn parse_int(data: &[u8], pos: usize) -> Result<(i64, usize), Error> {
    let mut i = pos + 1;
    while i < data.len() && data[i] != b'e' {
        i += 1;
    }
    if i >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let slice = &data[pos + 1..i];
    if slice.is_empty() {
        return Err(Error::InvalidInt);
    }
    if (slice.len() > 1 && slice[0] == b'0')
        || (slice.len() > 1 && slice[0] == b'-' && slice[1] == b'0')
    {
        return Err(Error::InvalidInt);
    }
    let s = std::str::from_utf8(slice).map_err(|_| Error::InvalidInt)?;
    let value = s.parse::<i64>().map_err(|_| Error::InvalidInt)?;
    Ok((value, i + 1))
}

fn parse_bytes(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut i = pos;
    while i < data.len() && is_digit(data[i]) {
        i += 1;
    }
    if i == pos || i >= data.len() || data[i] != b':' {
        return Err(Error::InvalidLen);
    }
    let slice = &data[pos..i];
    if slice.len() > 1 && slice[0] == b'0' {
        return Err(Error::InvalidLen);
    }
    let s = std::str::from_utf8(slice).map_err(|_| Error::InvalidLen)?;
    let len = s.parse::<usize>().map_err(|_| Error::InvalidLen)?;
    let start = i + 1;
    let end = start + len;
    if end > data.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok((data[start..end].to_vec(), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dict() {
        let value = Value::Dict(vec![
            (b"bar".to_vec(), Value::Int(42)),
            (
                b"foo".to_vec(),
                Value::List(vec![Value::Bytes(b"hi".to_vec())]),
            ),
        ]);
        let encoded = encode(&value);
        let decoded = parse(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn rejects_negative_zero() {
        assert!(parse(b"i-0e").is_err());
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(matches!(parse(b"i1ee"), Err(Error::TrailingData)));
    }

    #[test]
    fn rejects_invalid_dict_key_type() {
        assert!(matches!(parse(b"di1e1:ae"), Err(Error::InvalidDictKey)));
    }

    #[test]
    fn rejects_invalid_lengths_and_integers() {
        assert!(matches!(parse(b"03:abc"), Err(Error::InvalidLen)));
        assert!(matches!(parse(b"i01e"), Err(Error::InvalidInt)));
        assert!(matches!(parse(b"ie"), Err(Error::InvalidInt)));
    }

    #[test]
    fn parse_value_reports_next_offset() {
        let data = b"4:spami42e";
        let (first, pos) = parse_value(data, 0).unwrap();
        assert_eq!(first, Value::Bytes(b"spam".to_vec()));
        let (second, end) = parse_value(data, pos).unwrap();
        assert_eq!(second, Value::Int(42));
        assert_eq!(end, data.len());
    }
}

fn is_digit(b: u8) -> bool {
    b'0' <= b && b <= b'9'
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_integer() {
        let value = parse(b"i42e").unwrap();
        assert_eq!(value, Value::Int(42));
    }

    #[test]
    fn parse_bytes() {
        let value = parse(b"4:spam").unwrap();
        assert_eq!(value, Value::Bytes(b"spam".to_vec()));
    }

    #[test]
    fn parse_list_and_dict() {
        let value = parse(b"l4:spam4:eggse").unwrap();
        assert_eq!(
            value,
            Value::List(vec![
                Value::Bytes(b"spam".to_vec()),
                Value::Bytes(b"eggs".to_vec())
            ])
        );

        let value = parse(b"d3:cow3:moo4:spam4:eggse").unwrap();
        assert_eq!(
            value,
            Value::Dict(vec![
                (b"cow".to_vec(), Value::Bytes(b"moo".to_vec())),
                (b"spam".to_vec(), Value::Bytes(b"eggs".to_vec()))
            ])
        );
    }
}
