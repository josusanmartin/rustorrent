use std::io::{Read, Write};

use num_bigint::BigUint;
use num_traits::Num;

use crate::sha1;

pub enum CryptoMode {
    Plaintext,
    Rc4,
}

pub struct CipherState {
    enc: Rc4,
    dec: Rc4,
}

impl CipherState {
    pub fn new(enc_key: &[u8], dec_key: &[u8]) -> Self {
        let mut enc = Rc4::new(enc_key);
        let mut dec = Rc4::new(dec_key);
        enc.discard(1024);
        dec.discard(1024);
        Self { enc, dec }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.enc.apply(data);
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.dec.apply(data);
    }
}

/// MSE/PE initiator handshake (outbound connection).
///
/// Follows the standard BEP MSE/PE protocol:
///   Step 1: Send Ya (DH public key)
///   Step 2: Read Yb (peer's DH public key)
///   Step 3: Send HASH('req1', S) + XOR'd hash + ENCRYPT(VC, crypto_provide, PadC, len(IA), IA)
///   Step 4: Read peer's ENCRYPT(VC, crypto_select, PadD)
///
/// `initial_payload` is the BT handshake (68 bytes) sent as IA in step 3.
/// After this returns, the peer's BT handshake is the next thing in the encrypted stream.
pub fn initiate<RW: Read + Write>(
    stream: &mut RW,
    info_hash: [u8; 20],
    allow_plain: bool,
    initial_payload: &[u8],
) -> Result<(CryptoMode, Option<CipherState>), String> {
    // Step 1: Send Ya (96 bytes, no padding)
    let (priv_key, pub_key) = dh_generate();
    let pub_bytes = to_fixed_bytes(&pub_key, 96);
    stream
        .write_all(&pub_bytes)
        .map_err(|err| err.to_string())?;

    // Step 2: Read Yb (96 bytes)
    let mut peer_pub = [0u8; 96];
    stream
        .read_exact(&mut peer_pub)
        .map_err(|err| err.to_string())?;
    let peer_pub = BigUint::from_bytes_be(&peer_pub);

    // Compute shared secret S, padded to 96 bytes
    let shared = peer_pub.modpow(&priv_key, &prime());
    let shared_bytes = to_fixed_bytes(&shared, 96);

    // Compute identification hashes
    let hash_req1 = sha1_bytes(b"req1", &shared_bytes);
    let hash_req2 = sha1_bytes(b"req2", &info_hash);
    let hash_req3 = sha1_bytes(b"req3", &shared_bytes);
    let xor = xor_hash(&hash_req2, &hash_req3);

    // Derive RC4 keys: initiator encrypts with keyA, decrypts with keyB
    let (enc_key, dec_key) = derive_keys(&shared_bytes, &info_hash, true);

    // Set up encryption stream (initiator outgoing)
    let mut enc = Rc4::new(&enc_key);
    enc.discard(1024);

    // Build step 3 encrypted portion: VC + crypto_provide + len(PadC) + len(IA) + IA
    let mut provide = 0x02u32; // RC4
    if allow_plain {
        provide |= 0x01; // also offer plaintext
    }
    let ia_len = initial_payload.len() as u16;
    let mut enc_data = Vec::with_capacity(8 + 4 + 2 + 2 + initial_payload.len());
    enc_data.extend_from_slice(&[0u8; 8]); // VC (verification constant)
    enc_data.extend_from_slice(&provide.to_be_bytes()); // crypto_provide
    enc_data.extend_from_slice(&0u16.to_be_bytes()); // len(PadC) = 0
    enc_data.extend_from_slice(&ia_len.to_be_bytes()); // len(IA)
    enc_data.extend_from_slice(initial_payload); // IA
    enc.apply(&mut enc_data);

    // Send step 3: plaintext hashes + encrypted data
    stream
        .write_all(&hash_req1)
        .and_then(|_| stream.write_all(&xor))
        .and_then(|_| stream.write_all(&enc_data))
        .map_err(|err| err.to_string())?;

    // Step 4: Scan for peer's encrypted VC
    // The peer may have sent PadB after Yb, so we scan up to 520 bytes.
    // Compute what encrypted VC looks like: RC4 keystream XOR'd with 8 zeros
    let mut vc_pattern = [0u8; 8];
    {
        let mut dec_preview = Rc4::new(&dec_key);
        dec_preview.discard(1024);
        dec_preview.apply(&mut vc_pattern);
    }

    // Read byte-by-byte and search for the VC pattern
    let mut scan_buf = Vec::with_capacity(528);
    let max_scan = 520; // 512 max PadB + 8 VC
    let vc_offset;
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|err| format!("mse vc scan: {err}"))?;
        scan_buf.push(byte[0]);
        if scan_buf.len() >= 8 {
            let start = scan_buf.len() - 8;
            if scan_buf[start..] == vc_pattern {
                vc_offset = start;
                break;
            }
        }
        if scan_buf.len() > max_scan {
            return Err("mse vc sync failed".to_string());
        }
    }

    // Set up decryption stream positioned after VC
    let mut dec = Rc4::new(&dec_key);
    dec.discard(1024 + 8); // skip past VC

    // We may have over-read bytes after VC into scan_buf
    let extra_start = vc_offset + 8;
    let mut extra = scan_buf[extra_start..].to_vec();
    dec.apply(&mut extra);

    // Read crypto_select (4) + len(PadD) (2)
    let header_need = 6usize.saturating_sub(extra.len());
    let mut header_buf = Vec::with_capacity(6);
    header_buf.extend_from_slice(&extra[..extra.len().min(6)]);
    if header_need > 0 {
        let mut more = vec![0u8; header_need];
        stream
            .read_exact(&mut more)
            .map_err(|err| format!("mse read header: {err}"))?;
        dec.apply(&mut more);
        header_buf.extend_from_slice(&more);
    }

    let crypto_select =
        u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
    let pad_d_len = u16::from_be_bytes([header_buf[4], header_buf[5]]) as usize;

    // Handle remaining extra bytes and PadD
    let leftover = if extra.len() > 6 {
        extra[6..].to_vec()
    } else {
        vec![]
    };
    let pad_to_skip = pad_d_len.saturating_sub(leftover.len());
    if pad_to_skip > 0 {
        let mut pad = vec![0u8; pad_to_skip];
        stream
            .read_exact(&mut pad)
            .map_err(|err| format!("mse read padD: {err}"))?;
        dec.apply(&mut pad);
    }

    if crypto_select & 0x02 != 0 {
        let cipher = CipherState { enc, dec };
        return Ok((CryptoMode::Rc4, Some(cipher)));
    }
    if allow_plain && crypto_select & 0x01 != 0 {
        return Ok((CryptoMode::Plaintext, None));
    }
    Err("mse crypto selection failed".to_string())
}

/// MSE/PE responder handshake (inbound connection).
///
/// `first_byte` is the first byte already read from the stream (to distinguish
/// plaintext vs MSE). Returns the matched info_hash and the peer's initial
/// payload (BT handshake). After this returns, the caller should send their
/// BT handshake directly through the encrypted stream.
pub fn accept<RW: Read + Write>(
    stream: &mut RW,
    info_hashes: &[[u8; 20]],
    first_byte: u8,
    allow_plain: bool,
) -> Result<(CryptoMode, Option<CipherState>, [u8; 20], Vec<u8>), String> {
    // Read Ya (first byte already consumed)
    let mut peer_pub = [0u8; 96];
    peer_pub[0] = first_byte;
    stream
        .read_exact(&mut peer_pub[1..])
        .map_err(|err| err.to_string())?;
    let peer_pub = BigUint::from_bytes_be(&peer_pub);

    // Send Yb (no padding)
    let (priv_key, pub_key) = dh_generate();
    let pub_bytes = to_fixed_bytes(&pub_key, 96);
    stream
        .write_all(&pub_bytes)
        .map_err(|err| err.to_string())?;

    // Compute shared secret S, padded to 96 bytes
    let shared = peer_pub.modpow(&priv_key, &prime());
    let shared_bytes = to_fixed_bytes(&shared, 96);

    let hash_req1 = sha1_bytes(b"req1", &shared_bytes);
    let hash_req3 = sha1_bytes(b"req3", &shared_bytes);

    // Scan for HASH('req1', S) in stream (skip PadA from peer)
    let mut scan_buf = Vec::with_capacity(540);
    let max_scan = 532; // 512 max PadA + 20 hash
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|err| format!("mse req1 scan: {err}"))?;
        scan_buf.push(byte[0]);
        if scan_buf.len() >= 20 {
            let start = scan_buf.len() - 20;
            if scan_buf[start..] == hash_req1 {
                break;
            }
        }
        if scan_buf.len() > max_scan {
            return Err("mse req1 sync failed".to_string());
        }
    }

    // Read XOR'd hash (20 bytes)
    let mut xor_buf = [0u8; 20];
    stream
        .read_exact(&mut xor_buf)
        .map_err(|err| err.to_string())?;
    let hash_req2 = xor_hash(&xor_buf, &hash_req3);
    let info_hash = match find_info_hash(info_hashes, &hash_req2) {
        Some(hash) => hash,
        None => return Err("mse unknown info hash".to_string()),
    };

    // Derive keys: responder decrypts with keyA (initiator's enc key)
    let (dec_key, enc_key) = derive_keys(&shared_bytes, &info_hash, true);

    // Set up decryption for initiator's encrypted data
    let mut dec = Rc4::new(&dec_key);
    dec.discard(1024);

    // Read and decrypt: VC (8) + crypto_provide (4) + len(PadC) (2)
    let mut enc_header = [0u8; 14];
    stream
        .read_exact(&mut enc_header)
        .map_err(|err| err.to_string())?;
    dec.apply(&mut enc_header);

    // Verify VC (first 8 bytes should be zeros)
    if enc_header[..8] != [0u8; 8] {
        return Err("mse vc verification failed".to_string());
    }

    let crypto_provide =
        u32::from_be_bytes([enc_header[8], enc_header[9], enc_header[10], enc_header[11]]);
    let pad_c_len = u16::from_be_bytes([enc_header[12], enc_header[13]]) as usize;

    // Skip PadC
    if pad_c_len > 0 {
        if pad_c_len > 512 {
            return Err("mse PadC too large".to_string());
        }
        let mut pad = vec![0u8; pad_c_len];
        stream.read_exact(&mut pad).map_err(|err| err.to_string())?;
        dec.apply(&mut pad);
    }

    // Read len(IA) (2 bytes)
    let mut ia_len_buf = [0u8; 2];
    stream
        .read_exact(&mut ia_len_buf)
        .map_err(|err| err.to_string())?;
    dec.apply(&mut ia_len_buf);
    let ia_len = u16::from_be_bytes(ia_len_buf) as usize;

    // Read IA (initial payload = peer's BT handshake)
    let mut ia = vec![0u8; ia_len];
    if ia_len > 0 {
        stream.read_exact(&mut ia).map_err(|err| err.to_string())?;
        dec.apply(&mut ia);
    }

    // Determine crypto_select
    let crypto_select: u32 = if crypto_provide & 0x02 != 0 {
        0x02
    } else if allow_plain && crypto_provide & 0x01 != 0 {
        0x01
    } else {
        return Err("mse no compatible crypto".to_string());
    };

    // Set up encryption for our outgoing data and send step 4 response
    let mut enc = Rc4::new(&enc_key);
    enc.discard(1024);

    let mut resp_data = Vec::with_capacity(14);
    resp_data.extend_from_slice(&[0u8; 8]); // VC
    resp_data.extend_from_slice(&crypto_select.to_be_bytes());
    resp_data.extend_from_slice(&0u16.to_be_bytes()); // len(PadD) = 0
    enc.apply(&mut resp_data);
    stream
        .write_all(&resp_data)
        .map_err(|err| err.to_string())?;

    if crypto_select & 0x02 != 0 {
        // Note: dec is for decrypting initiator's data (continuing from IA),
        // enc is for encrypting our data (continuing from step 4 response)
        let cipher = CipherState { enc, dec };
        return Ok((CryptoMode::Rc4, Some(cipher), info_hash, ia));
    }

    Ok((CryptoMode::Plaintext, None, info_hash, ia))
}

fn find_info_hash(info_hashes: &[[u8; 20]], target: &[u8; 20]) -> Option<[u8; 20]> {
    info_hashes
        .iter()
        .find(|hash| &sha1_bytes(b"req2", hash.as_slice()) == target)
        .copied()
}

fn sha1_bytes(prefix: &[u8], data: &[u8]) -> [u8; 20] {
    let mut buf = Vec::with_capacity(prefix.len() + data.len());
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(data);
    sha1::sha1(&buf)
}

fn xor_hash(a: &[u8], b: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn derive_keys(shared: &[u8], info_hash: &[u8; 20], initiator: bool) -> ([u8; 20], [u8; 20]) {
    let key_a = sha1_bytes(b"keyA", &[shared, info_hash.as_slice()].concat());
    let key_b = sha1_bytes(b"keyB", &[shared, info_hash.as_slice()].concat());
    if initiator {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    }
}

fn dh_generate() -> (BigUint, BigUint) {
    let mut priv_bytes = [0u8; 96];
    fill_random(&mut priv_bytes);
    let priv_key = BigUint::from_bytes_be(&priv_bytes);
    let pub_key = BigUint::from(2u8).modpow(&priv_key, &prime());
    (priv_key, pub_key)
}

fn to_fixed_bytes(value: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > len {
        bytes = bytes[bytes.len() - len..].to_vec();
    }
    if bytes.len() < len {
        let mut out = vec![0u8; len - bytes.len()];
        out.extend_from_slice(&bytes);
        return out;
    }
    bytes
}

fn prime() -> BigUint {
    let hex = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
    BigUint::from_str_radix(hex, 16).expect("prime")
}

fn fill_random(buf: &mut [u8]) {
    let mut seed = next_u64();
    for chunk in buf.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        for (i, slot) in chunk.iter_mut().enumerate() {
            *slot = ((seed >> (i * 8)) & 0xff) as u8;
        }
    }
}

fn next_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    static SEED: AtomicU64 = AtomicU64::new(0x1234_9876_55AA_33CC);
    INIT.get_or_init(|| {
        SEED.store(crate::system_entropy_u64(), Ordering::Relaxed);
    });
    let mut x = SEED.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    SEED.store(x, Ordering::Relaxed);
    x
}

struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256u16 {
            let idx = i as usize;
            j = j.wrapping_add(s[idx]).wrapping_add(key[idx % key.len()]);
            s.swap(idx, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            let k = self.s[idx as usize];
            *byte ^= k;
        }
    }

    fn discard(&mut self, count: usize) {
        let mut buf = vec![0u8; count];
        self.apply(&mut buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn xor_and_key_derivation_are_consistent() {
        let a = [0xAAu8; 20];
        let b = [0x0Fu8; 20];
        let x = xor_hash(&a, &b);
        assert_eq!(x, [0xA5u8; 20]);

        let shared = [3u8; 96];
        let info_hash = [9u8; 20];
        let (i_enc, i_dec) = derive_keys(&shared, &info_hash, true);
        let (r_enc, r_dec) = derive_keys(&shared, &info_hash, false);
        assert_eq!(i_enc, r_dec);
        assert_eq!(i_dec, r_enc);
    }

    #[test]
    fn to_fixed_bytes_pads_and_truncates() {
        let small = BigUint::from(0x1234u32);
        let padded = to_fixed_bytes(&small, 4);
        assert_eq!(padded, vec![0x00, 0x00, 0x12, 0x34]);

        let large = BigUint::from_str_radix("1122334455", 16).unwrap();
        let truncated = to_fixed_bytes(&large, 3);
        assert_eq!(truncated, vec![0x33, 0x44, 0x55]);
    }

    #[test]
    fn cipher_state_roundtrip() {
        let mut cipher = CipherState::new(b"key", b"key");
        let mut data = b"hello world".to_vec();
        let original = data.clone();
        cipher.encrypt(&mut data);
        assert_ne!(data, original);
        cipher.decrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn find_info_hash_matches_req2_digest() {
        let target = [7u8; 20];
        let other = [8u8; 20];
        let req2_target = sha1_bytes(b"req2", &target);
        let found = find_info_hash(&[other, target], &req2_target);
        assert_eq!(found, Some(target));
    }

    #[test]
    fn mse_initiate_accept_roundtrip_over_tcp() {
        let info_hash = [5u8; 20];
        let initial_payload = b"bt-handshake";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).unwrap();
            let (mode, mut cipher, matched_hash, ia) =
                accept(&mut stream, &[info_hash], first[0], false).unwrap();
            assert!(matches!(mode, CryptoMode::Rc4));
            assert_eq!(matched_hash, info_hash);
            assert_eq!(ia, initial_payload);

            let mut outbound = b"pong".to_vec();
            if let Some(c) = cipher.as_mut() {
                c.encrypt(&mut outbound);
            }
            stream.write_all(&outbound).unwrap();

            let mut inbound = [0u8; 4];
            stream.read_exact(&mut inbound).unwrap();
            if let Some(c) = cipher.as_mut() {
                c.decrypt(&mut inbound);
            }
            assert_eq!(&inbound, b"ping");
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let (mode, mut cipher) = initiate(&mut client, info_hash, false, initial_payload).unwrap();
        assert!(matches!(mode, CryptoMode::Rc4));

        let mut inbound = [0u8; 4];
        client.read_exact(&mut inbound).unwrap();
        if let Some(c) = cipher.as_mut() {
            c.decrypt(&mut inbound);
        }
        assert_eq!(&inbound, b"pong");

        let mut outbound = b"ping".to_vec();
        if let Some(c) = cipher.as_mut() {
            c.encrypt(&mut outbound);
        }
        client.write_all(&outbound).unwrap();
        server.join().unwrap();
    }
}
