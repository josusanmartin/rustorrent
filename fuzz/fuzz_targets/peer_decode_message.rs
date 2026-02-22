#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

mod peer {
    include!("../../src/peer.rs");
}

fuzz_target!(|data: &[u8]| {
    let _ = peer::decode_message(data);
    if data.len() >= 4 {
        let mut cursor = Cursor::new(data);
        let _ = peer::read_message(&mut cursor);
    }
});
