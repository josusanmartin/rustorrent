#![no_main]

use libfuzzer_sys::fuzz_target;

mod bencode {
    include!("../../src/bencode.rs");
}

fuzz_target!(|data: &[u8]| {
    let _ = bencode::parse(data);
    if !data.is_empty() {
        let _ = bencode::parse_value(data, 0);
    }
});
