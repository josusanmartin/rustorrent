#![no_main]

use libfuzzer_sys::fuzz_target;

pub fn log_stderr(_args: std::fmt::Arguments<'_>) {}

mod bencode {
    include!("../../src/bencode.rs");
}

mod http {
    include!("../../src/http.rs");

    pub fn fuzz_parse_http_response(data: &[u8]) {
        let _ = parse_http_response(data);
    }
}

mod tracker {
    include!("../../src/tracker.rs");

    pub fn fuzz_parse_http_response(data: &[u8]) {
        let _ = parse_http_response(data);
    }

    pub fn fuzz_parse_tracker_body(data: &[u8]) {
        let _ = parse_tracker_body(data);
    }
}

fuzz_target!(|data: &[u8]| {
    http::fuzz_parse_http_response(data);
    tracker::fuzz_parse_http_response(data);
    tracker::fuzz_parse_tracker_body(data);
});
