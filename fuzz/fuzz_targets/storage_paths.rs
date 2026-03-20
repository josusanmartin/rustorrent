#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;

fn clean_segment(bytes: &[u8]) -> Result<OsString, ()> {
    if bytes.is_empty() {
        return Err(());
    }
    if bytes == b"." || bytes == b".." {
        return Err(());
    }
    if bytes.iter().any(|b| *b == 0 || *b == b'/' || *b == b'\\') {
        return Err(());
    }
    if bytes.iter().any(|b| *b < 0x20) {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsStringExt::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec())
            .map(OsString::from)
            .map_err(|_| ())
    }
}

fuzz_target!(|data: &[u8]| {
    // Fuzz clean_segment with raw bytes.
    let _ = clean_segment(data);

    // Also fuzz with segments derived from splitting the input.
    for segment in data.split(|b| *b == b'/') {
        let _ = clean_segment(segment);
    }
});
