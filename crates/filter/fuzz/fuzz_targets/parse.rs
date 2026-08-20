//! Fuzz the parser with arbitrary bytes: must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sumidero_filter::parse_list(&text);
});
