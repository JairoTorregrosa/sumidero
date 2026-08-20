//! Fuzz the matcher: build an engine from one half of the input, query it
//! with the other half. Must never panic, whatever the bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sumidero_filter::{EngineBuilder, parse_list};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (rules, query) = match text.split_once('\u{0}') {
        Some((r, q)) => (r, q),
        None => (text.as_ref(), "sub.example.com"),
    };
    let parsed = parse_list(rules);
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let engine = builder.build();
    let _ = engine.verdict(query);
});
