//! Measure the engine on real lists: build time, heap, verdict cost.
//!
//! `cargo run --release -p sumidero-filter --example measure -- <lists...>`
//! Prints one JSON line so runs can be compared by an agent.

#![allow(clippy::cast_precision_loss, reason = "display-only ratios")]

use std::hint::black_box;
use std::time::Instant;

use sumidero_filter::{EngineBuilder, Verdict};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    assert!(!paths.is_empty(), "usage: measure <list files...>");
    let texts: Vec<String> = paths
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}")))
        .collect();

    let t = Instant::now();
    let mut builder = EngineBuilder::new();
    let mut probes = Vec::new();
    for text in &texts {
        builder.add_list_text(text);
        // Every 97th rule-looking line becomes a blocked probe.
        probes.extend(
            text.lines()
                .filter_map(|l| l.strip_prefix("||").and_then(|l| l.strip_suffix('^')))
                .step_by(97)
                .map(str::to_owned),
        );
    }
    let engine = builder.build();
    let build_ms = t.elapsed().as_secs_f64() * 1e3;

    let allowed = [
        "www.google.com",
        "i.ytimg.com",
        "graph.facebook.com",
        "api.github.com",
        "a.very.deep.and.unlikely.name.in.some.zone.example",
        "www.wikipedia.org",
        "edge-chat.instagram.com",
        "clients4.google.com",
    ];
    let n = 400_000;
    let t = Instant::now();
    for i in 0..n {
        black_box(engine.verdict(black_box(allowed[i % allowed.len()])));
    }
    let allowed_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;

    let t = Instant::now();
    let mut blocked = 0usize;
    for p in &probes {
        if matches!(engine.verdict(p), Verdict::Block { .. }) {
            blocked += 1;
        }
    }
    let blocked_us = t.elapsed().as_secs_f64() * 1e6 / probes.len().max(1) as f64;

    println!(
        "{{\"rules\":{},\"build_ms\":{build_ms:.0},\"engine_heap_mb\":{:.1},\"allowed_verdict_us\":{allowed_us:.3},\"blocked_verdict_us\":{blocked_us:.3},\"probes\":{},\"probes_blocked\":{blocked}}}",
        engine.rule_count(),
        engine.heap_bytes() as f64 / 1e6,
        probes.len(),
    );
}
