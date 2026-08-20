//! Lookup benchmark against real blocklists.
//!
//! Requires `SUMIDERO_BENCH_LISTS` (colon-separated file paths) and refuses
//! to run without it — a bench that silently measures a toy list would
//! produce meaningless numbers.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sumidero_filter::{EngineBuilder, Pattern, parse_list};

fn bench_lookup(c: &mut Criterion) {
    let lists = std::env::var("SUMIDERO_BENCH_LISTS").expect(
        "SUMIDERO_BENCH_LISTS must be set to colon-separated blocklist paths \
         (e.g. hagezi + stevenblack); refusing to bench a toy list",
    );
    let mut builder = EngineBuilder::new();
    let mut total_rules = 0usize;
    let mut sample_blocked: Option<String> = None;
    for path in lists.split(':') {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read blocklist {path}: {e}"));
        let parsed = parse_list(&text);
        total_rules += parsed.rules.len();
        if sample_blocked.is_none() {
            sample_blocked = parsed.rules.iter().find_map(|r| match &r.pattern {
                Pattern::Subtree(d) | Pattern::Exact(d) => Some(d.clone()),
                Pattern::Wildcard { .. } => None,
            });
        }
        builder.add_list(parsed.rules);
    }
    let engine = builder.build();
    let blocked = sample_blocked.expect("no exact/subtree rule found in lists");
    let blocked_sub = format!("deep.sub.{blocked}");
    println!("loaded {total_rules} rules; sample blocked domain: {blocked}");

    let mut group = c.benchmark_group("lookup");
    group.bench_function("miss_allowed", |b| {
        b.iter(|| black_box(engine.verdict(black_box("www.wikipedia.org"))));
    });
    group.bench_function("hit_blocked_apex", |b| {
        b.iter(|| black_box(engine.verdict(black_box(blocked.as_str()))));
    });
    group.bench_function("hit_blocked_subdomain", |b| {
        b.iter(|| black_box(engine.verdict(black_box(blocked_sub.as_str()))));
    });
    group.bench_function("miss_deep_name", |b| {
        b.iter(|| {
            black_box(engine.verdict(black_box(
                "a.very.deep.and.unlikely.name.in.some.zone.example",
            )));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);
