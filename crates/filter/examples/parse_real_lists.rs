//! Parse real blocklist files and report rule/issue counts.
//!
//! Usage: `cargo run --release -p sumidero-filter --example parse_real_lists -- <files...>`

use sumidero_filter::parse_list;

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    assert!(!paths.is_empty(), "usage: parse_real_lists <files...>");
    for path in &paths {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let start = std::time::Instant::now();
        let parsed = parse_list(&text);
        let elapsed = start.elapsed();
        println!(
            "{path}: {} rules, {} issues, parsed in {elapsed:?}",
            parsed.rules.len(),
            parsed.issues.len()
        );
        let mut by_reason = std::collections::BTreeMap::new();
        for issue in &parsed.issues {
            *by_reason
                .entry(format!("{:?}", issue.reason))
                .or_insert(0u32) += 1;
        }
        for (reason, n) in by_reason {
            println!("  {reason}: {n}");
        }
        for issue in parsed.issues.iter().take(5) {
            println!("  e.g. line {}: {}", issue.line, issue.text);
        }
    }
}
