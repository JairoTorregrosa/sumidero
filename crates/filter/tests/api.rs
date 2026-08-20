//! Engine API surface: detach, introspection, Display, edge engines.

use sumidero_filter::{EngineBuilder, IssueReason, OwnedVerdict, Verdict, parse_list};

fn engine_of(lists: &[&str]) -> sumidero_filter::Engine {
    let mut builder = EngineBuilder::new();
    for list in lists {
        let parsed = parse_list(list);
        assert!(parsed.issues.is_empty(), "{:?}", parsed.issues);
        builder.add_list(parsed.rules);
    }
    builder.build()
}

#[test]
fn detach_block_carries_list_line_and_text() {
    let engine = engine_of(&["! header\n||example.com^"]);
    let v = engine.verdict("sub.example.com").detach();
    assert_eq!(
        v,
        OwnedVerdict::Block(sumidero_filter::RuleHit {
            list: 0,
            line: 2,
            text: "||example.com^".to_string(),
        })
    );
}

#[test]
fn detach_nomatch_and_except() {
    let engine = engine_of(&["@@example.com"]);
    assert_eq!(engine.verdict("other.com").detach(), OwnedVerdict::NoMatch);
    assert!(matches!(
        engine.verdict("example.com").detach(),
        OwnedVerdict::Except(_)
    ));
}

#[test]
fn empty_engine_matches_nothing() {
    let engine = EngineBuilder::new().build();
    assert_eq!(engine.verdict("example.com"), Verdict::NoMatch);
    assert_eq!(engine.rule_count(), 0);
    assert_eq!(engine.list_count(), 0);
}

#[test]
fn engine_with_empty_list_matches_nothing() {
    let engine = engine_of(&["! only a comment"]);
    assert_eq!(engine.verdict("example.com"), Verdict::NoMatch);
    assert_eq!(engine.rule_count(), 0);
    assert_eq!(engine.list_count(), 1);
}

#[test]
fn three_lists_report_correct_indices() {
    let engine = engine_of(&["a.com", "b.com", "c.com"]);
    for (i, name) in ["a.com", "b.com", "c.com"].iter().enumerate() {
        match engine.verdict(name) {
            Verdict::Block { list, .. } => assert_eq!(list, i),
            v => panic!("expected block for {name}, got {v:?}"),
        }
    }
    assert_eq!(engine.rule_count(), 3);
    assert_eq!(engine.list_count(), 3);
}

#[test]
fn rule_count_sums_all_lists() {
    let engine = engine_of(&["a.com\nb.com", "||c.com^"]);
    assert_eq!(engine.rule_count(), 3);
    assert_eq!(engine.list_count(), 2);
}

#[test]
fn issue_reason_and_line_issue_display() {
    let parsed = parse_list("example.com##.banner");
    assert_eq!(parsed.issues.len(), 1);
    assert_eq!(
        parsed.issues[0].reason.to_string(),
        "cosmetic rule (not DNS filtering)"
    );
    assert_eq!(
        parsed.issues[0].to_string(),
        "line 1: example.com##.banner (cosmetic rule (not DNS filtering))"
    );
    assert_eq!(
        IssueReason::InvalidDomain.to_string(),
        "not a valid DNS name"
    );
}

#[test]
fn overlong_query_rejected_even_when_it_would_match() {
    // A >253-byte name that WOULD match `||com^` if the guard were absent:
    // this pins the guard itself, not the absence of rules.
    let engine = engine_of(&["||com^"]);
    let long = format!("{}.com", "a".repeat(250));
    assert!(long.len() > 253);
    assert_eq!(engine.verdict(&long), Verdict::NoMatch);
    // At exactly 253 bytes the same shape matches.
    let ok = format!("{}.com", "a".repeat(249));
    assert_eq!(ok.len(), 253);
    assert!(matches!(engine.verdict(&ok), Verdict::Block { .. }));
}

#[test]
fn streamed_add_matches_batch_add() {
    let text = "! header\n||blocked.test^\n@@safe.blocked.test\n*.ads.net\n0.0.0.0 hosts.test\nexample.com##.banner\n";
    let mut batch = EngineBuilder::new();
    let parsed = parse_list(text);
    let batch_issues = parsed.issues.len();
    batch.add_list(parsed.rules);
    let batch = batch.build();

    let mut streamed = EngineBuilder::new();
    let added = streamed.add_list_text(text);
    let streamed = streamed.build();

    assert_eq!(added.index, 0);
    assert_eq!(added.rules, batch.rule_count());
    assert_eq!(added.issues.len(), batch_issues);
    for name in [
        "blocked.test",
        "sub.blocked.test",
        "safe.blocked.test",
        "x.ads.net",
        "hosts.test",
        "sub.hosts.test",
        "unrelated.org",
    ] {
        assert_eq!(
            batch.verdict(name).detach(),
            streamed.verdict(name).detach(),
            "{name}"
        );
    }
}
