//! Property tests: the compiled engine agrees with a naive reference
//! matcher on randomly generated rule lists and query names.

use proptest::prelude::*;
use sumidero_filter::{EngineBuilder, Pattern, Rule, RuleAction, Verdict, parse_list};

/// Verdict without the rule reference, for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    NoMatch,
    Block,
    Except,
}

fn kind(v: &Verdict<'_>) -> Kind {
    match v {
        Verdict::NoMatch => Kind::NoMatch,
        Verdict::Block { .. } => Kind::Block,
        Verdict::Except { .. } => Kind::Except,
    }
}

/// Recursive glob matcher, deliberately a different algorithm from the
/// engine's iterative two-pointer implementation.
fn naive_glob(pat: &[u8], text: &[u8]) -> bool {
    match pat.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| naive_glob(rest, &text[skip..])),
        Some((&c, rest)) => text
            .split_first()
            .is_some_and(|(&t, trest)| t == c && naive_glob(rest, trest)),
    }
}

fn naive_matches(rule: &Rule, name: &str) -> bool {
    match &rule.pattern {
        Pattern::Exact(d) => name == d,
        Pattern::Subtree(d) => name == d || name.ends_with(&format!(".{d}")),
        Pattern::Wildcard {
            expr,
            include_subdomains,
        } => {
            if naive_glob(expr.as_bytes(), name.as_bytes()) {
                return true;
            }
            if *include_subdomains {
                let mut rest = name;
                while let Some(dot) = rest.find('.') {
                    rest = &rest[dot + 1..];
                    if naive_glob(expr.as_bytes(), rest.as_bytes()) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn naive_verdict(rules: &[Rule], name: &str) -> Kind {
    let name = name.to_ascii_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    if name.is_empty() || name.len() > 253 {
        return Kind::NoMatch;
    }
    let mut block = false;
    for rule in rules {
        if naive_matches(rule, name) {
            match rule.action {
                RuleAction::Except => return Kind::Except,
                RuleAction::Block => block = true,
            }
        }
    }
    if block { Kind::Block } else { Kind::NoMatch }
}

/// A small closed world of labels so rules and queries collide often.
fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a".to_string()),
        Just("b".to_string()),
        Just("ads".to_string()),
        Just("tracker".to_string()),
        Just("example".to_string()),
        Just("com".to_string()),
        Just("net".to_string()),
        Just("ad2".to_string()),
        Just("a-b".to_string()),
        Just("_dmarc".to_string()),
    ]
}

fn domain() -> impl Strategy<Value = String> {
    prop::collection::vec(label(), 1..5).prop_map(|labels| labels.join("."))
}

/// A query name: a domain, sometimes uppercased and/or with a trailing dot.
fn query() -> impl Strategy<Value = String> {
    (domain(), proptest::bool::ANY, proptest::bool::ANY).prop_map(|(d, upper, dotted)| {
        let d = if upper { d.to_ascii_uppercase() } else { d };
        if dotted { format!("{d}.") } else { d }
    })
}

/// One rule line in the v1 subset, built from a random domain.
fn rule_line() -> impl Strategy<Value = String> {
    let form = (domain(), 0u8..9).prop_map(|(d, kind)| match kind {
        0 => format!("||{d}^"),
        1 => d,
        2 => format!("*.{d}"),
        3 => format!("||{d}.*^"),
        4 => format!("||{d}"),
        5 => format!("{d}^"),
        6 => format!("||*.{d}^"),
        7 => format!("{d}.*"),
        _ => format!("0.0.0.0 {d}"),
    });
    (proptest::bool::ANY, form).prop_map(|(except, line)| {
        // Hosts lines cannot carry @@; fall back to the plain line.
        if except && !line.starts_with("0.0.0.0") {
            format!("@@{line}")
        } else {
            line
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn engine_agrees_with_naive_reference(
        lines in prop::collection::vec(rule_line(), 0..20),
        queries in prop::collection::vec(query(), 1..10),
    ) {
        let parsed = parse_list(&lines.join("\n"));
        prop_assert!(parsed.issues.is_empty(), "generator produced invalid rules: {:?}", parsed.issues);
        let rules = parsed.rules.clone();
        let mut builder = EngineBuilder::new();
        builder.add_list(parsed.rules);
        let engine = builder.build();
        for q in &queries {
            prop_assert_eq!(
                kind(&engine.verdict(q)),
                naive_verdict(&rules, q),
                "divergence on query {:?} against rules {:?}", q, lines
            );
        }
    }

    #[test]
    fn parse_never_panics(text in "\\PC*") {
        let _ = parse_list(&text);
    }

    #[test]
    fn verdict_never_panics(name in "\\PC*") {
        let parsed = parse_list("||example.com^\n@@safe.example.com\n*.ads.net");
        let mut builder = EngineBuilder::new();
        builder.add_list(parsed.rules);
        let engine = builder.build();
        let _ = engine.verdict(&name);
    }
}
