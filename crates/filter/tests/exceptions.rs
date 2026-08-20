//! Integration tests: exact rules and `@@` exceptions.

use sumidero_filter::{EngineBuilder, Pattern, RuleAction, Verdict, parse_list};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an engine from a single list string and return the verdict for `name`.
fn verdict_one(list: &str, name: &str) -> VerdictOwned {
    let parsed = parse_list(list);
    assert!(
        parsed.issues.is_empty(),
        "unexpected issues: {:?}",
        parsed.issues
    );
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let engine = builder.build();
    to_owned(engine.verdict(name))
}

/// Build an engine from two list strings and return the verdict for `name`.
fn verdict_two(list0: &str, list1: &str, name: &str) -> VerdictOwned {
    let p0 = parse_list(list0);
    let p1 = parse_list(list1);
    assert!(
        p0.issues.is_empty(),
        "unexpected issues in list 0: {:?}",
        p0.issues
    );
    assert!(
        p1.issues.is_empty(),
        "unexpected issues in list 1: {:?}",
        p1.issues
    );
    let mut builder = EngineBuilder::new();
    builder.add_list(p0.rules);
    builder.add_list(p1.rules);
    let engine = builder.build();
    to_owned(engine.verdict(name))
}

/// Owned snapshot of a [`Verdict`] so we can outlive the engine borrow.
#[derive(Debug, PartialEq, Eq)]
enum VerdictOwned {
    NoMatch,
    Block { list: usize },
    Except { list: usize },
}

fn to_owned(v: Verdict<'_>) -> VerdictOwned {
    match v {
        Verdict::NoMatch => VerdictOwned::NoMatch,
        Verdict::Block { list, .. } => VerdictOwned::Block { list },
        Verdict::Except { list, .. } => VerdictOwned::Except { list },
    }
}

// ---------------------------------------------------------------------------
// Exact-rule scope
// ---------------------------------------------------------------------------

#[test]
fn exact_blocks_exact_name() {
    assert_eq!(
        verdict_one("example.com", "example.com"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn exact_does_not_block_subdomain() {
    assert_eq!(
        verdict_one("example.com", "sub.example.com"),
        VerdictOwned::NoMatch
    );
}

#[test]
fn exact_does_not_block_superdomain() {
    assert_eq!(
        verdict_one("sub.example.com", "example.com"),
        VerdictOwned::NoMatch
    );
}

#[test]
fn exact_does_not_block_sibling() {
    assert_eq!(
        verdict_one("a.example.com", "b.example.com"),
        VerdictOwned::NoMatch
    );
}

// ---------------------------------------------------------------------------
// @@ on exact form produces Verdict::Except
// ---------------------------------------------------------------------------

#[test]
fn exact_exception_yields_except_over_block() {
    // Same list contains the block; distinct from the no-block case below.
    assert_eq!(
        verdict_one("example.com\n@@example.com", "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

// ---------------------------------------------------------------------------
// @@ on ||subtree form produces Verdict::Except
// ---------------------------------------------------------------------------

#[test]
fn subtree_exception_yields_except() {
    assert_eq!(
        verdict_one("@@||example.com^", "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn subtree_exception_yields_except_for_subdomain() {
    assert_eq!(
        verdict_one("@@||example.com^", "sub.example.com"),
        VerdictOwned::Except { list: 0 },
    );
}

// ---------------------------------------------------------------------------
// Exception with no matching block still yields Except (not NoMatch)
// ---------------------------------------------------------------------------

#[test]
fn exception_without_block_still_except() {
    assert_eq!(
        verdict_one("@@example.com", "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn subtree_exception_without_block_still_except() {
    assert_eq!(
        verdict_one("@@||example.com^", "deep.sub.example.com"),
        VerdictOwned::Except { list: 0 },
    );
}

// ---------------------------------------------------------------------------
// Exception wins over block — same list, both orderings
// ---------------------------------------------------------------------------

#[test]
fn exception_wins_over_block_same_list_block_first() {
    let list = "example.com\n@@example.com";
    assert_eq!(
        verdict_one(list, "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn exception_wins_over_block_same_list_except_first() {
    let list = "@@example.com\nexample.com";
    assert_eq!(
        verdict_one(list, "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

// ---------------------------------------------------------------------------
// Exception wins across different lists, regardless of order
// ---------------------------------------------------------------------------

#[test]
fn exception_in_list0_beats_block_in_list1() {
    assert_eq!(
        verdict_two("@@example.com", "example.com", "example.com"),
        VerdictOwned::Except { list: 0 },
    );
}

#[test]
fn exception_in_list1_beats_block_in_list0() {
    assert_eq!(
        verdict_two("example.com", "@@example.com", "example.com"),
        VerdictOwned::Except { list: 1 },
    );
}

#[test]
fn subtree_exception_in_list1_beats_subtree_block_in_list0() {
    assert_eq!(
        verdict_two("||example.com^", "@@||example.com^", "sub.example.com"),
        VerdictOwned::Except { list: 1 },
    );
}

// ---------------------------------------------------------------------------
// @@||domain^ exempts subdomains from a ||domain^ block
// ---------------------------------------------------------------------------

#[test]
fn subtree_exception_overrides_subtree_block_apex() {
    let list = "||example.com^\n@@||example.com^";
    assert_eq!(
        verdict_one(list, "example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn subtree_exception_overrides_subtree_block_subdomain() {
    let list = "||example.com^\n@@||example.com^";
    assert_eq!(
        verdict_one(list, "sub.example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn subtree_exception_overrides_subtree_block_deep_subdomain() {
    let list = "||example.com^\n@@||example.com^";
    assert_eq!(
        verdict_one(list, "a.b.c.example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

// ---------------------------------------------------------------------------
// Narrower exception inside a broader block
// ---------------------------------------------------------------------------

#[test]
fn narrow_exception_safe_subdomain_is_except() {
    let list = "||example.com^\n@@||safe.example.com^";
    assert_eq!(
        verdict_one(list, "safe.example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn narrow_exception_child_of_safe_is_except() {
    let list = "||example.com^\n@@||safe.example.com^";
    assert_eq!(
        verdict_one(list, "deep.safe.example.com"),
        VerdictOwned::Except { list: 0 }
    );
}

#[test]
fn narrow_exception_other_subdomain_still_blocked() {
    let list = "||example.com^\n@@||safe.example.com^";
    assert_eq!(
        verdict_one(list, "ads.example.com"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn narrow_exception_apex_still_blocked() {
    let list = "||example.com^\n@@||safe.example.com^";
    assert_eq!(
        verdict_one(list, "example.com"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn narrow_exception_across_lists() {
    assert_eq!(
        verdict_two(
            "||example.com^",
            "@@||safe.example.com^",
            "safe.example.com"
        ),
        VerdictOwned::Except { list: 1 },
    );
}

#[test]
fn narrow_exception_across_lists_non_safe_blocked() {
    assert_eq!(
        verdict_two(
            "||example.com^",
            "@@||safe.example.com^",
            "tracker.example.com"
        ),
        VerdictOwned::Block { list: 0 },
    );
}

// ---------------------------------------------------------------------------
// Case normalization
// ---------------------------------------------------------------------------

#[test]
fn exact_case_insensitive_match() {
    assert_eq!(
        verdict_one("Example.COM", "example.com"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn exact_case_insensitive_query() {
    assert_eq!(
        verdict_one("example.com", "EXAMPLE.COM"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn exception_case_insensitive() {
    let list = "EXAMPLE.COM\n@@example.com";
    assert_eq!(
        verdict_one(list, "Example.Com"),
        VerdictOwned::Except { list: 0 }
    );
}

// ---------------------------------------------------------------------------
// Trailing-dot normalization
// ---------------------------------------------------------------------------

#[test]
fn exact_rule_trailing_dot_stripped() {
    // Rule written with trailing dot should still match.
    assert_eq!(
        verdict_one("example.com.", "example.com"),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn query_trailing_dot_stripped() {
    assert_eq!(
        verdict_one("example.com", "example.com."),
        VerdictOwned::Block { list: 0 }
    );
}

#[test]
fn both_trailing_dots() {
    assert_eq!(
        verdict_one("example.com.", "example.com."),
        VerdictOwned::Block { list: 0 }
    );
}

// ---------------------------------------------------------------------------
// Parser shape assertions via ParsedList
// ---------------------------------------------------------------------------

#[test]
fn parse_exception_subtree_shape() {
    let parsed = parse_list("@@||foo.com^");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Except);
    assert_eq!(rule.pattern, Pattern::Subtree("foo.com".to_owned()));
    assert_eq!(rule.line, 1);
}

#[test]
fn parse_exception_subtree_no_caret_shape() {
    let parsed = parse_list("@@||foo.com");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Except);
    assert_eq!(rule.pattern, Pattern::Subtree("foo.com".to_owned()));
}

#[test]
fn parse_block_subtree_shape() {
    let parsed = parse_list("||foo.com^");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Block);
    assert_eq!(rule.pattern, Pattern::Subtree("foo.com".to_owned()));
}

#[test]
fn parse_exact_block_shape() {
    let parsed = parse_list("foo.com");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Block);
    assert_eq!(rule.pattern, Pattern::Exact("foo.com".to_owned()));
}

#[test]
fn parse_exact_exception_shape() {
    let parsed = parse_list("@@foo.com");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Except);
    assert_eq!(rule.pattern, Pattern::Exact("foo.com".to_owned()));
}

#[test]
fn parse_normalized_lowercase() {
    let parsed = parse_list("UPPER.COM");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("upper.com".to_owned())
    );
}

#[test]
fn parse_normalized_trailing_dot_stripped() {
    let parsed = parse_list("trailing.com.");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("trailing.com".to_owned())
    );
}

#[test]
fn parse_preserves_original_text() {
    let parsed = parse_list("@@||Foo.COM^");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].text, "@@||Foo.COM^");
}

#[test]
fn parse_multi_rule_list() {
    let parsed = parse_list("a.com\n@@b.com\n||c.com^\n@@||d.com^");
    assert_eq!(parsed.rules.len(), 4);
    assert_eq!(parsed.rules[0].line, 1);
    assert_eq!(parsed.rules[1].line, 2);
    assert_eq!(parsed.rules[2].line, 3);
    assert_eq!(parsed.rules[3].line, 4);
}
