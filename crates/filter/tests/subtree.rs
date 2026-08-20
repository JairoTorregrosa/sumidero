//! Integration tests for `||domain^` subtree rules.

use sumidero_filter::{EngineBuilder, Pattern, RuleAction, Verdict, parse_list};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Build an engine from a single blocklist string and return it.
fn engine_from(text: &str) -> sumidero_filter::Engine {
    let parsed = parse_list(text);
    assert!(
        parsed.issues.is_empty(),
        "unexpected issues: {:?}",
        parsed.issues
    );
    let mut b = EngineBuilder::new();
    b.add_list(parsed.rules);
    b.build()
}

/// Assert that the engine blocks the given name.
fn assert_blocked(engine: &sumidero_filter::Engine, name: &str) {
    let v = engine.verdict(name);
    assert!(
        matches!(v, Verdict::Block { .. }),
        "expected Block for {name:?}, got {v:?}"
    );
}

/// Assert that the engine does NOT match the given name.
fn assert_no_match(engine: &sumidero_filter::Engine, name: &str) {
    let v = engine.verdict(name);
    assert!(
        matches!(v, Verdict::NoMatch),
        "expected NoMatch for {name:?}, got {v:?}"
    );
}

// ---------------------------------------------------------------------------
// parser shape
// ---------------------------------------------------------------------------

#[test]
fn parse_subtree_rule_pattern() {
    let list = parse_list("||example.com^\n");
    assert_eq!(list.rules.len(), 1);
    let rule = &list.rules[0];
    assert_eq!(rule.action, RuleAction::Block);
    assert_eq!(rule.pattern, Pattern::Subtree("example.com".into()));
}

#[test]
fn parse_subtree_without_caret() {
    let list = parse_list("||example.com\n");
    assert_eq!(list.rules.len(), 1);
    assert_eq!(
        list.rules[0].pattern,
        Pattern::Subtree("example.com".into())
    );
}

#[test]
fn parse_subtree_preserves_original_text_with_caret() {
    let list = parse_list("||example.com^\n");
    assert_eq!(list.rules[0].text, "||example.com^");
}

#[test]
fn parse_subtree_preserves_original_text_without_caret() {
    let list = parse_list("||example.com\n");
    assert_eq!(list.rules[0].text, "||example.com");
}

#[test]
fn parse_subtree_domain_lowercased() {
    let list = parse_list("||Example.COM^\n");
    assert_eq!(
        list.rules[0].pattern,
        Pattern::Subtree("example.com".into())
    );
}

// ---------------------------------------------------------------------------
// basic matching: domain itself and subdomains
// ---------------------------------------------------------------------------

#[test]
fn blocks_exact_domain() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "example.com");
}

#[test]
fn blocks_one_level_subdomain() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "www.example.com");
}

#[test]
fn blocks_deep_subdomain() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "a.b.c.d.example.com");
}

// ---------------------------------------------------------------------------
// non-matches: siblings, superdomains, label-suffix traps
// ---------------------------------------------------------------------------

#[test]
fn no_match_superdomain_com() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "com");
}

#[test]
fn no_match_sibling_domain() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "notexample.com");
}

#[test]
fn no_match_prefix_sibling() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "aexample.com");
}

#[test]
fn no_match_different_tld() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "example.org");
}

#[test]
fn no_match_suffix_of_label() {
    // ||ample.com^ must NOT match example.com (different first label).
    let e = engine_from("||ample.com^");
    assert_no_match(&e, "example.com");
}

#[test]
fn suffix_rule_blocks_own_domain() {
    let e = engine_from("||ample.com^");
    assert_blocked(&e, "ample.com");
}

#[test]
fn suffix_rule_blocks_subdomain_of_own_domain() {
    let e = engine_from("||ample.com^");
    assert_blocked(&e, "sub.ample.com");
}

// ---------------------------------------------------------------------------
// caret optionality
// ---------------------------------------------------------------------------

#[test]
fn without_caret_blocks_domain() {
    let e = engine_from("||example.com");
    assert_blocked(&e, "example.com");
}

#[test]
fn without_caret_blocks_subdomain() {
    let e = engine_from("||example.com");
    assert_blocked(&e, "sub.example.com");
}

#[test]
fn without_caret_no_match_sibling() {
    let e = engine_from("||example.com");
    assert_no_match(&e, "notexample.com");
}

// ---------------------------------------------------------------------------
// case insensitivity
// ---------------------------------------------------------------------------

#[test]
fn case_insensitive_rule_blocks_lower_query() {
    let e = engine_from("||EXAMPLE.COM^");
    assert_blocked(&e, "example.com");
}

#[test]
fn case_insensitive_query_matches_lower_rule() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "EXAMPLE.COM");
}

#[test]
fn case_insensitive_mixed() {
    let e = engine_from("||ExAmPlE.CoM^");
    assert_blocked(&e, "eXaMpLe.cOm");
}

// ---------------------------------------------------------------------------
// trailing dot normalization
// ---------------------------------------------------------------------------

#[test]
fn query_trailing_dot_matches() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "example.com.");
}

#[test]
fn query_trailing_dot_subdomain() {
    let e = engine_from("||example.com^");
    assert_blocked(&e, "sub.example.com.");
}

#[test]
fn query_trailing_dot_no_match_sibling() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "notexample.com.");
}

#[test]
fn rule_trailing_dot_stripped() {
    // A rule written with a trailing dot should still be normalized.
    let list = parse_list("||example.com.^\n");
    // The doc says domain normalization strips one trailing dot, so this
    // should parse to Subtree("example.com").
    assert_eq!(list.rules.len(), 1);
    assert_eq!(
        list.rules[0].pattern,
        Pattern::Subtree("example.com".into())
    );
}

// ---------------------------------------------------------------------------
// multiple subtree rules
// ---------------------------------------------------------------------------

#[test]
fn multiple_rules_independent() {
    let e = engine_from("||foo.com^\n||bar.com^\n");
    assert_blocked(&e, "foo.com");
    assert_blocked(&e, "sub.foo.com");
    assert_blocked(&e, "bar.com");
    assert_blocked(&e, "sub.bar.com");
    assert_no_match(&e, "baz.com");
}

// ---------------------------------------------------------------------------
// nested subtree rules
// ---------------------------------------------------------------------------

#[test]
fn nested_subtree_parent_blocks_child_domain() {
    let e = engine_from("||example.com^\n||a.example.com^\n");
    assert_blocked(&e, "a.example.com");
}

#[test]
fn nested_subtree_parent_blocks_sibling_of_child() {
    let e = engine_from("||example.com^\n||a.example.com^\n");
    assert_blocked(&e, "b.example.com");
}

#[test]
fn nested_subtree_child_blocks_its_own_subdomain() {
    let e = engine_from("||example.com^\n||a.example.com^\n");
    assert_blocked(&e, "deep.a.example.com");
}

#[test]
fn nested_subtree_no_match_unrelated() {
    let e = engine_from("||example.com^\n||a.example.com^\n");
    assert_no_match(&e, "other.com");
}

// ---------------------------------------------------------------------------
// verdict carries list index
// ---------------------------------------------------------------------------

#[test]
fn verdict_list_index_first_list() {
    let list0 = parse_list("||alpha.com^");
    let list1 = parse_list("||beta.com^");
    let mut b = EngineBuilder::new();
    let idx0 = b.add_list(list0.rules);
    let _idx1 = b.add_list(list1.rules);
    let e = b.build();

    if let Verdict::Block { list, .. } = e.verdict("alpha.com") {
        assert_eq!(list, idx0);
    } else {
        panic!("expected Block for alpha.com");
    }
}

#[test]
fn verdict_list_index_second_list() {
    let list0 = parse_list("||alpha.com^");
    let list1 = parse_list("||beta.com^");
    let mut b = EngineBuilder::new();
    let _idx0 = b.add_list(list0.rules);
    let idx1 = b.add_list(list1.rules);
    let e = b.build();

    if let Verdict::Block { list, .. } = e.verdict("beta.com") {
        assert_eq!(list, idx1);
    } else {
        panic!("expected Block for beta.com");
    }
}

// ---------------------------------------------------------------------------
// rule.text and rule.line in verdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_rule_text_preserved() {
    let e = engine_from("||example.com^");
    if let Verdict::Block { rule, .. } = e.verdict("example.com") {
        assert_eq!(rule.text, "||example.com^");
    } else {
        panic!("expected Block");
    }
}

#[test]
fn verdict_rule_line_with_preceding_comments() {
    // Line 1: comment, Line 2: blank, Line 3: comment, Line 4: the rule.
    let text = "! list header\n\n! another comment\n||example.com^\n";
    let parsed = parse_list(text);
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].line, 4);

    let mut b = EngineBuilder::new();
    b.add_list(parsed.rules);
    let e = b.build();

    if let Verdict::Block { rule, .. } = e.verdict("example.com") {
        assert_eq!(rule.line, 4);
        assert_eq!(rule.text, "||example.com^");
    } else {
        panic!("expected Block");
    }
}

#[test]
fn parse_line_numbers_sequential() {
    let text = "||first.com^\n! comment\n||second.com^\n";
    let parsed = parse_list(text);
    assert_eq!(parsed.rules.len(), 2);
    assert_eq!(parsed.rules[0].line, 1);
    assert_eq!(parsed.rules[0].text, "||first.com^");
    assert_eq!(parsed.rules[1].line, 3);
    assert_eq!(parsed.rules[1].text, "||second.com^");
}

// ---------------------------------------------------------------------------
// edge: empty / oversized query
// ---------------------------------------------------------------------------

#[test]
fn empty_query_matches_nothing() {
    let e = engine_from("||example.com^");
    assert_no_match(&e, "");
}

#[test]
fn query_over_253_bytes_matches_nothing() {
    // A name that WOULD match if the length guard were absent.
    let e = engine_from("||example.com^");
    let long = format!("{}.example.com", "a".repeat(250));
    assert!(long.len() > 253);
    assert_no_match(&e, &long);
}
