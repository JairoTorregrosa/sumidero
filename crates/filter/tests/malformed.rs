//! Integration tests — malformed input, comments, cosmetic rules, modifiers.
//!
//! These tests pin the **contract** from `lib.rs`.

use sumidero_filter::{EngineBuilder, IssueReason, ParsedList, parse_list};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Shorthand: parse a single line and return its `ParsedList`.
fn parse_one(line: &str) -> ParsedList {
    parse_list(line)
}

/// Assert that a `ParsedList` contains exactly one issue with the expected
/// reason, line number, and trimmed text.
fn assert_single_issue(pl: &ParsedList, reason: IssueReason, line: u32, text: &str) {
    assert!(pl.rules.is_empty(), "expected no rules, got {:?}", pl.rules);
    assert_eq!(pl.issues.len(), 1, "expected 1 issue, got {:?}", pl.issues);
    let iss = &pl.issues[0];
    assert_eq!(iss.reason, reason, "wrong reason for {text:?}");
    assert_eq!(iss.line, line, "wrong line number for {text:?}");
    assert_eq!(iss.text, text, "issue text should be trimmed original");
}

// ===========================================================================
// Empty / blank
// ===========================================================================

#[test]
fn empty_string_yields_empty_parsed_list() {
    let pl = parse_list("");
    assert_eq!(pl, ParsedList::default());
}

#[test]
fn blank_lines_produce_no_rules_no_issues() {
    let pl = parse_list("   \n\t\n  \t  \n\n");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn whitespace_only_line_is_skipped() {
    let pl = parse_one("     ");
    assert_eq!(pl.rules.len(), 0);
    assert_eq!(pl.issues.len(), 0);
}

// ===========================================================================
// Comments
// ===========================================================================

#[test]
fn bang_comment_skipped() {
    let pl = parse_one("! this is a comment");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn hash_comment_skipped() {
    let pl = parse_one("# another comment");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn bang_comment_with_leading_whitespace_skipped() {
    let pl = parse_one("  ! indented comment");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn hash_comment_with_leading_whitespace_skipped() {
    let pl = parse_one("  # indented comment");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn multiple_comments_mixed() {
    let pl = parse_list("! first\n# second\n! third\n");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

// ===========================================================================
// Adblock Plus header line
// ===========================================================================

#[test]
fn adblock_header_produces_issue() {
    // Starts with `[`, which is not a valid domain character. The contract
    // rejects "everything else" loudly. Since it does not match any specific
    // syntax bucket (cosmetic, modifier, regex, single-pipe) it falls through
    // to InvalidDomain — the domain part is simply not a valid DNS name.
    let pl = parse_one("[Adblock Plus 2.0]");
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, "[Adblock Plus 2.0]");
}

// ===========================================================================
// Cosmetic rules
// ===========================================================================

#[test]
fn cosmetic_rule_element_hiding() {
    let pl = parse_one("example.com##.banner");
    assert_single_issue(&pl, IssueReason::CosmeticRule, 1, "example.com##.banner");
}

#[test]
fn cosmetic_rule_exception() {
    let pl = parse_one("example.com#@#.ad");
    assert_single_issue(&pl, IssueReason::CosmeticRule, 1, "example.com#@#.ad");
}

#[test]
fn cosmetic_rule_extended_css() {
    let pl = parse_one("example.com#?#div");
    assert_single_issue(&pl, IssueReason::CosmeticRule, 1, "example.com#?#div");
}

#[test]
fn cosmetic_rule_snippet() {
    let pl = parse_one("example.com#$#body");
    assert_single_issue(&pl, IssueReason::CosmeticRule, 1, "example.com#$#body");
}

// ===========================================================================
// Unsupported modifiers
// ===========================================================================

#[test]
fn modifier_important_unsupported() {
    let pl = parse_one("||ads.example^$important");
    assert_single_issue(
        &pl,
        IssueReason::UnsupportedModifier,
        1,
        "||ads.example^$important",
    );
}

#[test]
fn modifier_dnstype_unsupported() {
    let pl = parse_one("||ads.example^$dnstype=AAAA");
    assert_single_issue(
        &pl,
        IssueReason::UnsupportedModifier,
        1,
        "||ads.example^$dnstype=AAAA",
    );
}

// ===========================================================================
// Unsupported syntax
// ===========================================================================

#[test]
fn regex_rule_unsupported() {
    let pl = parse_one("/banner[0-9]+/");
    assert_single_issue(&pl, IssueReason::UnsupportedSyntax, 1, "/banner[0-9]+/");
}

#[test]
fn single_pipe_anchor_unsupported() {
    let pl = parse_one("|https://example.com");
    assert_single_issue(
        &pl,
        IssueReason::UnsupportedSyntax,
        1,
        "|https://example.com",
    );
}

// ===========================================================================
// Invalid domains
// ===========================================================================

#[test]
fn empty_domain_after_pipes() {
    // `||^` → domain part is empty after stripping `||` and `^`.
    let pl = parse_one("||^");
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, "||^");
}

#[test]
fn domain_with_space_invalid() {
    let pl = parse_one("||exa mple.com^");
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, "||exa mple.com^");
}

#[test]
fn plain_garbage_invalid_domain() {
    // Contains spaces and `!`; the contract says `!` after a rule is NOT a
    // comment and makes the line invalid.
    let pl = parse_one("not a domain!");
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, "not a domain!");
}

#[test]
fn overlong_label_invalid_domain() {
    // DNS label max is 63 bytes; an overall name max is 253. A single
    // 300-byte string without dots is both an overlong label and overlong name.
    let monster = "a".repeat(300);
    let pl = parse_one(&monster);
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, &monster);
}

#[test]
fn leading_hyphen_invalid_domain() {
    // RFC 952/1123: labels must not start with a hyphen.
    let pl = parse_one("||-leadinghyphen.com^");
    assert_single_issue(&pl, IssueReason::InvalidDomain, 1, "||-leadinghyphen.com^");
}

// ===========================================================================
// Line numbering
// ===========================================================================

#[test]
fn issues_carry_correct_one_based_line_numbers() {
    let input = "! comment\n\nexample.com##.banner\n||ads.example^$important\n/banner[0-9]+/\n";
    let pl = parse_list(input);
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 3);

    // Line 3: cosmetic
    assert_eq!(pl.issues[0].line, 3);
    assert_eq!(pl.issues[0].reason, IssueReason::CosmeticRule);
    assert_eq!(pl.issues[0].text, "example.com##.banner");

    // Line 4: modifier
    assert_eq!(pl.issues[1].line, 4);
    assert_eq!(pl.issues[1].reason, IssueReason::UnsupportedModifier);
    assert_eq!(pl.issues[1].text, "||ads.example^$important");

    // Line 5: regex
    assert_eq!(pl.issues[2].line, 5);
    assert_eq!(pl.issues[2].reason, IssueReason::UnsupportedSyntax);
    assert_eq!(pl.issues[2].text, "/banner[0-9]+/");
}

// ===========================================================================
// Mixed good and bad lines (garbage never aborts parsing)
// ===========================================================================

#[test]
fn mixed_good_and_bad_returns_both_rules_and_issues() {
    let input = "\
||ads.example.com^\n\
example.com##.banner\n\
tracker.example.org\n\
/banner[0-9]+/\n\
@@||safe.example.com^\n";

    let pl = parse_list(input);

    // Good rules: lines 1, 3, 5
    assert_eq!(pl.rules.len(), 3, "expected 3 good rules: {:#?}", pl.rules);

    // Line 1: ||ads.example.com^ → subtree block
    assert_eq!(pl.rules[0].line, 1);
    assert_eq!(pl.rules[0].text, "||ads.example.com^");

    // Line 3: tracker.example.org → exact block
    assert_eq!(pl.rules[1].line, 3);
    assert_eq!(pl.rules[1].text, "tracker.example.org");

    // Line 5: @@||safe.example.com^ → subtree exception
    assert_eq!(pl.rules[2].line, 5);
    assert_eq!(pl.rules[2].text, "@@||safe.example.com^");

    // Bad lines: 2 issues
    assert_eq!(pl.issues.len(), 2, "expected 2 issues: {:#?}", pl.issues);
    assert_eq!(pl.issues[0].line, 2);
    assert_eq!(pl.issues[0].reason, IssueReason::CosmeticRule);
    assert_eq!(pl.issues[1].line, 4);
    assert_eq!(pl.issues[1].reason, IssueReason::UnsupportedSyntax);
}

// ===========================================================================
// Engine integration: bad input never aborts, good rules still work
// ===========================================================================

#[test]
fn engine_from_mixed_list_blocks_good_rule() {
    let input = "\
||ads.example.com^\n\
example.com##.banner\n";

    let pl = parse_list(input);
    assert_eq!(pl.rules.len(), 1);
    assert_eq!(pl.issues.len(), 1);

    let mut builder = EngineBuilder::new();
    let _idx = builder.add_list(pl.rules);
    let _engine = builder.build();
    // Engine builds without panic — the cosmetic issue is separate.
}

// ===========================================================================
// No panics on any malformed input (sanity)
// ===========================================================================

#[test]
fn parse_list_does_not_panic_on_assorted_garbage() {
    let samples = [
        "",
        "   ",
        "\n\n\n",
        "!",
        "#",
        "[Adblock Plus 2.0]",
        "example.com##.banner",
        "example.com#@#.ad",
        "example.com#?#div",
        "example.com#$#body",
        "||ads.example^$important",
        "||ads.example^$dnstype=AAAA",
        "/banner[0-9]+/",
        "|https://example.com",
        "||^",
        "||exa mple.com^",
        "not a domain!",
        &"x".repeat(300),
        "||-leadinghyphen.com^",
        "||*.example.com^$third-party",
        "\t  \t",
        "@@||example.com^$important",
        "\0\x01\x02",
        "||example.com^\n||bad domain ^",
    ];
    for sample in &samples {
        let _ = parse_list(sample); // must not panic
    }
}

// ===========================================================================
// Trimming behaviour
// ===========================================================================

#[test]
fn issue_text_is_trimmed() {
    let pl = parse_one("   example.com##.banner   ");
    assert_single_issue(&pl, IssueReason::CosmeticRule, 1, "example.com##.banner");
}

// ===========================================================================
// Phase 1 review findings
// ===========================================================================

#[test]
fn generic_cosmetic_rules_reported_not_swallowed() {
    // Cosmetic rules with no domain prefix start with `#` but are NOT comments.
    for line in [
        "##.banner",
        "#@#.ad",
        "#?#div",
        "#$#body{}",
        "#%#//scriptlet",
    ] {
        let pl = parse_list(line);
        assert!(pl.rules.is_empty(), "{line}: no rule expected");
        assert_eq!(pl.issues.len(), 1, "{line}: must be reported, not dropped");
        assert_eq!(pl.issues[0].reason, IssueReason::CosmeticRule, "{line}");
    }
}

#[test]
fn hash_banner_and_hash_comments_still_skipped() {
    // `#` comments, `## text` headings, and `#####` banners are comments.
    let pl = parse_list("# comment\n## Section Title\n#########\n#\n##\n##\t x");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn domain_prefixed_snippet_rule_reported() {
    let pl = parse_list("example.com#%#//scriptlet('noop')");
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::CosmeticRule);
}

#[test]
fn wildcard_with_empty_literal_label_rejected() {
    for line in ["||*..com^", "||*.example..com^", "*..com", "a..*"] {
        let pl = parse_list(line);
        assert!(pl.rules.is_empty(), "{line}: must not produce a rule");
        assert_eq!(pl.issues.len(), 1, "{line}");
        assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain, "{line}");
    }
}

#[test]
fn wildcard_with_hyphen_boundary_literal_label_rejected() {
    for line in ["||*.-example.com^", "||*.example-.com^", "*.-bad.com"] {
        let pl = parse_list(line);
        assert!(pl.rules.is_empty(), "{line}: must not produce a rule");
        assert_eq!(pl.issues.len(), 1, "{line}");
        assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain, "{line}");
    }
}

#[test]
fn wildcard_starred_segments_stay_unconstrained() {
    // Segments containing `*` are not label-validated; literal ones are.
    let pl = parse_list("||ads.*^\n*.tracker.com\ntr*ck.com\n*ad*.com");
    assert_eq!(pl.rules.len(), 4);
    assert!(pl.issues.is_empty());
}

#[test]
fn label_longer_than_63_bytes_rejected() {
    let long = "a".repeat(64);
    let pl = parse_list(&format!("||{long}.com^"));
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain);
    // 63 bytes is still fine.
    let ok = "a".repeat(63);
    let pl = parse_list(&format!("||{ok}.com^"));
    assert_eq!(pl.rules.len(), 1);
    assert!(pl.issues.is_empty());
}

#[test]
fn trailing_hyphen_label_rejected() {
    let pl = parse_list("||trailinghyphen-.com^");
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain);
}

#[test]
fn inner_caret_unsupported_syntax() {
    let pl = parse_list("||ex^ample.com^");
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::UnsupportedSyntax);
}

#[test]
fn underscore_domains_accepted() {
    let pl = parse_list("_dmarc.example.com\n||_srv.example.com^");
    assert_eq!(pl.rules.len(), 2);
    assert!(pl.issues.is_empty());
}

#[test]
fn punycode_treated_as_opaque_ascii() {
    let pl = parse_list("xn--bcher-kva.example");
    assert_eq!(pl.rules.len(), 1);
    assert!(pl.issues.is_empty());
    // The Unicode form is not valid ASCII and is rejected, per contract.
    let pl = parse_list("bücher.example");
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain);
}

#[test]
fn accepted_rule_text_is_trimmed() {
    let pl = parse_list("   ||example.com^\t ");
    assert_eq!(pl.rules.len(), 1);
    assert_eq!(pl.rules[0].text, "||example.com^");
}
