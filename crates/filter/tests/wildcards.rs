//! Integration tests — wildcard rules (`*` in the domain part).

use sumidero_filter::{EngineBuilder, Pattern, RuleAction, Verdict, parse_list};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an engine from a single rule list given as text and return the verdict
/// for `name`.
fn verdict_for(rules: &str, name: &str) -> VerdictKind {
    let parsed = parse_list(rules);
    assert!(
        parsed.issues.is_empty(),
        "unexpected issues: {:?}",
        parsed.issues
    );
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let engine = builder.build();
    match engine.verdict(name) {
        Verdict::NoMatch => VerdictKind::NoMatch,
        Verdict::Block { .. } => VerdictKind::Block,
        Verdict::Except { .. } => VerdictKind::Except,
    }
}

/// Simplified verdict for assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerdictKind {
    NoMatch,
    Block,
    Except,
}

// ---------------------------------------------------------------------------
// *.tracker.com — star before a literal dot
// ---------------------------------------------------------------------------

#[test]
fn star_dot_prefix_matches_single_subdomain() {
    assert_eq!(
        verdict_for("*.tracker.com", "a.tracker.com"),
        VerdictKind::Block
    );
}

#[test]
fn star_dot_prefix_matches_deep_subdomain() {
    // `*` spans dots, so a.b.tracker.com matches via `*.tracker.com`.
    assert_eq!(
        verdict_for("*.tracker.com", "a.b.tracker.com"),
        VerdictKind::Block
    );
}

#[test]
fn star_dot_prefix_does_not_match_apex() {
    // `*.tracker.com` requires at least a literal `.` before `tracker.com`,
    // so the apex itself must NOT match.
    assert_eq!(
        verdict_for("*.tracker.com", "tracker.com"),
        VerdictKind::NoMatch
    );
}

// ---------------------------------------------------------------------------
// ads* — star at end of pattern (prefix wildcard)
// ---------------------------------------------------------------------------

#[test]
fn trailing_star_matches_exact_prefix_with_tld() {
    assert_eq!(verdict_for("ads*", "ads.example.com"), VerdictKind::Block);
}

#[test]
fn trailing_star_matches_longer_name() {
    assert_eq!(verdict_for("ads*", "adserver.net"), VerdictKind::Block);
}

#[test]
fn trailing_star_no_match_unrelated() {
    assert_eq!(verdict_for("ads*", "example.com"), VerdictKind::NoMatch);
}

// ---------------------------------------------------------------------------
// ||ads.*^ — wildcard with include_subdomains
// ---------------------------------------------------------------------------

#[test]
fn pipe_wildcard_matches_ads_example() {
    assert_eq!(verdict_for("||ads.*^", "ads.example"), VerdictKind::Block);
}

#[test]
fn pipe_wildcard_matches_ads_co_uk() {
    assert_eq!(verdict_for("||ads.*^", "ads.co.uk"), VerdictKind::Block);
}

#[test]
fn pipe_wildcard_matches_subdomain_of_match() {
    // `||` on a wildcard additionally covers subdomains of any match.
    assert_eq!(
        verdict_for("||ads.*^", "sub.ads.example"),
        VerdictKind::Block
    );
}

#[test]
fn pipe_wildcard_no_match_unrelated() {
    assert_eq!(verdict_for("||ads.*^", "example.com"), VerdictKind::NoMatch);
}

// ---------------------------------------------------------------------------
// Mid-name star: tr*ck.com
// ---------------------------------------------------------------------------

#[test]
fn mid_star_matches_track() {
    assert_eq!(verdict_for("tr*ck.com", "track.com"), VerdictKind::Block);
}

#[test]
fn mid_star_matches_trick() {
    assert_eq!(verdict_for("tr*ck.com", "trick.com"), VerdictKind::Block);
}

#[test]
fn mid_star_matches_truck() {
    assert_eq!(verdict_for("tr*ck.com", "truck.com"), VerdictKind::Block);
}

#[test]
fn mid_star_matches_empty_span() {
    // `*` matches the empty string, so `trck.com` matches `tr*ck.com`.
    assert_eq!(verdict_for("tr*ck.com", "trck.com"), VerdictKind::Block);
}

#[test]
fn mid_star_no_match_different_suffix() {
    assert_eq!(verdict_for("tr*ck.com", "track.net"), VerdictKind::NoMatch);
}

// ---------------------------------------------------------------------------
// Multiple stars: *ad*.com
// ---------------------------------------------------------------------------

#[test]
fn multi_star_matches_ads_example_com() {
    assert_eq!(
        verdict_for("*ad*.com", "ads.example.com"),
        VerdictKind::Block
    );
}

#[test]
fn multi_star_matches_badads_com() {
    assert_eq!(verdict_for("*ad*.com", "badads.com"), VerdictKind::Block);
}

#[test]
fn multi_star_matches_ad_com() {
    // Both stars match empty.
    assert_eq!(verdict_for("*ad*.com", "ad.com"), VerdictKind::Block);
}

#[test]
fn multi_star_no_match_wrong_tld() {
    assert_eq!(verdict_for("*ad*.com", "ads.net"), VerdictKind::NoMatch);
}

// ---------------------------------------------------------------------------
// Wildcard exception overriding a block
// ---------------------------------------------------------------------------

#[test]
fn wildcard_exception_unblocks_subdomains() {
    // Block apex `||metrics.example^`, but except subdomains via `@@||*.metrics.example^`.
    let rules = "||metrics.example^\n@@||*.metrics.example^";
    // A subdomain is excepted.
    assert_eq!(
        verdict_for(rules, "sub.metrics.example"),
        VerdictKind::Except
    );
}

#[test]
fn wildcard_exception_apex_stays_blocked() {
    // The exception is `@@||*.metrics.example^` — requires something before
    // the dot, so the apex itself stays blocked.
    let rules = "||metrics.example^\n@@||*.metrics.example^";
    assert_eq!(verdict_for(rules, "metrics.example"), VerdictKind::Block);
}

#[test]
fn wildcard_exception_deep_subdomain_excepted() {
    let rules = "||metrics.example^\n@@||*.metrics.example^";
    // `||` on the exception adds include_subdomains, so deep sub is excepted
    // (it matches *.metrics.example, and || adds sub-coverage).
    assert_eq!(
        verdict_for(rules, "a.b.metrics.example"),
        VerdictKind::Except
    );
}

// ---------------------------------------------------------------------------
// parse_list shape: Pattern::Wildcard fields
// ---------------------------------------------------------------------------

#[test]
fn parse_wildcard_without_pipes_yields_no_subdomains() {
    let parsed = parse_list("*.tracker.com");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Block);
    match &rule.pattern {
        Pattern::Wildcard {
            expr,
            include_subdomains,
        } => {
            assert_eq!(expr, "*.tracker.com");
            assert!(!include_subdomains);
        }
        other => panic!("expected Wildcard, got {other:?}"),
    }
}

#[test]
fn parse_wildcard_with_pipes_yields_include_subdomains() {
    let parsed = parse_list("||ads.*^");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Block);
    match &rule.pattern {
        Pattern::Wildcard {
            expr,
            include_subdomains,
        } => {
            assert_eq!(expr, "ads.*");
            assert!(include_subdomains);
        }
        other => panic!("expected Wildcard, got {other:?}"),
    }
}

#[test]
fn parse_wildcard_exception_with_pipes() {
    let parsed = parse_list("@@||*.metrics.example^");
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.action, RuleAction::Except);
    match &rule.pattern {
        Pattern::Wildcard {
            expr,
            include_subdomains,
        } => {
            assert_eq!(expr, "*.metrics.example");
            assert!(include_subdomains);
        }
        other => panic!("expected Wildcard, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Case-insensitive wildcard matching
// ---------------------------------------------------------------------------

#[test]
fn wildcard_matching_is_case_insensitive() {
    assert_eq!(
        verdict_for("*.tracker.com", "A.TRACKER.COM"),
        VerdictKind::Block
    );
}

#[test]
fn wildcard_matching_mixed_case() {
    assert_eq!(verdict_for("ads*", "AdServer.NET"), VerdictKind::Block);
}

// ---------------------------------------------------------------------------
// Star matching the empty string
// ---------------------------------------------------------------------------

#[test]
fn star_matches_empty_trailing() {
    // `ads*.com` — the star matches empty, so `ads.com` matches.
    assert_eq!(verdict_for("ads*.com", "ads.com"), VerdictKind::Block);
}

#[test]
fn star_matches_nonempty_trailing() {
    assert_eq!(verdict_for("ads*.com", "adsserver.com"), VerdictKind::Block);
}

#[test]
fn star_matches_dot_in_trailing() {
    // Star spans dots.
    assert_eq!(
        verdict_for("ads*.com", "ads.tracker.com"),
        VerdictKind::Block
    );
}
