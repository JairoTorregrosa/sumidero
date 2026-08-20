#![allow(clippy::needless_pass_by_value)]

use sumidero_filter::{
    EngineBuilder, IssueReason, ParsedList, Pattern, Rule, RuleAction, Verdict, parse_list,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn build_engine(text: &str) -> (sumidero_filter::Engine, ParsedList) {
    let parsed = parse_list(text);
    let rules = parsed.rules.clone();
    let mut builder = EngineBuilder::new();
    builder.add_list(rules);
    let engine = builder.build();
    (engine, parsed)
}

fn exact_block_rule<'a>(parsed: &'a ParsedList, domain: &str) -> &'a Rule {
    parsed
        .rules
        .iter()
        .find(|r| r.action == RuleAction::Block && r.pattern == Pattern::Exact(domain.to_owned()))
        .unwrap_or_else(|| panic!("no exact block rule for {domain}"))
}

// ---------------------------------------------------------------------------
// IP prefix variants
// ---------------------------------------------------------------------------

#[test]
fn hosts_0000_yields_exact_block() {
    let parsed = parse_list("0.0.0.0 example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    let r = &parsed.rules[0];
    assert_eq!(r.action, RuleAction::Block);
    assert_eq!(r.pattern, Pattern::Exact("example.com".into()));
    assert_eq!(r.line, 1);
}

#[test]
fn hosts_127001_yields_exact_block() {
    let parsed = parse_list("127.0.0.1 example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    let r = &parsed.rules[0];
    assert_eq!(r.action, RuleAction::Block);
    assert_eq!(r.pattern, Pattern::Exact("example.com".into()));
}

#[test]
fn hosts_ipv6_unspecified_yields_exact_block() {
    let parsed = parse_list(":: example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    let r = &parsed.rules[0];
    assert_eq!(r.action, RuleAction::Block);
    assert_eq!(r.pattern, Pattern::Exact("example.com".into()));
}

#[test]
fn hosts_ipv6_loopback_yields_exact_block() {
    let parsed = parse_list("::1 example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    let r = &parsed.rules[0];
    assert_eq!(r.action, RuleAction::Block);
    assert_eq!(r.pattern, Pattern::Exact("example.com".into()));
}

// ---------------------------------------------------------------------------
// multiple hostnames on one line
// ---------------------------------------------------------------------------

#[test]
fn hosts_multiple_names_yield_one_rule_each() {
    let parsed = parse_list("0.0.0.0 a.example.com b.example.com c.example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 3);
    for r in &parsed.rules {
        assert_eq!(r.action, RuleAction::Block);
        assert!(matches!(&r.pattern, Pattern::Exact(_)));
    }
    let names: Vec<&str> = parsed
        .rules
        .iter()
        .map(|r| match &r.pattern {
            Pattern::Exact(d) => d.as_str(),
            _ => panic!("expected Exact"),
        })
        .collect();
    assert!(names.contains(&"a.example.com"));
    assert!(names.contains(&"b.example.com"));
    assert!(names.contains(&"c.example.com"));
}

// ---------------------------------------------------------------------------
// trailing comments
// ---------------------------------------------------------------------------

#[test]
fn hosts_trailing_comment_stripped() {
    let parsed = parse_list("0.0.0.0 ads.example.com # block ads");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("ads.example.com".into())
    );
}

// ---------------------------------------------------------------------------
// tabs and repeated spaces
// ---------------------------------------------------------------------------

#[test]
fn hosts_tab_separator() {
    let parsed = parse_list("0.0.0.0\texample.com");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("example.com".into())
    );
}

#[test]
fn hosts_multiple_spaces_separator() {
    let parsed = parse_list("0.0.0.0    example.com");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("example.com".into())
    );
}

#[test]
fn hosts_mixed_whitespace() {
    let parsed = parse_list("0.0.0.0 \t  example.com \t  foo.com  ");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 2);
}

// ---------------------------------------------------------------------------
// well-known localhost names skipped silently
// ---------------------------------------------------------------------------

#[test]
fn hosts_localhost_skipped() {
    let parsed = parse_list("127.0.0.1 localhost");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_localhost_localdomain_skipped() {
    let parsed = parse_list("127.0.0.1 localhost.localdomain");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_local_skipped() {
    let parsed = parse_list("127.0.0.1 local");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_broadcasthost_skipped() {
    let parsed = parse_list("127.0.0.1 broadcasthost");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_ip6_localhost_skipped() {
    let parsed = parse_list("::1 ip6-localhost");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_ip6_loopback_skipped() {
    let parsed = parse_list("::1 ip6-loopback");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_ip6_allnodes_skipped() {
    let parsed = parse_list(":: ip6-allnodes");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_ip6_allrouters_skipped() {
    let parsed = parse_list(":: ip6-allrouters");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 0);
}

#[test]
fn hosts_line_with_localhost_plus_real_name() {
    // localhost is skipped, real name produces a rule
    let parsed = parse_list("0.0.0.0 localhost ads.example.com");
    assert_eq!(parsed.issues.len(), 0);
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].pattern,
        Pattern::Exact("ads.example.com".into())
    );
}

// ---------------------------------------------------------------------------
// realistic hosts-file header
// ---------------------------------------------------------------------------

#[test]
fn hosts_realistic_header_zero_rules_zero_issues() {
    let header = "\
# Host file generated by SomeBlocker
# Last updated: 2026-01-01
#
# This file is used to block ads and trackers.

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
0.0.0.0 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
:: ip6-allnodes
:: ip6-allrouters
";
    let parsed = parse_list(header);
    assert_eq!(parsed.rules.len(), 0, "rules: {:#?}", parsed.rules);
    assert_eq!(parsed.issues.len(), 0, "issues: {:#?}", parsed.issues);
}

// ---------------------------------------------------------------------------
// real IP -> unsupported hosts entry
// ---------------------------------------------------------------------------

#[test]
fn hosts_real_ip_unsupported() {
    let parsed = parse_list("1.2.3.4 example.com");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 1);
    assert_eq!(parsed.issues[0].reason, IssueReason::UnsupportedHostsEntry);
    assert_eq!(parsed.issues[0].line, 1);
}

#[test]
fn hosts_real_ipv6_unsupported() {
    let parsed = parse_list("2001:db8::1 example.com");
    assert_eq!(parsed.rules.len(), 0);
    assert_eq!(parsed.issues.len(), 1);
    assert_eq!(parsed.issues[0].reason, IssueReason::UnsupportedHostsEntry);
}

// ---------------------------------------------------------------------------
// mixed hosts + ABP lines
// ---------------------------------------------------------------------------

#[test]
fn mixed_hosts_and_abp_lines() {
    let input = "\
0.0.0.0 ads.tracker.com
||analytics.example.com^
127.0.0.1 spy.example.com
example.net
";
    let parsed = parse_list(input);
    assert_eq!(parsed.issues.len(), 0);
    // 3 block rules from hosts + 1 subtree from ABP + 1 exact from ABP
    assert_eq!(parsed.rules.len(), 4);

    // hosts-derived rules are exact blocks
    let _ = exact_block_rule(&parsed, "ads.tracker.com");
    let _ = exact_block_rule(&parsed, "spy.example.com");

    // ABP subtree
    let subtree = parsed
        .rules
        .iter()
        .find(|r| r.pattern == Pattern::Subtree("analytics.example.com".into()))
        .expect("subtree rule missing");
    assert_eq!(subtree.action, RuleAction::Block);

    // ABP exact
    let _ = exact_block_rule(&parsed, "example.net");
}

// ---------------------------------------------------------------------------
// hosts-derived rules match exactly: subdomains do NOT match
// ---------------------------------------------------------------------------

#[test]
fn hosts_exact_no_subdomain_match() {
    let (engine, _parsed) = build_engine("0.0.0.0 example.com");

    // exact match
    assert!(matches!(
        engine.verdict("example.com"),
        Verdict::Block { .. }
    ));

    // subdomain must NOT match
    assert!(matches!(
        engine.verdict("sub.example.com"),
        Verdict::NoMatch
    ));
    assert!(matches!(
        engine.verdict("a.b.example.com"),
        Verdict::NoMatch
    ));
}

#[test]
fn hosts_exact_case_insensitive() {
    let (engine, _parsed) = build_engine("0.0.0.0 Example.COM");
    assert!(matches!(
        engine.verdict("example.com"),
        Verdict::Block { .. }
    ));
    assert!(matches!(
        engine.verdict("EXAMPLE.COM"),
        Verdict::Block { .. }
    ));
}

// ---------------------------------------------------------------------------
// line numbers on hosts-derived rules
// ---------------------------------------------------------------------------

#[test]
fn hosts_line_numbers_correct() {
    let input = "\
# header comment
0.0.0.0 first.example.com
127.0.0.1 localhost
0.0.0.0 second.example.com
";
    let parsed = parse_list(input);
    assert_eq!(parsed.rules.len(), 2);

    let first = exact_block_rule(&parsed, "first.example.com");
    assert_eq!(first.line, 2);

    let second = exact_block_rule(&parsed, "second.example.com");
    assert_eq!(second.line, 4);
}

#[test]
fn hosts_multiple_names_on_line_share_line_number() {
    let input = "0.0.0.0 a.com b.com c.com";
    let parsed = parse_list(input);
    assert_eq!(parsed.rules.len(), 3);
    for r in &parsed.rules {
        assert_eq!(r.line, 1);
    }
}

// ---------------------------------------------------------------------------
// Localhost machinery with non-loopback IPs (real /etc/hosts headers)
// ---------------------------------------------------------------------------

#[test]
fn broadcasthost_with_broadcast_ip_skipped_silently() {
    let pl = parse_list("255.255.255.255 broadcasthost");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn ipv6_multicast_localhost_machinery_skipped_silently() {
    let pl = parse_list(
        "ff00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters",
    );
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn zone_id_loopback_localhost_skipped_silently() {
    let pl = parse_list("fe80::1%lo0 localhost");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn real_ip_with_real_hostname_still_reported() {
    let pl = parse_list("255.255.255.255 example.com");
    assert!(pl.rules.is_empty());
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::UnsupportedHostsEntry);
}

#[test]
fn hosts_sink_ip_with_invalid_hostname_reported() {
    let pl = parse_list("0.0.0.0 good.com -bad.com");
    assert_eq!(pl.rules.len(), 1);
    assert_eq!(pl.issues.len(), 1);
    assert_eq!(pl.issues[0].reason, IssueReason::InvalidDomain);
}

#[test]
fn hosts_bare_ip_line_skipped_silently() {
    let pl = parse_list("0.0.0.0\n127.0.0.1");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}

#[test]
fn ip6_allhosts_skipped_silently() {
    let pl = parse_list(":: ip6-allhosts");
    assert!(pl.rules.is_empty());
    assert!(pl.issues.is_empty());
}
