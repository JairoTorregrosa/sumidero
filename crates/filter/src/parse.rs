//! Blocklist parser: ABP-DNS subset + hosts format, mixed per line.
//!
//! The parser never allocates for a well-formed lowercase rule: it hands
//! out [`RuleRef`]s that borrow the list text, and the engine copies only
//! the bytes it keeps. A multi-million-line list is therefore parsed
//! without one heap allocation per rule (the cost that dominated startup
//! and the reload memory peak).

use std::borrow::Cow;
use std::net::IpAddr;

use crate::{IssueReason, LineIssue, ParsedList, Pattern, Rule, RuleAction};

/// Hostnames in hosts files that describe the local machine, not a block.
const LOCALHOST_NAMES: [&str; 11] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

const COSMETIC_MARKERS: [&str; 5] = ["##", "#@#", "#?#", "#$#", "#%#"];

/// A rule borrowed from the list text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleRef<'a> {
    pub action: RuleAction,
    pub pattern: PatternRef<'a>,
    /// The trimmed source line.
    pub text: &'a str,
    pub line: u32,
}

/// [`Pattern`] with a borrowed (or, for uppercase input, owned) domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatternRef<'a> {
    Exact(Cow<'a, str>),
    Subtree(Cow<'a, str>),
    Wildcard {
        expr: Cow<'a, str>,
        include_subdomains: bool,
    },
}

impl<'a> RuleRef<'a> {
    pub(crate) fn from_rule(rule: &'a Rule) -> Self {
        Self {
            action: rule.action,
            pattern: match &rule.pattern {
                Pattern::Exact(d) => PatternRef::Exact(Cow::Borrowed(d)),
                Pattern::Subtree(d) => PatternRef::Subtree(Cow::Borrowed(d)),
                Pattern::Wildcard {
                    expr,
                    include_subdomains,
                } => PatternRef::Wildcard {
                    expr: Cow::Borrowed(expr),
                    include_subdomains: *include_subdomains,
                },
            },
            text: &rule.text,
            line: rule.line,
        }
    }

    pub(crate) fn to_owned_rule(&self) -> Rule {
        Rule {
            action: self.action,
            pattern: match &self.pattern {
                PatternRef::Exact(d) => Pattern::Exact(d.to_string()),
                PatternRef::Subtree(d) => Pattern::Subtree(d.to_string()),
                PatternRef::Wildcard {
                    expr,
                    include_subdomains,
                } => Pattern::Wildcard {
                    expr: expr.to_string(),
                    include_subdomains: *include_subdomains,
                },
            },
            text: self.text.to_owned(),
            line: self.line,
        }
    }
}

/// Feed every rule of `text` to `sink`; rejected lines go to `issues`.
pub(crate) fn parse_list_streamed<'a>(
    text: &'a str,
    sink: &mut dyn FnMut(&RuleRef<'a>),
    issues: &mut Vec<LineIssue>,
) {
    for (idx, raw) in text.lines().enumerate() {
        let line_no = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        let line = raw.trim();
        if skip_or_report_comment(line, line_no, issues) {
            continue;
        }
        parse_line(line, line_no, sink, issues);
    }
}

pub(crate) fn parse_list(text: &str) -> ParsedList {
    let mut out = ParsedList::default();
    let mut rules = Vec::new();
    parse_list_streamed(
        text,
        &mut |r| rules.push(r.to_owned_rule()),
        &mut out.issues,
    );
    out.rules = rules;
    out
}

/// True when the line is blank or a comment (consumed here). Domainless
/// cosmetic rules (`##.banner`, `#@#…`, `#?#…`, `#$#…`, `#%#…`) are NOT
/// comments and are reported; `## heading` and `####` banners are.
fn skip_or_report_comment(line: &str, line_no: u32, issues: &mut Vec<LineIssue>) -> bool {
    if line.is_empty() || line.starts_with('!') {
        return true;
    }
    // `[Adblock Plus]`-style headers open most ABP lists: a format
    // marker, not a rule and not worth an issue on every load.
    if line.starts_with('[') && line.ends_with(']') {
        return true;
    }
    if line.starts_with('#') {
        let cosmetic = ["#@#", "#?#", "#$#", "#%#"]
            .iter()
            .any(|m| line.starts_with(m))
            || (line.starts_with("##")
                && line[2..]
                    .chars()
                    .next()
                    .is_some_and(|c| c != '#' && !c.is_whitespace()));
        if cosmetic {
            issues.push(LineIssue {
                line: line_no,
                text: line.to_string(),
                reason: IssueReason::CosmeticRule,
            });
        }
        return true;
    }
    false
}

fn parse_line<'a>(
    line: &'a str,
    line_no: u32,
    sink: &mut dyn FnMut(&RuleRef<'a>),
    issues: &mut Vec<LineIssue>,
) {
    let issue = |reason| LineIssue {
        line: line_no,
        text: line.to_string(),
        reason,
    };

    // Hosts line: first whitespace-separated token is an IP address
    // (possibly with a `%zone` suffix, as in `fe80::1%lo0`).
    if let Some(first) = line.split_whitespace().next()
        && let Ok(ip) = first.split('%').next().unwrap_or(first).parse::<IpAddr>()
    {
        parse_hosts_line(line, ip, line_no, sink, issues);
        return;
    }

    if COSMETIC_MARKERS.iter().any(|m| line.contains(m)) {
        issues.push(issue(IssueReason::CosmeticRule));
        return;
    }
    if line.contains('$') {
        issues.push(issue(IssueReason::UnsupportedModifier));
        return;
    }
    if line.len() > 1 && line.starts_with('/') && line.ends_with('/') {
        issues.push(issue(IssueReason::UnsupportedSyntax));
        return;
    }

    let (action, rest) = match line.strip_prefix("@@") {
        Some(rest) => (RuleAction::Except, rest),
        None => (RuleAction::Block, line),
    };
    let (subtree, rest) = match rest.strip_prefix("||") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    let rest = rest.strip_suffix('^').unwrap_or(rest);
    if rest.contains('^') || rest.starts_with('|') {
        issues.push(issue(IssueReason::UnsupportedSyntax));
        return;
    }

    let pattern = if rest.contains('*') {
        normalize_wildcard(rest).map(|expr| PatternRef::Wildcard {
            expr,
            include_subdomains: subtree,
        })
    } else {
        normalize_domain(rest).map(|domain| {
            if subtree {
                PatternRef::Subtree(domain)
            } else {
                PatternRef::Exact(domain)
            }
        })
    };
    let Some(pattern) = pattern else {
        issues.push(issue(IssueReason::InvalidDomain));
        return;
    };
    sink(&RuleRef {
        action,
        pattern,
        text: line,
        line: line_no,
    });
}

fn parse_hosts_line<'a>(
    line: &'a str,
    ip: IpAddr,
    line_no: u32,
    sink: &mut dyn FnMut(&RuleRef<'a>),
    issues: &mut Vec<LineIssue>,
) {
    // Strip a trailing `# comment` (hosts syntax only).
    let effective = line.split('#').next().unwrap_or(line).trim();
    // Localhost machinery describes the local machine regardless of the IP
    // (255.255.255.255 broadcasthost, ff02::1 ip6-allnodes, ...): skip it
    // silently before deciding whether the IP is a blockable sink.
    let is_localhost = |name: &str| {
        let bare = name.strip_suffix('.').unwrap_or(name);
        LOCALHOST_NAMES.iter().any(|l| l.eq_ignore_ascii_case(bare))
    };
    let mut names = effective
        .split_whitespace()
        .skip(1)
        .filter(|n| !is_localhost(n))
        .peekable();
    if names.peek().is_none() {
        return;
    }

    if !(ip.is_unspecified() || ip.is_loopback()) {
        issues.push(LineIssue {
            line: line_no,
            text: line.to_string(),
            reason: IssueReason::UnsupportedHostsEntry,
        });
        return;
    }
    for name in names {
        match normalize_domain(name) {
            Some(domain) => sink(&RuleRef {
                action: RuleAction::Block,
                pattern: PatternRef::Exact(domain),
                text: line,
                line: line_no,
            }),
            None => issues.push(LineIssue {
                line: line_no,
                text: line.to_string(),
                reason: IssueReason::InvalidDomain,
            }),
        }
    }
}

/// Strip one trailing dot and lowercase, borrowing when already lowercase.
fn lower_strip(s: &str) -> Cow<'_, str> {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

/// Lowercase, strip one trailing dot, validate as a DNS name.
pub(crate) fn normalize_domain(s: &str) -> Option<Cow<'_, str>> {
    let s = lower_strip(s);
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        // RFC 952/1123: labels must not start or end with a hyphen.
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    Some(s)
}

/// Like [`normalize_domain`] but the expression may contain `*`.
///
/// Requires at least one alphanumeric character: a rule matching purely on
/// stars and separators is a list bug, not a filter.
fn normalize_wildcard(s: &str) -> Option<Cow<'_, str>> {
    let s = lower_strip(s);
    if s.is_empty() || s.len() > 253 || !s.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let valid = s.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.' | b'*')
    });
    if !valid {
        return None;
    }
    // Literal segments (no `*`) are real labels and must obey label rules;
    // a pattern with an empty or hyphen-bounded literal label can never
    // match a valid DNS name and would otherwise be silently useless.
    for segment in s.split('.') {
        if segment.contains('*') {
            continue;
        }
        if segment.is_empty()
            || segment.len() > 63
            || segment.starts_with('-')
            || segment.ends_with('-')
        {
            return None;
        }
    }
    Some(s)
}
