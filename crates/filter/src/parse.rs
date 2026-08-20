//! Blocklist parser: ABP-DNS subset + hosts format, mixed per line.

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

/// Line-by-line parse feeding each rule to `sink` instead of collecting
/// them; issues accumulate in `issues`. The non-streaming [`parse_list`]
/// is this with a Vec sink.
pub(crate) fn parse_list_streamed(
    text: &str,
    sink: &mut dyn FnMut(&crate::Rule),
    issues: &mut Vec<LineIssue>,
) {
    let mut scratch = ParsedList::default();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        let line = raw.trim();
        if skip_or_report_comment(line, line_no, issues) {
            continue;
        }
        parse_line(line, line_no, &mut scratch);
        for rule in scratch.rules.drain(..) {
            sink(&rule);
        }
        issues.append(&mut scratch.issues);
    }
}

pub(crate) fn parse_list(text: &str) -> ParsedList {
    let mut out = ParsedList::default();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        let line = raw.trim();
        if skip_or_report_comment(line, line_no, &mut out.issues) {
            continue;
        }
        parse_line(line, line_no, &mut out);
    }
    out
}

/// True when the line is blank or a comment (consumed here). Domainless
/// cosmetic rules (`##.banner`, `#@#…`, `#?#…`, `#$#…`, `#%#…`) are NOT
/// comments and are reported; `## heading` and `####` banners are.
fn skip_or_report_comment(line: &str, line_no: u32, issues: &mut Vec<LineIssue>) -> bool {
    if line.is_empty() || line.starts_with('!') {
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

fn parse_line(line: &str, line_no: u32, out: &mut ParsedList) {
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
        parse_hosts_line(line, ip, line_no, out);
        return;
    }

    if COSMETIC_MARKERS.iter().any(|m| line.contains(m)) {
        out.issues.push(issue(IssueReason::CosmeticRule));
        return;
    }
    if line.contains('$') {
        out.issues.push(issue(IssueReason::UnsupportedModifier));
        return;
    }
    if line.len() > 1 && line.starts_with('/') && line.ends_with('/') {
        out.issues.push(issue(IssueReason::UnsupportedSyntax));
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
        out.issues.push(issue(IssueReason::UnsupportedSyntax));
        return;
    }

    let pattern = if rest.contains('*') {
        normalize_wildcard(rest).map(|expr| Pattern::Wildcard {
            expr,
            include_subdomains: subtree,
        })
    } else {
        normalize_domain(rest).map(|domain| {
            if subtree {
                Pattern::Subtree(domain)
            } else {
                Pattern::Exact(domain)
            }
        })
    };
    let Some(pattern) = pattern else {
        out.issues.push(issue(IssueReason::InvalidDomain));
        return;
    };
    out.rules.push(Rule {
        action,
        pattern,
        text: line.to_string(),
        line: line_no,
    });
}

fn parse_hosts_line(line: &str, ip: IpAddr, line_no: u32, out: &mut ParsedList) {
    // Strip a trailing `# comment` (hosts syntax only).
    let effective = line.split('#').next().unwrap_or(line).trim();
    // Localhost machinery describes the local machine regardless of the IP
    // (255.255.255.255 broadcasthost, ff02::1 ip6-allnodes, ...): skip it
    // silently before deciding whether the IP is a blockable sink.
    let names: Vec<&str> = effective
        .split_whitespace()
        .skip(1)
        .filter(|name| {
            let lowered = name.to_ascii_lowercase();
            let bare = lowered.strip_suffix('.').unwrap_or(&lowered).to_string();
            !LOCALHOST_NAMES.contains(&bare.as_str())
        })
        .collect();
    if names.is_empty() {
        return;
    }

    if !(ip.is_unspecified() || ip.is_loopback()) {
        out.issues.push(LineIssue {
            line: line_no,
            text: line.to_string(),
            reason: IssueReason::UnsupportedHostsEntry,
        });
        return;
    }
    for name in names {
        match normalize_domain(name) {
            Some(domain) => out.rules.push(Rule {
                action: RuleAction::Block,
                pattern: Pattern::Exact(domain),
                text: line.to_string(),
                line: line_no,
            }),
            None => out.issues.push(LineIssue {
                line: line_no,
                text: line.to_string(),
                reason: IssueReason::InvalidDomain,
            }),
        }
    }
}

/// Lowercase, strip one trailing dot, validate as a DNS name.
pub(crate) fn normalize_domain(s: &str) -> Option<String> {
    let s = s.to_ascii_lowercase();
    let s = s.strip_suffix('.').unwrap_or(&s);
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
    Some(s.to_string())
}

/// Like [`normalize_domain`] but the expression may contain `*`.
///
/// Requires at least one alphanumeric character: a rule matching purely on
/// stars and separators is a list bug, not a filter.
fn normalize_wildcard(s: &str) -> Option<String> {
    let s = s.to_ascii_lowercase();
    let s = s.strip_suffix('.').unwrap_or(&s);
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
    Some(s.to_string())
}
