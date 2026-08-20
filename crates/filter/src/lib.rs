//! Pure DNS filter engine for sumidero.
//!
//! Parses an ABP-DNS rule subset (`||domain^`, exact domains, `@@` exceptions,
//! wildcards) plus hosts-file lines, and matches query names against the
//! compiled rule set. No I/O in this crate.
//!
//! # Rule syntax (v1 subset)
//!
//! One rule per line. Leading/trailing whitespace is trimmed. Empty lines and
//! comment lines (starting with `!` or `#`) are skipped silently. `!` after a
//! rule is NOT a comment (domains cannot contain `!`, so a trailing `!...`
//! makes the line invalid); hosts lines may carry a trailing `# comment`.
//!
//! - `||example.com^` — blocks `example.com` and every subdomain. The
//!   trailing `^` is optional (`||example.com` is equivalent).
//! - `example.com` — blocks exactly `example.com` (no subdomains). One
//!   trailing `^` is stripped from any rule form, so `example.com^` is
//!   equivalent; a `^` anywhere else is unsupported syntax.
//! - `@@` prefix on either form above makes it an exception. Exceptions
//!   always win over block rules.
//! - `*` anywhere in the domain part makes the rule a wildcard; `*` matches
//!   any sequence of characters, including the empty string and dots.
//!   `||` on a wildcard rule additionally covers subdomains of any match.
//! - Hosts lines: `IP name [name...]`, optionally followed by `# comment`.
//!   If the IP is unspecified or loopback (`0.0.0.0`, `127.0.0.1`, `::`,
//!   `::1`), each name becomes an exact block rule. Well-known localhost
//!   names (`localhost`, `localhost.localdomain`, `local`, `broadcasthost`,
//!   and the `ip6-*` aliases) are skipped silently. Any other IP is an
//!   unsupported hosts entry (v1 has no rewrites) and is reported.
//!
//! Everything else is rejected loudly with a [`LineIssue`], never silently
//! dropped: cosmetic rules (`##`, `#@#`, `#?#`, `#$#`, `#%#`), rules with
//! `$modifiers`, `/regex/` rules, single-pipe anchors, and rules whose
//! domain part is not a valid DNS name.
//!
//! # Name normalization
//!
//! Rule domains and query names are ASCII-lowercased and stripped of one
//! trailing dot before matching. IDN/punycode is treated as opaque ASCII
//! labels (no Unicode mapping in v1). A query name that is empty or longer
//! than 253 bytes matches nothing.
//!
//! # Precedence
//!
//! Exception rules always beat block rules. When several rules of the same
//! action match, which one is reported in the verdict is unspecified.

mod engine;
mod parse;

pub use engine::Engine;

/// What a rule does when its pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Block the query (daemon answers NXDOMAIN).
    Block,
    /// Exception (`@@`): never block, overrides every block rule.
    Except,
}

/// How a rule's domain expression matches a query name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Matches exactly this domain (normalized lowercase, no trailing dot).
    Exact(String),
    /// Matches this domain and every subdomain (`||domain^`).
    Subtree(String),
    /// Expression containing `*`; `*` matches any character sequence
    /// (including empty and dots). With `include_subdomains` (from `||`),
    /// subdomains of any matching name also match.
    Wildcard {
        expr: String,
        include_subdomains: bool,
    },
}

/// One parsed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub action: RuleAction,
    pub pattern: Pattern,
    /// Original rule text, trimmed — for `explain` output.
    pub text: String,
    /// 1-based line number in the source list.
    pub line: u32,
}

/// Why a line was rejected.
///
/// The only `#[non_exhaustive]` enum in this crate, deliberately: new
/// rejection reasons are expected as the subset grows, while [`Pattern`],
/// [`RuleAction`], and [`Verdict`] shapes are the settled v1 contract and
/// stay exhaustively matchable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueReason {
    /// Cosmetic / element-hiding rule (`##`, `#@#`, `#?#`, `#$#`, `#%#`).
    CosmeticRule,
    /// Rule carries `$modifiers`, which v1 does not support.
    UnsupportedModifier,
    /// Hosts entry mapping to a real address (v1 has no rewrites).
    UnsupportedHostsEntry,
    /// Recognized adblock syntax outside the v1 subset (regex, anchors, ...).
    UnsupportedSyntax,
    /// The domain part is not a valid DNS name.
    InvalidDomain,
}

impl std::fmt::Display for IssueReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CosmeticRule => "cosmetic rule (not DNS filtering)",
            Self::UnsupportedModifier => "rule modifiers are not supported",
            Self::UnsupportedHostsEntry => "hosts entry maps to a real address",
            Self::UnsupportedSyntax => "syntax outside the supported subset",
            Self::InvalidDomain => "not a valid DNS name",
        };
        f.write_str(s)
    }
}

/// A rejected line: reported loudly, never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIssue {
    /// 1-based line number in the source list.
    pub line: u32,
    /// The offending line, trimmed.
    pub text: String,
    pub reason: IssueReason,
}

/// Result of streaming one list into an [`EngineBuilder`].
#[derive(Debug)]
pub struct AddedList {
    /// List index used in [`Verdict`].
    pub index: usize,
    /// Number of rules compacted into the engine.
    pub rules: usize,
    /// Rejected lines, reported loudly as always.
    pub issues: Vec<LineIssue>,
}

/// Result of parsing one list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedList {
    pub rules: Vec<Rule>,
    pub issues: Vec<LineIssue>,
}

/// Parse a whole blocklist (ABP-DNS subset and/or hosts format, mixed).
///
/// Never fails: unparseable lines land in [`ParsedList::issues`].
#[must_use]
pub fn parse_list(text: &str) -> ParsedList {
    parse::parse_list(text)
}

/// The rule that decided a verdict: a lightweight view into the
/// engine's shared storage (the engine does not keep full [`Rule`]
/// structs — at millions of rules the per-rule allocations dominated
/// memory on small hosts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedRule<'a> {
    pub action: RuleAction,
    /// Original rule text, trimmed — for `explain` output.
    pub text: &'a str,
    /// 1-based line number in the source list.
    pub line: u32,
}

/// The verdict for one query name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// No rule matched.
    NoMatch,
    /// A block rule matched (and no exception did).
    Block {
        /// Index of the list (order of [`EngineBuilder::add_list`] calls).
        list: usize,
        rule: MatchedRule<'a>,
    },
    /// An exception rule matched; overrides any block.
    Except { list: usize, rule: MatchedRule<'a> },
}

impl std::fmt::Display for LineIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {} ({})", self.line, self.text, self.reason)
    }
}

/// The rule behind a verdict, detached from the engine's lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    /// Index of the list (order of [`EngineBuilder::add_list`] calls).
    pub list: usize,
    /// 1-based line number of the rule in its list.
    pub line: u32,
    /// Original rule text.
    pub text: String,
}

/// A verdict that owns its data — for callers that must outlive the engine
/// borrow (hold it across an await, queue it for logging, serialize it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedVerdict {
    NoMatch,
    Block(RuleHit),
    Except(RuleHit),
}

impl Verdict<'_> {
    /// Copy the verdict out of the engine borrow.
    #[must_use]
    pub fn detach(&self) -> OwnedVerdict {
        let hit = |list: &usize, rule: &MatchedRule<'_>| RuleHit {
            list: *list,
            line: rule.line,
            text: rule.text.to_string(),
        };
        match self {
            Self::NoMatch => OwnedVerdict::NoMatch,
            Self::Block { list, rule } => OwnedVerdict::Block(hit(list, rule)),
            Self::Except { list, rule } => OwnedVerdict::Except(hit(list, rule)),
        }
    }
}

/// Builds an [`Engine`] from parsed lists.
///
/// Each `add_list` call compacts that list immediately and frees its
/// per-rule allocations, keeping peak memory during (re)loads low.
#[derive(Debug, Default)]
pub struct EngineBuilder {
    engine: Engine,
}

impl EngineBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one list's rules; returns the list index used in [`Verdict`].
    pub fn add_list(&mut self, rules: Vec<Rule>) -> usize {
        self.engine.add_list(rules)
    }

    /// Parse a whole list directly into compact storage, line by line,
    /// without ever materializing a `Vec<Rule>` — for memory-critical
    /// loads of multi-million-line lists. Returns the list index, the
    /// number of rules added, and the rejected lines.
    pub fn add_list_text(&mut self, text: &str) -> AddedList {
        let index = self.engine.begin_list();
        let mut rules = 0usize;
        let mut issues = Vec::new();
        parse::parse_list_streamed(
            text,
            &mut |rule| {
                rules += 1;
                self.engine.add_rule(rule);
            },
            &mut issues,
        );
        AddedList {
            index,
            rules,
            issues,
        }
    }

    /// Compile all added lists into a matcher.
    #[must_use]
    pub fn build(self) -> Engine {
        let mut engine = self.engine;
        engine.finish();
        engine
    }
}
