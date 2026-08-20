//! Compact compiled matcher.
//!
//! Memory layout is optimized for millions of rules on small hosts (the
//! deploy target is a shared 8GB Jetson): no per-node or per-rule heap
//! allocations. All rule text lives in one shared arena; subtree and
//! exact rules are sorted key spans over byte arenas resolved by binary
//! search. This replaced a HashMap-per-node label tree that cost ~400
//! bytes per rule; the arena layout costs ~65 bytes plus the text
//! itself (measured on the real 3.3M-rule list set).
//!
//! Subtree matching uses reversed-label keys: `doubleclick.net` is
//! stored as `net.doubleclick`, and a query matches if any of its
//! reversed label-boundary prefixes equals a stored key.

use crate::{MatchedRule, Pattern, Rule, RuleAction, Verdict};

/// Per-rule metadata, parallel arrays indexed by rule id.
#[derive(Debug, Default)]
struct Store {
    /// All rule texts, concatenated.
    text_arena: String,
    /// Prefix offsets into `text_arena`; rule `i` owns `off[i]..off[i+1]`.
    text_off: Vec<u32>,
    lines: Vec<u32>,
    lists: Vec<u16>,
    /// 0 = block, 1 = except.
    actions: Vec<u8>,
}

impl Store {
    fn push(&mut self, list: u16, rule: &Rule) -> u32 {
        let id = u32::try_from(self.lines.len()).expect("more than u32::MAX rules");
        self.text_arena.push_str(&rule.text);
        self.text_off
            .push(u32::try_from(self.text_arena.len()).expect("text arena exceeds 4GB"));
        self.lines.push(rule.line);
        self.lists.push(list);
        self.actions
            .push(u8::from(rule.action == RuleAction::Except));
        id
    }

    fn matched(&self, id: u32) -> (usize, MatchedRule<'_>) {
        let i = id as usize;
        let start = if i == 0 {
            0
        } else {
            self.text_off[i - 1] as usize
        };
        let end = self.text_off[i] as usize;
        let action = if self.actions[i] == 0 {
            RuleAction::Block
        } else {
            RuleAction::Except
        };
        (
            usize::from(self.lists[i]),
            MatchedRule {
                action,
                text: &self.text_arena[start..end],
                line: self.lines[i],
            },
        )
    }

    fn is_except(&self, id: u32) -> bool {
        self.actions[id as usize] == 1
    }

    fn len(&self) -> usize {
        self.lines.len()
    }
}

/// Sorted map from byte keys to rule ids, all keys in one arena.
/// Duplicate keys are allowed (same domain in several lists, or a block
/// and an exception on one domain) and stored adjacently after the sort.
#[derive(Debug, Default)]
struct KeyIndex {
    arena: Vec<u8>,
    /// (key offset, key len, rule id), sorted by key bytes after `build`.
    entries: Vec<(u32, u32, u32)>,
}

impl KeyIndex {
    fn insert(&mut self, key: &[u8], rule: u32) {
        let off = u32::try_from(self.arena.len()).expect("key arena exceeds 4GB");
        self.arena.extend_from_slice(key);
        self.entries
            .push((off, u32::try_from(key.len()).expect("key too long"), rule));
    }

    fn key(&self, entry: (u32, u32, u32)) -> &[u8] {
        &self.arena[entry.0 as usize..(entry.0 + entry.1) as usize]
    }

    fn sort(&mut self) {
        let arena = std::mem::take(&mut self.arena);
        self.entries
            .sort_unstable_by(|&a, &b| key_of(&arena, a).cmp(key_of(&arena, b)));
        self.arena = arena;
    }

    /// All rule ids whose key equals `needle`, in insertion-sorted order.
    fn equal_range<'a>(&'a self, needle: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        let start = self.entries.partition_point(|&e| self.key(e) < needle);
        self.entries[start..]
            .iter()
            .take_while(move |&&e| self.key(e) == needle)
            .map(|&(_, _, rule)| rule)
    }
}

fn key_of(arena: &[u8], e: (u32, u32, u32)) -> &[u8] {
    &arena[e.0 as usize..(e.0 + e.1) as usize]
}

/// `doubleclick.net` → `net.doubleclick` (labels reversed, dots kept).
fn reversed_labels(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len());
    for label in domain.rsplit('.') {
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(label.as_bytes());
    }
    out
}

#[derive(Debug)]
struct WildcardEntry {
    expr: Box<str>,
    include_subdomains: bool,
    rule: u32,
}

/// Compiled matcher for a set of parsed lists.
#[derive(Debug, Default)]
pub struct Engine {
    store: Store,
    subtree: KeyIndex,
    exact: KeyIndex,
    wildcards: Vec<WildcardEntry>,
    list_count: usize,
}

impl Engine {
    /// Start a new list; subsequent [`Self::add_rule`] calls belong to it.
    pub(crate) fn begin_list(&mut self) -> usize {
        let list = self.list_count;
        assert!(u16::try_from(list).is_ok(), "more than {} lists", u16::MAX);
        self.list_count += 1;
        list
    }

    /// Compact one rule into the current list.
    pub(crate) fn add_rule(&mut self, rule: &Rule) {
        let list_u16 =
            u16::try_from(self.list_count.saturating_sub(1)).expect("more than u16::MAX lists");
        let id = self.store.push(list_u16, rule);
        match &rule.pattern {
            Pattern::Exact(domain) => self.exact.insert(domain.as_bytes(), id),
            Pattern::Subtree(domain) => self.subtree.insert(&reversed_labels(domain), id),
            Pattern::Wildcard {
                expr,
                include_subdomains,
            } => self.wildcards.push(WildcardEntry {
                expr: expr.as_str().into(),
                include_subdomains: *include_subdomains,
                rule: id,
            }),
        }
    }

    /// Compact one list's rules into the engine (the rules are consumed
    /// and their per-rule allocations freed immediately).
    pub(crate) fn add_list(&mut self, rules: Vec<Rule>) -> usize {
        let list = self.begin_list();
        for rule in rules {
            self.add_rule(&rule);
        }
        list
    }

    pub(crate) fn finish(&mut self) {
        self.subtree.sort();
        self.exact.sort();
        self.store.text_arena.shrink_to_fit();
        self.store.text_off.shrink_to_fit();
        self.store.lines.shrink_to_fit();
        self.store.lists.shrink_to_fit();
        self.store.actions.shrink_to_fit();
        self.subtree.arena.shrink_to_fit();
        self.subtree.entries.shrink_to_fit();
        self.exact.arena.shrink_to_fit();
        self.exact.entries.shrink_to_fit();
    }

    /// Number of lists compiled into this engine.
    #[must_use]
    pub fn list_count(&self) -> usize {
        self.list_count
    }

    /// Total number of rules across all lists.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.store.len()
    }

    /// Evaluate one query name (any case, optional trailing dot).
    #[must_use]
    pub fn verdict(&self, name: &str) -> Verdict<'_> {
        // Fast path: most query names are already lowercase with no
        // trailing dot; avoid the per-query allocation for those.
        let lowered: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            name.to_ascii_lowercase().into()
        } else {
            name.into()
        };
        let name = lowered.strip_suffix('.').unwrap_or(&lowered);
        if name.is_empty() || name.len() > 253 {
            return Verdict::NoMatch;
        }

        let mut block: Option<u32> = None;
        // Returns true when the rule is an exception (search over).
        let mut consider = |id: u32| -> bool {
            if self.store.is_except(id) {
                true
            } else {
                block.get_or_insert(id);
                false
            }
        };

        // Exact rules.
        for id in self.exact.equal_range(name.as_bytes()) {
            if consider(id) {
                return self.except(id);
            }
        }
        // Subtree rules: each label-boundary prefix of the reversed name
        // is a candidate key.
        let rev = reversed_labels(name);
        let boundaries = rev
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| (b == b'.').then_some(i))
            .chain(std::iter::once(rev.len()));
        for end in boundaries {
            for id in self.subtree.equal_range(&rev[..end]) {
                if consider(id) {
                    return self.except(id);
                }
            }
        }
        // Wildcard rules.
        for w in &self.wildcards {
            if wildcard_matches(&w.expr, name, w.include_subdomains) && consider(w.rule) {
                return self.except(w.rule);
            }
        }

        match block {
            Some(id) => {
                let (list, rule) = self.store.matched(id);
                Verdict::Block { list, rule }
            }
            None => Verdict::NoMatch,
        }
    }

    fn except(&self, id: u32) -> Verdict<'_> {
        let (list, rule) = self.store.matched(id);
        Verdict::Except { list, rule }
    }
}

/// Does `expr` (with `*` matching any sequence, dots included) match `name`?
/// With `include_subdomains`, also try every suffix at a label boundary.
fn wildcard_matches(expr: &str, name: &str, include_subdomains: bool) -> bool {
    if glob_match(expr.as_bytes(), name.as_bytes()) {
        return true;
    }
    if include_subdomains {
        let mut rest = name;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if glob_match(expr.as_bytes(), rest.as_bytes()) {
                return true;
            }
        }
    }
    false
}

/// Classic two-pointer glob matcher; `*` matches any byte sequence.
fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pat.len() && (pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}
