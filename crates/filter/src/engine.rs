//! Compact compiled matcher.
//!
//! Layout, chosen for millions of rules on a small shared-memory host:
//!
//! - **Key indexes** (exact and subtree): structure-of-arrays over one
//!   byte arena, sorted by key and deduplicated, so a domain that several
//!   lists block is stored once. Subtree keys are reversed labels
//!   (`doubleclick.net` → `net.doubleclick`); a query probes each of its
//!   reversed label-boundary prefixes with a binary search.
//! - **Rule store**: per rule only list, line, flags and a text span.
//!   Canonical rule texts (`||d^`, `@@||d^`, `d`, `@@d`, `0.0.0.0 d`) are
//!   not stored: they are rebuilt from the key on the (rare) match that
//!   needs them. Only non-canonical texts live in the verbatim arena.
//! - **Wildcards**: indexed by the complete labels after their last `*`
//!   (`ads.*.example.com` → `example.com`). A wildcard can only match a
//!   name that ends with that suffix at a label boundary, so a query
//!   checks only the buckets of its own label suffixes plus the few
//!   wildcards that end in `*`. Before this, every query ran every
//!   wildcard glob: 94% of verdict time on the production rule set.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::parse::{PatternRef, RuleRef};
use crate::{MatchedRule, RuleAction, Verdict};

const FLAG_EXCEPT: u8 = 1;
/// Text form, bits 1..=3.
const FORM_SHIFT: u8 = 1;
const FORM_VERBATIM: u8 = 0;
/// `||domain^` (`@@` prefix when excepted); key = reversed domain.
const FORM_SUBTREE: u8 = 1;
/// `domain` (`@@` prefix when excepted); key = domain.
const FORM_EXACT: u8 = 2;
/// `domain^` (`@@` prefix when excepted); key = domain.
const FORM_EXACT_CARET: u8 = 3;
/// `0.0.0.0 domain`; key = domain.
const FORM_HOSTS_ZERO: u8 = 4;

/// Per-rule metadata, parallel arrays indexed by rule id.
#[derive(Debug, Default)]
struct Store {
    lists: Vec<u16>,
    lines: Vec<u32>,
    flags: Vec<u8>,
    /// Offset/length into the verbatim arena (verbatim form) or into the
    /// key arena of the rule's index (canonical forms).
    span_off: Vec<u32>,
    span_len: Vec<u8>,
    verbatim: String,
}

impl Store {
    fn push(&mut self, list: u16, line: u32, except: bool, form: u8) -> u32 {
        let id = u32::try_from(self.lines.len()).expect("more than u32::MAX rules");
        self.lists.push(list);
        self.lines.push(line);
        self.flags.push(u8::from(except) | (form << FORM_SHIFT));
        self.span_off.push(0);
        self.span_len.push(0);
        id
    }

    fn set_span(&mut self, id: u32, off: u32, len: usize) {
        self.span_off[id as usize] = off;
        self.span_len[id as usize] = u8::try_from(len).expect("rule span over 255 bytes");
    }

    fn push_verbatim(&mut self, id: u32, text: &str) {
        let off = u32::try_from(self.verbatim.len()).expect("verbatim arena exceeds 4GB");
        self.verbatim.push_str(text);
        // Rule texts are DNS names plus a few markers; anything longer is
        // truncated for display only (matching never reads this).
        let len = text.len().min(255);
        let len = (0..=len)
            .rev()
            .find(|&l| text.is_char_boundary(l))
            .unwrap_or(0);
        self.set_span(id, off, len);
    }

    fn is_except(&self, id: u32) -> bool {
        self.flags[id as usize] & FLAG_EXCEPT != 0
    }

    fn form(&self, id: u32) -> u8 {
        self.flags[id as usize] >> FORM_SHIFT
    }

    fn len(&self) -> usize {
        self.lines.len()
    }

    fn heap_bytes(&self) -> usize {
        self.lists.capacity() * 2
            + self.lines.capacity() * 4
            + self.flags.capacity()
            + self.span_off.capacity() * 4
            + self.span_len.capacity()
            + self.verbatim.capacity()
    }
}

/// Sorted, deduplicated byte keys → rule ids. Structure of arrays: a
/// 9-byte entry instead of a padded 12-byte tuple.
#[derive(Debug, Default)]
struct KeyIndex {
    arena: Vec<u8>,
    offs: Vec<u32>,
    lens: Vec<u8>,
    rules: Vec<u32>,
}

impl KeyIndex {
    fn insert(&mut self, key: &[u8], rule: u32) {
        let off = u32::try_from(self.arena.len()).expect("key arena exceeds 4GB");
        self.arena.extend_from_slice(key);
        self.offs.push(off);
        self.lens
            .push(u8::try_from(key.len()).expect("DNS names are at most 253 bytes"));
        self.rules.push(rule);
    }

    fn key(&self, i: usize) -> &[u8] {
        let off = self.offs[i] as usize;
        &self.arena[off..off + usize::from(self.lens[i])]
    }

    /// Sort by key, then rebuild the arena with each distinct key once.
    /// Calls `relocate(rule, new_off)` so rules that borrow their text
    /// from this arena follow their key.
    fn finish(&mut self, mut relocate: impl FnMut(u32, u32)) {
        let n = self.rules.len();
        let mut order: Vec<u32> = (0..u32::try_from(n).expect("index too large")).collect();
        order.sort_unstable_by(|&a, &b| self.key(a as usize).cmp(self.key(b as usize)));

        let mut arena = Vec::with_capacity(self.arena.len() / 2);
        let mut offs = Vec::with_capacity(n);
        let mut lens = Vec::with_capacity(n);
        let mut rules = Vec::with_capacity(n);
        let mut prev: Option<(usize, u32)> = None; // (sorted pos, new off)
        for (pos, &i) in order.iter().enumerate() {
            let i = i as usize;
            let new_off = match prev {
                Some((p, off)) if self.key(order[p] as usize) == self.key(i) => off,
                _ => {
                    let off = u32::try_from(arena.len()).expect("key arena exceeds 4GB");
                    arena.extend_from_slice(self.key(i));
                    prev = Some((pos, off));
                    off
                }
            };
            offs.push(new_off);
            lens.push(self.lens[i]);
            rules.push(self.rules[i]);
            relocate(self.rules[i], new_off);
        }
        arena.shrink_to_fit();
        *self = Self {
            arena,
            offs,
            lens,
            rules,
        };
    }

    /// Rule ids whose key equals `needle`.
    fn equal_range<'a>(&'a self, needle: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        let lo = partition_point(self.rules.len(), |i| self.key(i) < needle);
        (lo..self.rules.len())
            .take_while(move |&i| self.key(i) == needle)
            .map(move |i| self.rules[i])
    }

    fn heap_bytes(&self) -> usize {
        self.arena.capacity()
            + self.offs.capacity() * 4
            + self.lens.capacity()
            + self.rules.capacity() * 4
    }
}

/// `partition_point` over an index range (the keys are not a slice).
fn partition_point(len: usize, pred: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Write `domain`'s labels in reverse order into `out`
/// (`doubleclick.net` → `net.doubleclick`); returns the length.
fn reverse_labels_into(domain: &[u8], out: &mut [u8]) -> usize {
    let mut w = 0;
    for label in domain.rsplit(|&b| b == b'.') {
        if w > 0 {
            out[w] = b'.';
            w += 1;
        }
        out[w..w + label.len()].copy_from_slice(label);
        w += label.len();
    }
    w
}

#[derive(Debug)]
struct WildcardEntry {
    expr: Box<str>,
    include_subdomains: bool,
    rule: u32,
}

/// The complete labels after a wildcard's last `*`: the suffix every
/// name it can match must end with, at a label boundary.
fn wildcard_anchor(expr: &str) -> Option<&str> {
    let tail = &expr[expr.rfind('*')? + 1..];
    let dot = tail.find('.')?;
    let anchor = &tail[dot + 1..];
    (!anchor.is_empty()).then_some(anchor)
}

/// Compiled matcher for a set of parsed lists.
#[derive(Debug, Default)]
pub struct Engine {
    store: Store,
    subtree: KeyIndex,
    exact: KeyIndex,
    wildcards: Vec<WildcardEntry>,
    /// Anchor suffix → wildcard indexes.
    wildcard_buckets: HashMap<Box<str>, Vec<u32>>,
    /// Wildcards with no anchor (`ads.example.*`): checked for every name.
    wildcard_unanchored: Vec<u32>,
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

    /// Compact one rule into the current list, copying only what is kept.
    pub(crate) fn add_rule(&mut self, rule: &RuleRef<'_>) {
        let list = u16::try_from(self.list_count.saturating_sub(1)).expect("too many lists");
        let except = rule.action == RuleAction::Except;
        let body = if except {
            rule.text.strip_prefix("@@").unwrap_or(rule.text)
        } else {
            rule.text
        };
        match &rule.pattern {
            PatternRef::Subtree(domain) => {
                let canonical = body
                    .strip_prefix("||")
                    .and_then(|b| b.strip_suffix('^'))
                    .is_some_and(|d| d == domain.as_ref());
                let form = if canonical {
                    FORM_SUBTREE
                } else {
                    FORM_VERBATIM
                };
                let id = self.store.push(list, rule.line, except, form);
                let mut buf = [0u8; 256];
                let n = reverse_labels_into(domain.as_bytes(), &mut buf);
                self.subtree.insert(&buf[..n], id);
                if !canonical {
                    self.store.push_verbatim(id, rule.text);
                }
            }
            PatternRef::Exact(domain) => {
                let form = if body == domain.as_ref() {
                    FORM_EXACT
                } else if body.strip_suffix('^').is_some_and(|d| d == domain) {
                    FORM_EXACT_CARET
                } else if !except
                    && body
                        .strip_prefix("0.0.0.0")
                        .is_some_and(|d| d.len() == domain.len() + 1 && d[1..] == **domain)
                    && body.as_bytes()[7] == b' '
                {
                    FORM_HOSTS_ZERO
                } else {
                    FORM_VERBATIM
                };
                let id = self.store.push(list, rule.line, except, form);
                self.exact.insert(domain.as_bytes(), id);
                if form == FORM_VERBATIM {
                    self.store.push_verbatim(id, rule.text);
                }
            }
            PatternRef::Wildcard {
                expr,
                include_subdomains,
            } => {
                let id = self.store.push(list, rule.line, except, FORM_VERBATIM);
                self.store.push_verbatim(id, rule.text);
                let idx = u32::try_from(self.wildcards.len()).expect("too many wildcards");
                match wildcard_anchor(expr) {
                    Some(anchor) => self
                        .wildcard_buckets
                        .entry(anchor.into())
                        .or_default()
                        .push(idx),
                    None => self.wildcard_unanchored.push(idx),
                }
                self.wildcards.push(WildcardEntry {
                    expr: expr.as_ref().into(),
                    include_subdomains: *include_subdomains,
                    rule: id,
                });
            }
        }
    }

    pub(crate) fn finish(&mut self) {
        let Self {
            store,
            subtree,
            exact,
            ..
        } = self;
        subtree.finish(|rule, off| {
            if store.form(rule) == FORM_SUBTREE {
                store.span_off[rule as usize] = off;
            }
        });
        exact.finish(|rule, off| {
            if matches!(
                store.form(rule),
                FORM_EXACT | FORM_EXACT_CARET | FORM_HOSTS_ZERO
            ) {
                store.span_off[rule as usize] = off;
            }
        });
        // Canonical spans point at their key; set the key lengths now that
        // offsets are final (keys and domains have equal length).
        for i in 0..subtree.rules.len() {
            let rule = subtree.rules[i];
            if store.form(rule) == FORM_SUBTREE {
                store.span_len[rule as usize] = subtree.lens[i];
            }
        }
        for i in 0..exact.rules.len() {
            let rule = exact.rules[i];
            if matches!(
                store.form(rule),
                FORM_EXACT | FORM_EXACT_CARET | FORM_HOSTS_ZERO
            ) {
                store.span_len[rule as usize] = exact.lens[i];
            }
        }
        store.lists.shrink_to_fit();
        store.lines.shrink_to_fit();
        store.flags.shrink_to_fit();
        store.span_off.shrink_to_fit();
        store.span_len.shrink_to_fit();
        store.verbatim.shrink_to_fit();
        self.wildcards.shrink_to_fit();
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

    /// Heap bytes held by the compiled engine (for `status`).
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.store.heap_bytes()
            + self.subtree.heap_bytes()
            + self.exact.heap_bytes()
            + self
                .wildcards
                .iter()
                .map(|w| w.expr.len() + 24)
                .sum::<usize>()
            + self
                .wildcard_buckets
                .iter()
                .map(|(k, v)| k.len() + v.capacity() * 4 + 48)
                .sum::<usize>()
    }

    /// Evaluate one query name (any case, optional trailing dot).
    #[must_use]
    pub fn verdict(&self, name: &str) -> Verdict<'_> {
        // Most query names are already lowercase with no trailing dot;
        // avoid the per-query allocation for those.
        let lowered: Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
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

        for id in self.exact.equal_range(name.as_bytes()) {
            if consider(id) {
                return self.except(id);
            }
        }

        let mut buf = [0u8; 256];
        let n = reverse_labels_into(name.as_bytes(), &mut buf);
        let rev = &buf[..n];
        let boundaries = rev
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| (b == b'.').then_some(i))
            .chain(std::iter::once(n));
        for end in boundaries {
            for id in self.subtree.equal_range(&rev[..end]) {
                if consider(id) {
                    return self.except(id);
                }
            }
        }

        if !self.wildcards.is_empty() {
            let mut check = |idx: u32| -> Option<u32> {
                let w = &self.wildcards[idx as usize];
                (wildcard_matches(&w.expr, name, w.include_subdomains) && consider(w.rule))
                    .then_some(w.rule)
            };
            let mut suffix = name;
            loop {
                if let Some(bucket) = self.wildcard_buckets.get(suffix) {
                    for &idx in bucket {
                        if let Some(id) = check(idx) {
                            return self.except(id);
                        }
                    }
                }
                match suffix.find('.') {
                    Some(dot) => suffix = &suffix[dot + 1..],
                    None => break,
                }
            }
            for &idx in &self.wildcard_unanchored {
                if let Some(id) = check(idx) {
                    return self.except(id);
                }
            }
        }

        match block {
            Some(id) => {
                let (list, rule) = self.matched(id);
                Verdict::Block { list, rule }
            }
            None => Verdict::NoMatch,
        }
    }

    fn except(&self, id: u32) -> Verdict<'_> {
        let (list, rule) = self.matched(id);
        Verdict::Except { list, rule }
    }

    fn matched(&self, id: u32) -> (usize, MatchedRule<'_>) {
        let i = id as usize;
        let s = &self.store;
        let except = s.is_except(id);
        let (off, len) = (s.span_off[i] as usize, usize::from(s.span_len[i]));
        let at = if except { "@@" } else { "" };
        let text: Cow<'_, str> = match s.form(id) {
            FORM_SUBTREE => {
                let key = &self.subtree.arena[off..off + len];
                let mut buf = [0u8; 256];
                let n = reverse_labels_into(key, &mut buf);
                let domain = std::str::from_utf8(&buf[..n]).expect("keys are ASCII");
                format!("{at}||{domain}^").into()
            }
            FORM_EXACT | FORM_EXACT_CARET | FORM_HOSTS_ZERO => {
                let domain =
                    std::str::from_utf8(&self.exact.arena[off..off + len]).expect("keys are ASCII");
                match s.form(id) {
                    FORM_EXACT if except => format!("@@{domain}").into(),
                    FORM_EXACT => Cow::Borrowed(domain),
                    FORM_EXACT_CARET => format!("{at}{domain}^").into(),
                    _ => format!("0.0.0.0 {domain}").into(),
                }
            }
            _ => Cow::Borrowed(&s.verbatim[off..off + len]),
        };
        (
            usize::from(s.lists[i]),
            MatchedRule {
                action: if except {
                    RuleAction::Except
                } else {
                    RuleAction::Block
                },
                text,
                line: s.lines[i],
            },
        )
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
