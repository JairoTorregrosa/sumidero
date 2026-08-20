//! DNS response cache with hand-rolled LRU eviction.
//!
//! # Data structure
//!
//! `HashMap<CacheKey, usize>` maps each key to a slot index in a `Vec<Node>`.
//! Each `Node` carries the cached entry plus `prev`/`next` indices that form a
//! doubly-linked list ordered by recency (most-recent at head, least-recent at
//! tail). A separate free-list tracks reusable slots after eviction.
//!
//! All operations — `get`, `insert`, `evict` — are **O(1) amortized**.
//!
//! # Concurrency
//!
//! A single `std::sync::Mutex` wraps the entire structure. Entries are
//! held behind `Arc`, so the critical section of every operation is O(1)
//! pointer work: `get` clones the `Arc` under the lock and builds the
//! response message (which clones every record) outside it. Measured on
//! the 6-core Jetson: building inside the lock made six threads slower
//! in aggregate than one (276k vs 393k ops/s).
//!
//! # Size bounds
//!
//! The cache is bounded twice: by entry count (`capacity`) and by
//! estimated bytes ([`DEFAULT_MAX_BYTES`]). The process runs under a
//! hard `MemoryMax` with limited headroom, and 16k realistic
//! DNSSEC-signed entries measured 141 MB of RSS — an entry-count bound
//! alone does not bound memory. The byte estimate is wire size times a
//! measured in-memory slop factor plus fixed per-entry overhead;
//! whenever the estimated total exceeds the budget, LRU entries are
//! evicted.
//!
//! # TTL semantics
//!
//! On insert the **effective TTL** (how long the entry stays fresh) is
//! `max(min(record.ttl for each record in answer+authority), MIN_TTL_SECS)`.
//! An empty record set uses `MIN_TTL_SECS`.
//!
//! On `get`:
//! - **Fresh** (`elapsed < effective_ttl`): returns a clone with each record's
//!   TTL set to `max(original_record_ttl − elapsed, 1)`. Note: per-record TTLs
//!   are *not* clamped to `MIN_TTL_SECS`; a record whose original TTL was 10
//!   will show TTL 1 after 10 s even though the entry remains fresh for 300 s.
//! - **Stale** (`effective_ttl ≤ elapsed < effective_ttl + STALE_WINDOW_SECS`):
//!   returns a clone with all record TTLs set to `STALE_TTL_SECS` (30 s), a
//!   short fixed value that tells downstream resolvers to re-query soon.
//! - **Miss** (`elapsed ≥ effective_ttl + STALE_WINDOW_SECS`): the entry is
//!   lazily removed and `Miss` is returned.
//!
//! # `len()` semantics
//!
//! Returns the number of live slots, which is an **approximate upper bound**
//! on useful entries: it includes stale-but-servable entries and may include
//! entries that are past the stale window but have not yet been touched (and
//! thus not lazily evicted). Calling `get` on an expired key removes it.
//!
//! # Only `NOERROR` and `NXDOMAIN` are cached
//!
//! Other response codes (`SERVFAIL`, `REFUSED`, etc.) are never inserted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};

/// Minimum effective TTL in seconds. Even if every record has a lower TTL, the
/// entry stays fresh for at least this long.
pub const MIN_TTL_SECS: u64 = 300;

/// How long past the effective TTL a stale entry remains servable (seconds).
/// 30 minutes gives the upstream time to recover from a brief outage while
/// keeping the stale window bounded.
pub const STALE_WINDOW_SECS: u64 = 1800;

/// TTL set on every record in a stale response (seconds). A short value
/// signals to downstream caches/resolvers that they should re-query soon.
const STALE_TTL_SECS: u32 = 30;

/// Default budget for the estimated in-memory size of all cached
/// entries. Sized against the ~270 MB of `MemoryMax` headroom measured
/// above the reload peak (PERF.md): far more than a household working
/// set needs, small enough that a cache full of maximum-size answers
/// cannot squeeze the reload peak.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// In-memory bytes per entry ≈ wire size × this factor + fixed
/// overhead. Measured: 16,384 signed entries at ~6.1 KB wire cost
/// 141.6 MB RSS (~1.4× wire); 2× keeps the estimate conservative.
const BYTES_SLOP_FACTOR: usize = 2;

/// Fixed per-entry overhead estimate: map entry, slot, list pointers,
/// `Arc` and `Vec` bookkeeping.
const ENTRY_OVERHEAD_BYTES: usize = 512;

/// Estimate when a message fails to serialize (never seen in practice:
/// these messages were just decoded from or encoded to the wire).
const FALLBACK_WIRE_BYTES: usize = 4096;

/// Sentinel index meaning "no link" in the doubly-linked list.
const NONE: usize = usize::MAX;

// ---------------------------------------------------------------------------
// CacheKey
// ---------------------------------------------------------------------------

/// Cache lookup key: (query name, record type, DNS class).
///
/// `Name` already hashes and compares case-insensitively, so no additional
/// lowercasing is needed.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey {
    name: Name,
    rtype: RecordType,
    class: DNSClass,
}

impl CacheKey {
    /// Build a cache key.
    #[must_use]
    pub fn new(name: Name, rtype: RecordType, class: DNSClass) -> Self {
        Self { name, rtype, class }
    }
}

// ---------------------------------------------------------------------------
// Lookup result
// ---------------------------------------------------------------------------

/// Result of a cache lookup.
#[derive(Debug)]
pub enum Lookup {
    /// Entry is within its effective TTL. Record TTLs are decremented.
    Fresh(Message),
    /// Entry is past its effective TTL but within the stale window.
    /// Record TTLs are set to a fixed short value ([`STALE_TTL_SECS`]).
    Stale(Message),
    /// No usable entry (never stored, or past the stale window and removed).
    Miss,
}

// ---------------------------------------------------------------------------
// Internal node for the LRU list
// ---------------------------------------------------------------------------

/// One record in the original message, with its original TTL preserved.
#[derive(Clone)]
struct OriginalRecord {
    record: hickory_proto::rr::Record,
    original_ttl: u32,
}

/// Payload stored per cache entry.
#[derive(Clone)]
struct Entry {
    /// The response message template (answers + authorities stored with their
    /// original TTLs so we can compute decrements on get).
    answers: Vec<OriginalRecord>,
    authorities: Vec<OriginalRecord>,
    /// Metadata from the original message.
    response_code: ResponseCode,
    /// The effective TTL (already clamped to ≥ `MIN_TTL_SECS`).
    effective_ttl_secs: u64,
    /// Instant at which this entry was inserted (or last replaced).
    inserted_at: Instant,
}

/// A slot in the backing `Vec`. May be occupied or free.
enum Slot {
    Occupied(Node),
    Free { next_free: usize },
}

/// An occupied slot: entry + doubly-linked list pointers.
struct Node {
    key: CacheKey,
    entry: Arc<Entry>,
    /// Estimated in-memory size, counted against the byte budget.
    bytes: usize,
    prev: usize,
    next: usize,
}

// ---------------------------------------------------------------------------
// The LRU cache itself
// ---------------------------------------------------------------------------

struct Inner {
    map: HashMap<CacheKey, usize>,
    slots: Vec<Slot>,
    /// Index of the most-recently-used node (head of the list).
    head: usize,
    /// Index of the least-recently-used node (tail of the list).
    tail: usize,
    /// Head of the free-slot list.
    free_head: usize,
    /// Maximum number of entries.
    capacity: usize,
    /// Estimated bytes across all live entries.
    bytes_total: usize,
    /// Budget for `bytes_total`; exceeding it evicts LRU entries.
    max_bytes: usize,
}

/// Thread-safe DNS response cache with LRU eviction.
///
/// # Panics
///
/// [`Cache::new`] panics if `capacity` is zero.
pub struct Cache {
    inner: Mutex<Inner>,
}

impl Cache {
    /// Create a new cache that holds at most `capacity` entries.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero — a zero-capacity cache cannot serve any
    /// purpose and likely indicates a configuration error.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_max_bytes(capacity, DEFAULT_MAX_BYTES)
    }

    /// Create a cache bounded by `capacity` entries and `max_bytes` of
    /// estimated entry memory, whichever is hit first.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` or `max_bytes` is zero.
    #[must_use]
    pub fn with_max_bytes(capacity: usize, max_bytes: usize) -> Self {
        assert!(capacity > 0, "cache capacity must be > 0");
        assert!(max_bytes > 0, "cache byte budget must be > 0");
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(capacity),
                slots: Vec::with_capacity(capacity),
                head: NONE,
                tail: NONE,
                free_head: NONE,
                capacity,
                bytes_total: 0,
                max_bytes,
            }),
        }
    }

    /// Insert a DNS response into the cache.
    ///
    /// Only `NOERROR` and `NXDOMAIN` responses are cached; other response
    /// codes are silently ignored.
    ///
    /// If `key` already exists the entry is replaced in-place and its recency
    /// is refreshed (no double-counting against capacity).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn insert(&self, key: CacheKey, msg: &Message, now: Instant) {
        let rc = msg.metadata.response_code;
        if rc != ResponseCode::NoError && rc != ResponseCode::NXDomain {
            return;
        }

        let answers: Vec<OriginalRecord> = msg
            .answers
            .iter()
            .map(|r| OriginalRecord {
                record: r.clone(),
                original_ttl: r.ttl,
            })
            .collect();

        let authorities: Vec<OriginalRecord> = msg
            .authorities
            .iter()
            .map(|r| OriginalRecord {
                record: r.clone(),
                original_ttl: r.ttl,
            })
            .collect();

        // effective_ttl = max(min TTL across all records, MIN_TTL_SECS).
        let min_record_ttl = answers
            .iter()
            .chain(authorities.iter())
            .map(|r| u64::from(r.original_ttl))
            .min()
            .unwrap_or(MIN_TTL_SECS);

        let effective_ttl_secs = min_record_ttl.max(MIN_TTL_SECS);

        let entry = Arc::new(Entry {
            answers,
            authorities,
            response_code: rc,
            effective_ttl_secs,
            inserted_at: now,
        });
        // Estimated in-memory size, computed outside the lock. The wire
        // encoding was just produced or parsed for this message, so
        // serialization failure here is effectively unreachable.
        let bytes = msg.to_vec().map_or(FALLBACK_WIRE_BYTES, |wire| wire.len()) * BYTES_SLOP_FACTOR
            + ENTRY_OVERHEAD_BYTES;

        let mut inner = self.inner.lock().expect("cache mutex poisoned");

        // If the key already exists, update in-place and refresh recency.
        if let Some(&idx) = inner.map.get(&key) {
            if let Slot::Occupied(node) = &mut inner.slots[idx] {
                let old_bytes = node.bytes;
                node.entry = entry;
                node.bytes = bytes;
                inner.bytes_total = inner.bytes_total - old_bytes + bytes;
            }
            inner.move_to_head(idx);
            inner.evict_to_byte_budget();
            return;
        }

        // Evict if at capacity.
        if inner.map.len() >= inner.capacity {
            inner.evict_tail();
        }

        // Allocate a slot (reuse from free list or push).
        let idx = inner.alloc_slot(Node {
            key: key.clone(),
            entry,
            bytes,
            prev: NONE,
            next: NONE,
        });

        inner.map.insert(key, idx);
        inner.push_head(idx);
        inner.bytes_total += bytes;
        inner.evict_to_byte_budget();
    }

    /// Look up a cached response.
    ///
    /// Returns [`Lookup::Fresh`] with decremented TTLs, [`Lookup::Stale`]
    /// with short fixed TTLs, or [`Lookup::Miss`] (removing the entry if it
    /// was expired past the stale window).
    ///
    /// A successful lookup (Fresh or Stale) refreshes the entry's recency.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, key: &CacheKey, now: Instant) -> Lookup {
        let mut inner = self.inner.lock().expect("cache mutex poisoned");

        let Some(&idx) = inner.map.get(key) else {
            return Lookup::Miss;
        };

        let (effective_ttl_secs, inserted_at) = {
            let Slot::Occupied(node) = &inner.slots[idx] else {
                return Lookup::Miss;
            };
            (node.entry.effective_ttl_secs, node.entry.inserted_at)
        };

        let elapsed = now.duration_since(inserted_at);
        let elapsed_secs = elapsed.as_secs();

        if elapsed_secs >= effective_ttl_secs + STALE_WINDOW_SECS {
            // Past stale window — remove lazily.
            inner.remove(idx);
            return Lookup::Miss;
        }

        // Refresh recency for both fresh and stale hits.
        inner.move_to_head(idx);

        let Slot::Occupied(node) = &inner.slots[idx] else {
            return Lookup::Miss;
        };

        // Clone only the Arc under the lock; building the response
        // clones every record and must not serialize other readers.
        let entry = Arc::clone(&node.entry);
        drop(inner);

        if elapsed_secs < effective_ttl_secs {
            // Fresh: decrement per-record TTLs.
            let msg = build_response(&entry, |orig_ttl| {
                let elapsed_u32 = u32::try_from(elapsed_secs).unwrap_or(u32::MAX);
                orig_ttl.saturating_sub(elapsed_u32).max(1)
            });
            Lookup::Fresh(msg)
        } else {
            // Stale: fixed short TTL.
            let msg = build_response(&entry, |_| STALE_TTL_SECS);
            Lookup::Stale(msg)
        }
    }

    /// Number of entries currently in the cache.
    ///
    /// This is an approximate upper bound: it includes stale-but-servable
    /// entries and entries expired past the stale window that have not yet
    /// been lazily evicted by a `get` call.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("cache mutex poisoned").map.len()
    }

    /// Whether the cache contains zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Inner helpers
// ---------------------------------------------------------------------------

impl Inner {
    /// Remove a node from the linked list, map, and push it to the free list.
    fn remove(&mut self, idx: usize) {
        self.unlink(idx);
        if let Slot::Occupied(node) = &self.slots[idx] {
            // Saturation in release keeps the resolver alive if the
            // accounting ever drifts; the debug assert makes the drift
            // loud in every test run instead of silently absorbed.
            debug_assert!(
                self.bytes_total >= node.bytes,
                "cache byte accounting drifted: total {} < entry {}",
                self.bytes_total,
                node.bytes
            );
            self.bytes_total = self.bytes_total.saturating_sub(node.bytes);
            self.map.remove(&node.key);
        }
        self.slots[idx] = Slot::Free {
            next_free: self.free_head,
        };
        self.free_head = idx;
    }

    /// Evict LRU entries until the estimated bytes fit the budget.
    ///
    /// Never evicts the last remaining entry: a single answer larger
    /// than the whole budget (impossible at DNS wire sizes and any sane
    /// budget) must not loop or leave the cache useless.
    fn evict_to_byte_budget(&mut self) {
        while self.bytes_total > self.max_bytes && self.map.len() > 1 {
            self.evict_tail();
        }
    }

    /// Evict the least-recently-used entry (tail of the list).
    fn evict_tail(&mut self) {
        let tail = self.tail;
        if tail != NONE {
            self.remove(tail);
        }
    }

    /// Allocate a slot for a new node, reusing from the free list if possible.
    fn alloc_slot(&mut self, node: Node) -> usize {
        if self.free_head == NONE {
            let idx = self.slots.len();
            self.slots.push(Slot::Occupied(node));
            idx
        } else {
            let idx = self.free_head;
            if let Slot::Free { next_free } = self.slots[idx] {
                self.free_head = next_free;
            }
            self.slots[idx] = Slot::Occupied(node);
            idx
        }
    }

    /// Remove `idx` from the doubly-linked list (but do NOT free the slot).
    fn unlink(&mut self, idx: usize) {
        let Slot::Occupied(node) = &self.slots[idx] else {
            return;
        };
        let prev = node.prev;
        let next = node.next;

        if prev == NONE {
            self.head = next;
        } else if let Slot::Occupied(p) = &mut self.slots[prev] {
            p.next = next;
        }

        if next == NONE {
            self.tail = prev;
        } else if let Slot::Occupied(n) = &mut self.slots[next] {
            n.prev = prev;
        }

        if let Slot::Occupied(n) = &mut self.slots[idx] {
            n.prev = NONE;
            n.next = NONE;
        }
    }

    /// Move an existing node to the head of the list (most-recently-used).
    fn move_to_head(&mut self, idx: usize) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.push_head(idx);
    }

    /// Push `idx` as the new head of the list.
    fn push_head(&mut self, idx: usize) {
        if let Slot::Occupied(node) = &mut self.slots[idx] {
            node.prev = NONE;
            node.next = self.head;
        }
        if self.head != NONE
            && let Slot::Occupied(old_head) = &mut self.slots[self.head]
        {
            old_head.prev = idx;
        }
        self.head = idx;
        if self.tail == NONE {
            self.tail = idx;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `Message` from a cached entry, applying `ttl_fn` to compute each
/// record's TTL from its original value.
fn build_response(entry: &Entry, ttl_fn: impl Fn(u32) -> u32) -> Message {
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = entry.response_code;

    for orig in &entry.answers {
        let mut r = orig.record.clone();
        r.ttl = ttl_fn(orig.original_ttl);
        msg.add_answer(r);
    }
    for orig in &entry.authorities {
        let mut r = orig.record.clone();
        r.ttl = ttl_fn(orig.original_ttl);
        msg.add_authority(r);
    }
    msg
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};

    /// Helper: build a NOERROR response with one A record at the given TTL.
    fn noerror_a(name: &str, ttl: u32) -> Message {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let record = Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        msg.add_answer(record);
        msg
    }

    /// Helper: build a NOERROR with two answer records at different TTLs.
    fn noerror_two_records(name: &str, ttl1: u32, ttl2: u32) -> Message {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl1,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl2,
            RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
        ));
        msg
    }

    /// Helper: build an NXDOMAIN response with a SOA authority record.
    fn nxdomain(name: &str, ttl: u32) -> Message {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        // Use an A record in authority for simplicity; the cache doesn't
        // inspect RData types.
        let record = Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::UNSPECIFIED)),
        );
        msg.add_authority(record);
        msg
    }

    fn key(name: &str) -> CacheKey {
        CacheKey::new(Name::from_ascii(name).unwrap(), RecordType::A, DNSClass::IN)
    }

    // -----------------------------------------------------------------------
    // Basic insert + fresh get
    // -----------------------------------------------------------------------

    #[test]
    fn fresh_hit_returns_original_ttls_at_zero_elapsed() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);

        let result = cache.get(&k, now);
        let Lookup::Fresh(msg) = result else {
            panic!("expected Fresh");
        };
        assert_eq!(msg.answers[0].ttl, 3600);
    }

    #[test]
    fn fresh_hit_decrements_ttls() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);

        let later = now + Duration::from_secs(100);
        let Lookup::Fresh(msg) = cache.get(&k, later) else {
            panic!("expected Fresh");
        };
        assert_eq!(msg.answers[0].ttl, 3500);
    }

    #[test]
    fn fresh_hit_decremented_ttl_floors_at_1() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        // Record TTL 10, but effective_ttl = MIN_TTL_SECS = 300.
        // At elapsed = 50, the record's own TTL is 10 - 50 < 0 → floor at 1.
        cache.insert(k.clone(), &noerror_a("example.com.", 10), now);

        let later = now + Duration::from_secs(50);
        let Lookup::Fresh(msg) = cache.get(&k, later) else {
            panic!("expected Fresh — entry should be fresh for MIN_TTL_SECS");
        };
        assert_eq!(msg.answers[0].ttl, 1);
    }

    /// Entry with low record TTL stays fresh for `MIN_TTL_SECS`.
    #[test]
    fn min_ttl_clamp_raises_effective_ttl() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 10), now);

        // At elapsed = 299 it should still be Fresh.
        let at_299 = now + Duration::from_secs(MIN_TTL_SECS - 1);
        assert!(matches!(cache.get(&k, at_299), Lookup::Fresh(_)));

        // At elapsed = MIN_TTL_SECS it transitions to Stale.
        let at_min = now + Duration::from_secs(MIN_TTL_SECS);
        assert!(matches!(cache.get(&k, at_min), Lookup::Stale(_)));
    }

    /// Effective TTL is the minimum across all answer+authority records.
    #[test]
    fn effective_ttl_is_min_across_records() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(
            k.clone(),
            &noerror_two_records("example.com.", 600, 400),
            now,
        );

        // effective_ttl = max(min(600,400), 300) = 400.
        let at_399 = now + Duration::from_secs(399);
        assert!(matches!(cache.get(&k, at_399), Lookup::Fresh(_)));

        let at_400 = now + Duration::from_secs(400);
        assert!(matches!(cache.get(&k, at_400), Lookup::Stale(_)));
    }

    /// Per-record TTL decrement with two different record TTLs.
    #[test]
    fn per_record_ttl_decrement_independent() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(
            k.clone(),
            &noerror_two_records("example.com.", 600, 400),
            now,
        );

        let later = now + Duration::from_secs(100);
        let Lookup::Fresh(msg) = cache.get(&k, later) else {
            panic!("expected Fresh");
        };
        assert_eq!(msg.answers[0].ttl, 500); // 600 - 100
        assert_eq!(msg.answers[1].ttl, 300); // 400 - 100
    }

    // -----------------------------------------------------------------------
    // Stale window
    // -----------------------------------------------------------------------

    #[test]
    fn stale_within_window() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);

        // elapsed = effective_ttl (3600) → Stale
        let at_ttl = now + Duration::from_hours(1);
        let Lookup::Stale(msg) = cache.get(&k, at_ttl) else {
            panic!("expected Stale at exactly effective_ttl");
        };
        assert_eq!(msg.answers[0].ttl, STALE_TTL_SECS);
    }

    #[test]
    fn stale_at_end_of_window() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);

        // elapsed = effective_ttl + STALE_WINDOW_SECS - 1 → still Stale
        let at_end = now + Duration::from_secs(3600 + STALE_WINDOW_SECS - 1);
        assert!(matches!(cache.get(&k, at_end), Lookup::Stale(_)));
    }

    #[test]
    fn miss_past_stale_window() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);

        // elapsed = effective_ttl + STALE_WINDOW_SECS → Miss, entry removed
        let past = now + Duration::from_secs(3600 + STALE_WINDOW_SECS);
        assert!(matches!(cache.get(&k, past), Lookup::Miss));
        assert_eq!(cache.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Response code filtering
    // -----------------------------------------------------------------------

    #[test]
    fn noerror_cached() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 300), now);
        assert!(matches!(cache.get(&k, now), Lookup::Fresh(_)));
    }

    #[test]
    fn nxdomain_cached() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("nx.example.com.");
        cache.insert(k.clone(), &nxdomain("nx.example.com.", 300), now);
        let Lookup::Fresh(msg) = cache.get(&k, now) else {
            panic!("expected Fresh");
        };
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn servfail_not_cached() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("fail.example.com.");
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        cache.insert(k.clone(), &msg, now);
        assert!(matches!(cache.get(&k, now), Lookup::Miss));
    }

    #[test]
    fn refused_not_cached() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("refused.example.com.");
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::Refused;
        cache.insert(k.clone(), &msg, now);
        assert!(matches!(cache.get(&k, now), Lookup::Miss));
    }

    // -----------------------------------------------------------------------
    // LRU eviction
    // -----------------------------------------------------------------------

    #[test]
    fn eviction_removes_lru() {
        let cache = Cache::new(2);
        let now = Instant::now();

        let k1 = key("a.example.com.");
        let k2 = key("b.example.com.");
        let k3 = key("c.example.com.");

        cache.insert(k1.clone(), &noerror_a("a.example.com.", 3600), now);
        cache.insert(k2.clone(), &noerror_a("b.example.com.", 3600), now);
        // k1 is LRU. Inserting k3 should evict k1.
        cache.insert(k3.clone(), &noerror_a("c.example.com.", 3600), now);

        assert!(matches!(cache.get(&k1, now), Lookup::Miss));
        assert!(matches!(cache.get(&k2, now), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&k3, now), Lookup::Fresh(_)));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn get_refreshes_recency() {
        let cache = Cache::new(2);
        let now = Instant::now();

        let k1 = key("a.example.com.");
        let k2 = key("b.example.com.");
        let k3 = key("c.example.com.");

        cache.insert(k1.clone(), &noerror_a("a.example.com.", 3600), now);
        cache.insert(k2.clone(), &noerror_a("b.example.com.", 3600), now);

        // Access k1 so k2 becomes LRU.
        let _ = cache.get(&k1, now);

        cache.insert(k3.clone(), &noerror_a("c.example.com.", 3600), now);

        // k2 should have been evicted, not k1.
        assert!(matches!(cache.get(&k1, now), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&k2, now), Lookup::Miss));
        assert!(matches!(cache.get(&k3, now), Lookup::Fresh(_)));
    }

    #[test]
    fn capacity_one_edge() {
        let cache = Cache::new(1);
        let now = Instant::now();

        let k1 = key("a.example.com.");
        let k2 = key("b.example.com.");

        cache.insert(k1.clone(), &noerror_a("a.example.com.", 3600), now);
        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.get(&k1, now), Lookup::Fresh(_)));

        cache.insert(k2.clone(), &noerror_a("b.example.com.", 3600), now);
        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.get(&k1, now), Lookup::Miss));
        assert!(matches!(cache.get(&k2, now), Lookup::Fresh(_)));
    }

    #[test]
    fn replace_existing_updates_in_place() {
        let cache = Cache::new(2);
        let now = Instant::now();

        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 100), now);
        cache.insert(k.clone(), &noerror_a("example.com.", 500), now);

        assert_eq!(cache.len(), 1);
        let Lookup::Fresh(msg) = cache.get(&k, now) else {
            panic!("expected Fresh");
        };
        // Should have the updated TTL.
        assert_eq!(msg.answers[0].ttl, 500);
    }

    // -----------------------------------------------------------------------
    // Case-insensitive key
    // -----------------------------------------------------------------------

    #[test]
    fn case_insensitive_key() {
        let cache = Cache::new(16);
        let now = Instant::now();

        let k_lower = key("example.com.");
        let k_upper = CacheKey::new(
            Name::from_ascii("EXAMPLE.COM.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );

        cache.insert(k_lower, &noerror_a("example.com.", 3600), now);
        assert!(matches!(cache.get(&k_upper, now), Lookup::Fresh(_)));
        assert_eq!(cache.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Empty record set → MIN_TTL_SECS
    // -----------------------------------------------------------------------

    #[test]
    fn empty_record_set_uses_min_ttl() {
        let cache = Cache::new(16);
        let now = Instant::now();

        let k = key("empty.example.com.");
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        // No answers, no authorities.
        cache.insert(k.clone(), &msg, now);

        // Should be fresh for MIN_TTL_SECS.
        let at = now + Duration::from_secs(MIN_TTL_SECS - 1);
        assert!(matches!(cache.get(&k, at), Lookup::Fresh(_)));

        let at_min = now + Duration::from_secs(MIN_TTL_SECS);
        assert!(matches!(cache.get(&k, at_min), Lookup::Stale(_)));
    }

    // -----------------------------------------------------------------------
    // Byte budget
    // -----------------------------------------------------------------------

    /// A message with a payload of roughly `size` wire bytes.
    fn bulky(name: &str, size: usize) -> Message {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            3600,
            RData::Unknown {
                code: RecordType::TXT,
                rdata: hickory_proto::rr::rdata::NULL::with(vec![0x55; size]),
            },
        ));
        msg
    }

    #[test]
    fn byte_budget_evicts_lru_before_entry_count() {
        // Budget fits roughly three 4KB entries (est ≈ 8K + overhead
        // each), capacity is far larger — bytes must bind first.
        let cache = Cache::with_max_bytes(100, 30_000);
        let now = Instant::now();
        for i in 0..6u8 {
            let name = format!("b{i}.example.com.");
            cache.insert(key(&name), &bulky(&name, 4096), now);
        }
        let inner_bytes = cache.inner.lock().unwrap().bytes_total;
        assert!(
            inner_bytes <= 30_000,
            "estimated bytes must stay within budget, at {inner_bytes}"
        );
        assert!(
            cache.len() < 6,
            "byte budget must have evicted entries, len {}",
            cache.len()
        );
        // The survivors are the most recently used.
        assert!(matches!(
            cache.get(&key("b5.example.com."), now),
            Lookup::Fresh(_)
        ));
        assert!(matches!(
            cache.get(&key("b0.example.com."), now),
            Lookup::Miss
        ));
    }

    #[test]
    fn replacing_an_entry_adjusts_byte_accounting() {
        let cache = Cache::with_max_bytes(100, 1 << 20);
        let now = Instant::now();
        let k = key("swap.example.com.");
        cache.insert(k.clone(), &bulky("swap.example.com.", 16_384), now);
        let big = cache.inner.lock().unwrap().bytes_total;
        cache.insert(k.clone(), &bulky("swap.example.com.", 64), now);
        let small = cache.inner.lock().unwrap().bytes_total;
        assert!(
            small < big,
            "shrinking a replaced entry must shrink the total ({big} -> {small})"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eviction_returns_bytes_to_the_budget() {
        let cache = Cache::with_max_bytes(2, 1 << 20);
        let now = Instant::now();
        cache.insert(key("a.example.com."), &bulky("a.example.com.", 4096), now);
        cache.insert(key("b.example.com."), &bulky("b.example.com.", 4096), now);
        let two = cache.inner.lock().unwrap().bytes_total;
        // Capacity eviction: a third entry evicts the LRU.
        cache.insert(key("c.example.com."), &bulky("c.example.com.", 4096), now);
        let still_two = cache.inner.lock().unwrap().bytes_total;
        assert_eq!(cache.len(), 2);
        assert_eq!(two, still_two, "evicted entries must give their bytes back");
    }

    #[test]
    #[should_panic(expected = "byte budget must be > 0")]
    fn zero_byte_budget_panics() {
        let _ = Cache::with_max_bytes(16, 0);
    }

    // -----------------------------------------------------------------------
    // Zero capacity panics
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _ = Cache::new(0);
    }

    // -----------------------------------------------------------------------
    // len / is_empty
    // -----------------------------------------------------------------------

    #[test]
    fn len_and_is_empty() {
        let cache = Cache::new(16);
        let now = Instant::now();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let k = key("example.com.");
        cache.insert(k.clone(), &noerror_a("example.com.", 3600), now);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Concurrent access
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_access_no_deadlock_or_panic() {
        use std::sync::Arc;

        let cache = Arc::new(Cache::new(64));
        let now = Instant::now();

        // Pre-populate some entries.
        for i in 0..32u8 {
            let name = format!("{i}.example.com.");
            let k = key(&name);
            cache.insert(k, &noerror_a(&name, 3600), now);
        }

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    let base = Instant::now();
                    for i in 0..100u8 {
                        let name = format!("{}.example.com.", (t * 10 + i) % 64);
                        let k = key(&name);
                        cache.insert(k.clone(), &noerror_a(&name, 3600), base);
                        let _ = cache.get(&k, base);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert!(cache.len() <= 64);
    }

    // -----------------------------------------------------------------------
    // Stale response has correct response code
    // -----------------------------------------------------------------------

    #[test]
    fn stale_preserves_response_code() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("nx.example.com.");
        cache.insert(k.clone(), &nxdomain("nx.example.com.", 300), now);

        let stale_time = now + Duration::from_secs(MIN_TTL_SECS);
        let Lookup::Stale(msg) = cache.get(&k, stale_time) else {
            panic!("expected Stale");
        };
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    // -----------------------------------------------------------------------
    // Authority records TTL decrement
    // -----------------------------------------------------------------------

    #[test]
    fn authority_records_ttl_decremented() {
        let cache = Cache::new(16);
        let now = Instant::now();
        let k = key("auth.example.com.");
        cache.insert(k.clone(), &nxdomain("auth.example.com.", 600), now);

        let later = now + Duration::from_secs(200);
        let Lookup::Fresh(msg) = cache.get(&k, later) else {
            panic!("expected Fresh");
        };
        assert_eq!(msg.authorities[0].ttl, 400); // 600 - 200
    }
}
