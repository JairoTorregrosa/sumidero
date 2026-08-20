//! Compiled safe-search rewrite table.
//!
//! When enabled, certain search-engine query names are rewritten to their
//! safe-search CNAME targets before upstream resolution. This mirrors
//! `AdGuard` Home's local safe-search feature.

/// Known two-part country-code TLD suffixes for Google domains.
const TWO_PART_TLDS: &[&str] = &["com.br", "co.uk", "com.au", "com.mx", "co.jp", "co.in"];

/// The set of provider names this module supports.
const SUPPORTED_PROVIDERS: &[&str] = &["google", "youtube", "bing", "duckduckgo"];

/// Configuration error for the safe-search module.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// An unknown provider name was supplied.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A compiled safe-search rewrite table.
///
/// Constructed once at startup; [`rewrite`](SafeSearch::rewrite) is called on
/// every non-blocked query in the pipeline.
/// Bit flags for enabled providers (avoids clippy `struct_excessive_bools`).
const GOOGLE: u8 = 1;
const YOUTUBE: u8 = 1 << 1;
const BING: u8 = 1 << 2;
const DUCKDUCKGO: u8 = 1 << 3;
const ALL: u8 = GOOGLE | YOUTUBE | BING | DUCKDUCKGO;

#[derive(Debug)]
pub struct SafeSearch {
    enabled: u8,
}

impl SafeSearch {
    /// Build a new rewrite table.
    ///
    /// * `enabled = false` → the table is empty; [`rewrite`](Self::rewrite)
    ///   always returns `None`.
    /// * `enabled = true, providers = &[]` → **all** supported providers are
    ///   active.
    /// * Unknown provider names → [`ConfigError::Invalid`] naming the bad
    ///   provider and listing the supported ones.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if any provider name is not in the
    /// supported set.
    pub fn new(enabled: bool, providers: &[&str]) -> Result<Self, ConfigError> {
        if !enabled {
            return Ok(Self { enabled: 0 });
        }

        for p in providers {
            if !SUPPORTED_PROVIDERS.contains(p) {
                return Err(ConfigError::Invalid(format!(
                    "unknown safe-search provider \"{p}\"; supported: {}",
                    SUPPORTED_PROVIDERS.join(", "),
                )));
            }
        }

        if providers.is_empty() {
            return Ok(Self { enabled: ALL });
        }

        let mut bits: u8 = 0;
        for p in providers {
            bits |= match *p {
                "google" => GOOGLE,
                "youtube" => YOUTUBE,
                "bing" => BING,
                "duckduckgo" => DUCKDUCKGO,
                _ => unreachable!(), // validated above
            };
        }
        Ok(Self { enabled: bits })
    }

    /// If `qname` matches a safe-search rewrite rule, return the CNAME target.
    ///
    /// `qname` is assumed already normalized: lowercase, no trailing dot.
    #[must_use]
    pub fn rewrite(&self, qname: &str) -> Option<&'static str> {
        if self.enabled & YOUTUBE != 0 {
            match qname {
                "www.youtube.com"
                | "m.youtube.com"
                | "youtubei.googleapis.com"
                | "youtube.googleapis.com"
                | "www.youtube-nocookie.com" => {
                    return Some("restrictmoderate.youtube.com");
                }
                _ => {}
            }
        }

        if self.enabled & BING != 0 && qname == "www.bing.com" {
            return Some("strict.bing.com");
        }

        if self.enabled & DUCKDUCKGO != 0
            && (qname == "duckduckgo.com" || qname == "www.duckduckgo.com")
        {
            return Some("safe.duckduckgo.com");
        }

        if self.enabled & GOOGLE != 0 && is_google_search_domain(qname) {
            return Some("forcesafesearch.google.com");
        }

        None
    }
}

/// Returns `true` when `qname` is `www.google.<tld>` with a plausible TLD.
///
/// Plausible means: a known two-part TLD (e.g. `co.uk`), or a single
/// component of 2–6 ASCII-alphabetic characters.
fn is_google_search_domain(qname: &str) -> bool {
    let rest = match qname.strip_prefix("www.google.") {
        Some(r) if !r.is_empty() => r,
        _ => return false,
    };

    // Two-part country TLDs.
    if TWO_PART_TLDS.contains(&rest) {
        return true;
    }

    // Single-part TLD: 2–6 ASCII alpha characters.
    (2..=6).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructor ──────────────────────────────────────────────────

    #[test]
    fn disabled_returns_none_for_everything() {
        let ss = SafeSearch::new(false, &[]).unwrap();
        assert!(ss.rewrite("www.google.com").is_none());
        assert!(ss.rewrite("www.youtube.com").is_none());
        assert!(ss.rewrite("www.bing.com").is_none());
        assert!(ss.rewrite("duckduckgo.com").is_none());
    }

    #[test]
    fn unknown_provider_fails_loud() {
        let err = SafeSearch::new(true, &["google", "altavista"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("altavista"),
            "error should name the bad provider: {msg}"
        );
        assert!(msg.contains("google"), "error should list supported: {msg}");
        assert!(
            msg.contains("youtube"),
            "error should list supported: {msg}"
        );
    }

    #[test]
    fn empty_providers_enables_all() {
        let ss = SafeSearch::new(true, &[]).unwrap();
        assert!(ss.rewrite("www.google.com").is_some());
        assert!(ss.rewrite("www.youtube.com").is_some());
        assert!(ss.rewrite("www.bing.com").is_some());
        assert!(ss.rewrite("duckduckgo.com").is_some());
    }

    #[test]
    fn subset_only_rewrites_that_subset() {
        let ss = SafeSearch::new(true, &["bing"]).unwrap();
        assert_eq!(ss.rewrite("www.bing.com"), Some("strict.bing.com"));
        assert!(ss.rewrite("www.google.com").is_none());
        assert!(ss.rewrite("www.youtube.com").is_none());
        assert!(ss.rewrite("duckduckgo.com").is_none());
    }

    // ── Google mappings ──────────────────────────────────────────────

    #[test]
    fn google_www_dot_google_com() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert_eq!(
            ss.rewrite("www.google.com"),
            Some("forcesafesearch.google.com")
        );
    }

    #[test]
    fn google_country_tld_simple() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        for tld in ["de", "fr", "es", "it", "ru", "ca"] {
            let name = format!("www.google.{tld}");
            assert_eq!(
                ss.rewrite(&name),
                Some("forcesafesearch.google.com"),
                "should rewrite {name}"
            );
        }
    }

    #[test]
    fn google_two_part_tlds() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        for tld in TWO_PART_TLDS {
            let name = format!("www.google.{tld}");
            assert_eq!(
                ss.rewrite(&name),
                Some("forcesafesearch.google.com"),
                "should rewrite {name}"
            );
        }
    }

    #[test]
    fn google_bare_domain_no_www() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("google.com").is_none());
    }

    #[test]
    fn google_evil_prefix() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("evil-www.google.com").is_none());
    }

    #[test]
    fn google_evil_suffix() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("www.google.evil.com").is_none());
    }

    #[test]
    fn google_too_long_tld() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        // 7 alpha chars — exceeds the 2–6 rule.
        assert!(ss.rewrite("www.google.notatld").is_none());
    }

    #[test]
    fn google_dotted_evil() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("www.google.com.evil.com").is_none());
    }

    #[test]
    fn google_single_char_tld_rejected() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("www.google.x").is_none());
    }

    #[test]
    fn google_numeric_tld_rejected() {
        let ss = SafeSearch::new(true, &["google"]).unwrap();
        assert!(ss.rewrite("www.google.123").is_none());
    }

    // ── YouTube mappings ─────────────────────────────────────────────

    #[test]
    fn youtube_all_domains() {
        let ss = SafeSearch::new(true, &["youtube"]).unwrap();
        let domains = [
            "www.youtube.com",
            "m.youtube.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "www.youtube-nocookie.com",
        ];
        for d in domains {
            assert_eq!(
                ss.rewrite(d),
                Some("restrictmoderate.youtube.com"),
                "should rewrite {d}"
            );
        }
    }

    // ── Bing mapping ─────────────────────────────────────────────────

    #[test]
    fn bing_rewrite() {
        let ss = SafeSearch::new(true, &["bing"]).unwrap();
        assert_eq!(ss.rewrite("www.bing.com"), Some("strict.bing.com"));
    }

    // ── DuckDuckGo mappings ──────────────────────────────────────────

    #[test]
    fn duckduckgo_both_forms() {
        let ss = SafeSearch::new(true, &["duckduckgo"]).unwrap();
        assert_eq!(ss.rewrite("duckduckgo.com"), Some("safe.duckduckgo.com"));
        assert_eq!(
            ss.rewrite("www.duckduckgo.com"),
            Some("safe.duckduckgo.com")
        );
    }

    // ── Non-matching names ───────────────────────────────────────────

    #[test]
    fn unrelated_domain_not_rewritten() {
        let ss = SafeSearch::new(true, &[]).unwrap();
        assert!(ss.rewrite("example.com").is_none());
        assert!(ss.rewrite("www.example.com").is_none());
        assert!(ss.rewrite("google.com").is_none());
    }
}
