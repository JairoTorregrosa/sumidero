//! Safe-search enforcement: CNAME rewrites for search engines.
//!
//! When a provider is enabled, its search hostnames are answered locally
//! as a CNAME to the provider's enforced endpoint (the method each
//! provider documents for networks), followed by the endpoint's records.
//!
//! Host sets, verified 2026-10-31 against the providers' own pages and
//! `AdGuard` Home v0.107.79 `internal/filtering/safesearch/rules/`:
//!
//! - Google: `www.google.<tld>` for every domain in
//!   <https://www.google.com/supported_domains> (187, includes
//!   `com.co`) plus the 7 extra TLDs `AdGuard` Home also rewrites, to
//!   `forcesafesearch.google.com`.
//! - `YouTube`: the 5 hosts Google lists for Restricted Mode, to
//!   `restrictmoderate.youtube.com` (Moderate, as `AdGuard` Home).
//! - Bing: `www.bing.com`, `edgeservices.bing.com` to `strict.bing.com`.
//! - `DuckDuckGo`: `duckduckgo.com`, `www.`, `start.` to
//!   `safe.duckduckgo.com`.

/// Providers this module knows, in the order they are documented.
pub const SUPPORTED_PROVIDERS: &[&str] = &["google", "youtube", "bing", "duckduckgo"];

/// Google search TLDs (`www.google.<tld>`), sorted for binary search.
const GOOGLE_TLDS: &[&str] = &[
    "ad", "ae", "al", "am", "as", "at", "az", "ba", "be", "bf", "bg", "bi", "bj", "bs", "bt", "by",
    "ca", "cat", "cd", "cf", "cg", "ch", "ci", "cl", "cm", "cn", "co", "co.ao", "co.bw", "co.ck",
    "co.cr", "co.id", "co.il", "co.in", "co.jp", "co.ke", "co.kr", "co.ls", "co.ma", "co.mz",
    "co.nz", "co.th", "co.tz", "co.ug", "co.uk", "co.uz", "co.ve", "co.vi", "co.za", "co.zm",
    "co.zw", "com", "com.af", "com.ag", "com.ai", "com.ar", "com.au", "com.bd", "com.bh", "com.bn",
    "com.bo", "com.br", "com.bz", "com.co", "com.cu", "com.cy", "com.do", "com.ec", "com.eg",
    "com.et", "com.fj", "com.gh", "com.gi", "com.gt", "com.hk", "com.jm", "com.kh", "com.kw",
    "com.lb", "com.ly", "com.mm", "com.mt", "com.mx", "com.my", "com.na", "com.nf", "com.ng",
    "com.ni", "com.np", "com.om", "com.pa", "com.pe", "com.pg", "com.ph", "com.pk", "com.pr",
    "com.py", "com.qa", "com.sa", "com.sb", "com.sg", "com.sl", "com.sv", "com.tj", "com.tr",
    "com.tw", "com.ua", "com.uy", "com.vc", "com.vn", "cv", "cz", "de", "dj", "dk", "dm", "dz",
    "ee", "es", "fi", "fm", "fr", "ga", "ge", "gg", "gl", "gm", "gp", "gr", "gy", "hn", "hr", "ht",
    "hu", "ie", "im", "iq", "is", "it", "je", "jo", "kg", "ki", "kz", "la", "li", "lk", "lt", "lu",
    "lv", "md", "me", "mg", "mk", "ml", "mn", "ms", "mu", "mv", "mw", "ne", "nl", "no", "nr", "nu",
    "pl", "pn", "ps", "pt", "ro", "rs", "ru", "rw", "sc", "se", "sh", "si", "sk", "sm", "sn", "so",
    "sr", "st", "td", "tg", "tk", "tl", "tm", "tn", "to", "tt", "vg", "vu", "ws",
];

const YOUTUBE_HOSTS: &[&str] = &[
    "m.youtube.com",
    "www.youtube-nocookie.com",
    "www.youtube.com",
    "youtube.googleapis.com",
    "youtubei.googleapis.com",
];
const BING_HOSTS: &[&str] = &["edgeservices.bing.com", "www.bing.com"];
const DUCKDUCKGO_HOSTS: &[&str] = &[
    "duckduckgo.com",
    "start.duckduckgo.com",
    "www.duckduckgo.com",
];

const GOOGLE: u8 = 1;
const YOUTUBE: u8 = 1 << 1;
const BING: u8 = 1 << 2;
const DUCKDUCKGO: u8 = 1 << 3;
const ALL: u8 = GOOGLE | YOUTUBE | BING | DUCKDUCKGO;

/// Configuration error for the safe-search module.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    /// An unknown provider name was supplied.
    #[error("unknown safe-search provider \"{0}\"; supported: google, youtube, bing, duckduckgo")]
    UnknownProvider(String),
}

/// Check provider names without building a table (used by config
/// validation, so `check` and `reload` reject what startup would).
///
/// # Errors
///
/// [`ConfigError::UnknownProvider`] for the first unknown name.
pub fn validate_providers<S: AsRef<str>>(providers: &[S]) -> Result<(), ConfigError> {
    for p in providers {
        if !SUPPORTED_PROVIDERS.contains(&p.as_ref()) {
            return Err(ConfigError::UnknownProvider(p.as_ref().to_owned()));
        }
    }
    Ok(())
}

/// A compiled safe-search rewrite table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeSearch {
    enabled: u8,
}

impl SafeSearch {
    /// Build the table.
    ///
    /// * `enabled = false`: nothing is rewritten.
    /// * `enabled = true, providers = []`: every supported provider (the
    ///   documented meaning of an empty list in the config).
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownProvider`] if a name is not supported.
    pub fn new<S: AsRef<str>>(enabled: bool, providers: &[S]) -> Result<Self, ConfigError> {
        validate_providers(providers)?;
        if !enabled {
            return Ok(Self { enabled: 0 });
        }
        if providers.is_empty() {
            return Ok(Self { enabled: ALL });
        }
        let bits = providers.iter().fold(0, |bits, p| {
            bits | match p.as_ref() {
                "google" => GOOGLE,
                "youtube" => YOUTUBE,
                "bing" => BING,
                _ => DUCKDUCKGO,
            }
        });
        Ok(Self { enabled: bits })
    }

    /// The CNAME target that enforces safe search for `qname`, if any.
    ///
    /// `qname` must be normalized: lowercase, no trailing dot.
    #[must_use]
    pub fn rewrite(&self, qname: &str) -> Option<&'static str> {
        let on = |bit: u8| self.enabled & bit != 0;
        if on(YOUTUBE) && YOUTUBE_HOSTS.binary_search(&qname).is_ok() {
            return Some("restrictmoderate.youtube.com");
        }
        if on(BING) && BING_HOSTS.binary_search(&qname).is_ok() {
            return Some("strict.bing.com");
        }
        if on(DUCKDUCKGO) && DUCKDUCKGO_HOSTS.binary_search(&qname).is_ok() {
            return Some("safe.duckduckgo.com");
        }
        if on(GOOGLE)
            && let Some(tld) = qname.strip_prefix("www.google.")
            && GOOGLE_TLDS.binary_search(&tld).is_ok()
        {
            return Some("forcesafesearch.google.com");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> SafeSearch {
        SafeSearch::new(true, &["google", "youtube", "bing", "duckduckgo"]).unwrap()
    }

    #[test]
    fn tables_are_sorted_for_binary_search() {
        for table in [GOOGLE_TLDS, YOUTUBE_HOSTS, BING_HOSTS, DUCKDUCKGO_HOSTS] {
            assert!(table.windows(2).all(|w| w[0] < w[1]), "unsorted: {table:?}");
        }
        assert_eq!(GOOGLE_TLDS.len(), 194);
    }

    /// The hostnames a browser in this household actually resolves.
    #[test]
    fn household_search_hosts_are_rewritten() {
        let ss = all();
        for (host, target) in [
            ("www.google.com", "forcesafesearch.google.com"),
            ("www.google.com.co", "forcesafesearch.google.com"),
            ("www.google.es", "forcesafesearch.google.com"),
            ("www.google.com.mx", "forcesafesearch.google.com"),
            ("www.google.co", "forcesafesearch.google.com"),
            ("www.youtube.com", "restrictmoderate.youtube.com"),
            ("m.youtube.com", "restrictmoderate.youtube.com"),
            ("youtubei.googleapis.com", "restrictmoderate.youtube.com"),
            ("www.bing.com", "strict.bing.com"),
            ("edgeservices.bing.com", "strict.bing.com"),
            ("duckduckgo.com", "safe.duckduckgo.com"),
            ("start.duckduckgo.com", "safe.duckduckgo.com"),
        ] {
            assert_eq!(ss.rewrite(host), Some(target), "{host}");
        }
    }

    /// Lookalikes and unrelated hosts pass through untouched.
    #[test]
    fn lookalikes_are_not_rewritten() {
        let ss = all();
        for host in [
            "google.com",
            "mail.google.com",
            "www.google.evil.com",
            "www.google.com.evil.com",
            "evil-www.google.com",
            "www.google.notatld",
            "www.youtube.com.evil.net",
            "bing.com",
            "example.com",
        ] {
            assert_eq!(ss.rewrite(host), None, "{host}");
        }
    }

    #[test]
    fn only_enabled_providers_rewrite() {
        let ss = SafeSearch::new(true, &["bing"]).unwrap();
        assert_eq!(ss.rewrite("www.bing.com"), Some("strict.bing.com"));
        assert_eq!(ss.rewrite("www.google.com"), None);
        assert_eq!(
            SafeSearch::new(false, &["bing"])
                .unwrap()
                .rewrite("www.bing.com"),
            None
        );
        assert_eq!(
            SafeSearch::new::<&str>(true, &[])
                .unwrap()
                .rewrite("www.google.com.co"),
            Some("forcesafesearch.google.com")
        );
    }

    #[test]
    fn a_typo_in_a_provider_is_rejected_even_when_disabled() {
        let err = SafeSearch::new(false, &["gogle"]).unwrap_err();
        assert!(err.to_string().contains("gogle"), "{err}");
    }
}
