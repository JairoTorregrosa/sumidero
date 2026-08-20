//! Shadow mode: mirror every query to a reference resolver (the live
//! `AdGuard`) and record divergences for triage before cutover.
//!
//! Comparison is verdict + response shape, not byte equality: upstream
//! rotation legitimately changes answer records. The known stylistic
//! difference — sumidero blocks with NXDOMAIN, `AdGuard` with `0.0.0.0` —
//! is auto-classified `expected` (settled design).

use std::net::SocketAddr;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;

use crate::db::{DbWriter, LogEvent};

/// Divergence classes written to the database.
pub const CLASS_EXPECTED: &str = "expected";
pub const CLASS_WE_BLOCK: &str = "we-block-they-answer";
pub const CLASS_THEY_BLOCK: &str = "they-block-we-answer";
pub const CLASS_RCODE: &str = "rcode-mismatch";

/// Does this response look like a block? NXDOMAIN, or NOERROR whose
/// A/AAAA answers are all unspecified addresses (`AdGuard`'s `0.0.0.0`).
#[must_use]
pub fn looks_blocked(resp: &Message) -> bool {
    match resp.metadata.response_code {
        ResponseCode::NXDomain => true,
        ResponseCode::NoError => {
            let mut saw_addr = false;
            for record in &resp.answers {
                match &record.data {
                    RData::A(a) => {
                        saw_addr = true;
                        if !a.0.is_unspecified() {
                            return false;
                        }
                    }
                    RData::AAAA(a) => {
                        saw_addr = true;
                        if !a.0.is_unspecified() {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
            saw_addr
        }
        _ => false,
    }
}

fn describe(resp: &Message, blocked_verdict: bool) -> String {
    let rcode = resp.metadata.response_code;
    let style = if blocked_verdict {
        "blocked/"
    } else if looks_blocked(resp) {
        "blocky/"
    } else {
        ""
    };
    format!("{style}{rcode}")
}

/// Compare our answer against the reference's. `ours_blocked` is the
/// filter verdict (we know why WE answered NXDOMAIN; we infer why they
/// did). Returns `(ours, theirs, class)` when the outcomes diverge.
#[must_use]
pub fn classify(
    ours: &Message,
    ours_blocked: bool,
    theirs: &Message,
) -> Option<(String, String, String)> {
    let theirs_blocked = looks_blocked(theirs);
    let ours_desc = describe(ours, ours_blocked);
    let theirs_desc = describe(theirs, false);
    let class = match (ours_blocked, theirs_blocked) {
        (true, true) => {
            if ours.metadata.response_code == theirs.metadata.response_code {
                return None; // same style, same outcome
            }
            CLASS_EXPECTED // NXDOMAIN vs 0.0.0.0: settled as benign
        }
        (true, false) => {
            // AdGuard blocks non-address qtypes (HTTPS, TXT, ...) with an
            // empty NOERROR: no records at all is its block style too.
            if theirs.metadata.response_code == ResponseCode::NoError && theirs.answers.is_empty() {
                CLASS_EXPECTED
            } else {
                CLASS_WE_BLOCK
            }
        }
        (false, true) => {
            // We didn't filter it, but our answer may still look blocked
            // (genuine upstream NXDOMAIN, or upstream returning 0.0.0.0):
            // then both agree and there is nothing to report.
            if looks_blocked(ours) {
                return None;
            }
            CLASS_THEY_BLOCK
        }
        (false, false) => {
            if ours.metadata.response_code == theirs.metadata.response_code {
                return None;
            }
            CLASS_RCODE
        }
    };
    Some((ours_desc, theirs_desc, class.to_string()))
}

/// At most this many reference comparisons in flight; beyond it new
/// queries are sampled out (each pending compare holds a task, a socket,
/// and a receive buffer for up to 3s — unbounded, a slow reference could
/// erase the engine's memory savings).
const MAX_INFLIGHT: usize = 64;

/// Handle to the reference resolver.
#[derive(Debug, Clone)]
pub struct Shadow {
    pub addr: SocketAddr,
    limiter: std::sync::Arc<tokio::sync::Semaphore>,
}

impl Shadow {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            limiter: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT)),
        }
    }
}

impl Shadow {
    /// Ask the reference resolver over plain UDP (3s timeout).
    async fn reference_query(&self, request: &Message) -> Result<Message, String> {
        let bytes = request.to_vec().map_err(|e| e.to_string())?;
        let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| e.to_string())?;
        sock.send_to(&bytes, self.addr)
            .await
            .map_err(|e| e.to_string())?;
        // Plain-UDP responses fit the classic 512B or our EDNS 1232 hint;
        // 4KB covers any sane reference without a 64KB allocation per task.
        let mut buf = vec![0u8; 4096];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv_from(&mut buf))
                .await
                .map_err(|_| "reference timed out".to_string())?
                .map_err(|e| e.to_string())?;
        Message::from_vec(&buf[..n]).map_err(|e| e.to_string())
    }

    /// Fire-and-forget comparison of one answered query.
    pub fn spawn_compare(
        &self,
        request: Message,
        ours: Message,
        ours_blocked: bool,
        qname: String,
        qtype: u16,
        writer: DbWriter,
    ) {
        let Ok(permit) = std::sync::Arc::clone(&self.limiter).try_acquire_owned() else {
            return; // saturated: sampling out is better than piling up
        };
        let shadow = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let theirs = match shadow.reference_query(&request).await {
                Ok(t) => t,
                Err(err) => {
                    tracing::warn!(%err, qname, "shadow reference query failed");
                    return;
                }
            };
            if let Some((ours_desc, theirs_desc, class)) = classify(&ours, ours_blocked, &theirs) {
                let event = LogEvent::Divergence {
                    ts: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs().cast_signed()),
                    qname,
                    qtype,
                    ours: ours_desc,
                    theirs: theirs_desc,
                    class,
                };
                if !writer.log(event) {
                    tracing::warn!("divergence log queue full; dropped a record");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, Record};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn resp(rcode: ResponseCode) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m
    }

    fn resp_a(ip: Ipv4Addr) -> Message {
        let mut m = resp(ResponseCode::NoError);
        m.add_answer(Record::from_rdata(
            Name::from_ascii("x.test.").unwrap(),
            60,
            RData::A(A(ip)),
        ));
        m
    }

    #[test]
    fn adguard_zero_answer_looks_blocked() {
        assert!(looks_blocked(&resp_a(Ipv4Addr::UNSPECIFIED)));
        assert!(looks_blocked(&resp(ResponseCode::NXDomain)));
        assert!(!looks_blocked(&resp_a(Ipv4Addr::new(1, 2, 3, 4))));
        // NOERROR with no address records at all: can't call it a block.
        assert!(!looks_blocked(&resp(ResponseCode::NoError)));
        // AAAA :: counts as blocked.
        let mut m = resp(ResponseCode::NoError);
        m.add_answer(Record::from_rdata(
            Name::from_ascii("x.test.").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
        ));
        assert!(looks_blocked(&m));
    }

    #[test]
    fn both_block_different_style_is_expected() {
        let ours = resp(ResponseCode::NXDomain);
        let theirs = resp_a(Ipv4Addr::UNSPECIFIED);
        let (o, t, class) = classify(&ours, true, &theirs).unwrap();
        assert_eq!(class, CLASS_EXPECTED);
        assert!(o.starts_with("blocked/"));
        assert!(t.starts_with("blocky/"));
    }

    #[test]
    fn both_block_same_style_is_no_divergence() {
        let ours = resp(ResponseCode::NXDomain);
        let theirs = resp(ResponseCode::NXDomain);
        assert!(classify(&ours, true, &theirs).is_none());
    }

    #[test]
    fn we_block_they_empty_noerror_is_expected() {
        // AdGuard blocks non-address qtypes (HTTPS/TXT/...) with an empty
        // NOERROR; that is its block style, not a disagreement.
        let ours = resp(ResponseCode::NXDomain);
        let theirs = resp(ResponseCode::NoError);
        let (_, _, class) = classify(&ours, true, &theirs).unwrap();
        assert_eq!(class, CLASS_EXPECTED);
    }

    #[test]
    fn we_block_they_answer() {
        let ours = resp(ResponseCode::NXDomain);
        let theirs = resp_a(Ipv4Addr::new(93, 184, 216, 34));
        let (_, _, class) = classify(&ours, true, &theirs).unwrap();
        assert_eq!(class, CLASS_WE_BLOCK);
    }

    #[test]
    fn they_block_we_answer() {
        let ours = resp_a(Ipv4Addr::new(93, 184, 216, 34));
        let theirs = resp_a(Ipv4Addr::UNSPECIFIED);
        let (_, _, class) = classify(&ours, false, &theirs).unwrap();
        assert_eq!(class, CLASS_THEY_BLOCK);
    }

    #[test]
    fn matching_answers_no_divergence() {
        // Different records, same outcome class: not a divergence.
        let ours = resp_a(Ipv4Addr::new(1, 1, 1, 1));
        let theirs = resp_a(Ipv4Addr::new(2, 2, 2, 2));
        assert!(classify(&ours, false, &theirs).is_none());
    }

    #[test]
    fn upstream_nxdomain_for_both_no_divergence() {
        // A genuinely nonexistent name: both NXDOMAIN, ours NOT via filter.
        let ours = resp(ResponseCode::NXDomain);
        let theirs = resp(ResponseCode::NXDomain);
        assert!(classify(&ours, false, &theirs).is_none());
    }

    #[test]
    fn rcode_mismatch() {
        let ours = resp(ResponseCode::ServFail);
        let theirs = resp_a(Ipv4Addr::new(1, 1, 1, 1));
        let (_, _, class) = classify(&ours, false, &theirs).unwrap();
        assert_eq!(class, CLASS_RCODE);
    }
}
