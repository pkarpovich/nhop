//! The published upstream list: every address the operator named, each judged by its own verdict.

use crate::proxy::{Upstream, Upstreams};
use crate::upstream::HealthHandle;

/// One upstream as the dialer and the patrol see it: where it is and the verdict judging it.
///
/// A dial holds a clone of the entry it dialled, so its verdict write lands on the handle of the
/// address it was made against even when a reload has published another list since.
#[derive(Debug, Clone)]
pub struct UpstreamEntry {
    upstream: Upstream,
    health: HealthHandle,
}

impl UpstreamEntry {
    /// Returns the address as the operator wrote it and as it is dialled.
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Returns the verdict on this address alone.
    pub fn health(&self) -> &HealthHandle {
        &self.health
    }
}

/// Upstreams new connections are handed to, in the operator's order, empty until a load names one.
#[derive(Debug, Clone, Default)]
pub struct UpstreamEntries(Vec<UpstreamEntry>);

impl UpstreamEntries {
    /// Returns the entries for `next`, keeping the verdict of every address this list already judges.
    ///
    /// An address both lists name keeps its [`HealthHandle`], so a reload does not drop a working
    /// upstream to [`HealthState::Down`] and send every `prefer` destination direct until the
    /// patrol confirms it again. A new address starts `Down`, as it would in a daemon just started,
    /// and an address removed and later added back is new: a dial still holding the handle it had
    /// before the removal can no longer reach the verdict that replaced it.
    ///
    /// [`HealthState::Down`]: nhop_ipc::HealthState::Down
    pub fn adopted(&self, next: &Upstreams) -> Self {
        let Self(kept) = self;
        let mut entries = Vec::with_capacity(next.as_slice().len());
        for upstream in next.as_slice() {
            let mut health = None;
            for UpstreamEntry {
                upstream: listed,
                health: judged,
            } in kept
            {
                if listed.socket() == upstream.socket() {
                    health = Some(judged.clone());
                    break;
                }
            }
            entries.push(UpstreamEntry {
                upstream: upstream.clone(),
                health: health.unwrap_or_default(),
            });
        }
        Self(entries)
    }

    /// Returns the entry preferred over every other, absent while no upstream is configured.
    pub fn first(&self) -> Option<&UpstreamEntry> {
        let Self(entries) = self;
        entries.first()
    }

    /// Returns the entries in order of preference.
    pub fn as_slice(&self) -> &[UpstreamEntry] {
        let Self(entries) = self;
        entries
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use nhop_ipc::{HealthState, UpstreamAddr};

    use super::*;
    use crate::daemon::state::LiveUpstream;

    const A: &str = "192.0.2.10:1080";
    const B: &str = "192.0.2.11:1080";
    const C: &str = "192.0.2.12:1080";

    fn written(addr: &str) -> UpstreamAddr {
        UpstreamAddr(format!("socks5://{addr}"))
    }

    fn listed(addrs: &[&str]) -> Upstreams {
        let Some((first, rest)) = addrs.split_first() else {
            panic!("a staged list names at least one upstream");
        };
        let mut fallbacks = Vec::with_capacity(rest.len());
        for addr in rest {
            fallbacks.push(written(addr));
        }
        Upstreams::parse(written(first), fallbacks).unwrap()
    }

    fn entry(live: &LiveUpstream, addr: &str) -> UpstreamEntry {
        let addr: SocketAddr = addr.parse().unwrap();
        for entry in live.snapshot().as_slice() {
            if entry.upstream().socket() == addr {
                return entry.clone();
            }
        }
        panic!("{addr} is not published");
    }

    #[test]
    fn nothing_is_published_until_a_load_names_an_upstream() {
        let live = LiveUpstream::default();

        assert!(live.snapshot().first().is_none());
    }

    #[test]
    fn the_published_entries_keep_the_written_order() {
        let live = LiveUpstream::default();

        live.publish(&listed(&[B, A, C]));

        let mut order = Vec::new();
        for entry in live.snapshot().as_slice() {
            order.push(entry.upstream().socket().to_string());
        }
        assert_eq!(order, vec![B, A, C]);
    }

    #[test]
    fn a_reload_keeps_the_verdict_of_an_address_it_keeps() {
        let live = LiveUpstream::default();
        live.publish(&listed(&[A, B]));
        entry(&live, A).health().seed(HealthState::Up);
        let settled = entry(&live, A).health().verdict();

        live.publish(&listed(&[B, A, C]));

        assert_eq!(entry(&live, A).health().verdict(), settled);
        assert_eq!(entry(&live, C).health().state(), HealthState::Down);
    }

    #[test]
    fn an_address_removed_and_added_back_starts_down() {
        let live = LiveUpstream::default();
        live.publish(&listed(&[A]));
        entry(&live, A).health().seed(HealthState::Up);

        live.publish(&listed(&[B]));
        live.publish(&listed(&[A]));

        assert_eq!(entry(&live, A).health().state(), HealthState::Down);
    }
}
