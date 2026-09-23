//! The rigs behind each identity: the worker name a share's username carries after the
//! address (`bc1q....rig3`), when it last sent a share, how many, its work over the hashrate
//! span, and which gateway connection it came through. Read by the stats interface so a
//! miner's page can list its rigs; nothing is paid by worker, so none of this is stored.

use ratum::hashrate;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

/// The span a worker's hashrate is read over: the stats interface's.
pub const SPAN_SECS: u64 = 10 * ratum::SECS_PER_MINUTE;
/// A worker that has sent no share for this long is forgotten.
pub const IDLE_SECS: u64 = ratum::SECS_PER_HOUR;
/// The workers held for one identity; past it the quietest is replaced.
pub const MAX_WORKERS_PER_IDENTITY: usize = 256;
/// The identities held; past it the quietest identity is forgotten.
pub const MAX_IDENTITIES: usize = 1 << 16;
const MAX_SAMPLES: usize = 4096;
const SWEEP_EVERY: u64 = 4096;

struct Worker {
    last_share_at: u64,
    shares: u64,
    samples: VecDeque<(u64, u64)>,
    /// The gateway connection the newest share came through, as a short tag of its peer
    /// address, so a miner can tell its gateways apart without the address being shown.
    gateway: String,
}

impl Worker {
    fn work_since(&self, cutoff: u64) -> u128 {
        self.samples.iter().filter(|(at, _)| *at >= cutoff).map(|(_, d)| u128::from(*d)).sum()
    }
}

/// One worker as the stats interface lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkerRow {
    pub name: String,
    pub hashrate_hs: f64,
    pub last_share_at: u64,
    pub shares: u64,
    pub gateway: String,
}

#[derive(Default)]
pub struct Workers {
    by_identity: HashMap<String, HashMap<String, Worker>>,
    observations: u64,
}

/// The worker name in `username`: what follows the first `.`, or empty.
pub fn worker_name(username: &str) -> &str {
    ratum::username::split_address_worker(username).1.strip_prefix('.').unwrap_or("")
}

/// A short tag of a gateway's peer address: the first 8 hex digits of its SHA-256d.
pub fn gateway_tag(peer: SocketAddr) -> String {
    let hash = ratum::bitcoin::sha256d(peer.to_string().as_bytes());
    hex::encode(&hash[..4])
}

impl Workers {
    /// Records a credited share of `difficulty` from `worker` of `identity`, through `peer`.
    pub fn note(
        &mut self,
        identity: &str,
        worker: &str,
        peer: SocketAddr,
        difficulty: u64,
        now: u64,
    ) {
        self.observations += 1;
        if self.observations.is_multiple_of(SWEEP_EVERY) {
            self.sweep(now);
        }
        if !self.by_identity.contains_key(identity) && self.by_identity.len() >= MAX_IDENTITIES {
            self.forget_quietest_identity();
        }
        let workers = self.by_identity.entry(identity.to_string()).or_default();
        if !workers.contains_key(worker)
            && workers.len() >= MAX_WORKERS_PER_IDENTITY
            && let Some(quietest) =
                workers.iter().min_by_key(|(_, w)| w.last_share_at).map(|(name, _)| name.clone())
        {
            workers.remove(&quietest);
        }
        let w = workers.entry(worker.to_string()).or_insert_with(|| Worker {
            last_share_at: now,
            shares: 0,
            samples: VecDeque::new(),
            gateway: String::new(),
        });
        w.last_share_at = now;
        w.shares += 1;
        w.gateway = gateway_tag(peer);
        w.samples.push_back((now, difficulty));
        if w.samples.len() > MAX_SAMPLES {
            w.samples.pop_front();
        }
        let cutoff = now.saturating_sub(SPAN_SECS);
        while w.samples.front().is_some_and(|(at, _)| *at < cutoff) {
            w.samples.pop_front();
        }
    }

    /// The workers of `identity` that sent a share within `IDLE_SECS` of `now`, most
    /// recent first.
    pub fn of(&self, identity: &str, now: u64) -> Vec<WorkerRow> {
        let Some(workers) = self.by_identity.get(identity) else { return Vec::new() };
        let cutoff = now.saturating_sub(SPAN_SECS);
        let mut rows: Vec<WorkerRow> = workers
            .iter()
            .filter(|(_, w)| now.saturating_sub(w.last_share_at) <= IDLE_SECS)
            .map(|(name, w)| WorkerRow {
                name: name.clone(),
                hashrate_hs: hashrate::from_work(
                    w.work_since(cutoff),
                    Duration::from_secs(SPAN_SECS),
                ),
                last_share_at: w.last_share_at,
                shares: w.shares,
                gateway: w.gateway.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            b.last_share_at.cmp(&a.last_share_at).then_with(|| a.name.cmp(&b.name))
        });
        rows
    }

    fn sweep(&mut self, now: u64) {
        let cutoff = now.saturating_sub(IDLE_SECS);
        self.by_identity.retain(|_, workers| {
            workers.retain(|_, w| w.last_share_at >= cutoff);
            !workers.is_empty()
        });
    }

    fn forget_quietest_identity(&mut self) {
        let quietest = self
            .by_identity
            .iter()
            .map(|(id, ws)| (ws.values().map(|w| w.last_share_at).max().unwrap_or(0), id.clone()))
            .min()
            .map(|(_, id)| id);
        if let Some(id) = quietest {
            self.by_identity.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);

    #[test]
    fn the_worker_name_follows_the_first_dot() {
        assert_eq!(worker_name("bc1qx.rig3"), "rig3");
        assert_eq!(worker_name("bc1qx"), "");
        assert_eq!(worker_name("bc1qx.a.b"), "a.b");
        assert_eq!(gateway_tag(PEER).len(), 8);
    }

    #[test]
    fn workers_are_listed_with_their_rate_and_forgotten_when_idle() {
        let mut w = Workers::default();
        for i in 0..10u64 {
            w.note("a", "rig1", PEER, 16384, 1000 + i * 30);
        }
        w.note("a", "rig2", PEER, 16384, 1300);
        let rows = w.of("a", 1300);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].name.as_str(), rows[0].shares), ("rig2", 1), "most recent first");
        assert_eq!((rows[1].name.as_str(), rows[1].shares), ("rig1", 10));
        let expected = hashrate::from_work(10 * 16384, Duration::from_secs(SPAN_SECS));
        assert!((rows[1].hashrate_hs - expected).abs() < 1.0);
        assert!(w.of("a", 1300 + IDLE_SECS + 1).is_empty(), "idle: not listed");
        assert!(w.of("b", 1300).is_empty());
        for i in 0..SWEEP_EVERY {
            w.note("b", "x", PEER, 1, 10_000 + i);
        }
        assert!(!w.by_identity.contains_key("a"), "swept once idle");
    }

    #[test]
    fn the_worker_count_per_identity_is_bounded() {
        let mut w = Workers::default();
        for i in 0..(MAX_WORKERS_PER_IDENTITY + 5) {
            w.note("a", &format!("rig{i}"), PEER, 1, 1000 + i as u64);
        }
        assert_eq!(w.by_identity["a"].len(), MAX_WORKERS_PER_IDENTITY);
        assert!(!w.by_identity["a"].contains_key("rig0"), "the quietest was replaced");
    }
}
