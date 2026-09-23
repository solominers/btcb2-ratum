//! Test values the pool's own tests build on: two regtest addresses, a server whose window holds
//! given shares, and the ledger records.

use crate::cli::Options;
use crate::ledger::blocks::{BlockRecords, FoundBlock, OwedBlock};
use crate::ledger::split::{FeeOutput, Payout, PublicGateway, SplitPolicy};
use crate::ledger::{Ledger, Share, WindowRule};
use crate::limiter::{Limiter, Rules};
use crate::server::Server;
use crate::settings::Resolved;
use crate::verify::SharePolicy;
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::config::ClientConfig;
use ratum::rpc;

/// A regtest address whose script is `ratum::fixtures::p2wpkh(0xa1)`.
pub const ALICE: &str = "bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc";
/// A regtest address whose script is `ratum::fixtures::p2wpkh(0xb2)`.
pub const BOB: &str = "bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a";
/// A regtest address whose script is `ratum::fixtures::p2wpkh(0xc3)`: where a test's operator
/// fee goes.
pub const FEE_ADDRESS: &str = "bcrt1qc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rpz2hyw";

/// A regtest P2WPKH address whose 20-byte program is `seed` repeated, so a test names as many
/// distinct identities as it needs.
pub fn regtest_p2wpkh_address(seed: &[u8]) -> String {
    let program: Vec<u8> = seed.iter().copied().cycle().take(20).collect();
    let hrp = bech32::Hrp::parse("bcrt").unwrap();
    bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &program).unwrap()
}

/// A server on regtest whose window holds `shares`, each an identity and its difficulty.
pub fn server_with(shares: &[(&str, u64)]) -> Server {
    server_on(ledger_with(shares, &[]), BlockRecords::default())
}

/// `server_with` under an operator fee of `fee_bps` paid to `FEE_ADDRESS`.
pub fn server_with_fee(shares: &[(&str, u64)], fee_bps: u16) -> Server {
    server_with_fees(shares, &[(FEE_ADDRESS, fee_bps)])
}

/// `server_with` under the operator `fees`, each a regtest address and its basis points.
pub fn server_with_fees(shares: &[(&str, u64)], fees: &[(&str, u16)]) -> Server {
    server_on(ledger_with(shares, fees), BlockRecords::default())
}

/// The fee outputs `fees` name, each a regtest address and its basis points.
pub fn fee_outputs(fees: &[(&str, u16)]) -> Vec<FeeOutput> {
    fees.iter()
        .map(|(address, bps)| FeeOutput {
            address: address.to_string(),
            script_pubkey: crate::payout::address_script(address, Some(rpc::Chain::Regtest))
                .unwrap_or_else(|| panic!("{address} is not a regtest address")),
            bps: *bps,
        })
        .collect()
}

/// An unbounded window holding `shares`, each an identity and its difficulty, under the
/// operator `fees`.
pub fn ledger_with(shares: &[(&str, u64)], fees: &[(&str, u16)]) -> Ledger {
    let policy = SplitPolicy { fees: fee_outputs(fees), public_gateway: None };
    let mut ledger = Ledger::new(WindowRule::fixed(u128::MAX), policy);
    for (i, (identity, difficulty)) in shares.iter().enumerate() {
        let mut hash = [0u8; 32];
        hash[0] = i as u8;
        ledger.record(share(1_000 + i as u64, identity, *difficulty, hash, "")).unwrap();
    }
    ledger
}

/// A port nothing listens on: the node of a server whose test reads none.
pub const UNREACHABLE_NODE: &str = "http://127.0.0.1:1";

/// `server` over `ledger` and `records` with the node at `UNREACHABLE_NODE`.
pub fn server_on(ledger: Ledger, records: BlockRecords) -> Server {
    server(ledger, records, UNREACHABLE_NODE)
}

/// A server on regtest over `ledger` and `records` with the node at `node_url` (a
/// `FakeNode`'s), as `Server::new` builds it at startup.
pub fn server(ledger: Ledger, records: BlockRecords, node_url: &str) -> Server {
    let Resolved { mut settings, .. } = crate::settings::resolve(&Options::default()).unwrap();
    settings.motd = String::new();
    settings.listen = "0.0.0.0:28915".into();
    settings.max_connections = 8;
    let share_policy = SharePolicy {
        config: ClientConfig {
            payout_script: POOL.to_vec(),
            prime_id: 1,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1,
            v3: None,
        },
        chain: Some(rpc::Chain::Regtest),
    };
    let node = rpc::Client::new(node_url, "u", "p", None).unwrap();
    let limiter = Limiter::new(Rules::default());
    Server::new(settings, share_policy, KeyPairs::generate(), node, (ledger, records), limiter)
        .unwrap()
}

/// A server whose window holds 100 work from `ALICE` on the public gateway (tag "public") and
/// 100 from `BOB` on an own gateway.
pub fn server_with_public_gateway_fee(fee_bps: u16, subsidy_bps: u16) -> Server {
    let server = server_with(&[]);
    let gateway = PublicGateway { tag: "public".into(), fee_bps, subsidy_bps };
    let policy = SplitPolicy { public_gateway: Some(gateway), ..SplitPolicy::default() };
    let mut l = ratum::lock(&server.ledger);
    *l = Ledger::new(WindowRule::fixed(u128::MAX), policy);
    for (i, (identity, tag)) in [(ALICE, "public"), (BOB, "own")].iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, 100, [i as u8 + 0x10; 32], tag)).unwrap();
    }
    drop(l);
    server
}

pub const POOL: [u8; 4] = [0x00, 0x14, 0xee, 0xee];

pub use ratum::fixtures::hash;

pub struct Scratch(std::path::PathBuf);

impl Scratch {
    pub fn new(what: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ratum-ledger-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn share(
    accepted_at: u64,
    identity: &str,
    difficulty: u64,
    block_hash: [u8; 32],
    tag_secondary: &str,
) -> Share {
    Share {
        accepted_at,
        identity: identity.to_string(),
        difficulty,
        block_hash,
        tag_secondary: tag_secondary.to_string(),
    }
}

pub fn payout(identity: &str, sats: u64) -> Payout {
    Payout { identity: identity.into(), sats }
}

pub fn owed(n: u64, settled: Option<u64>) -> OwedBlock {
    OwedBlock {
        found_at: 100 + n,
        height: 961_640 + n as u32,
        block_hash: hash(0xb10c_0000 + n),
        settled_at: settled,
        entries: vec![payout("alice", 200 + n), payout("bob", 100)],
    }
}

pub fn found(n: u64, cumulative_work: u128) -> FoundBlock {
    FoundBlock {
        found_at: 100 + n,
        height: 961_640 + n as u32,
        block_hash: hash(0xf00_0000 + n),
        paid_to_split: n * 10,
        paid_to_pool: 5,
        finder: "alice".into(),
        tag_secondary: "bob".into(),
        network_difficulty: 100.5,
        cumulative_work,
    }
}
