//! The split as outputs: each identity's address decoded to the script that pays it, the ones no
//! address decodes left with the pool, and the coinbaser response carrying the rest.

use crate::ledger::split::{Payout, SplitPolicy, Weights};
use crate::server::Server;
use log::{info, warn};
use ratum::bitcoin::address;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::messages::coinbaser::{
    CoinbaserResponse, MAX_COINBASER_BLOB_LEN, MAX_COINBASER_OUTPUT_SCRIPT_LEN,
    MAX_COINBASER_OUTPUTS,
};
use ratum::{lock, rpc};
use std::net::SocketAddr;
use std::sync::Arc;

const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

/// A split of at most `MAX_COINBASER_OUTPUTS` outputs of address scripts fits the message,
/// so `CoinbaserResponse::encode` refuses no split `dictated_outputs` produces.
const _: () = assert!(
    address::MAX_SCRIPT_LEN <= MAX_COINBASER_OUTPUT_SCRIPT_LEN
        && size_of::<u8>()
            + MAX_COINBASER_OUTPUTS * (size_of::<u64>() + 1 + address::MAX_SCRIPT_LEN)
            <= MAX_COINBASER_BLOB_LEN
);

const ADDRESS_TYPES: &str = "P2PKH, P2SH, P2WPKH, P2WSH or P2TR";

/// What one identity is paid and the script paying it: the `Payout` the split produced,
/// plus the output script `address_script` decoded its identity to. Holding the payout
/// rather than restating its fields is what lets the owed path take it back without
/// rebuilding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedOutput {
    pub payout: Payout,
    pub script_pubkey: Vec<u8>,
}

impl DictatedOutput {
    pub fn output(&self) -> TxOut {
        TxOut { value: self.payout.sats, script_pubkey: self.script_pubkey.clone() }
    }
}

/// The script paid to `address` (a miner's identity or `--payout-address`): none unless it is
/// a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address with the prefixes of `chain`, the chain the
/// node reported at startup, or with those of any chain when `chain` is none or has no known
/// prefixes.
pub fn address_script(address: &str, chain: Option<rpc::Chain>) -> Option<Vec<u8>> {
    address::to_output_script(address, chain.and_then(rpc::Chain::address_prefixes))
}

/// Why `address_script` gives no script on `chain`.
pub fn unpayable_reason(chain: Option<rpc::Chain>) -> String {
    match chain.filter(|c| c.address_prefixes().is_some()) {
        Some(chain) => format!("not a {ADDRESS_TYPES} address of chain {}", chain.name()),
        None => format!("not a {ADDRESS_TYPES} address"),
    }
}

/// The outputs dictated for `value`: the operator fee outputs first, then the split of the
/// rest (`Weights::split`). The ledger lock is held only to copy the fees and the window's
/// weights (`Ledger::weights_for`): the sort, the amounts and the address decoding run
/// without it.
pub fn dictated_outputs(server: &Server, value: u64) -> Vec<DictatedOutput> {
    let (fees, weights, miners_value) = {
        let l = lock(&server.ledger);
        let (weights, miners_value) = l.weights_for(value);
        (fee_outputs(l.split_policy(), value), weights, miners_value)
    };
    with_fees(fees, weights, miners_value, server.share_policy.chain)
}

/// The fee outputs of `policy` on `value`, each `FeeOutput::bps` of it; a fee that rounds to
/// nothing dictates no output.
fn fee_outputs(policy: &SplitPolicy, value: u64) -> Vec<DictatedOutput> {
    policy
        .fee_amounts(value)
        .filter(|(_, sats)| *sats != 0)
        .map(|(fee, sats)| DictatedOutput {
            payout: Payout { identity: Arc::from(fee.address.as_str()), sats },
            script_pubkey: fee.script_pubkey.clone(),
        })
        .collect()
}

/// `fees` followed by the split of `miners_value` among the output slots the fees leave.
fn with_fees(
    mut fees: Vec<DictatedOutput>,
    weights: Weights,
    miners_value: u64,
    chain: Option<rpc::Chain>,
) -> Vec<DictatedOutput> {
    let room = MAX_COINBASER_OUTPUTS.saturating_sub(fees.len());
    fees.extend(outputs_for(weights.split_at_most(miners_value, room), chain));
    fees
}

/// The split as outputs to the identities `address_script` gives a script for; the others are
/// logged and left to the pool's script as the remainder.
fn outputs_for(split: Vec<Payout>, chain: Option<rpc::Chain>) -> Vec<DictatedOutput> {
    let mut kept = Vec::with_capacity(split.len());
    for payout in split {
        match address_script(&payout.identity, chain) {
            Some(script) => kept.push(DictatedOutput { payout, script_pubkey: script }),
            None => warn!(
                "      {} cannot be paid ({}); its {} sats are left out of the split and stay \
                 with the pool",
                payout.identity,
                unpayable_reason(chain),
                payout.sats
            ),
        }
    }
    kept
}

/// Whether a gateway's coinbase value is within a factor of `COINBASE_VALUE_TOLERANCE` of the
/// node's template; true while the node has given no template.
pub fn value_is_plausible(server: &Server, peer: SocketAddr, value: u64) -> bool {
    let Some(reference) = server.node_state.coinbase_value() else { return true };
    let low = (reference as f64 / COINBASE_VALUE_TOLERANCE) as u64;
    let high = (reference as f64 * COINBASE_VALUE_TOLERANCE) as u64;
    if (low..=high).contains(&value) {
        return true;
    }
    warn!(
        "[{peer}]      refusing a split for {value} sats: this node's template pays \
         {reference} sats"
    );
    false
}

/// The outputs dictated for `value` and the coinbaser response carrying them.
pub fn dictate(
    server: &Server,
    peer: SocketAddr,
    value: u64,
    coinbaser_id: u8,
) -> (Vec<DictatedOutput>, Vec<u8>) {
    let (fees, weights, miners_value, window_shares, window_work) = {
        let l = lock(&server.ledger);
        let (weights, miners_value) = l.weights_for(value);
        (fee_outputs(l.split_policy(), value), weights, miners_value, l.len(), l.total_work())
    };
    let fee_outputs = fees.len();
    let fee_sats: u64 = fees.iter().map(|d| d.payout.sats).sum();
    let dictated = with_fees(fees, weights, miners_value, server.share_policy.chain);
    let paid: u64 = dictated.iter().map(|d| d.payout.sats).sum::<u64>() - fee_sats;
    info!(
        "[{peer}]      paying {} miners {paid} of {value} sats from a window of {window_shares} \
         shares ({window_work} work), {fee_sats} sats to {fee_outputs} fee output(s)",
        dictated.len() - fee_outputs,
    );
    let outputs = dictated.iter().map(DictatedOutput::output).collect();
    let payload = CoinbaserResponse { value, coinbaser_id, outputs }
        .encode()
        .expect("a split of payable outputs totalling at most the value encodes");
    (dictated, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        ALICE, BOB, FEE_ADDRESS, POOL, regtest_p2wpkh_address, server_with, server_with_fee,
        server_with_fees, server_with_public_gateway_fee,
    };
    use crate::ledger::split::FeeOutput;
    use ratum::fixtures::p2wpkh;

    const MAIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn coinbaser_outputs(server: &Server, value: u64) -> Vec<TxOut> {
        dictated_outputs(server, value).iter().map(DictatedOutput::output).collect()
    }

    #[test]
    fn an_address_is_paid_when_it_carries_the_prefixes_of_the_nodes_chain() {
        let regtest = Some(rpc::Chain::Regtest);
        assert_eq!(address_script(ALICE, regtest), Some(p2wpkh(0xa1)));
        assert_eq!(address_script(BOB, regtest), Some(p2wpkh(0xb2)));
        assert_eq!(address_script(MAIN_ADDRESS, regtest), None, "a mainnet address");
        assert!(address_script(MAIN_ADDRESS, None).is_some(), "no chain read at startup");
        assert!(
            address_script(MAIN_ADDRESS, Some(rpc::Chain::Other)).is_some(),
            "a chain with no known prefixes"
        );
        assert_eq!(
            unpayable_reason(regtest),
            "not a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address of chain regtest"
        );
        assert_eq!(unpayable_reason(None), "not a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address");
        assert_eq!(unpayable_reason(Some(rpc::Chain::Other)), unpayable_reason(None));
    }

    #[test]
    fn a_split_names_every_miner_and_never_the_pool() {
        let server = server_with(&[(ALICE, 3), (BOB, 1)]);
        let outputs = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(750_000, p2wpkh(0xa1)), (250_000, p2wpkh(0xb2))]
        );
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn a_fee_is_dictated_as_its_own_output_ahead_of_the_split() {
        let server = server_with_fee(&[(ALICE, 3), (BOB, 1)], 100);
        let outputs = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(10_000, p2wpkh(0xc3)), (742_500, p2wpkh(0xa1)), (247_500, p2wpkh(0xb2))]
        );
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000, "nothing is left");
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn several_fees_are_each_taken_on_the_whole_value_and_one_under_the_minimum_is_not_taken() {
        let server = server_with_fees(&[(ALICE, 1)], &[(FEE_ADDRESS, 25), (BOB, 50)]);
        let outputs = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(2_500, p2wpkh(0xc3)), (5_000, p2wpkh(0xb2)), (992_500, p2wpkh(0xa1))]
        );
        let outputs = coinbaser_outputs(&server, 100_000);
        assert_eq!(outputs.len(), 1, "250 and 500 sats are under the minimum output: no fee");
        assert_eq!(outputs[0].value, 100_000, "and the miners keep it");
    }

    fn with_bps(bps: u16) -> SplitPolicy {
        let fee = FeeOutput { address: FEE_ADDRESS.into(), script_pubkey: p2wpkh(0xc3), bps };
        SplitPolicy { fees: vec![fee], ..SplitPolicy::default() }
    }

    #[test]
    fn the_fee_is_rounded_down_so_the_operator_never_over_takes() {
        assert_eq!(SplitPolicy::default().fee_on(1_000_000), 0, "no fee by default");
        assert_eq!(with_bps(50).fee_on(1_000_000), 5_000, "0.5%");
        assert_eq!(with_bps(100).fee_on(1_000_000), 10_000);
        assert_eq!(with_bps(100).fee_on(1), 0);
        assert_eq!(with_bps(100).fee_bps(), 100);
    }

    #[test]
    fn the_fee_outputs_count_against_the_output_limit() {
        let miners: Vec<(String, u64)> =
            (0..600u16).map(|i| (regtest_p2wpkh_address(&i.to_be_bytes()), 1)).collect();
        let refs: Vec<(&str, u64)> = miners.iter().map(|(a, w)| (a.as_str(), *w)).collect();
        let server = server_with_fees(&refs, &[(FEE_ADDRESS, 25), (BOB, 50)]);
        let outputs = coinbaser_outputs(&server, 100_000_000_000);
        assert_eq!(outputs.len(), MAX_COINBASER_OUTPUTS, "2 fee outputs and 510 miners");
    }

    #[test]
    fn an_empty_window_names_nobody() {
        let server = server_with(&[]);
        assert!(coinbaser_outputs(&server, 1_000_000).is_empty());
    }

    #[test]
    fn an_identity_that_is_not_an_address_of_the_chain_leaves_its_amount_to_the_pool() {
        for unpayable in ["nonsense", MAIN_ADDRESS] {
            let server = server_with(&[(ALICE, 3), (unpayable, 1)]);
            let outputs = coinbaser_outputs(&server, 1_000_000);
            assert_eq!(outputs.len(), 1, "{unpayable}");
            assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
            assert_eq!(outputs[0].value, 750_000);
            assert_eq!(1_000_000 - outputs[0].value, 250_000);
        }
    }

    #[test]
    fn the_dictated_split_charges_the_public_gateway_fee_and_reassigns_it() {
        let server = server_with_public_gateway_fee(5_000, 10_000);
        let outputs = coinbaser_outputs(&server, 200_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(150_000, p2wpkh(0xb2)), (50_000, p2wpkh(0xa1))]
        );

        let off = server_with_public_gateway_fee(0, 0);
        let outputs = coinbaser_outputs(&off, 200_000);
        assert_eq!(outputs.iter().map(|o| o.value).collect::<Vec<_>>(), vec![100_000, 100_000]);
    }

    #[test]
    fn the_minimum_is_applied_before_the_identities_are_decoded() {
        let server = server_with(&[(ALICE, 999), (BOB, 1)]);
        let outputs = coinbaser_outputs(&server, 500_000);
        assert_eq!(outputs.len(), 1, "bob's 500 is under the minimum");
        assert_eq!(outputs[0].value, 500_000);
    }
}
