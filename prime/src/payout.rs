//! The split as outputs: each identity's address decoded to the script that pays it, the ones no
//! address decodes left with the pool, and the coinbaser response carrying the rest.

use crate::ledger::carry::CarryDelta;
use crate::ledger::split::{Payout, Split, SplitPolicy, Weights};
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

/// What a split is dictated from, copied under the ledger lock: the fee outputs, the
/// finder's cut, the window's weights and the value they divide.
struct Plan {
    fees: Vec<DictatedOutput>,
    finder: Option<(Arc<str>, Vec<u8>, u64)>,
    weights: Weights,
    window_value: u64,
    window_shares: usize,
    window_work: u128,
}

/// The plan for `value` on a connection whose identity is `finder`: the fees off the top,
/// then the finder's cut of the rest when the finder is an address the pool can pay, then
/// the window's share.
fn plan(server: &Server, value: u64, finder: Option<&str>) -> Plan {
    let chain = server.share_policy.chain;
    let finder = finder.and_then(|f| address_script(f, chain).map(|script| (f, script)));
    let l = lock(&server.ledger);
    let policy = l.split_policy();
    let fees = fee_outputs(policy, value);
    let after_fees = policy.miners_share(value);
    let finder = finder.and_then(|(identity, script)| {
        let sats = policy.finder_cut(after_fees);
        (sats != 0).then(|| (Arc::from(identity), script, sats))
    });
    let window_value = after_fees - finder.as_ref().map_or(0, |f| f.2);
    Plan {
        fees,
        finder,
        weights: l.weights(),
        window_value,
        window_shares: l.len(),
        window_work: l.total_work(),
    }
}

/// The plan's outputs and carry deltas: the fees, the finder's cut (merged into the finder's
/// window payout when it has one), and the window's split among the output slots left.
fn outputs_of(plan: Plan, chain: Option<rpc::Chain>) -> (Vec<DictatedOutput>, Vec<CarryDelta>) {
    let Plan { mut fees, finder, weights, window_value, .. } = plan;
    let reserved = fees.len() + usize::from(finder.is_some());
    let room = MAX_COINBASER_OUTPUTS.saturating_sub(reserved);
    let Split { mut payouts, carry_deltas } = weights.split_at_most(window_value, room);
    if let Some((identity, script_pubkey, sats)) = finder {
        match payouts.iter_mut().find(|p| p.identity == identity) {
            Some(p) => p.sats += sats,
            None => fees.push(DictatedOutput { payout: Payout { identity, sats }, script_pubkey }),
        }
    }
    fees.extend(outputs_for(payouts, chain));
    (fees, carry_deltas)
}

/// The outputs dictated for `value` to a connection of identity `finder`, and the carry
/// deltas they move. The ledger lock is held only to copy the plan: the sort, the amounts
/// and the address decoding run without it.
pub fn dictated(
    server: &Server,
    value: u64,
    finder: Option<&str>,
) -> (Vec<DictatedOutput>, Vec<CarryDelta>) {
    outputs_of(plan(server, value, finder), server.share_policy.chain)
}

/// `dictated` without the carry.
pub fn dictated_outputs(server: &Server, value: u64, finder: Option<&str>) -> Vec<DictatedOutput> {
    dictated(server, value, finder).0
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

/// The outputs dictated for `value` to a connection of identity `finder`, the carry they
/// move, and the coinbaser response carrying them.
pub fn dictate(
    server: &Server,
    peer: SocketAddr,
    value: u64,
    coinbaser_id: u8,
    finder: Option<&str>,
) -> (Vec<DictatedOutput>, Vec<CarryDelta>, Vec<u8>) {
    // A connection whose identity is not yet known (a gateway whose hello named none, before
    // its first share) is dictated nothing while a finder's cut is set: a split without the
    // cut would pay the cut to the window and lose it, while a coinbase paying the pool's
    // script alone is recorded as owed, with the cut, if a block is found on it.
    if finder.is_none() && lock(&server.ledger).split_policy().finder_bps > 0 {
        info!(
            "[{peer}]      dictating no outputs: the connection's identity is not known yet \
             (no identity in its hello, no share credited), and the finder's cut needs it; a \
             block found on this job is owed in full"
        );
        let payload = CoinbaserResponse { value, coinbaser_id, outputs: Vec::new() }
            .encode()
            .expect("an empty split encodes");
        return (Vec::new(), Vec::new(), payload);
    }
    let plan = plan(server, value, finder);
    let (fee_outputs, window_shares, window_work) =
        (plan.fees.len(), plan.window_shares, plan.window_work);
    let fee_sats: u64 = plan.fees.iter().map(|d| d.payout.sats).sum();
    let finder_text = match &plan.finder {
        Some((identity, _, sats)) => format!("{sats} sats to the finder {identity}, "),
        None => String::new(),
    };
    let (dictated, carry) = outputs_of(plan, server.share_policy.chain);
    let total: u64 = dictated.iter().map(|d| d.payout.sats).sum();
    info!(
        "[{peer}]      paying {total} of {value} sats: {fee_sats} sats to {fee_outputs} fee \
         output(s), {finder_text}the rest over a window of {window_shares} shares \
         ({window_work} work) in {} output(s); {} carry delta(s)",
        dictated.len() - fee_outputs,
        carry.len()
    );
    let outputs = dictated.iter().map(DictatedOutput::output).collect();
    let payload = CoinbaserResponse { value, coinbaser_id, outputs }
        .encode()
        .expect("a split of payable outputs totalling at most the value encodes");
    (dictated, carry, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        ALICE, BOB, CAROL, FEE_ADDRESS, POOL, regtest_p2wpkh_address, server_with, server_with_fee,
        server_with_fees, server_with_public_gateway_fee,
    };
    use crate::ledger::split::FeeOutput;
    use ratum::fixtures::p2wpkh;

    const MAIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn coinbaser_outputs(server: &Server, value: u64) -> Vec<TxOut> {
        dictated_outputs(server, value, None).iter().map(DictatedOutput::output).collect()
    }

    fn values(outputs: &[DictatedOutput]) -> Vec<(u64, Vec<u8>)> {
        outputs.iter().map(|o| (o.payout.sats, o.script_pubkey.clone())).collect()
    }

    #[test]
    fn the_finder_takes_its_cut_after_the_fees_and_the_window_divides_the_rest() {
        let server = server_with_fee(&[(ALICE, 3), (BOB, 1)], 100);
        lock(&server.ledger).set_finder_bps(8_000);
        // The fee takes 10_000; the finder 80% of the 990_000 left; the window the rest.
        let outputs = dictated_outputs(&server, 1_000_000, Some(CAROL));
        assert_eq!(
            values(&outputs),
            vec![
                (10_000, p2wpkh(0xc3)),
                (792_000, p2wpkh(0xd4)),
                (148_500, p2wpkh(0xa1)),
                (49_500, p2wpkh(0xb2))
            ]
        );
        assert_eq!(outputs.iter().map(|o| o.payout.sats).sum::<u64>(), 1_000_000);
        let merged = dictated_outputs(&server, 1_000_000, Some(ALICE));
        assert_eq!(
            values(&merged),
            vec![(10_000, p2wpkh(0xc3)), (792_000 + 148_500, p2wpkh(0xa1)), (49_500, p2wpkh(0xb2))],
            "a finder in the window is paid once"
        );
        let unpayable = dictated_outputs(&server, 1_000_000, Some("nonsense"));
        assert_eq!(
            values(&unpayable)[1],
            (742_500, p2wpkh(0xa1)),
            "no cut without a payable finder"
        );
        assert_eq!(values(&dictated_outputs(&server, 1_000_000, None))[1].0, 742_500);
        assert_eq!(
            dictated_outputs(&server, 600, Some(CAROL)).len(),
            1,
            "a cut under the minimum: none"
        );
    }

    #[test]
    fn a_connection_without_an_identity_is_dictated_nothing_while_a_finders_cut_is_set() {
        const PEER: SocketAddr =
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
        let server = server_with(&[(ALICE, 3), (BOB, 1)]);
        let (outputs, carry, _) = dictate(&server, PEER, 1_000_000, 1, None);
        assert_eq!(outputs.len(), 2, "no cut set: the window is dictated");
        lock(&server.ledger).set_finder_bps(8_000);
        let (outputs, carry2, _) = dictate(&server, PEER, 1_000_000, 2, None);
        assert!(outputs.is_empty(), "the cut needs an identity: nothing is dictated");
        assert!(carry2.is_empty(), "nobody was left out of a split that paid nobody");
        let (outputs, _, _) = dictate(&server, PEER, 1_000_000, 3, Some(CAROL));
        assert_eq!(outputs.len(), 3, "the cut to carol and the window");
        assert!(carry.is_empty());
    }

    #[test]
    fn an_identity_left_out_carries_its_weight_into_the_next_split() {
        let server = server_with(&[(ALICE, 999), (BOB, 1)]);
        let (outputs, deltas) = dictated(&server, 500_000, None);
        assert_eq!(outputs.len(), 1, "bob's 500 is under the minimum");
        let bob: Arc<str> = Arc::from(BOB);
        assert_eq!(deltas, [CarryDelta { identity: Arc::clone(&bob), work: 1 }]);
        lock(&server.ledger).apply_carry(&[7; 32], &deltas, 1).unwrap();
        assert_eq!(lock(&server.ledger).carry().get(BOB), 1);

        let (outputs, deltas) = dictated(&server, 500_000, None);
        assert_eq!(
            values(&outputs),
            vec![(499_000, p2wpkh(0xa1)), (1_000, p2wpkh(0xb2))],
            "bob weighs 2 of 1001"
        );
        assert_eq!(
            deltas,
            [CarryDelta { identity: Arc::clone(&bob), work: -1 }],
            "paid: the carry is spent"
        );
        lock(&server.ledger).apply_carry(&[8; 32], &deltas, 2).unwrap();
        assert_eq!(lock(&server.ledger).carry().get(BOB), 0);

        // An identity with a carry and no share in the window is still in the split.
        let carol: Arc<str> = Arc::from(CAROL);
        let owed = [CarryDelta { identity: Arc::clone(&carol), work: 1_000 }];
        lock(&server.ledger).apply_carry(&[9; 32], &owed, 3).unwrap();
        let (outputs, deltas) = dictated(&server, 500_000, None);
        assert_eq!(
            values(&outputs)[0],
            (250_125, p2wpkh(0xd4)),
            "carol weighs 1000 of the 1999 left once bob's 250 is under the minimum"
        );
        assert_eq!(
            deltas,
            [CarryDelta { identity: carol, work: -1_000 }, CarryDelta { identity: bob, work: 1 }]
        );
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
