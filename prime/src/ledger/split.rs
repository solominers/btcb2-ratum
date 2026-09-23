//! Dividing a block's value over the window: the operator fee taken first, the public gateway fee
//! charged on the work of shares carrying its tag and partly reassigned to the rest, and the
//! amounts the remaining weights give, subject to a minimum and an output count.

use super::carry::CarryDelta;
use super::{IdentityState, Ledger, most_work_first};
use ratum::datum::messages::coinbaser::MAX_COINBASER_OUTPUTS;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// Shared with the window's entry for the identity, so a split allocates no name.
    pub identity: Arc<str>,
    pub sats: u64,
}

/// The public gateway: the secondary coinbase tag its shares carry, the fee charged on their
/// work at each split, and the portion of that fee reassigned to own-gateway miners. A fee of
/// 0 basis points charges and reassigns nothing; the tag then only separates own-gateway work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGateway {
    pub tag: String,
    pub fee_bps: u16,
    pub subsidy_bps: u16,
}

/// The smallest output written, the P2PKH dust threshold: an identity whose amount would fall
/// under it leaves the split.
pub const MIN_PAYOUT: u64 = 546;

/// The operator fee outputs a split may carry.
pub const MAX_FEE_OUTPUTS: usize = 4;
/// The most the fee outputs may take together, in basis points: 10%.
pub const MAX_TOTAL_FEE_BPS: u16 = 1000;

/// One operator fee: the address paid, its script, and the basis points of the coinbase value
/// it takes. The fees are dictated as outputs ahead of the miners' split, so they reach their
/// addresses in the coinbase itself and never pass through the pool's payout script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeOutput {
    pub address: String,
    pub script_pubkey: Vec<u8>,
    pub bps: u16,
}

/// What a block's value is split by: the operator fees taken off the top as their own
/// outputs, and the public gateway fee charged on the window's weights. The fees change while
/// the pool runs (`Ledger::set_fees`); the public gateway is fixed at startup, since the
/// window credits own-gateway work by its tag as each share is recorded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitPolicy {
    pub fees: Vec<FeeOutput>,
    /// The finder's cut of what the fees leave, in basis points: paid to the identity of the
    /// connection a split is dictated to, ahead of the window's split.
    pub finder_bps: u16,
    pub public_gateway: Option<PublicGateway>,
}

impl SplitPolicy {
    /// The finder's cut of `after_fees`, rounded down; 0 when it would fall under
    /// `MIN_PAYOUT`, since no output under it is written and the window then divides it.
    pub fn finder_cut(&self, after_fees: u64) -> u64 {
        let sats = basis_points_of(u128::from(after_fees), self.finder_bps) as u64;
        if sats >= MIN_PAYOUT { sats } else { 0 }
    }

    /// The basis points every fee output takes together.
    pub fn fee_bps(&self) -> u16 {
        self.fees.iter().map(|f| f.bps).sum()
    }

    /// Each fee output's amount of `value`, in the fees' order: `bps` of the value rounded
    /// down, so the operator never over-takes, and 0 where that falls under `MIN_PAYOUT`,
    /// since no output under it is written and the fee is then not taken. Each amount is
    /// computed on the whole value, not on what the fees before it left, so the fees are
    /// independent of their order.
    pub fn fee_amounts(&self, value: u64) -> impl Iterator<Item = (&FeeOutput, u64)> {
        self.fees.iter().map(move |f| {
            let sats = basis_points_of(u128::from(value), f.bps) as u64;
            (f, if sats >= MIN_PAYOUT { sats } else { 0 })
        })
    }

    /// What the fee outputs take of `value` together; `miners_share` is the rest, so the two
    /// total the value exactly.
    pub fn fee_on(&self, value: u64) -> u64 {
        self.fee_amounts(value).map(|(_, sats)| sats).sum()
    }

    pub fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicGatewayFeeWork {
    pub public_gateway_work: u128,
    pub fee_work: u128,
    pub reassigned_work: u128,
    pub own_gateway_work: u128,
}

fn basis_points_of(work: u128, bps: u16) -> u128 {
    work.saturating_mul(u128::from(bps)) / u128::from(ratum::BASIS_POINTS_PER_UNIT)
}

/// The public gateway fee charged on one identity's work: `fee_bps` of the work its shares
/// carried the public gateway's tag on. This is the one expression of that charge.
/// `public_gateway_fee_work` sums it and `weights` deducts it from the same identity, so the
/// weights and the retained fee work total `total_work` exactly; `weights_total_the_window`
/// pins that.
fn charged_work(state: &IdentityState, fee_bps: u16) -> u128 {
    basis_points_of(state.work - state.own_gateway_work, fee_bps)
}

/// The part of `fee_work` handed back to own-gateway miners: none while no share carried an
/// own-gateway tag, since there is nobody to reassign it to. The one expression of that rule.
fn reassigned_work(gateway: &PublicGateway, fee_work: u128, own_gateway_work: u128) -> u128 {
    if own_gateway_work == 0 { 0 } else { basis_points_of(fee_work, gateway.subsidy_bps) }
}

/// One identity's weight in a split: its window work (after the public gateway fee) and its
/// carry; the split orders by their sum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightEntry {
    pub identity: Arc<str>,
    pub window: u128,
    pub carry: u128,
}

impl WeightEntry {
    pub fn weight(&self) -> u128 {
        self.window + self.carry
    }
}

/// Each identity's weight in the split and the fee work the pool retains, copied out of the
/// window under the ledger lock so that the split (a sort and the amounts) runs without it.
///
/// The window weights and the retained fee work total the window's work, because every
/// identity is charged by `charged_work` in `Ledger::weights` and by the same function in
/// `public_gateway_fee_work`, and `given` sums the reassignments handed out;
/// `weights_total_the_window` pins it. The carry is added on top of that, and is what an
/// identity is owed by the miners who divided an earlier block without it.
#[derive(Clone, Debug, Default)]
pub struct Weights {
    /// Each identity with work in the window or a carry, in the window's order.
    pub(super) entries: Vec<WeightEntry>,
    /// What the public gateway fee charged less what it reassigned; the denominator includes
    /// it, so it reaches the pool's script as the remainder.
    pub(super) retained_by_pool: u128,
}

/// A split's outcome: the amounts, and the carry deltas of the identities left out (their
/// window weight, added) and paid (their carry, spent), which apply if a block is found on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub payouts: Vec<Payout>,
    pub carry_deltas: Vec<CarryDelta>,
}

impl Weights {
    /// The split of `value`, already less the operator fees and the finder's cut, among at
    /// most `MAX_COINBASER_OUTPUTS` identities of at least `MIN_PAYOUT`, most weight first.
    pub fn split(self, value: u64) -> Split {
        self.split_with(value, MIN_PAYOUT, MAX_COINBASER_OUTPUTS)
    }

    /// `split` among at most `max_outputs` identities: what is left of the output count once
    /// the outputs dictated beside the split are counted.
    pub fn split_at_most(self, value: u64, max_outputs: usize) -> Split {
        self.split_with(value, MIN_PAYOUT, max_outputs)
    }

    fn split_with(self, value: u64, min_payout: u64, max_outputs: usize) -> Split {
        let Self { mut entries, retained_by_pool } = self;
        let total: u128 = entries.iter().map(WeightEntry::weight).sum::<u128>() + retained_by_pool;
        if total == 0 || value == 0 || max_outputs == 0 {
            // Nothing is divided, so nobody is left out of a division: no carry moves.
            return Split::default();
        }
        entries
            .sort_by(|a, b| most_work_first((&a.identity, a.weight()), (&b.identity, b.weight())));
        let mut dropped = entries.split_off(entries.len().min(max_outputs));
        let mut work: u128 =
            entries.iter().map(WeightEntry::weight).sum::<u128>() + retained_by_pool;

        while let Some(last) = entries.last() {
            let w = last.weight();
            if work == 0 {
                dropped.append(&mut entries);
                break;
            }
            if u128::from(value).saturating_mul(w) / work >= u128::from(min_payout) {
                break;
            }
            work -= w;
            dropped.extend(entries.pop());
        }

        let mut left = value;
        let mut payouts = Vec::with_capacity(entries.len());
        let mut carry_deltas = Vec::new();
        for e in entries {
            if work == 0 {
                dropped.push(e);
                continue;
            }
            let amount = (u128::from(left).saturating_mul(e.weight()) / work) as u64;
            left -= amount;
            work -= e.weight();
            if amount == 0 {
                dropped.push(e);
                continue;
            }
            if e.carry != 0 {
                let identity = Arc::clone(&e.identity);
                carry_deltas.push(CarryDelta { identity, work: -(e.carry as i128) });
            }
            payouts.push(Payout { identity: e.identity, sats: amount });
        }
        for e in dropped {
            if e.window != 0 {
                carry_deltas.push(CarryDelta { identity: e.identity, work: e.window as i128 });
            }
        }
        Split { payouts, carry_deltas }
    }
}

impl Ledger {
    /// The work the public gateway fee charges and reassigns; none without a public gateway.
    pub fn public_gateway_fee_work(&self) -> Option<PublicGatewayFeeWork> {
        let gateway = self.split_policy.public_gateway.as_ref()?;
        let mut public_gateway_work = 0u128;
        let mut fee_work = 0u128;
        let mut own_gateway_work = 0u128;
        for (_, state) in self.identities.iter() {
            public_gateway_work += state.work - state.own_gateway_work;
            fee_work += charged_work(state, gateway.fee_bps);
            own_gateway_work += state.own_gateway_work;
        }
        let reassigned_work = reassigned_work(gateway, fee_work, own_gateway_work);
        Some(PublicGatewayFeeWork {
            public_gateway_work,
            fee_work,
            reassigned_work,
            own_gateway_work,
        })
    }

    /// Each identity's weight in the split and the fee work the pool retains: what the
    /// public gateway fee charged less what it reassigned, plus each identity's carry, and
    /// the identities with a carry but no share in the window. One pass over the window,
    /// taken under the ledger lock; `Weights::split` then runs without it.
    pub fn weights(&self) -> Weights {
        let fee_bps = self.split_policy.public_gateway.as_ref().map_or(0, |g| g.fee_bps);
        let PublicGatewayFeeWork { fee_work, reassigned_work, own_gateway_work, .. } =
            self.public_gateway_fee_work().unwrap_or_default();
        let mut given = 0u128;
        let mut entries = Vec::with_capacity(self.identities.len() + self.carry.len());
        for (identity, state) in self.identities.iter() {
            let own = state.own_gateway_work;
            let extra =
                reassigned_work.saturating_mul(own).checked_div(own_gateway_work).unwrap_or(0);
            given += extra;
            entries.push(WeightEntry {
                identity: Arc::clone(identity),
                window: state.work - charged_work(state, fee_bps) + extra,
                carry: self.carry.get(identity),
            });
        }
        for (identity, carry) in self.carry.iter() {
            if carry != 0 && !self.identities.contains(identity) {
                entries.push(WeightEntry { identity: Arc::clone(identity), window: 0, carry });
            }
        }
        Weights { entries, retained_by_pool: fee_work.saturating_sub(given) }
    }

    /// What the window's split of `value` is computed from: the weights, and `value` less
    /// the operator fees and the finder's cut. A caller holding the ledger lock takes these
    /// and releases it before `Weights::split`.
    pub fn weights_for(&self, value: u64) -> (Weights, u64) {
        let after_fees = self.split_policy.miners_share(value);
        (self.weights(), after_fees - self.split_policy.finder_cut(after_fees))
    }

    /// The window's split of `value`: `weights_for` and `Weights::split` in one call.
    #[cfg(test)]
    pub fn split(&self, value: u64) -> Vec<Payout> {
        let (weights, value) = self.weights_for(value);
        weights.split(value).payouts
    }

    #[cfg(test)]
    pub(super) fn split_value(
        &self,
        value: u64,
        min_payout: u64,
        max_outputs: usize,
    ) -> Vec<Payout> {
        self.weights().split_with(value, min_payout, max_outputs).payouts
    }
}
