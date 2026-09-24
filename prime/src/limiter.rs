//! The hashrate limiter: each identity (a payout address, one lottery ticket) may bring at most
//! a bounded hashrate, measured over several periods at once. A short period with a high
//! threshold catches a large miner within a minute, and a long period with a low threshold
//! holds the cap the pool is built around, while the variance of a small miner's share
//! arrivals over a short period never reaches the short period's threshold. An identity over
//! any bracket has its shares refused (`RejectReason::HashLimit`) while it stays over: nothing
//! is banned, so nobody can be locked out for a day by a burst of shares, their own or
//! anyone else's. Which shares are refused depends on the gateway they come through: the
//! identity's home gateway, the one that has mined it the most over the last `HOME_DAYS`,
//! keeps its shares accepted unless its own shares alone are over, and every other gateway's
//! are refused. A gateway pointing hashrate at someone else's address to get it refused
//! only gets itself refused. The operators can still ban an identity by hand (`--ban`), for
//! `--ban-secs`, longer each time when escalation is set; bans are written to the ledger
//! file, so a restart keeps them.
//!
//! A share is placed at its header time, no earlier than `REPLAY_ALLOWANCE` before its
//! acceptance: a gateway that reconnects replays the shares it queued while it was away, and
//! those would read as a burst at their acceptance time, while a header time can be pushed
//! back only that far and by then the longer brackets have the measure.

use crate::ledger::db::{self, DbResult as _};
use bytes::{Buf as _, BufMut as _};
use log::warn;
use ratum::hashrate;
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// The bans by identity: since, until, times banned, and the reason of the newest ban. A row
/// stays after its ban ends, since `times` is what escalation counts.
pub(crate) const BANS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bans");

/// How far back a share's header time may place it: what the gateway's stale-share rule lets
/// it replay after a reconnect (`share_stale_seconds + work_update_seconds`, 270 s at most).
pub const REPLAY_ALLOWANCE_SECS: u64 = 300;
/// The most samples kept for one identity, whatever the periods: a share every second for the
/// longest bracket the pool allows would need more, and then the reading is of the newest.
const MAX_SAMPLES: usize = 16384;
/// The brackets a rule set may hold.
pub const MAX_BRACKETS: usize = 8;
pub const MIN_PERIOD_SECS: u64 = 10;
pub const MAX_PERIOD_SECS: u64 = ratum::SECS_PER_DAY;
/// The longest a ban may run, escalation included.
const MAX_BAN_SECS: u64 = 365 * ratum::SECS_PER_DAY;
/// How many observations pass between sweeps of identities that have gone quiet.
const SWEEP_EVERY: u64 = 4096;
/// How far back a gateway's accepted work for an identity counts towards being its home.
pub const HOME_DAYS: u64 = 7;
/// How many shares a gateway's record for an identity takes between writes to the ledger
/// file, besides the writes a new record and a new day bring.
const HOME_WRITE_EVERY: u32 = 64;
/// The gateways that have mined each identity: `identity NUL key` to the record's first
/// share time and its accepted work by day, so a restart keeps each identity's home.
pub(crate) const GATEWAYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("gateways");
/// The most a reading may exceed a threshold by under `--hash-limit-sigma`, however few
/// shares it rests on: an identity sending a handful of high-difficulty shares gets no wider
/// an allowance than this.
pub const MAX_SIGMA_TOLERANCE: f64 = 0.25;
pub const MAX_SIGMA: f64 = 10.0;

/// One measure: the hashrate over `period` an identity may not exceed.
#[derive(Clone, Debug, PartialEq)]
pub struct Bracket {
    pub period_secs: u64,
    pub threshold_hs: f64,
}

/// What the limiter enforces: the brackets, shortest period first, and the ban they lead to.
/// No brackets is no limit.
#[derive(Clone, Debug, PartialEq)]
pub struct Rules {
    pub brackets: Vec<Bracket>,
    pub ban_secs: u64,
    /// The factor each repeat ban is longer by: 1 for the same length every time.
    pub escalation: f64,
    /// The statistical margin: a reading over `n` shares must exceed the threshold by
    /// `sigma / sqrt(n)` of it (at most `MAX_SIGMA_TOLERANCE`) to ban, since a rate measured
    /// from `n` share arrivals wobbles by about `1 / sqrt(n)` of itself. 0 bans on the
    /// threshold itself.
    pub sigma: f64,
}

impl Default for Rules {
    fn default() -> Self {
        Self { brackets: Vec::new(), ban_secs: ratum::SECS_PER_DAY, escalation: 1.0, sigma: 0.0 }
    }
}

impl Rules {
    pub fn longest_period(&self) -> u64 {
        self.brackets.iter().map(|b| b.period_secs).max().unwrap_or(0)
    }

    /// How long the ban after `prior` earlier bans runs.
    /// The rate a reading over `shares` shares must exceed for `bracket` to ban.
    pub fn allowed(&self, bracket: &Bracket, shares: usize) -> f64 {
        let tolerance = if self.sigma > 0.0 {
            (self.sigma / (shares.max(1) as f64).sqrt()).min(MAX_SIGMA_TOLERANCE)
        } else {
            0.0
        };
        bracket.threshold_hs * (1.0 + tolerance)
    }

    pub fn ban_length(&self, prior: u32) -> u64 {
        let factor = self.escalation.max(1.0).powi(prior.min(64) as i32);
        let secs = (self.ban_secs as f64 * factor).min(MAX_BAN_SECS as f64);
        if secs.is_finite() { (secs as u64).max(1) } else { MAX_BAN_SECS }
    }

    pub fn describe(&self) -> String {
        if self.brackets.is_empty() {
            return "hash-limit: none\n".to_string();
        }
        let each: Vec<String> = self
            .brackets
            .iter()
            .map(|b| format!("{} {}", period_text(b.period_secs), hashrate_text(b.threshold_hs)))
            .collect();
        format!(
            "hash-limit: {} (over any bracket: refused while over)\nhash-limit-sigma: {}\nban-secs: {} ({})\nban-escalation: {}\n",
            each.join(", "),
            self.sigma,
            self.ban_secs,
            period_text(self.ban_secs),
            self.escalation
        )
    }

    pub fn json(&self) -> Value {
        json!({
            "brackets": self.brackets.iter().map(|b| json!({
                "period_secs": b.period_secs,
                "threshold_hs": b.threshold_hs,
            })).collect::<Vec<_>>(),
            "ban_secs": self.ban_secs,
            "ban_escalation": self.escalation,
            "sigma": self.sigma,
        })
    }
}

/// `text` as a bracket: `PERIOD=RATE`, the period a number of seconds, minutes or hours
/// (`90s`, `5m`, `2h`) and the rate hashes per second with an optional K, M, G, T or P.
pub fn parse_bracket(text: &str) -> Result<Bracket, String> {
    let Some((period, rate)) = text.split_once('=') else {
        return Err(format!("{text:?} must be PERIOD=RATE, as in 5m=50T"));
    };
    let period_secs = parse_period(period.trim())
        .ok_or_else(|| format!("{text:?}: {period:?} is not a period like 90s, 5m or 2h"))?;
    if !(MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&period_secs) {
        return Err(format!(
            "{text:?}: the period must be from {MIN_PERIOD_SECS} seconds to {} hours",
            MAX_PERIOD_SECS / ratum::SECS_PER_HOUR
        ));
    }
    let threshold_hs = parse_hashrate(rate.trim())
        .ok_or_else(|| format!("{text:?}: {rate:?} is not a hashrate like 3.5T or 100T"))?;
    if threshold_hs <= 0.0 || threshold_hs.is_nan() {
        return Err(format!("{text:?}: the rate must be above 0"));
    }
    Ok(Bracket { period_secs, threshold_hs })
}

/// The rules `entries` name (each `parse_bracket`), sorted by period: at most `MAX_BRACKETS`,
/// no two on one period.
pub fn rules_from(
    entries: &[String],
    ban_secs: u64,
    escalation: f64,
    sigma: f64,
) -> Result<Rules, String> {
    let mut brackets = Vec::new();
    for entry in entries.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
        let bracket = parse_bracket(entry).map_err(|e| format!("--hash-limit {e}"))?;
        if brackets.iter().any(|b: &Bracket| b.period_secs == bracket.period_secs) {
            return Err(format!(
                "--hash-limit names the period {} twice",
                period_text(bracket.period_secs)
            ));
        }
        brackets.push(bracket);
    }
    if brackets.len() > MAX_BRACKETS {
        return Err(format!(
            "--hash-limit names {} brackets; at most {MAX_BRACKETS}",
            brackets.len()
        ));
    }
    brackets.sort_by_key(|b| b.period_secs);
    if ban_secs == 0 || ban_secs > MAX_BAN_SECS {
        return Err(format!("--ban-secs must be from 1 to {MAX_BAN_SECS} (a year)"));
    }
    if !escalation.is_finite() || escalation < 1.0 {
        return Err("--ban-escalation must be 1 (every ban the same length) or more".to_string());
    }
    if !sigma.is_finite() || !(0.0..=MAX_SIGMA).contains(&sigma) {
        return Err(format!("--hash-limit-sigma must be from 0 (refuse on the threshold itself) to {MAX_SIGMA}"));
    }
    Ok(Rules { brackets, ban_secs, escalation, sigma })
}

pub fn parse_period(text: &str) -> Option<u64> {
    let (number, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit() && *c != '.') {
        Some((i, _)) => text.split_at(i),
        None => (text, "s"),
    };
    let n: f64 = number.parse().ok()?;
    let secs = match unit.trim() {
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n * ratum::SECS_PER_MINUTE as f64,
        "h" | "hr" | "hrs" => n * ratum::SECS_PER_HOUR as f64,
        "d" => n * ratum::SECS_PER_DAY as f64,
        _ => return None,
    };
    (secs.is_finite() && secs >= 0.0).then(|| secs.round() as u64)
}

pub fn parse_hashrate(text: &str) -> Option<f64> {
    let text = text.trim_end_matches("H/s").trim_end_matches("h/s").trim();
    let (number, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit() && *c != '.') {
        Some((i, _)) => text.split_at(i),
        None => (text, ""),
    };
    let n: f64 = number.parse().ok()?;
    let scale = match unit.trim() {
        "" => 1.0,
        "K" | "k" => 1e3,
        "M" => 1e6,
        "G" | "g" => 1e9,
        "T" | "t" => 1e12,
        "P" | "p" => 1e15,
        _ => return None,
    };
    Some(n * scale)
}

pub fn period_text(secs: u64) -> String {
    if secs.is_multiple_of(ratum::SECS_PER_DAY) {
        format!("{}d", secs / ratum::SECS_PER_DAY)
    } else if secs.is_multiple_of(ratum::SECS_PER_HOUR) {
        format!("{}h", secs / ratum::SECS_PER_HOUR)
    } else if secs.is_multiple_of(ratum::SECS_PER_MINUTE) {
        format!("{}m", secs / ratum::SECS_PER_MINUTE)
    } else {
        format!("{secs}s")
    }
}

pub fn hashrate_text(hs: f64) -> String {
    let units = [(1e15, "PH/s"), (1e12, "TH/s"), (1e9, "GH/s"), (1e6, "MH/s"), (1e3, "KH/s")];
    for (scale, unit) in units {
        if hs >= scale {
            let n = hs / scale;
            return if n.fract() == 0.0 {
                format!("{n:.0} {unit}")
            } else {
                format!("{n:.2} {unit}")
            };
        }
    }
    format!("{hs:.0} H/s")
}

/// One ban: when it began, when it ends, how many bans the identity has had this one
/// included, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ban {
    pub identity: String,
    pub since: u64,
    pub until: u64,
    pub times: u32,
    pub reason: String,
}

impl Ban {
    pub fn active(&self, now: u64) -> bool {
        self.until > now
    }

    pub fn json(&self) -> Value {
        json!({
            "identity": self.identity,
            "since": self.since,
            "until": self.until,
            "times": self.times,
            "reason": self.reason,
        })
    }
}

/// A gateway's DATUM signing key, which its hello carries and nothing else can produce.
pub type GatewayKey = [u8; 32];

/// One accepted share: when it was placed, its difficulty, and the gateway it came through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sample {
    at: u64,
    difficulty: u64,
    gateway: GatewayKey,
}

/// The recent shares of one identity, oldest first.
#[derive(Default)]
struct Ring {
    samples: VecDeque<Sample>,
}

impl Ring {
    fn push(&mut self, sample: Sample) {
        self.samples.push_back(sample);
        if self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    fn trim(&mut self, cutoff: u64) {
        while self.samples.front().is_some_and(|s| s.at < cutoff) {
            self.samples.pop_front();
        }
    }

    /// The samples since `cutoff`, those of `gateway` only when one is named.
    fn since<'a>(
        &'a self,
        cutoff: u64,
        gateway: Option<&'a GatewayKey>,
    ) -> impl Iterator<Item = &'a Sample> + 'a {
        self.samples
            .iter()
            .filter(move |s| s.at >= cutoff && gateway.is_none_or(|g| s.gateway == *g))
    }

    fn work_since(&self, cutoff: u64, gateway: Option<&GatewayKey>) -> u128 {
        self.since(cutoff, gateway).map(|s| u128::from(s.difficulty)).sum()
    }

    fn count_since(&self, cutoff: u64, gateway: Option<&GatewayKey>) -> usize {
        self.since(cutoff, gateway).count()
    }

    /// The gateways with a share since `cutoff`, in the order first seen there.
    fn gateways_since(&self, cutoff: u64) -> Vec<GatewayKey> {
        let mut v: Vec<GatewayKey> = Vec::new();
        for s in self.since(cutoff, None) {
            if !v.contains(&s.gateway) {
                v.push(s.gateway);
            }
        }
        v
    }

    fn newest(&self) -> Option<u64> {
        self.samples.back().map(|s| s.at)
    }
}

/// What one gateway has mined for one identity: when its first share came, and its accepted
/// work by day (unix day), newest last, at most `HOME_DAYS` days.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GatewayRecord {
    first_seen: u64,
    days: VecDeque<(u64, u64)>,
    unwritten: u32,
}

impl GatewayRecord {
    /// Adds `difficulty` of work on `day`; whether the record should be written now.
    fn add(&mut self, day: u64, difficulty: u64) -> bool {
        let new_day = match self.days.back_mut() {
            Some((d, work)) if *d == day => {
                *work = work.saturating_add(difficulty);
                false
            }
            _ => {
                self.days.push_back((day, difficulty));
                while self.days.len() as u64 > HOME_DAYS {
                    self.days.pop_front();
                }
                true
            }
        };
        self.unwritten += 1;
        if new_day || self.unwritten >= HOME_WRITE_EVERY {
            self.unwritten = 0;
            return true;
        }
        false
    }

    fn work_from_day(&self, day: u64) -> u128 {
        self.days.iter().filter(|(d, _)| *d >= day).map(|(_, w)| u128::from(*w)).sum()
    }
}

/// Why a share is refused by the limiter: the reading over its bracket, the identity's home
/// gateway if it has one, and whether the refused share came through that home gateway (its
/// own shares alone being over) or another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub home: Option<GatewayKey>,
    pub own: bool,
}

/// An identity over its cap now, as the stats report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Throttled {
    pub identity: String,
    pub since: u64,
    pub reason: String,
    pub home: Option<GatewayKey>,
    /// The gateways with a share in the longest bracket's window, the home one aside: the
    /// ones whose shares are being refused.
    pub refused: Vec<GatewayKey>,
}

impl Throttled {
    pub fn json(&self) -> Value {
        json!({
            "identity": self.identity,
            "since": self.since,
            "reason": self.reason,
            "home_gateway": self.home.as_ref().map(crate::workers::gateway_tag),
            "refused_gateways": self.refused.iter().map(crate::workers::gateway_tag).collect::<Vec<_>>(),
        })
    }
}

/// The reading of `ring` over each bracket at `now`, the shares of `gateway` alone when one
/// is named: the first bracket it is over, described.
fn over(rules: &Rules, ring: &Ring, now: u64, gateway: Option<&GatewayKey>) -> Option<String> {
    rules.brackets.iter().find_map(|b| {
        let cutoff = now.saturating_sub(b.period_secs);
        let work = ring.work_since(cutoff, gateway);
        let hs = hashrate::from_work(work, Duration::from_secs(b.period_secs));
        let shares = ring.count_since(cutoff, gateway);
        let allowed = rules.allowed(b, shares);
        (hs > allowed).then(|| {
            if allowed > b.threshold_hs {
                format!(
                    "{} over {} is over the {} limit ({} allowed for a reading of {shares} shares)",
                    hashrate_text(hs),
                    period_text(b.period_secs),
                    hashrate_text(b.threshold_hs),
                    hashrate_text(allowed)
                )
            } else {
                format!(
                    "{} over {} is over the {} limit",
                    hashrate_text(hs),
                    period_text(b.period_secs),
                    hashrate_text(b.threshold_hs)
                )
            }
        })
    })
}

pub struct Limiter {
    rules: Rules,
    rings: HashMap<String, Ring>,
    /// Every identity ever banned, with its newest ban; `Ban::active` says whether it holds.
    bans: HashMap<String, Ban>,
    /// The gateways that have mined each identity (`home_of`).
    homes: HashMap<String, HashMap<GatewayKey, GatewayRecord>>,
    /// When each identity now over its cap first read over, since it last read under.
    throttled_since: HashMap<String, u64>,
    db: Option<Arc<Database>>,
    observations: u64,
}

impl Limiter {
    /// A limiter holding its bans and gateway records in memory only.
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            rings: HashMap::new(),
            bans: HashMap::new(),
            homes: HashMap::new(),
            throttled_since: HashMap::new(),
            db: None,
            observations: 0,
        }
    }

    /// A limiter over the ledger file's ban and gateway tables, read back now.
    pub fn open(rules: Rules, db: Arc<Database>) -> io::Result<Self> {
        let mut bans = HashMap::new();
        let mut homes: HashMap<String, HashMap<GatewayKey, GatewayRecord>> = HashMap::new();
        let r = db.begin_read().db()?;
        if let Ok(table) = r.open_table(GATEWAYS) {
            for entry in table.iter().db()? {
                let (key, value) = entry.db()?;
                match unpack_gateway(key.value(), value.value()) {
                    Some((identity, gateway, record)) => {
                        homes.entry(identity).or_default().insert(gateway, record);
                    }
                    None => warn!("skipping a gateway row that did not unpack"),
                }
            }
        }
        // The table exists once a ban was written; before that there is nothing to read.
        if let Ok(table) = r.open_table(BANS) {
            for entry in table.iter().db()? {
                let (key, value) = entry.db()?;
                match unpack_ban(key.value(), value.value()) {
                    Some(ban) => {
                        bans.insert(ban.identity.clone(), ban);
                    }
                    None => warn!("skipping a ban row that did not unpack"),
                }
            }
        }
        drop(r);
        Ok(Self {
            rules,
            rings: HashMap::new(),
            bans,
            homes,
            throttled_since: HashMap::new(),
            db: Some(db),
            observations: 0,
        })
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// Replaces the rules; the samples and the bans stay.
    pub fn set_rules(&mut self, rules: Rules) {
        self.rules = rules;
    }

    /// The ban holding `identity` at `now`, if any.
    pub fn ban_of(&self, identity: &str, now: u64) -> Option<&Ban> {
        self.bans.get(identity).filter(|b| b.active(now))
    }

    /// Every ban holding at `now`, soonest to end first.
    pub fn active_bans(&self, now: u64) -> Vec<Ban> {
        let mut v: Vec<Ban> = self.bans.values().filter(|b| b.active(now)).cloned().collect();
        v.sort_by_key(|b| (b.until, b.identity.clone()));
        v
    }

    /// Whether a share of `identity` through `gateway` is refused now: the identity's reading
    /// is over a bracket, and the share is not from its home gateway, or is and the home
    /// gateway's own shares alone are over. A refused share is not recorded, so the reading
    /// falls as the window rolls and the refusals end on their own.
    pub fn check(&mut self, identity: &str, gateway: &GatewayKey, now: u64) -> Option<Refusal> {
        if self.rules.brackets.is_empty() {
            return None;
        }
        let longest = self.rules.longest_period();
        let Some(ring) = self.rings.get_mut(identity) else {
            self.throttled_since.remove(identity);
            return None;
        };
        ring.trim(now.saturating_sub(longest));
        let Some(reason) = over(&self.rules, ring, now, None) else {
            self.throttled_since.remove(identity);
            return None;
        };
        self.throttled_since.entry(identity.to_string()).or_insert(now);
        let home = self.home_of(identity, now);
        if home.as_ref() == Some(gateway) {
            let ring = &self.rings[identity];
            let own = over(&self.rules, ring, now, Some(gateway))?;
            return Some(Refusal { reason: format!("{own}, from this gateway alone"), home, own: true });
        }
        Some(Refusal { reason, home, own: false })
    }

    /// The gateway that has mined `identity` the most over the last `HOME_DAYS`; the earliest
    /// seen when two are level. None while nothing has been recorded for the identity.
    pub fn home_of(&self, identity: &str, now: u64) -> Option<GatewayKey> {
        let from_day = (now / ratum::SECS_PER_DAY).saturating_sub(HOME_DAYS - 1);
        self.homes
            .get(identity)?
            .iter()
            .map(|(key, r)| (r.work_from_day(from_day), std::cmp::Reverse(r.first_seen), *key))
            .filter(|(work, _, _)| *work > 0)
            .max()
            .map(|(_, _, key)| key)
    }

    /// Records an accepted share of `identity` through `gateway`: `difficulty` at the header
    /// time `ntime`, accepted at `now`.
    pub fn observe(
        &mut self,
        identity: &str,
        gateway: &GatewayKey,
        ntime: u64,
        difficulty: u64,
        now: u64,
    ) {
        if self.rules.brackets.is_empty() {
            return;
        }
        let at = ntime.clamp(now.saturating_sub(REPLAY_ALLOWANCE_SECS), now);
        let longest = self.rules.longest_period();
        self.observations += 1;
        if self.observations.is_multiple_of(SWEEP_EVERY) {
            let cutoff = now.saturating_sub(longest);
            self.rings.retain(|_, ring| ring.newest().is_some_and(|newest| newest >= cutoff));
            let stale_day = (now / ratum::SECS_PER_DAY).saturating_sub(HOME_DAYS);
            self.homes.retain(|_, gateways| {
                gateways.retain(|_, r| r.days.back().is_some_and(|(d, _)| *d >= stale_day));
                !gateways.is_empty()
            });
        }
        let ring = self.rings.entry(identity.to_string()).or_default();
        ring.push(Sample { at, difficulty, gateway: *gateway });
        ring.trim(now.saturating_sub(longest));
        let record = self.homes.entry(identity.to_string()).or_default().entry(*gateway).or_insert_with(
            || GatewayRecord { first_seen: now, days: VecDeque::new(), unwritten: 0 },
        );
        if record.add(now / ratum::SECS_PER_DAY, difficulty) {
            let record = record.clone();
            self.write_gateway(identity, gateway, &record);
        }
    }

    /// Every identity over its cap at `now`, the longest over first.
    pub fn throttled(&self, now: u64) -> Vec<Throttled> {
        let longest = self.rules.longest_period();
        let mut v: Vec<Throttled> = self
            .rings
            .iter()
            .filter_map(|(identity, ring)| {
                let reason = over(&self.rules, ring, now, None)?;
                let home = self.home_of(identity, now);
                let refused = ring
                    .gateways_since(now.saturating_sub(longest))
                    .into_iter()
                    .filter(|g| Some(g) != home.as_ref())
                    .collect();
                Some(Throttled {
                    identity: identity.clone(),
                    since: self.throttled_since.get(identity).copied().unwrap_or(now),
                    reason,
                    home,
                    refused,
                })
            })
            .collect();
        v.sort_by(|a, b| a.since.cmp(&b.since).then_with(|| a.identity.cmp(&b.identity)));
        v
    }

    fn write_gateway(&self, identity: &str, gateway: &GatewayKey, record: &GatewayRecord) {
        let Some(db) = &self.db else { return };
        let written = db::write(db, |w| {
            w.open_table(GATEWAYS)
                .db()?
                .insert(gateway_key(identity, gateway).as_slice(), pack_gateway(record).as_slice())
                .db()?;
            Ok(())
        });
        if let Err(e) = written {
            warn!("could not write the gateway record of {identity} to the ledger file ({e})");
        }
    }

    /// Bans `identity` from `now` for `secs`, or for the rules' length after its earlier
    /// bans when none is given, and writes the ban to the file.
    pub fn ban(&mut self, identity: &str, now: u64, secs: Option<u64>, reason: String) -> Ban {
        let prior = self.bans.get(identity).map_or(0, |b| b.times);
        let secs = secs.unwrap_or_else(|| self.rules.ban_length(prior)).clamp(1, MAX_BAN_SECS);
        let ban = Ban {
            identity: identity.to_string(),
            since: now,
            until: now.saturating_add(secs),
            times: prior.saturating_add(1),
            reason,
        };
        self.write(&ban);
        self.bans.insert(identity.to_string(), ban.clone());
        ban
    }

    /// Ends the ban on `identity` at `now`, keeping its count; whether one was holding.
    pub fn unban(&mut self, identity: &str, now: u64) -> bool {
        let Some(ban) = self.bans.get_mut(identity).filter(|b| b.active(now)) else { return false };
        ban.until = now;
        let ban = ban.clone();
        self.write(&ban);
        true
    }

    fn write(&self, ban: &Ban) {
        let Some(db) = &self.db else { return };
        let written = db::write(db, |w| {
            w.open_table(BANS)
                .db()?
                .insert(ban.identity.as_bytes(), pack_ban(ban).as_slice())
                .db()?;
            Ok(())
        });
        if let Err(e) = written {
            warn!(
                "could not write the ban on {} to the ledger file ({e}); it holds in memory",
                ban.identity
            );
        }
    }
}

const BAN_PREFIX_LEN: usize = 8 + 8 + 4;

fn pack_ban(b: &Ban) -> Vec<u8> {
    let mut v = Vec::with_capacity(BAN_PREFIX_LEN + b.reason.len());
    v.put_u64_le(b.since);
    v.put_u64_le(b.until);
    v.put_u32_le(b.times);
    v.put_slice(b.reason.as_bytes());
    v
}

fn unpack_ban(key: &[u8], mut value: &[u8]) -> Option<Ban> {
    if value.len() < BAN_PREFIX_LEN {
        return None;
    }
    let since = value.get_u64_le();
    let until = value.get_u64_le();
    let times = value.get_u32_le();
    Some(Ban {
        identity: String::from_utf8(key.to_vec()).ok()?,
        since,
        until,
        times,
        reason: String::from_utf8_lossy(value).into_owned(),
    })
}

fn gateway_key(identity: &str, gateway: &GatewayKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(identity.len() + 1 + gateway.len());
    v.extend_from_slice(identity.as_bytes());
    v.push(0);
    v.extend_from_slice(gateway);
    v
}

fn pack_gateway(r: &GatewayRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + r.days.len() * 16);
    v.put_u64_le(r.first_seen);
    for (day, work) in &r.days {
        v.put_u64_le(*day);
        v.put_u64_le(*work);
    }
    v
}

fn unpack_gateway(key: &[u8], mut value: &[u8]) -> Option<(String, GatewayKey, GatewayRecord)> {
    let (identity, rest) = key.split_at_checked(key.len().checked_sub(33)?)?;
    let gateway: GatewayKey = rest[1..].try_into().ok()?;
    if rest[0] != 0 || value.len() < 8 || !(value.len() - 8).is_multiple_of(16) {
        return None;
    }
    let first_seen = value.get_u64_le();
    let mut days = VecDeque::new();
    while value.remaining() >= 16 {
        let day = value.get_u64_le();
        days.push_back((day, value.get_u64_le()));
    }
    Some((
        String::from_utf8(identity.to_vec()).ok()?,
        gateway,
        GatewayRecord { first_seen, days, unwritten: 0 },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: f64 = 1e12;
    /// The gateway the tests' shares come through unless another is named.
    const G: GatewayKey = [1u8; 32];

    fn rules(entries: &[&str]) -> Rules {
        let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        rules_from(&entries, ratum::SECS_PER_DAY, 1.0, 0.0).unwrap()
    }

    fn starter() -> Rules {
        rules(&["1m=100T", "5m=50T", "30m=10T", "2h=3.5T"])
    }

    /// The difficulty a miner of `hs` hashes per second solves in `secs`, as one share.
    fn work_for(hs: f64, secs: f64) -> u64 {
        (hs * secs / (1u64 << 32) as f64) as u64
    }

    #[test]
    fn brackets_parse_from_period_and_rate_and_sort_by_period() {
        let r = rules(&["2h=3.5T", "1m=100T", " ", "5m = 50 T"]);
        assert_eq!(
            r.brackets,
            vec![
                Bracket { period_secs: 60, threshold_hs: 100.0 * T },
                Bracket { period_secs: 300, threshold_hs: 50.0 * T },
                Bracket { period_secs: 7200, threshold_hs: 3.5 * T },
            ]
        );
        assert_eq!(r.longest_period(), 7200);
        assert_eq!(parse_period("90s"), Some(90));
        assert_eq!(parse_period("1.5h"), Some(5400));
        assert_eq!(parse_period("45"), Some(45), "bare seconds");
        assert_eq!(parse_period("2d"), Some(172_800));
        assert_eq!(parse_period("x"), None);
        assert_eq!(parse_hashrate("100T"), Some(100.0 * T));
        assert_eq!(parse_hashrate("3.5 TH/s"), Some(3.5 * T));
        assert_eq!(parse_hashrate("500G"), Some(5e11));
        assert_eq!(parse_hashrate("12"), Some(12.0));
        assert_eq!(parse_hashrate("T"), None);
        for (entry, what) in [
            ("5m", "PERIOD=RATE"),
            ("x=1T", "not a period"),
            ("5m=lots", "not a hashrate"),
            ("5m=0", "above 0"),
            ("5s=1T", "from 10 seconds"),
            ("2d=1T", "to 24 hours"),
        ] {
            let e = parse_bracket(entry).unwrap_err();
            assert!(e.contains(what), "{entry}: {e}");
        }
        let twice = rules_from(&["5m=1T".into(), "300s=2T".into()], 60, 1.0, 0.0).unwrap_err();
        assert!(twice.contains("twice"), "{twice}");
        assert!(rules_from(&[], 0, 1.0, 0.0).unwrap_err().contains("--ban-secs"));
        assert!(rules_from(&[], 60, 0.5, 0.0).unwrap_err().contains("--ban-escalation"));
        assert!(rules_from(&[], 60, 1.0, -1.0).unwrap_err().contains("--hash-limit-sigma"));
        assert!(rules_from(&[], 60, 1.0, 11.0).unwrap_err().contains("--hash-limit-sigma"));
        assert!(rules_from(&[], 60, 1.0, 0.0).unwrap().brackets.is_empty(), "no brackets: no limit");
    }

    #[test]
    fn text_forms_are_short() {
        assert_eq!(period_text(60), "1m");
        assert_eq!(period_text(7200), "2h");
        assert_eq!(period_text(90), "90s");
        assert_eq!(period_text(86400), "1d");
        assert_eq!(hashrate_text(3.5 * T), "3.50 TH/s");
        assert_eq!(hashrate_text(100.0 * T), "100 TH/s");
        assert_eq!(hashrate_text(2.5e9), "2.50 GH/s");
        assert_eq!(hashrate_text(12.0), "12 H/s");
        let text = starter().describe();
        assert!(
            text.starts_with("hash-limit: 1m 100 TH/s, 5m 50 TH/s, 30m 10 TH/s, 2h 3.50 TH/s"),
            "{text}"
        );
        assert!(text.contains("ban-secs: 86400 (1d)"), "{text}");
        assert_eq!(Rules::default().describe(), "hash-limit: none\n");
    }

    /// Observes a share and returns whether the next one from the same gateway is refused.
    fn share(l: &mut Limiter, identity: &str, gateway: &GatewayKey, ntime: u64, diff: u64, now: u64) -> Option<Refusal> {
        l.observe(identity, gateway, ntime, diff, now);
        l.check(identity, gateway, now)
    }

    #[test]
    fn a_miner_under_the_cap_is_never_refused_and_one_over_it_is_refused_while_it_stays_over() {
        let mut l = Limiter::new(starter());
        // 3 TH/s, a share every 20 seconds for three hours: under every bracket.
        let diff = work_for(3.0 * T, 20.0);
        for i in 0..(3 * 3600 / 20) {
            let now = 1_000_000 + i * 20;
            assert_eq!(share(&mut l, "small", &G, now, diff, now), None, "share {i}");
        }
        assert!(l.throttled(1_000_000 + 3 * 3600).is_empty());
        // 4 TH/s: under the short brackets, over the 2 hour one once two hours are in.
        let mut l = Limiter::new(starter());
        let diff = work_for(4.0 * T, 20.0);
        let mut refused_at = None;
        for i in 0..(3 * 3600 / 20) {
            let now = 1_000_000 + i * 20;
            if let Some(r) = share(&mut l, "four", &G, now, diff, now) {
                refused_at = Some((i * 20, r));
                break;
            }
        }
        let (secs, r) = refused_at.expect("4 TH/s is over the 3.5 TH/s cap");
        assert!((6300..=7200).contains(&secs), "refused {secs}s in: the 2h reading fills first");
        assert!(r.reason.contains("over 2h is over the 3.50 TH/s limit"), "{}", r.reason);
        assert!(r.own && r.home == Some(G), "its one gateway is its home, and alone over: {r:?}");
        let now = 1_000_000 + secs;
        let t = l.throttled(now);
        assert_eq!((t.len(), t[0].identity.as_str(), t[0].since, t[0].home), (1, "four", now, Some(G)));
        assert!(t[0].refused.is_empty(), "nothing but the home gateway has mined it");
        // Nothing is banned; once the window rolls past the shares, the refusals end.
        assert!(l.ban_of("four", now).is_none() && l.active_bans(now).is_empty());
        assert_eq!(l.check("four", &G, now + 7201), None, "the reading emptied");
        assert!(l.throttled(now + 7201).is_empty());
    }

    #[test]
    fn a_gateway_pouring_hashrate_at_another_miners_address_is_the_one_refused() {
        let attacker: GatewayKey = [9u8; 32];
        let mut l = Limiter::new(starter());
        let diff = work_for(3.0 * T, 20.0);
        // The miner's own gateway mines the address at 3 TH/s for three days.
        let day = ratum::SECS_PER_DAY;
        let start = 10 * day;
        for i in 0..(3 * day / 20) {
            let now = start + i * 20;
            assert_eq!(share(&mut l, "victim", &G, now, diff, now), None);
        }
        let now = start + 3 * day;
        assert_eq!(l.home_of("victim", now), Some(G));
        // Then someone points 200 TH/s at it for a minute.
        let big = work_for(200.0 * T, 5.0);
        let mut refused = None;
        for i in 0..12 {
            let at = now + i * 5;
            match l.check("victim", &attacker, at) {
                Some(r) => {
                    refused = Some(r);
                    break;
                }
                None => l.observe("victim", &attacker, at, big, at),
            }
        }
        // The 2 hour reading, nearly full from the miner's own shares, tips first.
        let r = refused.expect("the burst puts the address over a bracket");
        assert!(!r.own && r.home == Some(G), "not the home gateway: {r:?}");
        assert!(r.reason.contains("over 2h is over the 3.50 TH/s limit"), "{}", r.reason);
        // The miner's own shares are still accepted: its own reading is under every bracket.
        assert_eq!(share(&mut l, "victim", &G, now + 60, diff, now + 60), None);
        let t = l.throttled(now + 60);
        assert_eq!((t.len(), t[0].home, t[0].refused.as_slice()), (1, Some(G), &[attacker][..]));
        // A minute of a burst does not make the attacker the home gateway.
        assert_eq!(l.home_of("victim", now + 60), Some(G));
        // Two hours on, the burst has rolled out of every window and the attacker's shares
        // would be accepted again, until they are over again.
        assert_eq!(l.check("victim", &attacker, now + 7300), None);
        assert!(l.throttled(now + 7300).is_empty());
    }

    #[test]
    fn a_miner_over_the_cap_on_two_gateways_keeps_the_home_one() {
        let second: GatewayKey = [2u8; 32];
        let mut l = Limiter::new(starter());
        let diff = work_for(3.0 * T, 20.0);
        let start = 20 * ratum::SECS_PER_DAY;
        // 3 TH/s on the first gateway for a day, then 3 TH/s more on a second one: 6 TH/s.
        for i in 0..(ratum::SECS_PER_DAY / 20) {
            let now = start + i * 20;
            assert_eq!(share(&mut l, "m", &G, now, diff, now), None);
        }
        let from = start + ratum::SECS_PER_DAY;
        let mut first_refusal = None;
        for i in 0..(3 * 3600 / 20) {
            let now = from + i * 20;
            assert_eq!(l.check("m", &G, now), None, "the home gateway alone is under: share {i}");
            l.observe("m", &G, now, diff, now);
            if first_refusal.is_none() {
                match l.check("m", &second, now) {
                    Some(r) => first_refusal = Some((i * 20, r)),
                    None => l.observe("m", &second, now, diff, now),
                }
            }
        }
        let (secs, r) = first_refusal.expect("6 TH/s is over the 2h cap");
        assert!(secs <= 7200, "{secs}");
        assert!(!r.own && r.home == Some(G), "{r:?}");
        // Alone over: the home gateway is refused too.
        let mut l = Limiter::new(starter());
        let diff = work_for(10.0 * T, 20.0);
        let refused = (0..(3 * 3600 / 20)).find_map(|i| {
            let now = start + i * 20;
            share(&mut l, "big", &G, now, diff, now)
        });
        assert!(refused.is_some_and(|r| r.own), "10 TH/s on one gateway");
    }

    #[test]
    fn a_large_miner_is_caught_by_the_short_bracket_in_a_minute() {
        let mut l = Limiter::new(starter());
        // 200 TH/s at a difficulty solved every 5 seconds.
        let diff = work_for(200.0 * T, 5.0);
        let mut refused_at = None;
        for i in 0..1000 {
            let now = 1_000_000 + i * 5;
            if let Some(r) = share(&mut l, "big", &G, now, diff, now) {
                refused_at = Some((i * 5, r));
                break;
            }
        }
        let (secs, r) = refused_at.unwrap();
        assert!(secs <= 60, "refused after {secs}s");
        assert!(r.reason.contains("over 1m is over the 100 TH/s limit"), "{}", r.reason);
    }

    #[test]
    fn a_replayed_burst_is_placed_at_its_header_times() {
        let mut l = Limiter::new(starter());
        let diff = work_for(3.0 * T, 20.0);
        // Four minutes of a 3 TH/s miner's shares arrive in one second after a reconnect:
        // 4 minutes of work in a 1 minute reading would be 12 TH/s at acceptance time.
        let now = 1_000_000;
        for i in 0..12 {
            let ntime = now - 240 + i * 20;
            assert_eq!(share(&mut l, "replay", &G, ntime, diff, now), None, "share {i} at {ntime}");
        }
        // But a header time further back than the allowance is placed at the allowance: out
        // of a 1 minute reading, at the edge of a 5 minute one.
        let big = work_for(10.0 * T, 60.0);
        let mut l = Limiter::new(rules(&["1m=1T"]));
        assert_eq!(share(&mut l, "old", &G, now - 3600, big, now), None);
        let mut l = Limiter::new(rules(&["5m=1T"]));
        assert!(share(&mut l, "old", &G, now - 3600, big, now).is_some(), "an hour-old ntime counts");
        let mut l = Limiter::new(rules(&["1m=1T"]));
        assert!(share(&mut l, "future", &G, now + 3600, big, now).is_some(), "a future one counts now");
    }

    #[test]
    fn the_sigma_margin_spares_a_miner_near_the_cap_and_still_refuses_one_over_it() {
        let mut rules = starter();
        rules.sigma = 3.0;
        // A share every 20 seconds is 360 shares over the 2 hour bracket: a margin of
        // 3 / sqrt(360), 15.8%, so 4.05 TH/s is allowed on the 3.5 TH/s cap.
        let bracket = &rules.brackets[3];
        assert_eq!(bracket.period_secs, 7200);
        let allowed = rules.allowed(bracket, 360);
        assert!((4.05 * T..4.06 * T).contains(&allowed), "{allowed}");
        assert!((rules.allowed(bracket, 1) - 3.5 * T * 1.25).abs() < 1.0, "few shares: the cap on the margin");
        assert_eq!(starter().allowed(bracket, 360), 3.5 * T, "sigma 0: the threshold itself");

        // 4 TH/s, 14% over the cap, is under the margin: never refused.
        let mut l = Limiter::new(rules.clone());
        let diff = work_for(4.0 * T, 20.0);
        for i in 0..(6 * 3600 / 20) {
            let now = 1_000_000 + i * 20;
            assert_eq!(share(&mut l, "near", &G, now, diff, now), None, "share {i}");
        }
        // 4.5 TH/s, 29% over, is refused within the period, and the reason names the margin.
        let mut l = Limiter::new(rules);
        let diff = work_for(4.5 * T, 20.0);
        let r = (0..(3 * 3600 / 20))
            .find_map(|i| {
                let now = 1_000_000 + i * 20;
                share(&mut l, "over", &G, now, diff, now)
            })
            .expect("4.5 TH/s is over the margin");
        assert!(
            r.reason.contains("over the 3.50 TH/s limit (") && r.reason.contains(" allowed for a reading of "),
            "{}",
            r.reason
        );
    }

    #[test]
    fn bans_escalate_unban_and_persist() {
        let dir = std::env::temp_dir().join(format!("ratum-limiter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bans.redb");
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let rules = rules_from(&["1m=1T".into()], 100, 2.0, 0.0).unwrap();
        assert_eq!(
            (rules.ban_length(0), rules.ban_length(1), rules.ban_length(3)),
            (100, 200, 800)
        );
        let mut l = Limiter::open(rules.clone(), Arc::clone(&db)).unwrap();
        assert!(l.active_bans(0).is_empty());
        let first = l.ban("a", 1000, None, "manual".into());
        assert_eq!((first.until, first.times), (1100, 1));
        assert!(l.unban("a", 1050));
        assert!(!l.unban("a", 1050), "already ended");
        assert!(l.ban_of("a", 1050).is_none());
        let second = l.ban("a", 2000, None, "again".into());
        assert_eq!((second.until, second.times), (2200, 2), "twice as long the second time");
        let fixed = l.ban("b", 2000, Some(5), "ops".into());
        assert_eq!(fixed.until, 2005);
        assert_eq!(
            l.active_bans(2001).iter().map(|b| b.identity.as_str()).collect::<Vec<_>>(),
            ["b", "a"],
            "soonest to end first"
        );

        let reopened = Limiter::open(rules.clone(), Arc::clone(&db)).unwrap();
        assert_eq!(reopened.ban_of("a", 2100), Some(&second));
        assert_eq!(reopened.ban_of("a", 2200), None);
        assert_eq!(reopened.bans.get("a").map(|b| b.times), Some(2), "the count survives");

        // The gateway records persist too: a new record and a new day write at once.
        let mut l = reopened;
        let day = ratum::SECS_PER_DAY;
        l.observe("v", &G, 30 * day, 10, 30 * day);
        l.observe("v", &G, 31 * day, 5, 31 * day);
        let other: GatewayKey = [7u8; 32];
        l.observe("v", &other, 31 * day + 1, 100, 31 * day + 1);
        let reopened = Limiter::open(rules, db).unwrap();
        let v = &reopened.homes["v"];
        assert_eq!(v[&G].days, VecDeque::from([(30, 10), (31, 5)]));
        assert_eq!(v[&G].first_seen, 30 * day);
        assert_eq!(v[&other].days, VecDeque::from([(31, 100)]));
        assert_eq!(reopened.home_of("v", 31 * day + 2), Some(other), "the most work in the week");
        assert_eq!(reopened.home_of("v", 45 * day), None, "nothing within the week");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ring_is_bounded_and_quiet_identities_are_swept() {
        let mut l = Limiter::new(rules(&["10s=1P"]));
        for _ in 0..(MAX_SAMPLES + 10) {
            l.observe("busy", &G, 5_000_000, 1, 5_000_000);
        }
        assert_eq!(l.rings["busy"].samples.len(), MAX_SAMPLES);
        let mut l = Limiter::new(rules(&["10s=1P"]));
        l.observe("gone", &G, 1000, 1, 1000);
        for i in 0..SWEEP_EVERY {
            l.observe("here", &G, 10_000 + i, 1, 10_000 + i);
        }
        assert!(!l.rings.contains_key("gone"), "an identity quiet for the longest period");
        assert!(l.rings.contains_key("here"));
        // The gateway records of an identity quiet for HOME_DAYS are swept too.
        let far = 10_000 + (HOME_DAYS + 2) * ratum::SECS_PER_DAY;
        for i in 0..SWEEP_EVERY {
            l.observe("later", &G, far + i, 1, far + i);
        }
        assert!(!l.homes.contains_key("gone") && !l.homes.contains_key("here"));
        assert!(l.homes.contains_key("later"));
    }

    #[test]
    fn without_brackets_nothing_is_observed() {
        let mut l = Limiter::new(Rules::default());
        l.observe("x", &G, 1, u64::MAX, 1);
        assert_eq!(l.check("x", &G, 1), None);
        assert!(l.rings.is_empty() && l.homes.is_empty());
    }
}
