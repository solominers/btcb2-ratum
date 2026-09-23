//! The hashrate limiter: each identity (a payout address, one lottery ticket) may bring at most
//! a bounded hashrate, measured over several periods at once. A short period with a high
//! threshold catches a large miner within a minute, and a long period with a low threshold
//! holds the cap the pool is built around, while the variance of a small miner's share
//! arrivals over a short period never reaches the short period's threshold. An identity over
//! any bracket is banned: its shares are refused (`RejectReason::HashLimit`) until the ban
//! ends, for longer each time when escalation is set. Bans are written to the ledger file, so
//! a restart keeps them.
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
}

impl Default for Rules {
    fn default() -> Self {
        Self { brackets: Vec::new(), ban_secs: ratum::SECS_PER_DAY, escalation: 1.0 }
    }
}

impl Rules {
    pub fn longest_period(&self) -> u64 {
        self.brackets.iter().map(|b| b.period_secs).max().unwrap_or(0)
    }

    /// How long the ban after `prior` earlier bans runs.
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
            "hash-limit: {} (over any bracket: banned)\nban-secs: {} ({})\nban-escalation: {}\n",
            each.join(", "),
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
    if !(threshold_hs > 0.0) {
        return Err(format!("{text:?}: the rate must be above 0"));
    }
    Ok(Bracket { period_secs, threshold_hs })
}

/// The rules `entries` name (each `parse_bracket`), sorted by period: at most `MAX_BRACKETS`,
/// no two on one period.
pub fn rules_from(entries: &[String], ban_secs: u64, escalation: f64) -> Result<Rules, String> {
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
    Ok(Rules { brackets, ban_secs, escalation })
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
    if secs % ratum::SECS_PER_DAY == 0 {
        format!("{}d", secs / ratum::SECS_PER_DAY)
    } else if secs % ratum::SECS_PER_HOUR == 0 {
        format!("{}h", secs / ratum::SECS_PER_HOUR)
    } else if secs % ratum::SECS_PER_MINUTE == 0 {
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

/// The recent shares of one identity: their times and difficulties, oldest first.
#[derive(Default)]
struct Ring {
    samples: VecDeque<(u64, u64)>,
}

impl Ring {
    fn push(&mut self, at: u64, difficulty: u64) {
        self.samples.push_back((at, difficulty));
        if self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    fn trim(&mut self, cutoff: u64) {
        while self.samples.front().is_some_and(|(at, _)| *at < cutoff) {
            self.samples.pop_front();
        }
    }

    fn work_since(&self, cutoff: u64) -> u128 {
        self.samples.iter().filter(|(at, _)| *at >= cutoff).map(|(_, d)| u128::from(*d)).sum()
    }

    fn newest(&self) -> Option<u64> {
        self.samples.back().map(|(at, _)| *at)
    }
}

pub struct Limiter {
    rules: Rules,
    rings: HashMap<String, Ring>,
    /// Every identity ever banned, with its newest ban; `Ban::active` says whether it holds.
    bans: HashMap<String, Ban>,
    db: Option<Arc<Database>>,
    observations: u64,
}

impl Limiter {
    /// A limiter holding its bans in memory only.
    pub fn new(rules: Rules) -> Self {
        Self { rules, rings: HashMap::new(), bans: HashMap::new(), db: None, observations: 0 }
    }

    /// A limiter over the ledger file's ban table, read back now.
    pub fn open(rules: Rules, db: Arc<Database>) -> io::Result<Self> {
        let mut bans = HashMap::new();
        let r = db.begin_read().db()?;
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
        Ok(Self { rules, rings: HashMap::new(), bans, db: Some(db), observations: 0 })
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

    /// Records a share of `identity`: `difficulty` at the header time `ntime`, accepted at
    /// `now`. The ban the share's reading leads to, if any, which begins now: this share was
    /// under the limit when it was accepted; the next is refused.
    pub fn observe(
        &mut self,
        identity: &str,
        ntime: u64,
        difficulty: u64,
        now: u64,
    ) -> Option<Ban> {
        if self.rules.brackets.is_empty() {
            return None;
        }
        let at = ntime.clamp(now.saturating_sub(REPLAY_ALLOWANCE_SECS), now);
        let longest = self.rules.longest_period();
        self.observations += 1;
        if self.observations % SWEEP_EVERY == 0 {
            let cutoff = now.saturating_sub(longest);
            self.rings.retain(|_, ring| ring.newest().is_some_and(|newest| newest >= cutoff));
        }
        let ring = self.rings.entry(identity.to_string()).or_default();
        ring.push(at, difficulty);
        ring.trim(now.saturating_sub(longest));
        let over = self.rules.brackets.iter().find_map(|b| {
            let work = ring.work_since(now.saturating_sub(b.period_secs));
            let hs = hashrate::from_work(work, Duration::from_secs(b.period_secs));
            (hs > b.threshold_hs).then(|| {
                format!(
                    "{} over {} is over the {} limit",
                    hashrate_text(hs),
                    period_text(b.period_secs),
                    hashrate_text(b.threshold_hs)
                )
            })
        })?;
        Some(self.ban(identity, now, None, over))
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

#[cfg(test)]
mod tests {
    use super::*;

    const T: f64 = 1e12;

    fn rules(entries: &[&str]) -> Rules {
        let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        rules_from(&entries, ratum::SECS_PER_DAY, 1.0).unwrap()
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
        let twice = rules_from(&["5m=1T".into(), "300s=2T".into()], 60, 1.0).unwrap_err();
        assert!(twice.contains("twice"), "{twice}");
        assert!(rules_from(&[], 0, 1.0).unwrap_err().contains("--ban-secs"));
        assert!(rules_from(&[], 60, 0.5).unwrap_err().contains("--ban-escalation"));
        assert!(rules_from(&[], 60, 1.0).unwrap().brackets.is_empty(), "no brackets: no limit");
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

    #[test]
    fn a_miner_under_the_cap_is_never_banned_and_one_over_it_is_banned_within_the_period() {
        let mut l = Limiter::new(starter());
        // 3 TH/s, a share every 20 seconds for three hours: under every bracket.
        let diff = work_for(3.0 * T, 20.0);
        for i in 0..(3 * 3600 / 20) {
            let now = 1_000_000 + i * 20;
            assert_eq!(l.observe("small", now, diff, now), None, "share {i}");
        }
        // 4 TH/s: under the short brackets, over the 2 hour one once two hours are in.
        let mut l = Limiter::new(starter());
        let diff = work_for(4.0 * T, 20.0);
        let mut banned_at = None;
        for i in 0..(3 * 3600 / 20) {
            let now = 1_000_000 + i * 20;
            if let Some(ban) = l.observe("four", now, diff, now) {
                banned_at = Some((i * 20, ban));
                break;
            }
        }
        let (secs, ban) = banned_at.expect("4 TH/s is over the 3.5 TH/s cap");
        assert!(secs >= 6300 && secs <= 7200, "banned {secs}s in: the 2h reading fills first");
        assert!(ban.reason.contains("over 2h is over the 3.50 TH/s limit"), "{}", ban.reason);
        assert_eq!(
            (ban.since, ban.until, ban.times),
            (1_000_000 + secs, 1_000_000 + secs + 86400, 1)
        );
        assert!(l.ban_of("four", 1_000_000 + secs + 86399).is_some());
        assert!(l.ban_of("four", 1_000_000 + secs + 86400).is_none(), "the ban ends");
        assert!(l.ban_of("small", 0).is_none());
    }

    #[test]
    fn a_large_miner_is_caught_by_the_short_bracket_in_a_minute() {
        let mut l = Limiter::new(starter());
        // 200 TH/s at a difficulty solved every 5 seconds.
        let diff = work_for(200.0 * T, 5.0);
        let mut banned_at = None;
        for i in 0..1000 {
            let now = 1_000_000 + i * 5;
            if let Some(ban) = l.observe("big", now, diff, now) {
                banned_at = Some((i * 5, ban));
                break;
            }
        }
        let (secs, ban) = banned_at.unwrap();
        assert!(secs <= 60, "banned after {secs}s");
        assert!(ban.reason.contains("over 1m is over the 100 TH/s limit"), "{}", ban.reason);
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
            assert_eq!(l.observe("replay", ntime, diff, now), None, "share {i} at {ntime}");
        }
        // But a header time further back than the allowance is placed at the allowance: out
        // of a 1 minute reading, at the edge of a 5 minute one.
        let big = work_for(10.0 * T, 60.0);
        let mut l = Limiter::new(rules(&["1m=1T"]));
        assert_eq!(l.observe("old", now - 3600, big, now), None);
        let mut l = Limiter::new(rules(&["5m=1T"]));
        assert!(l.observe("old", now - 3600, big, now).is_some(), "an hour-old ntime counts");
        let mut l = Limiter::new(rules(&["1m=1T"]));
        assert!(l.observe("future", now + 3600, big, now).is_some(), "a future one counts now");
    }

    #[test]
    fn bans_escalate_unban_and_persist() {
        let dir = std::env::temp_dir().join(format!("ratum-limiter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bans.redb");
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let rules = rules_from(&["1m=1T".into()], 100, 2.0).unwrap();
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

        let reopened = Limiter::open(rules, db).unwrap();
        assert_eq!(reopened.ban_of("a", 2100), Some(&second));
        assert_eq!(reopened.ban_of("a", 2200), None);
        assert_eq!(reopened.bans.get("a").map(|b| b.times), Some(2), "the count survives");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ring_is_bounded_and_quiet_identities_are_swept() {
        let mut l = Limiter::new(rules(&["10s=1P"]));
        for _ in 0..(MAX_SAMPLES + 10) {
            l.observe("busy", 5_000_000, 1, 5_000_000);
        }
        assert_eq!(l.rings["busy"].samples.len(), MAX_SAMPLES);
        let mut l = Limiter::new(rules(&["10s=1P"]));
        l.observe("gone", 1000, 1, 1000);
        for i in 0..SWEEP_EVERY {
            l.observe("here", 10_000 + i, 1, 10_000 + i);
        }
        assert!(!l.rings.contains_key("gone"), "an identity quiet for the longest period");
        assert!(l.rings.contains_key("here"));
    }

    #[test]
    fn without_brackets_nothing_is_observed() {
        let mut l = Limiter::new(Rules::default());
        assert_eq!(l.observe("x", 1, u64::MAX, 1), None);
        assert!(l.rings.is_empty());
    }
}
