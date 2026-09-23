//! The settings that change while the pool runs. They are read from the settings file again
//! on `--reload`, on `--set` (which writes the file first) and, unless `--watch-config false`,
//! whenever the file changes; each reading installs the live settings and names the others
//! whose value in the file differs from the one the pool started with, since those apply only
//! at a restart.

use crate::cli::{self, Options, ReadError};
use crate::ledger::split::FeeOutput;
use crate::limiter::Rules;
use crate::server::Server;
use crate::settings;
use log::{info, warn};
use ratum::lock;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// The settings a reload applies, by their names in the file. Every other setting applies at
/// a restart.
pub const LIVE_SETTINGS: &[&str] =
    &["fee", "finder-bps", "hash-limit", "ban-secs", "ban-escalation"];

/// How often the settings file is looked at for a change.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// How old a change must be before it is applied, so a file still being written is not read
/// half way.
const SETTLE: Duration = Duration::from_secs(1);

/// What the pool keeps between readings: the modification time of the file as last applied,
/// so the watcher applies a change once and not again after `--set` wrote it.
#[derive(Default)]
pub struct State {
    applied_mtime: Mutex<Option<SystemTime>>,
}

/// The live settings as the pool installs them.
#[derive(Clone, Debug, PartialEq)]
pub struct Live {
    pub fees: Vec<FeeOutput>,
    pub finder_bps: u16,
    pub rules: Rules,
}

impl Live {
    /// The live settings `o` names, decoded for `chain` as at startup.
    pub fn from_options(o: &Options, chain: Option<ratum::rpc::Chain>) -> Result<Self, String> {
        Ok(Self {
            fees: settings::fees(o, chain)?,
            finder_bps: settings::finder_bps(o)?,
            rules: settings::limiter_rules(o)?,
        })
    }

    /// The live settings the pool holds now.
    pub fn current(server: &Server) -> Self {
        let (fees, finder_bps) = {
            let l = lock(&server.ledger);
            (l.split_policy().fees.clone(), l.split_policy().finder_bps)
        };
        Self { fees, finder_bps, rules: lock(&server.limiter).rules().clone() }
    }

    /// Installs these settings where each is read from; the lines describing what changed,
    /// none when nothing did.
    pub fn apply(self, server: &Server) -> Vec<String> {
        let mut changes = Vec::new();
        let current = Self::current(server);
        if current.fees != self.fees {
            changes.push(format!(
                "fee: {} (was {})",
                fees_text(&self.fees),
                fees_text(&current.fees)
            ));
            lock(&server.ledger).set_fees(self.fees);
        }
        if current.finder_bps != self.finder_bps {
            changes.push(format!(
                "finder-bps: {} (was {})",
                finder_text(self.finder_bps),
                finder_text(current.finder_bps)
            ));
            lock(&server.ledger).set_finder_bps(self.finder_bps);
        }
        if current.rules != self.rules {
            changes.push(format!(
                "hashrate limiter: {} (was {})",
                one_line(&self.rules.describe()),
                one_line(&current.rules.describe())
            ));
            lock(&server.limiter).set_rules(self.rules);
        }
        changes
    }

    /// The settings, one line each, as `--show-settings` prints them.
    pub fn describe(&self) -> String {
        format!(
            "fee: {}\nfinder-bps: {}\n{}",
            fees_text(&self.fees),
            finder_text(self.finder_bps),
            self.rules.describe()
        )
    }
}

fn finder_text(bps: u16) -> String {
    format!("{bps} ({}%)", f64::from(bps) / 100.0)
}

/// A multi-line description on one line.
fn one_line(text: &str) -> String {
    text.trim_end().replace('\n', "; ")
}

/// The fees as one line: each address and its basis points, or `none`.
pub fn fees_text(fees: &[FeeOutput]) -> String {
    if fees.is_empty() {
        return "none".to_string();
    }
    let each: Vec<String> = fees
        .iter()
        .map(|f| format!("{} {} bps ({}%)", f.address, f.bps, f64::from(f.bps) / 100.0))
        .collect();
    format!(
        "{} ({} bps together)",
        each.join(", "),
        fees.iter().map(|f| u32::from(f.bps)).sum::<u32>()
    )
}

/// `--show-settings`: the live settings the pool holds, and the file they are read from.
pub fn show(server: &Server) -> String {
    let mut text = Live::current(server).describe();
    match &server.settings.config_path {
        Some(path) => writeln!(text, "settings file: {}", path.display()).unwrap(),
        None => text.push_str("settings file: none (started without --config or --data-dir)\n"),
    }
    text
}

fn config_path(server: &Server) -> Result<&Path, String> {
    server.settings.config_path.as_deref().ok_or_else(|| {
        "the pool started without --config or --data-dir, so it has no settings file to read \
         the live settings from"
            .to_string()
    })
}

/// `--reload`: reads the settings file again and applies the live settings. The text is what
/// changed, and which settings changed in the file that only a restart applies.
pub fn reload(server: &Server) -> Result<String, String> {
    let path = config_path(server)?;
    let file = cli::read_file(path).map_err(|e| match e {
        ReadError::NotFound => format!("{}: {e}", path.display()),
        ReadError::Other(text) => text,
    })?;
    apply_file(server, &file, path)
}

/// Installs the live settings of `file`, read from `path`, and records the file's
/// modification time as applied.
fn apply_file(server: &Server, file: &Options, path: &Path) -> Result<String, String> {
    let live = Live::from_options(file, server.share_policy.chain)?;
    let mut out = String::new();
    let changes = live.apply(server);
    if changes.is_empty() {
        writeln!(out, "{}: the live settings are unchanged", path.display()).unwrap();
    }
    for change in changes {
        info!("settings: {change}");
        writeln!(out, "{}: {change}", path.display()).unwrap();
    }
    let restart_only = restart_only_changes(&server.settings.file_options, file);
    if !restart_only.is_empty() {
        writeln!(
            out,
            "changed in the file since the pool started but applied only at a restart: {}",
            restart_only.join(", ")
        )
        .unwrap();
    }
    *lock(&server.live.applied_mtime) = modified(path);
    Ok(out)
}

/// The names of the settings whose value in `now` differs from `then`, the live ones aside,
/// in the file's order of names.
fn restart_only_changes(then: &Options, now: &Options) -> Vec<String> {
    let table = |o: &Options| match toml::Value::try_from(o) {
        Ok(toml::Value::Table(t)) => t,
        _ => toml::Table::new(),
    };
    let (then, now) = (table(then), table(now));
    let mut names: Vec<&String> = then.keys().chain(now.keys()).collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|name| !LIVE_SETTINGS.contains(&name.as_str()))
        .filter(|name| then.get(*name) != now.get(*name))
        .cloned()
        .collect()
}

/// `--set`: writes each `SETTING=VALUE` to the settings file, keeping the rest of the file as
/// it is, then reloads. A value is TOML; a bare word is taken as a string and, for a list
/// setting, a comma-separated list of strings. An empty value removes the setting, which
/// returns it to its default.
pub fn set(server: &Server, assignments: &[String]) -> Result<String, String> {
    let path = config_path(server)?;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut doc: toml_edit::DocumentMut =
        text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
    for assignment in assignments {
        let Some((name, value)) = assignment.split_once('=') else {
            return Err(format!("--set takes SETTING=VALUE, got {assignment:?}"));
        };
        let (name, value) = (name.trim(), value.trim());
        if value.is_empty() {
            doc.remove(name);
            continue;
        }
        let item = parse_value(name, value)?;
        doc[name] = item;
    }
    let new_text = doc.to_string();
    let file: Options = toml::from_str(&new_text).map_err(|e| e.to_string())?;
    // Refused before the file is written, so a bad value never reaches it.
    Live::from_options(&file, server.share_policy.chain)?;
    write_atomically(path, &new_text)?;
    let mut out = format!("wrote {}\n", path.display());
    out.push_str(&apply_file(server, &file, path)?);
    Ok(out)
}

/// `value` as the TOML item of the setting `name`: as written, else as a string, else as a
/// list of strings split at commas, whichever first reads as that setting.
fn parse_value(name: &str, value: &str) -> Result<toml_edit::Item, String> {
    let quoted = |s: &str| toml::Value::String(s.to_string()).to_string();
    let list =
        format!("[{}]", value.split(',').map(|s| quoted(s.trim())).collect::<Vec<_>>().join(", "));
    let mut first_error = None;
    for candidate in [value.to_string(), quoted(value), list] {
        let line = format!("{name} = {candidate}\n");
        match toml::from_str::<Options>(&line) {
            Ok(_) => {
                let doc: toml_edit::DocumentMut = line.parse().map_err(|e| format!("{e}"))?;
                return Ok(doc[name].clone());
            }
            Err(e) => {
                first_error.get_or_insert_with(|| e.to_string());
            }
        }
    }
    Err(format!("--set {name}={value}: {}", first_error.unwrap_or_default().trim()))
}

/// Writes `text` to `path` through a temporary file in its directory, so a reader sees the
/// old file or the new one and never a part. A new file is readable by its owner only, since
/// the file may hold the node's password.
fn write_atomically(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("toml.tmp");
    let write = || -> std::io::Result<()> {
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0o600);
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Applies the live settings each time the settings file changes, on a thread, when the
/// pool has a settings file and `--watch-config` is on.
pub fn watch(server: Arc<Server>) {
    let Some(path) = server.settings.config_path.clone() else { return };
    if !server.settings.watch_config {
        info!("not watching {} (--watch-config false)", path.display());
        return;
    }
    *lock(&server.live.applied_mtime) = modified(&path);
    info!("watching {} for changes to the live settings", path.display());
    ratum::thread::spawn("config-watch", move || {
        loop {
            std::thread::sleep(WATCH_INTERVAL);
            let now = modified(&path);
            if now == *lock(&server.live.applied_mtime) {
                continue;
            }
            if now.is_some_and(|m| m.elapsed().is_ok_and(|age| age < SETTLE)) {
                continue;
            }
            match reload(&server) {
                Ok(text) => info!("{}: reloaded\n{}", path.display(), text.trim_end()),
                Err(e) => {
                    warn!("{}: changed but not applied: {e}", path.display());
                    // The change is recorded so the same failure is not logged every tick;
                    // the next change is read again.
                    *lock(&server.live.applied_mtime) = now;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{ALICE, BOB, FEE_ADDRESS, fee_outputs, server_with};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scratch_file(text: &str) -> std::path::PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ratum-live-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ratum.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn server_on_file(text: &str) -> (Server, std::path::PathBuf) {
        let path = scratch_file(text);
        let mut server = server_with(&[(ALICE, 1)]);
        // The default finder's cut, as `main` sets it: a file naming none changes nothing.
        lock(&server.ledger).set_finder_bps(8_000);
        server.settings.config_path = Some(path.clone());
        server.settings.file_options = toml::from_str(text).unwrap();
        (server, path)
    }

    #[test]
    fn a_reload_installs_the_fees_the_file_names_and_reports_the_rest() {
        let (server, path) = server_on_file("min-diff = 16384\n");
        assert_eq!(Live::current(&server).fees, Vec::new());
        let text = reload(&server).unwrap();
        assert!(text.contains("unchanged"), "{text}");

        std::fs::write(&path, format!("min-diff = 8192\nfee = [\"{FEE_ADDRESS}=25\"]\n")).unwrap();
        let text = reload(&server).unwrap();
        assert_eq!(Live::current(&server).fees, fee_outputs(&[(FEE_ADDRESS, 25)]));
        assert!(text.contains("fee: ") && text.contains("25 bps (0.25%)"), "{text}");
        assert!(text.contains("only at a restart: min-diff"), "{text}");

        std::fs::write(&path, "min-diff = 16384\nfinder-bps = 5000\n").unwrap();
        let text = reload(&server).unwrap();
        assert!(Live::current(&server).fees.is_empty(), "a fee removed from the file is removed");
        assert!(text.contains("finder-bps: 5000 (50%) (was 8000 (80%))"), "{text}");
        assert_eq!(Live::current(&server).finder_bps, 5_000);
        std::fs::write(&path, "min-diff = 16384\n").unwrap();
        let text = reload(&server).unwrap();
        assert_eq!(Live::current(&server).finder_bps, 8_000, "removed: back to the default");
        assert!(!text.contains("restart"), "back to the startup value: {text}");

        let limits = "hash-limit = [\"1m=100T\", \"2h=3.5T\"]\nban-secs = 3600\n";
        std::fs::write(&path, limits).unwrap();
        let text = reload(&server).unwrap();
        assert!(text.contains("hashrate limiter: hash-limit: 1m 100 TH/s, 2h 3.50 TH/s"), "{text}");
        let rules = Live::current(&server).rules;
        assert_eq!((rules.brackets.len(), rules.ban_secs, rules.escalation), (2, 3600, 1.0));
        std::fs::write(&path, "ban-escalation = 0.5\n").unwrap();
        assert!(reload(&server).unwrap_err().contains("--ban-escalation"));
        assert_eq!(Live::current(&server).rules, rules, "refused: unchanged");
    }

    #[test]
    fn a_bad_file_is_refused_and_leaves_the_settings_as_they_were() {
        let (server, path) = server_on_file(&format!("fee = [\"{FEE_ADDRESS}=25\"]\n"));
        reload(&server).unwrap();
        std::fs::write(&path, "fee = [\"nonsense=25\"]\n").unwrap();
        let e = reload(&server).unwrap_err();
        assert!(e.contains("--fee address"), "{e}");
        assert_eq!(Live::current(&server).fees, fee_outputs(&[(FEE_ADDRESS, 25)]));
        std::fs::write(&path, "min-dif = 1\n").unwrap();
        assert!(reload(&server).unwrap_err().contains("min-dif"));
        std::fs::remove_file(&path).unwrap();
        assert!(reload(&server).unwrap_err().contains("does not exist"));
    }

    #[test]
    fn set_writes_the_file_keeping_its_comments_and_applies_it() {
        let (server, path) = server_on_file("# the node\nmin-diff = 16384 # floor\n");
        let text = set(&server, &[format!("fee={FEE_ADDRESS}=25,{BOB}=0.5%")]).unwrap();
        assert!(text.contains("wrote"), "{text}");
        assert_eq!(Live::current(&server).fees, fee_outputs(&[(FEE_ADDRESS, 25), (BOB, 50)]));
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.starts_with("# the node\nmin-diff = 16384 # floor\n"), "{written}");
        assert!(
            written.contains(&format!("fee = [\"{FEE_ADDRESS}=25\", \"{BOB}=0.5%\"]")),
            "{written}"
        );

        set(&server, &[format!("fee=[\"{FEE_ADDRESS}=1\"]"), "motd=hello there".into()]).unwrap();
        assert_eq!(Live::current(&server).fees, fee_outputs(&[(FEE_ADDRESS, 1)]));
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("motd = \"hello there\""), "a bare value is a string: {written}");

        let text = set(&server, &["fee=".into()]).unwrap();
        assert!(Live::current(&server).fees.is_empty(), "an empty value removes the setting");
        assert!(!std::fs::read_to_string(&path).unwrap().contains("fee"), "{text}");
    }

    #[test]
    fn set_refuses_a_bad_value_before_writing() {
        let (server, path) = server_on_file("min-diff = 16384\n");
        let before = std::fs::read_to_string(&path).unwrap();
        for (assignment, what) in [
            ("fee=nonsense=25", "--fee address"),
            ("min-dif=1", "min-dif"),
            ("min-diff=soon", "min-diff"),
            ("fee", "SETTING=VALUE"),
        ] {
            let e = set(&server, &[assignment.to_string()]).unwrap_err();
            assert!(e.contains(what), "{assignment}: {e}");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "nothing was written");
        let restart = set(&server, &["min-diff=8192".into()]).unwrap();
        assert!(restart.contains("only at a restart: min-diff"), "{restart}");
    }

    #[test]
    fn without_a_settings_file_the_live_commands_say_so() {
        let server = server_with(&[]);
        assert!(reload(&server).unwrap_err().contains("no settings file"));
        assert!(set(&server, &["fee=".into()]).unwrap_err().contains("no settings file"));
        assert!(show(&server).contains("settings file: none"));
    }

    #[test]
    fn the_settings_are_described_one_per_line() {
        let rules = Rules::default();
        let live = Live {
            fees: fee_outputs(&[(FEE_ADDRESS, 25), (ALICE, 100)]),
            finder_bps: 8_000,
            rules: rules.clone(),
        };
        assert_eq!(
            live.describe(),
            format!(
                "fee: {FEE_ADDRESS} 25 bps (0.25%), {ALICE} 100 bps (1%) (125 bps together)\n\
                 finder-bps: 8000 (80%)\nhash-limit: none\n"
            )
        );
        assert_eq!(
            Live { fees: Vec::new(), finder_bps: 0, rules }.describe(),
            "fee: none\nfinder-bps: 0 (0%)\nhash-limit: none\n"
        );
    }
}
