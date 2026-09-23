//! The command line and the settings file, which share one field list: every setting can be written
//! in either, and a flag given on the command line overrides the file's value. The settings
//! `live` names are read from the file again while the pool runs.

use clap::Parser as _;
use log::warn;
use std::path::{Path, PathBuf};

pub const USAGE_EXIT: i32 = 2;

macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit($crate::cli::USAGE_EXIT);
    }};
}

pub(crate) use fatal;

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize, clap::Parser)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[command(
    name = "ratum-prime",
    version = crate::VERSION,
    about = "DATUM Prime: the pool server of the DATUM protocol",
    allow_negative_numbers = true,
    args_override_self = true
)]
pub struct Options {
    #[arg(long)]
    pub listen: Option<String>,
    #[arg(long)]
    pub stats_listen: Option<String>,
    #[arg(long)]
    pub data_dir: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub config: Option<String>,
    #[arg(long)]
    pub motd: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub require_v3: Option<bool>,
    #[arg(long)]
    pub min_diff: Option<u64>,
    #[arg(long)]
    pub max_connections: Option<usize>,
    #[arg(long)]
    pub max_connections_per_ip: Option<usize>,
    #[arg(long)]
    pub payout_address: Option<String>,
    #[arg(long)]
    pub coinbase_tag: Option<String>,
    #[arg(long)]
    pub ledger_keep_shares: Option<u64>,
    #[arg(long)]
    pub window: Option<f64>,
    /// Each operator fee as `ADDRESS=BPS` or `ADDRESS=PERCENT%`, at most `MAX_FEE_OUTPUTS`;
    /// comma-separated on the command line, a list in the file. Live: a change to the file
    /// applies without a restart.
    #[arg(long, value_name = "ADDRESS=BPS", value_delimiter = ',')]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fee: Vec<String>,
    /// Whether the pool re-reads the settings file when it changes (on by default).
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub watch_config: Option<bool>,
    /// Each hashrate bracket as `PERIOD=RATE` (`1m=100T`); comma-separated on the command
    /// line, a list in the file. Live.
    #[arg(long, value_name = "PERIOD=RATE", value_delimiter = ',')]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_limit: Vec<String>,
    /// How long a ban runs; with `--ban`, the length of that ban. Live.
    #[arg(long)]
    pub ban_secs: Option<u64>,
    /// The factor each repeat ban is longer by. Live.
    #[arg(long)]
    pub ban_escalation: Option<f64>,
    #[arg(long)]
    pub public_gateway_fee_bps: Option<u16>,
    #[arg(long)]
    pub public_gateway_fee_subsidy_bps: Option<u16>,
    #[arg(long)]
    pub public_gateway_tag: Option<String>,
    #[arg(long)]
    pub rpc: Option<String>,
    #[arg(long)]
    pub rpc_cookie: Option<String>,
    #[arg(long)]
    pub poll: Option<f64>,
    #[arg(long)]
    #[serde(skip)]
    pub dump_ledger: bool,
    #[arg(long)]
    #[serde(skip)]
    pub settle_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub void_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub record_owed: Option<String>,
    #[arg(long, value_name = "IDENTITY=SATS")]
    #[serde(skip)]
    pub owed: Vec<String>,
    #[arg(long, value_name = "PATH")]
    #[serde(skip)]
    pub snapshot: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub offline: bool,
    /// Re-read the settings file and apply the live settings, in the running pool.
    #[arg(long)]
    #[serde(skip)]
    pub reload: bool,
    /// Write `SETTING=VALUE` to the settings file and apply it, in the running pool.
    #[arg(long, value_name = "SETTING=VALUE", action = clap::ArgAction::Append)]
    #[serde(skip)]
    pub set: Vec<String>,
    /// Print the live settings the running pool holds.
    #[arg(long)]
    #[serde(skip)]
    pub show_settings: bool,
    /// Print the bans holding in the running pool.
    #[arg(long)]
    #[serde(skip)]
    pub bans: bool,
    /// Ban an identity in the running pool, for `--ban-secs` or the rules' length.
    #[arg(long, value_name = "IDENTITY")]
    #[serde(skip)]
    pub ban: Option<String>,
    /// End the ban on an identity in the running pool.
    #[arg(long, value_name = "IDENTITY")]
    #[serde(skip)]
    pub unban: Option<String>,
}

/// The options as `load` resolved them: the command line over the file, and what the file
/// alone held (what a reload compares against).
pub struct Loaded {
    pub options: Options,
    pub file: Options,
}

/// The settings file the command line names: `--config`, or `ratum.toml` in `--data-dir`.
pub fn config_path(command_line: &Options) -> Option<PathBuf> {
    match (&command_line.config, &command_line.data_dir) {
        (Some(p), _) => Some(PathBuf::from(p)),
        (None, Some(dir)) => Some(PathBuf::from(dir).join("ratum.toml")),
        (None, None) => None,
    }
}

/// The options on the command line applied over those of the settings file: the file
/// `--config` names, or `ratum.toml` in `--data-dir`.
pub fn load() -> Loaded {
    let command_line = Options::parse();
    let file = match config_path(&command_line) {
        Some(path) => load_file(&path, command_line.config.is_some()),
        None => Options::default(),
    };
    let mut options = file.clone();
    options.update_from(std::env::args_os());
    if command_line.rpc.as_deref().is_some_and(has_password) {
        warn!(
            "--rpc carries the node's password in this process's command line, where any local \
             user can read it; a configuration file and --rpc-cookie do not"
        );
    }
    Loaded { options, file }
}

/// Whether `url` carries a `user:password@` before its host.
fn has_password(url: &str) -> bool {
    ratum::rpc::redact_url(url) != url
}

fn load_file(path: &Path, required: bool) -> Options {
    match read_file(path) {
        Ok(c) => c,
        Err(ReadError::NotFound) if !required => Options::default(),
        Err(e) => fatal!("{e}"),
    }
}

/// Why a settings file could not be read.
#[derive(Debug)]
pub enum ReadError {
    NotFound,
    Other(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("the settings file does not exist"),
            Self::Other(text) => f.write_str(text),
        }
    }
}

/// The settings `path` holds; a file that does not exist is `ReadError::NotFound`.
pub fn read_file(path: &Path) -> Result<Options, ReadError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::NotFound),
        Err(e) => return Err(ReadError::Other(format!("cannot read {}: {e}", path.display()))),
    };
    match toml::from_str(&text) {
        Ok(c) => {
            warn_if_readable(path, &c);
            Ok(c)
        }
        Err(e) => Err(ReadError::Other(format!("{}: {e}", path.display()))),
    }
}

#[cfg(unix)]
fn warn_if_readable(path: &Path, settings: &Options) {
    use std::os::unix::fs::PermissionsExt as _;
    if !settings.rpc.as_deref().is_some_and(has_password) {
        return;
    }
    let Ok(mode) = std::fs::metadata(path).map(|m| m.permissions().mode()) else { return };
    if mode & 0o077 != 0 {
        warn!(
            "{} holds a password and is readable by more than its owner (mode {:03o}); \
             chmod 600 it",
            path.display(),
            mode & 0o777
        );
    }
}

#[cfg(not(unix))]
fn warn_if_readable(_path: &Path, _settings: &Options) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_toml(text: &str) -> Result<Options, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn settings_parse_into_their_typed_fields() {
        let c = parse_toml(
            "rpc = \"http://ratum:pw@127.0.0.1:8332\"\nmin-diff = 16384\nwindow = 8.5\n\
             public-gateway-fee-bps = 200\npublic-gateway-fee-subsidy-bps = 7500\n\
             public-gateway-tag = \"public\"\n",
        )
        .unwrap();
        assert_eq!(c.min_diff, Some(16384));
        assert_eq!(c.window, Some(8.5));
        assert_eq!(c.rpc, Some("http://ratum:pw@127.0.0.1:8332".to_string()));
        assert_eq!(c.public_gateway_fee_bps, Some(200));
        assert_eq!(c.public_gateway_fee_subsidy_bps, Some(7500));
        assert_eq!(c.public_gateway_tag, Some("public".to_string()));
        assert_eq!(c.listen, None, "a setting not written stays unset");
    }

    #[test]
    fn nothing_written_is_nothing_set() {
        assert_eq!(parse_toml("").unwrap(), Options::default());
        assert_eq!(parse_toml("# only a comment\n").unwrap(), Options::default());
    }

    #[test]
    fn a_setting_may_be_annotated() {
        let c = parse_toml(
            "# the smallest share difficulty credited\nmin-diff = 16384  # a power of two\n",
        )
        .unwrap();
        assert_eq!(c.min_diff, Some(16384));
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_where_it_is() {
        let e = parse_toml("motd = \"fine\"\nmin-diff = \"soon\"\n").unwrap_err().to_string();
        assert!(e.contains("min-diff"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn a_name_the_pool_does_not_have_is_refused() {
        let e = parse_toml("min-dif = 1\n").unwrap_err().to_string();
        assert!(e.contains("min-dif"), "{e}");
        assert!(e.contains("min-diff"), "the ones it does have are named: {e}");
    }

    #[test]
    fn a_configuration_file_cannot_name_another_one() {
        let e = parse_toml("config = \"/etc/other.toml\"\n").unwrap_err().to_string();
        assert!(e.contains("config"), "{e}");
    }

    #[test]
    fn a_configuration_file_cannot_hold_a_ledger_command() {
        for text in [
            "dump-ledger = true\n",
            "settle-block = \"list\"\n",
            "void-block = \"00\"\n",
            "record-owed = \"00\"\n",
            "owed = [\"alice=1\"]\n",
            "snapshot = \"/backups/main.redb\"\n",
            "offline = true\n",
            "reload = true\n",
            "set = [\"fee=[]\"]\n",
            "show-settings = true\n",
            "bans = true\n",
            "ban = \"x\"\n",
            "unban = \"x\"\n",
        ] {
            let e = parse_toml(text).expect_err("a command is not a setting").to_string();
            assert!(e.contains("unknown field"), "{text:?}: {e}");
        }
    }

    #[test]
    fn text_that_is_not_settings_is_an_error() {
        for text in ["oops\n", "min-diff = \n", "[section]\nmin-diff = 1\n"] {
            let e = parse_toml(text).expect_err("not settings").to_string();
            assert!(!e.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_flag_given_as_well_overrides_the_file() {
        let argv = ["ratum-prime", "--min-diff", "1024", "--require-v3"];
        let mut merged = Options {
            min_diff: Some(16384),
            motd: Some("file".into()),
            require_v3: Some(false),
            ..Options::default()
        };
        merged.update_from(argv);
        assert_eq!(merged.min_diff, Some(1024));
        assert_eq!(merged.motd.as_deref(), Some("file"), "a flag not given keeps the file's value");
        assert_eq!(merged.require_v3, Some(true), "a bare flag overrides the file's false");
        assert!(!merged.dump_ledger);
    }

    #[test]
    fn the_command_line_and_the_file_share_one_field_list() {
        let c = Options::parse_from(["ratum-prime", "--min-diff", "16384", "--dump-ledger"]);
        assert_eq!(c.min_diff, Some(16384));
        assert!(c.dump_ledger);
        assert_eq!(
            parse_toml("min-diff = 16384\n").unwrap(),
            Options { dump_ledger: false, ..c },
            "the same setting reads the same from either source"
        );
    }

    #[test]
    fn the_fees_are_a_list_in_the_file_and_comma_separated_on_the_command_line() {
        let c = parse_toml("fee = [\"bcrt1qa=25\", \"bcrt1qb=0.5%\"]\n").unwrap();
        assert_eq!(c.fee, ["bcrt1qa=25", "bcrt1qb=0.5%"]);
        assert!(parse_toml("").unwrap().fee.is_empty(), "no fee unless written");
        let c = Options::parse_from(["ratum-prime", "--fee", "bcrt1qa=25,bcrt1qb=50"]);
        assert_eq!(c.fee, ["bcrt1qa=25", "bcrt1qb=50"]);
        let mut merged = parse_toml("fee = [\"bcrt1qa=25\"]\n").unwrap();
        merged.update_from(["ratum-prime", "--fee", "bcrt1qc=1"]);
        assert_eq!(merged.fee, ["bcrt1qc=1"], "the flag replaces the file's list");
        let mut kept = parse_toml("fee = [\"bcrt1qa=25\"]\n").unwrap();
        kept.update_from(["ratum-prime", "--motd", "hi"]);
        assert_eq!(kept.fee, ["bcrt1qa=25"], "a flag not given keeps the file's list");
    }

    #[test]
    fn the_settings_serialize_back_to_the_file_form_without_the_unset_ones() {
        let c = Options { min_diff: Some(16384), fee: vec!["a=1".into()], ..Default::default() };
        let text = toml::to_string(&c).unwrap();
        assert_eq!(text, "min-diff = 16384\nfee = [\"a=1\"]\n");
        assert_eq!(toml::to_string(&Options::default()).unwrap(), "");
    }

    #[test]
    fn set_is_given_once_per_setting() {
        let c = Options::parse_from(["ratum-prime", "--set", "fee=[]", "--set", "motd=\"x\""]);
        assert_eq!(c.set, ["fee=[]", "motd=\"x\""]);
        assert!(Options::parse_from(["ratum-prime", "--reload"]).reload);
        assert!(Options::parse_from(["ratum-prime", "--show-settings"]).show_settings);
        let path = config_path(&Options { data_dir: Some("/pool".into()), ..Default::default() });
        assert_eq!(path, Some(PathBuf::from("/pool/ratum.toml")));
        let named = Options { config: Some("/etc/r.toml".into()), ..Default::default() };
        assert_eq!(config_path(&named), Some(PathBuf::from("/etc/r.toml")));
        assert_eq!(config_path(&Options::default()), None);
    }

    #[test]
    fn a_password_is_recognized_in_the_url() {
        assert!(has_password("http://ratum:pw@127.0.0.1:8332"));
        assert!(!has_password("http://ratum@127.0.0.1:8332"));
        assert!(!has_password("http://127.0.0.1:8332"));
    }
}
