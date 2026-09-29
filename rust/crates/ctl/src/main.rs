//! `fortressctl` — the FortressWAF CLI management tool.
//!
//! Port of `cmd/ctl/main.go`. Subcommands, flags, endpoints and output
//! formatting are preserved.

use std::io::Read;
use std::process::exit;
use std::time::Duration;

use clap::{Parser, Subcommand};

const VERSION: &str = "dev";
const COMMIT: &str = "unknown";
const BUILD_DATE: &str = "unknown";

#[derive(Parser, Debug)]
#[command(name = "fortressctl", about = "FortressWAF CLI management tool")]
struct Cli {
    /// WAF API URL (or FORTRESS_API_URL).
    #[arg(long, default_value = "localhost:8443", global = true)]
    api_url: String,
    /// API key for auth (or FORTRESS_API_KEY).
    #[arg(long, default_value = "", global = true)]
    api_key: String,
    /// HTTP request timeout in seconds.
    #[arg(long, default_value_t = 10, global = true)]
    timeout: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage protected sites.
    Site {
        #[command(subcommand)]
        cmd: SiteCmd,
    },
    /// Manage WAF rules.
    Rule {
        #[command(subcommand)]
        cmd: RuleCmd,
    },
    /// View and export logs.
    Logs {
        #[command(subcommand)]
        cmd: LogsCmd,
    },
    /// Manage virtual patches.
    Patch {
        #[command(subcommand)]
        cmd: PatchCmd,
    },
    /// Manage WAF configuration.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Show WAF status.
    Status,
    /// Show fortressctl version.
    Version,
}

#[derive(Subcommand, Debug)]
enum SiteCmd {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        origin: String,
    },
    List,
    Remove {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum RuleCmd {
    Create {
        #[arg(long)]
        file: String,
    },
    List {
        #[arg(long, default_value = "")]
        severity: String,
        #[arg(long, default_value = "")]
        tag: String,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    Test {
        #[arg(long)]
        id: String,
        #[arg(long)]
        request: String,
    },
}

#[derive(Subcommand, Debug)]
enum LogsCmd {
    Tail {
        #[arg(long, default_value = "")]
        site: String,
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    Export {
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = "")]
        output: String,
    },
}

#[derive(Subcommand, Debug)]
enum PatchCmd {
    Apply {
        #[arg(long)]
        cve: String,
    },
    Revoke {
        #[arg(long)]
        cve: String,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    Validate,
    Export {
        #[arg(long, default_value = "")]
        output: String,
    },
    Diff {
        #[arg(long)]
        file: String,
    },
    Apply {
        #[arg(long)]
        file: String,
    },
}

struct Client {
    base: String,
    api_key: String,
    timeout: Duration,
}

impl Client {
    fn new(api_url: &str, api_key: &str, timeout_secs: u64) -> Self {
        let mut base = api_url.to_string();
        if !base.starts_with("http") {
            base = format!("http://{base}");
        }
        Client {
            base,
            api_key: api_key.to_string(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base, path)
    }

    /// Issue a request and print the reply, matching `handleResponse`.
    fn do_json(&self, method: &str, path: &str, body: Option<serde_json::Value>) {
        let url = self.url(path);
        let mut req = ureq::request(method, &url).timeout(self.timeout);
        if !self.api_key.is_empty() {
            req = req.set("X-API-Key", &self.api_key);
        }
        let resp = match body {
            Some(b) => req
                .set("Content-Type", "application/json")
                .set("Accept", "application/json")
                .send_string(&b.to_string()),
            None => req.set("Accept", "application/json").call(),
        };

        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_code, r)) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                exit(1);
            }
        };
        handle_response(resp);
    }

    /// Issue a raw request and return the body (or exit on error).
    fn do_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
        content_type: &str,
    ) -> (u16, Vec<u8>) {
        let url = self.url(path);
        let mut req = ureq::request(method, &url).timeout(self.timeout);
        if !self.api_key.is_empty() {
            req = req.set("X-API-Key", &self.api_key);
        }
        let resp = match body {
            Some(b) => req.set("Content-Type", content_type).send_string(&b),
            None => req.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                exit(1);
            }
        };
        let status = resp.status();
        let mut bytes = Vec::new();
        let _ = resp.into_reader().read_to_end(&mut bytes);
        (status, bytes)
    }
}

/// Port of `handleResponse`.
fn handle_response(resp: ureq::Response) {
    let status = resp.status();
    let text = resp.into_string().unwrap_or_default();

    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&text);
    match parsed {
        Ok(result) => {
            if status >= 400 {
                let msg = result.get("error").and_then(|v| v.as_str()).unwrap_or("");
                let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                if detail.is_empty() {
                    eprintln!("Error {status}: {msg}");
                } else {
                    eprintln!("Error {status}: {msg} - {detail}");
                }
                exit(1);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        }
        Err(_) => {
            if status >= 400 {
                eprintln!("Error {status}: {text}");
                exit(1);
            }
            if !text.is_empty() {
                println!("{text}");
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Environment fallbacks, matching the PersistentPreRunE in Go.
    let api_url = std::env::var("FORTRESS_API_URL")
        .ok()
        .filter(|s| !s.is_empty() && cli.api_url == "localhost:8443")
        .unwrap_or(cli.api_url);
    let api_key = std::env::var("FORTRESS_API_KEY")
        .ok()
        .filter(|s| !s.is_empty() && cli.api_key.is_empty())
        .unwrap_or(cli.api_key);

    let client = Client::new(&api_url, &api_key, cli.timeout);

    match cli.command {
        Command::Site { cmd } => match cmd {
            SiteCmd::Add {
                name,
                domain,
                origin,
            } => {
                let domains: Vec<String> = domain.split(',').map(|s| s.to_string()).collect();
                client.do_json(
                    "POST",
                    "/sites",
                    Some(serde_json::json!({
                        "name": name,
                        "domains": domains,
                        "upstream": origin,
                        "waf_enabled": true,
                    })),
                );
            }
            SiteCmd::List => client.do_json("GET", "/sites", None),
            SiteCmd::Remove { name } => client.do_json("DELETE", &format!("/sites/{name}"), None),
        },
        Command::Rule { cmd } => match cmd {
            RuleCmd::Create { file } => {
                let data = read_file_or_exit(&file);
                let ct = content_type_for(&file);
                client.do_raw("POST", "/rules", Some(data), ct);
                // Re-read for output parity with handleResponse.
                client.do_json("GET", "/rules", None);
            }
            RuleCmd::List { severity, tag } => {
                let mut qs = Vec::new();
                if !severity.is_empty() {
                    qs.push(format!("severity={severity}"));
                }
                if !tag.is_empty() {
                    qs.push(format!("tag={tag}"));
                }
                let path = if qs.is_empty() {
                    "/rules".to_string()
                } else {
                    format!("/rules?{}", qs.join("&"))
                };
                client.do_json("GET", &path, None);
            }
            RuleCmd::Delete { id } => client.do_json("DELETE", &format!("/rules/{id}"), None),
            RuleCmd::Test { id, request } => {
                let data = read_file_or_exit(&request);
                let body: serde_json::Value = serde_json::from_str(&data)
                    .unwrap_or_else(|_| serde_json::json!({"request": {"raw": data}}));
                client.do_json("POST", &format!("/rules/{id}/test"), Some(body));
            }
        },
        Command::Logs { cmd } => match cmd {
            LogsCmd::Tail { site, limit } => {
                let mut qs = Vec::new();
                if !site.is_empty() {
                    qs.push(format!("site={site}"));
                }
                if limit > 0 {
                    qs.push(format!("limit={limit}"));
                }
                let path = if qs.is_empty() {
                    "/logs/tail".to_string()
                } else {
                    format!("/logs/tail?{}", qs.join("&"))
                };
                tail_logs(&client, &path);
            }
            LogsCmd::Export { format, output } => {
                let (status, data) =
                    client.do_raw("GET", &format!("/logs/export?format={format}"), None, "");
                if status >= 400 {
                    eprintln!("Error {status}: {}", String::from_utf8_lossy(&data));
                    exit(1);
                }
                let out = if output.is_empty() {
                    format!("fortress-logs-{}.{}", datestamp(), format)
                } else {
                    output
                };
                write_file_or_exit(&out, &data);
                println!("Exported {} bytes to {out}", data.len());
            }
        },
        Command::Patch { cmd } => match cmd {
            PatchCmd::Apply { cve } => {
                client.do_json(
                    "POST",
                    &format!("/patches/{cve}/apply"),
                    Some(serde_json::json!({"cve": cve})),
                );
            }
            PatchCmd::Revoke { cve } => {
                client.do_json("POST", &format!("/patches/{cve}/revoke"), None);
            }
        },
        Command::Config { cmd } => match cmd {
            ConfigCmd::Validate => {
                client.do_json("POST", "/config/validate", None);
            }
            ConfigCmd::Export { output } => {
                let (status, data) = client.do_raw("GET", "/config/export", None, "");
                if status >= 400 {
                    eprintln!("Error {status}: {}", String::from_utf8_lossy(&data));
                    exit(1);
                }
                if output.is_empty() {
                    println!("{}", String::from_utf8_lossy(&data));
                    return;
                }
                write_file_or_exit(&output, &data);
                println!("Configuration exported to {output} ({} bytes)", data.len());
            }
            ConfigCmd::Diff { file } => {
                let data = read_file_or_exit(&file);
                let ct = content_type_for(&file);
                client.do_raw("POST", "/config/diff", Some(data), ct);
                client.do_json("GET", "/config", None);
            }
            ConfigCmd::Apply { file } => {
                let data = read_file_or_exit(&file);
                let ct = content_type_for(&file);
                client.do_raw("POST", "/config/import", Some(data), ct);
                client.do_json("GET", "/config", None);
            }
        },
        Command::Status => client.do_json("GET", "/status", None),
        Command::Version => {
            println!("fortressctl {VERSION}");
            println!("  commit:     {COMMIT}");
            println!("  build date: {BUILD_DATE}");
            println!("  rust version: {}", rustc_version());
        }
    }
}

fn read_file_or_exit(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file: {e}");
            exit(1);
        }
    }
}

fn write_file_or_exit(path: &str, data: &[u8]) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(e) = std::fs::write(path, data) {
        eprintln!("Error writing file: {e}");
        exit(1);
    }
}

fn content_type_for(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        "application/x-yaml"
    } else {
        "application/json"
    }
}

fn tail_logs(client: &Client, path: &str) {
    let url = client.url(path);
    let mut req = ureq::get(&url).timeout(client.timeout);
    if !client.api_key.is_empty() {
        req = req.set("X-API-Key", &client.api_key);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            exit(1);
        }
    };
    let text = resp.into_string().unwrap_or_default();
    let result: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Error: {text}");
            exit(1);
        }
    };

    let entries = result
        .get("logs")
        .and_then(|v| v.as_array())
        .or_else(|| result.get("entries").and_then(|v| v.as_array()));

    match entries {
        Some(entries) => {
            for entry in entries {
                println!(
                    "{}",
                    serde_json::to_string_pretty(entry).unwrap_or_default()
                );
                println!("---");
            }
        }
        None => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        }
    }
}

fn datestamp() -> String {
    // "20060102-150405" in UTC.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if m <= 2 {
        (y + 1, m, d)
    } else {
        (y, m, d)
    }
}

fn rustc_version() -> String {
    // A stable, non-Go equivalent line.
    format!("rustc {}", option_env!("RUSTC_VERSION").unwrap_or("stable"))
}
