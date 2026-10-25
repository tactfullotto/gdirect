mod api;
mod auth;
mod download;
mod drive;
mod mount;
mod scan;
mod store;
mod tui;
mod upload;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{net::IpAddr, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Browse, download and upload Google Drive files")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Local SQLite state file (default: platform data directory)
    #[arg(long, global = true)]
    db: Option<PathBuf>,
}
#[derive(Args, Clone, Default)]
struct Route {
    /// Connect to this Google IP instead of the best scanned one
    #[arg(long)]
    ip: Option<IpAddr>,
    /// TLS identity hostname to use instead of the original Google hostname
    /// (the Host header still carries the real Google hostname)
    #[arg(long)]
    sni: Option<String>,
    /// Send no TLS SNI (downloads only); the certificate is still verified
    #[arg(long, conflicts_with = "sni")]
    no_sni: bool,
}
impl Route {
    /// Explicit identity choice: Some(name) to forge, Some("") for no SNI,
    /// None to follow the scanned route and allow automatic fallback.
    fn sni(&self) -> Option<String> {
        if self.no_sni {
            Some(String::new())
        } else {
            self.sni.clone()
        }
    }
}
#[derive(Args, Clone, Default)]
struct Transfer {
    #[command(flatten)]
    route: Route,
    /// CA bundle for certificate verification (default: bundled Google GTS roots)
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Connections per download, 1-16 (default: value saved in browse, else 8)
    #[arg(short = 'j', long, value_parser = clap::value_parser!(u8).range(1..=16))]
    connections: Option<u8>,
}
#[derive(Subcommand, Clone)]
enum Commands {
    /// Probe Google endpoints and save working IPs in SQLite
    Scan {
        /// Probe only the IPs in this file (one per line, # starts a comment)
        #[arg(long, conflicts_with = "list")]
        ips: Option<PathBuf>,
        /// Show saved endpoints instead of scanning
        #[arg(long)]
        list: bool,
    },
    /// Sign in with a Google Desktop OAuth client JSON
    Login {
        /// Sign in again in the browser using the saved OAuth client
        #[arg(long)]
        reauth: bool,
        /// Google Desktop OAuth client JSON (opens browser)
        #[arg(long, conflicts_with = "credentials")]
        client_secret: Option<PathBuf>,
        /// Import existing authorized_user credentials JSON (e.g. on a headless server)
        #[arg(long, conflicts_with = "reauth")]
        credentials: Option<PathBuf>,
    },
    /// Remove saved credentials from SQLite; scanned IPs are kept
    Logout,
    /// Browse and manage folders; ? lists the keys (d download, a create, r rename, D trash)
    Browse {
        /// Folder ID to open
        #[arg(default_value = "root")]
        folder: String,
        /// Download directory
        #[arg(short, long, default_value = "downloads")]
        output: PathBuf,
        #[command(flatten)]
        transfer: Transfer,
    },
    /// List a Drive folder
    Ls {
        /// Folder ID to list
        #[arg(default_value = "root")]
        folder: String,
        /// Print JSON instead of tab-separated columns
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        route: Route,
    },
    /// Mount Drive locally using rclone (macOS NFS; Linux/Windows FUSE)
    Mount {
        /// Mount directory (default: ~/GoogleDrive)
        path: Option<PathBuf>,
        /// Mount without write access
        #[arg(long)]
        read_only: bool,
        /// Stay in the foreground and stop with Ctrl-C (always on Windows)
        #[arg(long)]
        foreground: bool,
        /// Parallel rclone transfers, 1-16 (default: value saved in browse, else 8)
        #[arg(short = 'j', long, value_parser = clap::value_parser!(u8).range(1..=16))]
        connections: Option<u8>,
    },
    /// Unmount this database's background mount
    Unmount,
    /// Upload a local file (repeat the command to resume)
    Upload {
        /// Local file to upload
        file: PathBuf,
        /// Destination folder ID
        #[arg(long, default_value = "root")]
        parent: String,
        /// Name in Drive (default: local file name)
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        route: Route,
    },
    /// Download a file ID or sharing URL (repeat the command to resume)
    Download {
        /// Drive file ID or sharing URL
        file: String,
        /// Output file (default: downloads/<name> when logged in; required for public files)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Export a Google document as this MIME type, e.g. application/pdf
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        transfer: Transfer,
    },
}
/// Effective route: endpoint, TLS identity (None = real hostname) and whether
/// an automatic identity fallback is allowed on transport failure.
fn direct_route(db: &store::Store, route: &Route) -> Result<(IpAddr, Option<String>, bool)> {
    let explicit = route.sni();
    let auto = explicit.is_none();
    if let Some(ip) = route.ip {
        return Ok((ip, explicit, auto));
    }
    let scanned = match db.best_route()? {
        Some(route) => route,
        None => scan::run(db, None)?,
    };
    let stored = (!scanned.sni.is_empty()).then_some(scanned.sni);
    Ok((scanned.ip, explicit.or(stored), auto))
}
fn run(cli: Cli) -> Result<()> {
    let db_path = cli.db.clone().map(Ok).unwrap_or_else(store::default_path)?;
    let db = store::Store::open(&db_path)?;
    let saved = || -> u8 {
        db.setting("connections")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8)
            .clamp(1, 16)
    };
    let command = cli.command.unwrap_or_else(|| Commands::Browse {
        folder: "root".into(),
        output: "downloads".into(),
        transfer: Transfer::default(),
    });
    match command {
        Commands::Scan { list: true, .. } => {
            for e in db.endpoints()? {
                match e.latency_ms {
                    Some(ms) if e.sni.is_empty() => println!("{}\tOK\t{ms} ms", e.ip),
                    Some(ms) => println!("{}\tOK\t{ms} ms (SNI {})", e.ip, e.sni),
                    None => println!("{}\tunavailable\t{}", e.ip, e.error.unwrap_or_default()),
                }
            }
        }
        Commands::Scan { ips, .. } => {
            scan::run(&db, ips.as_deref())?;
        }
        Commands::Unmount => mount::unmount(&db)?,
        Commands::Logout => logout(&db)?,
        Commands::Mount {
            path,
            read_only,
            foreground,
            connections,
        } => {
            let api = api::Api::new(db_path, None, None, false)?;
            let connections = connections.unwrap_or_else(saved);
            mount::run(&api, path.as_deref(), read_only, foreground, connections)?;
        }
        Commands::Login {
            reauth,
            client_secret,
            credentials,
        } => {
            let api = api::Api::new(db_path, None, None, false)?;
            let email = api.login(reauth, client_secret.as_deref(), credentials.as_deref())?;
            println!("Logged in: {email}\nSQLite: {}", api.db.display());
            if !reauth && client_secret.is_none() && credentials.is_none() {
                println!("To switch accounts: gdirect login --reauth");
            }
        }
        Commands::Ls {
            folder,
            json,
            route,
        } => {
            let (ip, sni, auto) = direct_route(&db, &route)?;
            let api = api::Api::new(db_path, Some(ip), sni, auto)?;
            let files = api.list(&folder)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&files)?);
            } else {
                for f in files {
                    println!(
                        "{}\t{}\t{}\t{}",
                        if f.folder() { "DIR" } else { "FILE" },
                        f.id,
                        f.size.as_deref().unwrap_or("-"),
                        f.name
                    );
                }
            }
        }
        Commands::Upload {
            file,
            parent,
            name,
            route,
        } => {
            let (ip, sni, auto) = direct_route(&db, &route)?;
            let api = api::Api::new(db_path, Some(ip), sni, auto)?;
            let uploaded = api.upload(&file, &parent, name.as_deref())?;
            println!("{}\t{}", uploaded.id, uploaded.name);
        }
        Commands::Download {
            file,
            output,
            export,
            transfer,
        } => {
            let (ip, sni, auto) = direct_route(&db, &transfer.route)?;
            let api = api::Api::new(db_path, Some(ip), sni.clone(), auto)?;
            let connections = transfer.connections.unwrap_or_else(saved);
            start_download(
                &api,
                file,
                output,
                export,
                ip,
                sni,
                auto,
                &transfer,
                connections,
            )?;
        }
        Commands::Browse {
            folder,
            output,
            transfer,
        } => {
            let (ip, sni, auto) = direct_route(&db, &transfer.route)?;
            let api = api::Api::new(db_path, Some(ip), sni.clone(), auto)?;
            let options = tui::Options {
                folder,
                output,
                ip: Some(ip),
                sni,
                auto,
                connections: transfer.connections.unwrap_or_else(saved),
                ca_cert: transfer.ca_cert,
            };
            tui::run(api, options)?;
        }
    }
    Ok(())
}
fn logout(db: &store::Store) -> Result<()> {
    anyhow::ensure!(
        db.setting("mount")?.is_none(),
        "a background mount is recorded; run gdirect unmount first"
    );
    match db.clear_auth()? {
        Some(account) => println!(
            "Logged out {account}: removed saved credentials, OAuth client, access token and upload sessions. Scanned IPs are kept."
        ),
        None => println!("No saved login; nothing removed."),
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn start_download(
    api: &api::Api,
    file: String,
    output: Option<PathBuf>,
    export: Option<String>,
    ip: IpAddr,
    sni: Option<String>,
    auto: bool,
    transfer: &Transfer,
    connections: u8,
) -> Result<()> {
    let db = store::Store::open(&api.db)?;
    let token = if db.account()?.is_some() || std::env::var_os("GDIRECT_ACCESS_TOKEN").is_some() {
        Some(api.download_token()?)
    } else {
        None
    };
    let id = drive::FileRef::parse(&file)?.id;
    let metadata = if token.is_some() {
        Some(api.metadata(&id)?)
    } else {
        None
    };
    if let Some(meta) = &metadata {
        anyhow::ensure!(
            !meta.folder(),
            "select a file inside the folder with gdirect browse"
        );
        anyhow::ensure!(
            meta.downloadable(),
            "{} has no downloadable content",
            meta.mime_type
        );
        anyhow::ensure!(
            !meta.workspace() || export.is_some(),
            "this is a Google document; add --export application/pdf (or another export MIME type)"
        );
    }
    let output = output
        .or_else(|| {
            metadata
                .as_ref()
                .map(|meta| api::destination(std::path::Path::new("downloads"), meta))
        })
        .context("public download requires -o FILE")?;
    download::run(
        download::Args {
            file,
            output,
            ip: Some(ip),
            sni,
            auto,
            db: Some(api.db.clone()),
            md5: metadata
                .as_ref()
                .filter(|_| export.is_none())
                .and_then(|meta| meta.md5_checksum.clone()),
            token,
            export,
            connections,
            ca_cert: transfer.ca_cert.clone(),
        },
        None,
    )
}
fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("gdirect").chain(args.iter().copied()))
    }
    #[test]
    fn commands_and_scoped_options() {
        let cli = parse(&["browse", "-j", "8"]).unwrap();
        assert!(
            matches!(cli.command, Some(Commands::Browse { transfer, .. }) if transfer.connections == Some(8))
        );
        assert!(parse(&["browse", "-j", "0"]).is_err());
        assert!(parse(&[]).unwrap().command.is_none());
        assert!(parse(&["lgoin"]).is_err());
        assert!(parse(&["file_id", "-o", "out.bin"]).is_err());
        assert!(parse(&["--auth", "ls"]).is_err());
        assert!(parse(&["scan", "--list", "--db", "x.sqlite3"]).is_ok());
        assert!(parse(&["login", "--ip", "1.1.1.1"]).is_err());
        assert!(parse(&["scan", "-o", "x"]).is_err());
        assert!(parse(&["ls", "--sni", "g.cn"]).is_ok());
        assert!(parse(&["upload", "f", "--ip", "1.1.1.1", "-j", "2"]).is_err());
        assert!(parse(&["mount", "--ip", "1.1.1.1"]).is_err());
        assert!(parse(&["mount", "-j", "4"]).is_ok());
        assert!(matches!(
            parse(&["logout"]).unwrap().command,
            Some(Commands::Logout)
        ));
        assert!(parse(&["download", "id", "--sni", "g.cn", "--no-sni"]).is_err());
        let cli = parse(&["download", "id", "--no-sni", "--ip", "1.1.1.1", "-o", "f"]).unwrap();
        let Some(Commands::Download { transfer, .. }) = cli.command else {
            panic!()
        };
        assert_eq!(transfer.route.sni().as_deref(), Some(""));
    }
}
