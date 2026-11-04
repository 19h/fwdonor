mod bulk;
mod dashboard;
mod error;
mod firmwares;
mod http;
mod jobs;
mod ledger;
mod limits;
mod reclassify;
mod revisions;
mod telegram;
mod uploads;

// Shared with the client (src/lib.rs); `crate::config` etc. keep working.
use fwdonor::{analyze, config, pow};

use std::future::IntoFuture;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::analyze::{Analyzer, Verdict};
use crate::config::Config;
use crate::telegram::client::{Credentials, TdClient};

#[derive(Parser)]
#[command(name = "fwdonor", version, about = "Firmware donation drop-box for zr.ax")]
struct Cli {
    /// Path to fwdonor.toml (defaults apply when omitted).
    #[arg(short, long, global = true, env = "FWDONOR_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web service and the Telegram poster.
    Serve,
    /// Log the TDLib bot in (prompts for the token) and check group access.
    Login,
    /// Print the policy JSON the browser receives (lists and limits).
    Policy,
    /// Print the URL of the page that issues bulk upload links (the key is
    /// created when the server first starts).
    AdminUrl,
    /// Print the URL of the firmware dashboard (its own key, also created
    /// when the server first starts).
    DashboardUrl,
    /// Print the donation verdict zrax gives each file.
    Check {
        /// Emit one JSON object per line instead of a table.
        #[arg(long)]
        json: bool,
        files: Vec<PathBuf>,
    },
}

extern "C" {
    fn _exit(code: i32) -> !;
}

const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// Set once a graceful shutdown starts, so closing TDLib isn't mistaken for
/// a lost session.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Leave without running C++ static destructors: TDLib's destructors race its
/// own worker threads during exit() and can crash the process. Everything we
/// persist (ledger, sidecars) is fsynced before this point.
pub fn hard_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    unsafe { _exit(code) }
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e:#}");
            1
        }
    };
    hard_exit(code)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref())?;
    match cli.command {
        Command::Check { json, files } => check(&config, json, &files),
        Command::Policy => {
            let policy = serde_json::json!({
                "max_file_bytes": config.limits.max_file_bytes,
                "min_file_bytes": config.limits.min_file_bytes,
                "policy": config.policy,
            });
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        Command::AdminUrl => {
            let key = bulk::grants::read_key(&config.admin_key_path())
                .context("start the server once first (`fwdonor serve` creates the key)")?;
            println!("{}/g/{key}", config.public_url.trim_end_matches('/'));
            Ok(())
        }
        Command::DashboardUrl => {
            let key = bulk::grants::read_key(&config.dashboard_key_path())
                .context("start the server once first (`fwdonor serve` creates the key)")?;
            println!("{}/d/{key}", config.public_url.trim_end_matches('/'));
            Ok(())
        }
        Command::Serve => {
            init_tracing();
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(serve(config))
        }
        Command::Login => {
            init_tracing();
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(login(config))
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

async fn connect_telegram(config: &Config, creds: &Credentials) -> Result<(Arc<TdClient>, i64)> {
    let client = TdClient::start(&config.telegram.tdjson, config.telegram.log_verbosity)?;
    client.authorize(creds, &config.tdlib_dir()).await?;
    let (_, chat_id) = client.check_chat(config.telegram.chat_id).await?;
    Ok((client, chat_id))
}

async fn serve(config: Config) -> Result<()> {
    let config = Arc::new(config);
    private_dir(&config.runtime_dir)?;
    private_dir(&config.spool_dir)?;
    private_dir(&config.bulk.dir)?;
    private_dir(&config.firmware_dir)?;
    if !config.dist_dir.join("index.html").exists() {
        tracing::warn!("{} has no index.html; run scripts/build.sh", config.dist_dir.display());
    }
    // Bind first: during a restart the kernel queues connections until the
    // server below starts answering, instead of refusing them.
    let listener = tokio::net::TcpListener::bind(config.bind).await.with_context(|| format!("binding {}", config.bind))?;

    let ledger = Arc::new(ledger::Ledger::open(&config.ledger_path())?);
    let revisions = Arc::new(revisions::Revisions::open(&config.zrax_revs_path(), config::zrax_rev(), uploads::unix_now())?);
    let analyzer = Analyzer::new(
        config.limits.analysis_concurrency,
        Duration::from_secs(config.limits.analysis_timeout_secs),
        Arc::new(config.policy.clone()),
    );
    analyzer.warm_up().await;
    let pow = Arc::new(pow::PowGate::new(config.pow.bits, config.pow.ttl_secs));
    let limiter = Arc::new(limits::Limiter::new(config.limits.clone()));
    // The dashboard's index hears about every record the store writes.
    let catalog = Arc::new(dashboard::catalog::Catalog::new());
    let firmwares = Arc::new(
        firmwares::Firmwares::open(&config.firmware_dir, catalog.clone())
            .with_context(|| format!("opening {}", config.firmware_dir.display()))?,
    );
    let queue = Arc::new(jobs::PostQueue::default());
    let uploads = Arc::new(uploads::Uploads::new(
        config.clone(),
        pow.clone(),
        limiter.clone(),
        ledger.clone(),
        analyzer.clone(),
        queue.clone(),
        revisions,
        firmwares.clone(),
    ));
    let recovered = uploads.recover()?;
    let bulk = bulk::Bulk::open(config.clone())?;
    tracing::info!(
        "zrax {}, {} posted so far, {recovered} job(s) resumed",
        analyze::zrax_label(),
        ledger.len()
    );

    let mut chat_id = config.telegram.chat_id;
    let client = if config.telegram.dry_run {
        tracing::warn!("telegram.dry_run is set: files are logged and deleted, not posted");
        None
    } else {
        let creds = Credentials::load(&config.credentials_path())?;
        if creds.bot_token.as_deref().unwrap_or("").is_empty() {
            // EX_CONFIG: systemd's RestartPreventExitStatus=78 stops retrying.
            tracing::error!("not logged in: run `fwdonor login` (see README)");
            hard_exit(78);
        }
        let (client, effective) = connect_telegram(&config, &creds).await?;
        chat_id = effective;
        let mut auth = client.auth_state();
        tokio::spawn(async move {
            while auth.changed().await.is_ok() {
                let state = auth.borrow().clone();
                if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                if state != "authorizationStateReady" {
                    tracing::error!("TDLib left the ready state ({state}); exiting for a clean restart");
                    hard_exit(75);
                }
            }
        });
        Some(client)
    };

    // Build the dashboard's index in the background (it reads every record).
    {
        let (catalog, ledger, dir) = (catalog.clone(), ledger.clone(), config.firmware_dir.clone());
        tokio::task::spawn_blocking(move || {
            let entries = ledger.entries().unwrap_or_else(|e| {
                tracing::error!("dashboard: reading the ledger failed: {e:#}");
                Vec::new()
            });
            // Posts before the supergroup's upgrade went to a basic group (no links).
            let chats: Vec<i64> =
                telegram::backfill::eras(&entries).into_iter().map(|era| if era == 0 { chat_id } else { 0 }).collect();
            catalog.load(&entries, &chats, &dir);
        });
    }

    let telegram = client.clone();
    let edits = Arc::new(telegram::poster::EditQueue::default());
    let poster = telegram::poster::Poster {
        client,
        chat_id,
        queue: queue.clone(),
        uploads: uploads.clone(),
        ledger: ledger.clone(),
        firmwares: firmwares.clone(),
        edits: edits.clone(),
    };
    tokio::spawn(poster.run());

    // After a zrax update, classify the store again (once the index is built).
    let reclassify_status = reclassify::status("off");
    let inflight = reclassify::Inflight::new(config.reclassify_inflight_path());
    if config.reclassify.enabled {
        reclassify_status.lock().unwrap().state = "waiting";
        let reclassifier = reclassify::Reclassifier {
            firmwares: firmwares.clone(),
            policy: Arc::new(config.policy.clone()),
            edits: edits.clone(),
            zrax: analyze::zrax_label(),
            threads: config.reclassify.threads,
            memory_mib: config.reclassify.memory_mib,
            inflight: inflight.clone(),
            status: reclassify_status.clone(),
        };
        tokio::spawn(reclassifier.run());
    }

    // Images posted before the firmware store existed come back from the group.
    let backfill_status = telegram::backfill::status("off");
    if let Some(client) = telegram.clone().filter(|_| config.firmware_backfill) {
        backfill_status.lock().unwrap().state = "waiting";
        let backfill = telegram::backfill::Backfill {
            client,
            chat_id,
            ledger: ledger.clone(),
            firmwares: firmwares.clone(),
            analyzer,
            previous_chats: config.telegram.previous_chat_ids.clone(),
            status: backfill_status.clone(),
        };
        tokio::spawn(backfill.run());
    }

    {
        let (uploads, pow, limiter, bulk) = (uploads.clone(), pow.clone(), limiter.clone(), bulk.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                uploads.sweep();
                bulk.sweep();
                pow.prune();
                limiter.prune();
            }
        });
    }

    let dashboard = Arc::new(dashboard::Dashboard::open(&config, catalog, backfill_status, reclassify_status, edits)?);
    let app = http::router(http::AppState {
        config: config.clone(),
        pow,
        uploads,
        queue,
        ledger,
        bulk: bulk.clone(),
        dashboard,
    });
    tracing::info!("listening on http://{}", config.bind);
    let stop = Arc::new(tokio::sync::Notify::new());
    let server = {
        let stop = stop.clone();
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move { stop.notified().await })
            .into_future()
    };
    tokio::pin!(server);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = &mut server => result?,
        _ = async { tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} } } => {
            tracing::info!("shutting down");
            stop.notify_one();
            // The files being classified didn't cause this exit.
            inflight.close();
            // Upload state doesn't survive a restart anyway (clients start
            // those files again), so don't hold the restart for slow chunks.
            if tokio::time::timeout(SHUTDOWN_GRACE, &mut server).await.is_err() {
                tracing::warn!("requests still open after {SHUTDOWN_GRACE:?}; exiting anyway");
            }
        }
    }
    // Bulk uploads continue after the restart; save where their hashes are.
    let _ = tokio::task::spawn_blocking(move || bulk.checkpoint_all()).await;
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(client) = telegram {
        client.close().await;
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

async fn login(config: Config) -> Result<()> {
    private_dir(&config.runtime_dir)?;
    let path = config.credentials_path();
    let existing = if path.exists() { Some(Credentials::load(&path)?) } else { None };

    let (api_id, api_hash) = match &existing {
        Some(c) => (c.api_id, c.api_hash.clone()),
        None => {
            let id: i64 = prompt("Telegram API ID (my.telegram.org): ")?.parse().context("API ID must be a number")?;
            let hash = rpassword::prompt_password("Telegram API hash: ")?.trim().to_string();
            (id, hash)
        }
    };
    let token = rpassword::prompt_password("Bot token from @BotFather: ")?.trim().to_string();
    let valid = token.split_once(':').is_some_and(|(id, secret)| {
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && secret.len() >= 30
    });
    if !valid {
        bail!("that does not look like a bot token (expected 123456:ABC…)");
    }

    // A different bot needs a fresh TDLib session.
    if existing.as_ref().and_then(|c| c.bot_token.as_deref()) != Some(token.as_str()) && config.tdlib_dir().exists() {
        std::fs::remove_dir_all(config.tdlib_dir())?;
    }
    let creds = Credentials {
        api_id,
        api_hash,
        database_encryption_key: existing
            .as_ref()
            .map(|c| c.database_encryption_key.clone())
            .unwrap_or_else(Credentials::new_key),
        bot_token: Some(token),
    };
    creds.save(&path)?;
    let creds = Credentials::load(&path)?;

    let (client, _) = connect_telegram(&config, &creds).await?;
    println!("Logged in. Credentials saved to {} (mode 600).", path.display());
    client.close().await;
    Ok(())
}

fn check(config: &Config, json: bool, files: &[PathBuf]) -> Result<()> {
    for path in files {
        let verdict = match std::fs::read(path) {
            Ok(data) if (data.len() as u64) > config.limits.max_file_bytes => {
                Verdict::Rejected { reason: "too large".into() }
            }
            Ok(data) => analyze::evaluate(&data, &config.policy),
            Err(e) => Verdict::Rejected { reason: format!("read failed: {e}") },
        };
        if json {
            let line = serde_json::json!({ "path": path, "result": verdict });
            println!("{line}");
            continue;
        }
        match verdict {
            Verdict::Accepted(s) => println!(
                "ACCEPT  {:<9} {:<14} {:<24} {:>3}-bit {:>5.1}%  {}",
                s.basis,
                s.format,
                s.isa.as_deref().unwrap_or("-"),
                s.bitwidth,
                s.confidence * 100.0,
                path.display()
            ),
            Verdict::Rejected { reason } => println!("reject  {:<50}  {}", reason, path.display()),
        }
    }
    Ok(())
}
