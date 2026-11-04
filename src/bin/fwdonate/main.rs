//! fwdonate: donate firmware images to fwdonor.zr.ax from the command line.
//!
//! It goes through the same steps as the page:
//! - zrax classifies every file locally, using the same library, revision and
//!   policy lists the server applies, so the server has nothing to reject.
//! - Files the collection already has are skipped by their SHA-256.
//! - The rest go through the proof of work and a chunked upload, two at a time.
//!
//! Failures that look temporary (the server restarting, a limit, a pause) are
//! retried forever, at most 20 s apart. Uploads the server lost are sent again.
//!
//!   fwdonate -n your_name firmware.bin dumps/ more/

mod api;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use walkdir::WalkDir;

use fwdonor::analyze::{evaluate, Summary, Verdict};
use fwdonor::config::zrax_rev;
use fwdonor::pow::{leading_zero_bits, seed, work_hash};

use api::{backoff, Api, ApiError, InitRequest, InitResponse, PolicyResponse, Status, MAX_BACKOFF};

/// Times the server may fail to post a file (Telegram trouble) before the
/// file counts as failed.
const SERVER_FAILURE_ATTEMPTS: u32 = 3;

#[derive(Parser)]
#[command(
    name = "fwdonate",
    version,
    about = "Donate firmware images to the zrax corpus (fwdonor.zr.ax)",
    after_help = "Files zrax doesn't recognize as firmware never leave this machine. Exit status: 0 when \
                  everything was donated, already known or skipped; 2 when some files failed or were \
                  rejected; 130 when interrupted."
)]
struct Cli {
    /// Files and directories to donate (directories are searched recursively).
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Name to credit: letters, digits, '_', '.' and '-', up to 32, e.g. your
    /// Telegram handle.
    #[arg(short, long, env = "FWDONOR_NAME", default_value = "anonymous")]
    name: String,

    /// The donation server.
    #[arg(long, env = "FWDONOR_SERVER", default_value = "https://fwdonor.zr.ax", value_name = "URL")]
    server: String,

    /// Files in flight at once (the server allows 2 uploads per address).
    #[arg(short, long, default_value_t = 2, value_name = "N")]
    jobs: usize,

    /// Start the next file as soon as the server has this one, without
    /// waiting for it to be posted. Faster, but a large run then fills the
    /// Telegram queue ahead of everyone else's donations.
    #[arg(long)]
    no_wait: bool,

    /// Files classified at once (each is read into memory whole).
    #[arg(long, default_value_t = default_check_jobs(), value_name = "N")]
    check_jobs: usize,

    /// Follow symbolic links inside directories.
    #[arg(short = 'L', long)]
    follow_links: bool,

    /// Classify and look files up, but upload nothing.
    #[arg(long)]
    dry_run: bool,

    /// Also list skipped files (not firmware, too small or too large).
    #[arg(short, long)]
    verbose: bool,
}

fn default_check_jobs() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(4)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The server's rule for donor names (src/uploads.rs `sanitize_username`),
/// except that a name it would replace with "anonymous" is an error here.
fn donor_name(raw: &str) -> Result<String> {
    let name = raw.trim().trim_start_matches('@');
    let valid = !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid {
        bail!("--name may only use letters, digits, '_', '.' and '-' (up to 32 characters)");
    }
    Ok(name.to_string())
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let name = donor_name(&cli.name)?;
    if cli.jobs == 0 || cli.check_jobs == 0 {
        bail!("--jobs and --check-jobs must be at least 1");
    }
    let api = Api::new(&cli.server)?;
    let ours = zrax_rev();

    let notices = Notices::default();
    let policy = persist(&notices, || api.policy(ours))
        .await
        .with_context(|| format!("{} doesn't look like a fwdonor server", cli.server))?;
    if policy.zrax_rev != ours {
        bail!(
            "the server runs zrax {} and no longer accepts this build (zrax {}): rebuild fwdonate from the \
             current fwdonor source",
            short(policy.zrax_latest.as_deref().unwrap_or(&policy.zrax_rev)),
            short(ours)
        );
    }
    eprintln!(
        "fwdonate {} · zrax {} · {} · donating as {name}{}",
        env!("CARGO_PKG_VERSION"),
        fwdonor::analyze::zrax_label(),
        cli.server,
        if cli.dry_run {
            " · dry run"
        } else if cli.no_wait {
            " · not waiting for posts"
        } else {
            ""
        }
    );
    if let Some(latest) = policy.zrax_latest.as_deref().filter(|latest| *latest != ours) {
        eprintln!(
            "note: the server runs a newer zrax ({}). This build still works for a few days; rebuild it from \
             the current fwdonor source to match.",
            short(latest)
        );
    }
    if policy.paused {
        eprintln!("note: donations are paused right now; files wait until they resume");
    }

    let ctx = Arc::new(Ctx {
        api,
        policy,
        name,
        dry_run: cli.dry_run,
        verbose: cli.verbose,
        wait_posted: !cli.no_wait,
        slots: Arc::new(Semaphore::new(cli.jobs)),
        counts: Counts::default(),
        stop: AtomicBool::new(false),
        receiving: Mutex::new(HashSet::new()),
        notices,
        started: Instant::now(),
    });

    let progress = tokio::spawn(progress(ctx.clone()));
    let interrupted = tokio::select! {
        result = pipeline(ctx.clone(), cli.paths, cli.follow_links, cli.check_jobs) => {
            result?;
            false
        }
        _ = tokio::signal::ctrl_c() => {
            ctx.stop.store(true, Ordering::SeqCst);
            let ids: Vec<String> = ctx.receiving.lock().unwrap().iter().cloned().collect();
            eprintln!("\ninterrupted: cancelling {} unfinished upload(s)", ids.len());
            futures_util::future::join_all(ids.iter().map(|id| ctx.api.cancel(id))).await;
            true
        }
    };
    progress.abort();

    let c = &ctx.counts;
    let load = |n: &AtomicU64| n.load(Ordering::SeqCst);
    let mut parts = Vec::new();
    if ctx.dry_run {
        parts.push(format!("{} would be donated ({})", load(&c.new), fmt_size(load(&c.new_bytes))));
    } else {
        parts.push(format!("{} donated ({})", load(&c.donated), fmt_size(load(&c.donated_bytes))));
    }
    parts.push(format!("{} already in the collection", load(&c.duplicate)));
    parts.push(format!("{} skipped{}", load(&c.skipped), if ctx.verbose { "" } else { " (-v lists them)" }));
    if load(&c.rejected) > 0 {
        parts.push(format!("{} rejected by the server", load(&c.rejected)));
    }
    parts.push(format!("{} failed", load(&c.failed)));
    if load(&c.stopped) > 0 {
        parts.push(format!("{} not sent", load(&c.stopped)));
    }
    eprintln!("{} in {}: {}", if interrupted { "stopped" } else { "done" }, fmt_duration(ctx.started.elapsed()), parts.join(", "));
    let waiting = load(&c.at_server);
    if interrupted && waiting > 0 {
        eprintln!("{waiting} upload(s) had already reached the server and will still be posted");
    }

    Ok(if interrupted {
        ExitCode::from(130)
    } else if load(&c.failed) + load(&c.rejected) > 0 || ctx.stop.load(Ordering::SeqCst) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

// ------------------------------------------------------------------ state

#[derive(Default)]
struct Counts {
    found: AtomicU64,
    checked: AtomicU64,
    skipped: AtomicU64,
    duplicate: AtomicU64,
    new: AtomicU64,
    new_bytes: AtomicU64,
    donated: AtomicU64,
    donated_bytes: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    stopped: AtomicU64,
    /// Waiting for an upload slot or uploading.
    to_upload: AtomicU64,
    uploading: AtomicU64,
    /// Completed uploads the server is verifying or posting.
    at_server: AtomicU64,
}

struct Ctx {
    api: Api,
    policy: PolicyResponse,
    name: String,
    dry_run: bool,
    verbose: bool,
    /// Keep a file's slot until it is posted (as the page does), so this run
    /// has at most `--jobs` files in the Telegram queue at a time.
    wait_posted: bool,
    /// Files in flight: a slot is held from the proof of work until the upload
    /// is complete, or until the file is posted with `wait_posted`.
    slots: Arc<Semaphore>,
    counts: Counts,
    /// Set on Ctrl-C or when the server stops accepting this client.
    stop: AtomicBool,
    /// Upload sessions still receiving data, cancelled on Ctrl-C.
    receiving: Mutex<HashSet<String>>,
    notices: Notices,
    started: Instant,
}

enum Outcome {
    Donated,
    Duplicate(String),
    Rejected(String),
    Failed(String),
    Skipped(String),
    /// Not attempted (interrupted, or the server stopped accepting us).
    Stopped,
}

impl Ctx {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Stop taking new files: nothing more can be donated in this run.
    fn halt(&self, why: &str) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            eprintln!("stopping: {why}");
        }
    }

    fn finish(&self, path: &Path, size: u64, summary: Option<&Summary>, outcome: Outcome) {
        let c = &self.counts;
        let (label, detail) = match outcome {
            Outcome::Donated => {
                c.donated.fetch_add(1, Ordering::SeqCst);
                c.donated_bytes.fetch_add(size, Ordering::SeqCst);
                ("donated", summary.map(|s| describe(s, size)).unwrap_or_default())
            }
            Outcome::Duplicate(why) => {
                c.duplicate.fetch_add(1, Ordering::SeqCst);
                ("known", why)
            }
            Outcome::Rejected(why) => {
                c.rejected.fetch_add(1, Ordering::SeqCst);
                ("rejected", why)
            }
            Outcome::Failed(why) => {
                c.failed.fetch_add(1, Ordering::SeqCst);
                ("failed", why)
            }
            Outcome::Skipped(why) => {
                c.skipped.fetch_add(1, Ordering::SeqCst);
                if !self.verbose {
                    return;
                }
                ("skipped", why)
            }
            Outcome::Stopped => {
                c.stopped.fetch_add(1, Ordering::SeqCst);
                return;
            }
        };
        println!("{label:<9} {}  {detail}", path.display());
    }

    /// Back off before retrying a transient failure.
    async fn wait(&self, err: &ApiError, attempt: u32) {
        self.notices.waiting(err);
        tokio::time::sleep(backoff(attempt, err.retry_after)).await;
    }

    /// Retry `f` through transient failures; other errors come back.
    async fn persist<T, F, Fut>(&self, f: F) -> Result<T, ApiError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        persist(&self.notices, f).await
    }

    fn receiving(&self, id: &str) -> Receiving<'_> {
        self.receiving.lock().unwrap().insert(id.to_string());
        Receiving { ctx: self, id: id.to_string() }
    }
}

async fn persist<T, F, Fut>(notices: &Notices, mut f: F) -> Result<T, ApiError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ApiError>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Ok(value) => {
                notices.recovered();
                return Ok(value);
            }
            Err(e) if e.transient() => {
                notices.waiting(&e);
                tokio::time::sleep(backoff(attempt, e.retry_after)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Retry notices, printed once rather than per request and file.
#[derive(Default)]
struct Notices {
    last: Mutex<Option<(String, Instant)>>,
}

impl Notices {
    fn waiting(&self, err: &ApiError) {
        let why = if err.server_down() {
            "the server isn't answering (it is probably restarting)".to_string()
        } else if err.is("paused") {
            "donations are paused".to_string()
        } else {
            err.message.clone()
        };
        let msg = format!("waiting: {why}; retrying every {} s at most", MAX_BACKOFF.as_secs());
        let mut last = self.last.lock().unwrap();
        if last.as_ref().is_none_or(|(m, at)| *m != msg || at.elapsed() > Duration::from_secs(60)) {
            eprintln!("{msg}");
            *last = Some((msg, Instant::now()));
        }
    }

    fn recovered(&self) {
        if self.last.lock().unwrap().take().is_some() {
            eprintln!("the server answers again; continuing");
        }
    }
}

/// Counts something for as long as it lives.
struct Gauge<'a>(&'a AtomicU64);

impl<'a> Gauge<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Receiving<'a> {
    ctx: &'a Ctx,
    id: String,
}

impl Drop for Receiving<'_> {
    fn drop(&mut self) {
        self.ctx.receiving.lock().unwrap().remove(&self.id);
    }
}

// --------------------------------------------------------------- pipeline

/// A file zrax accepted.
struct Candidate {
    path: PathBuf,
    size: u64,
    sha256: String,
    sha: [u8; 32],
    summary: Summary,
}

/// walk → classify (check_jobs at once) → look up hashes in batches →
/// upload (`--jobs` at once) → wait until posted.
async fn pipeline(ctx: Arc<Ctx>, paths: Vec<PathBuf>, follow_links: bool, check_jobs: usize) -> Result<()> {
    let (path_tx, mut path_rx) = mpsc::channel::<PathBuf>(1024);
    let (cand_tx, mut cand_rx) = mpsc::channel::<Candidate>(1024);
    let (up_tx, mut up_rx) = mpsc::channel::<Candidate>(64);

    let walker = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || walk(&ctx, paths, follow_links, path_tx))
    };

    let checker = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(check_jobs));
            let mut tasks = JoinSet::new();
            while let Some(path) = path_rx.recv().await {
                if ctx.stopped() {
                    break;
                }
                let permit = permits.clone().acquire_owned().await.expect("semaphore closed");
                let (ctx, tx) = (ctx.clone(), cand_tx.clone());
                tasks.spawn(async move {
                    let checked = {
                        let (ctx, path) = (ctx.clone(), path.clone());
                        tokio::task::spawn_blocking(move || check(&path, &ctx.policy)).await
                    };
                    drop(permit);
                    ctx.counts.checked.fetch_add(1, Ordering::SeqCst);
                    match checked {
                        Ok(Checked::Accepted(c)) => {
                            let _ = tx.send(c).await;
                        }
                        Ok(Checked::Skipped(why)) => ctx.finish(&path, 0, None, Outcome::Skipped(why)),
                        Ok(Checked::Failed(why)) => ctx.finish(&path, 0, None, Outcome::Failed(why)),
                        Err(e) => ctx.finish(&path, 0, None, Outcome::Failed(format!("check failed: {e}"))),
                    }
                });
                while tasks.try_join_next().is_some() {}
            }
            drop(cand_tx);
            while tasks.join_next().await.is_some() {}
        })
    };

    let lookup = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut seen: HashMap<String, PathBuf> = HashMap::new();
            let mut arrived = Vec::new();
            while cand_rx.recv_many(&mut arrived, 1000).await > 0 {
                let mut batch = Vec::new();
                for c in arrived.drain(..) {
                    match seen.get(&c.sha256) {
                        Some(first) => {
                            let why = format!("same file as {}", first.display());
                            ctx.finish(&c.path, c.size, None, Outcome::Duplicate(why));
                        }
                        None => {
                            seen.insert(c.sha256.clone(), c.path.clone());
                            batch.push(c);
                        }
                    }
                }
                if batch.is_empty() {
                    continue;
                }
                let shas: Vec<&str> = batch.iter().map(|c| c.sha256.as_str()).collect();
                let known = ctx.persist(|| ctx.api.known(&shas)).await;
                drop(shas);
                let known = match known {
                    Ok(known) => known,
                    Err(e) => {
                        for c in batch {
                            ctx.finish(&c.path, c.size, None, Outcome::Failed(format!("looking it up failed: {e}")));
                        }
                        continue;
                    }
                };
                for c in batch {
                    match known.get(&c.sha256) {
                        Some(k) if k.posted_at.is_some() => {
                            let when = k.date.as_deref().unwrap_or("earlier");
                            ctx.finish(&c.path, c.size, None, Outcome::Duplicate(format!("already in the collection (donated {when})")));
                        }
                        Some(_) => ctx.finish(&c.path, c.size, None, Outcome::Duplicate("being donated right now".into())),
                        None if ctx.dry_run => {
                            ctx.counts.new.fetch_add(1, Ordering::SeqCst);
                            ctx.counts.new_bytes.fetch_add(c.size, Ordering::SeqCst);
                            println!("{:<9} {}  {}", "new", c.path.display(), describe(&c.summary, c.size));
                        }
                        None => {
                            ctx.counts.to_upload.fetch_add(1, Ordering::SeqCst);
                            if let Err(mpsc::error::SendError(c)) = up_tx.send(c).await {
                                ctx.counts.to_upload.fetch_sub(1, Ordering::SeqCst);
                                ctx.finish(&c.path, c.size, None, Outcome::Stopped);
                            }
                        }
                    }
                }
            }
        })
    };

    let uploader = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            while let Some(c) = up_rx.recv().await {
                if ctx.stopped() {
                    ctx.counts.to_upload.fetch_sub(1, Ordering::SeqCst);
                    ctx.finish(&c.path, c.size, None, Outcome::Stopped);
                    continue;
                }
                // Waiting for a slot here (not in the task) keeps the stages
                // before from running far ahead of the uploads.
                let slot = ctx.slots.clone().acquire_owned().await.expect("semaphore closed");
                tasks.spawn(donate(ctx.clone(), c, slot));
                while tasks.try_join_next().is_some() {}
            }
            while tasks.join_next().await.is_some() {}
        })
    };

    walker.await?;
    checker.await?;
    lookup.await?;
    uploader.await?;
    Ok(())
}

fn walk(ctx: &Ctx, roots: Vec<PathBuf>, follow_links: bool, tx: mpsc::Sender<PathBuf>) {
    // The same file named twice (or reached through a link) counts once.
    let mut seen = HashSet::new();
    let mut send = |path: PathBuf| {
        if !seen.insert(std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone())) {
            return true;
        }
        ctx.counts.found.fetch_add(1, Ordering::SeqCst);
        tx.blocking_send(path).is_ok()
    };
    for root in roots {
        let meta = match std::fs::metadata(&root) {
            Ok(meta) => meta,
            Err(e) => {
                ctx.finish(&root, 0, None, Outcome::Failed(e.to_string()));
                continue;
            }
        };
        if meta.is_file() {
            if !send(root) {
                return;
            }
        } else if meta.is_dir() {
            for entry in WalkDir::new(&root).follow_links(follow_links).sort_by_file_name() {
                if ctx.stopped() {
                    return;
                }
                match entry {
                    Ok(entry) if entry.file_type().is_file() => {
                        if !send(entry.into_path()) {
                            return;
                        }
                    }
                    // Directories, and links unless following them.
                    Ok(_) => {}
                    Err(e) => eprintln!("warning: {e}"),
                }
            }
        } else {
            ctx.finish(&root, 0, None, Outcome::Failed("not a regular file or directory".into()));
        }
    }
}

enum Checked {
    Accepted(Candidate),
    Skipped(String),
    Failed(String),
}

/// Read, hash and classify one file with the server's own rule.
fn check(path: &Path, policy: &PolicyResponse) -> Checked {
    let too_large = |size: u64| {
        Checked::Skipped(format!("too large ({}, the limit is {})", fmt_size(size), fmt_size(policy.max_file_bytes)))
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > policy.max_file_bytes => return too_large(meta.len()),
        Ok(_) => {}
        Err(e) => return Checked::Failed(format!("read failed: {e}")),
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => return Checked::Failed(format!("read failed: {e}")),
    };
    let size = data.len() as u64;
    if size > policy.max_file_bytes {
        return too_large(size);
    }
    if size < policy.min_file_bytes {
        return Checked::Skipped("too small".into());
    }
    match std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(&data, &policy.policy))) {
        Ok(Verdict::Accepted(summary)) => {
            let sha: [u8; 32] = Sha256::digest(&data).into();
            Checked::Accepted(Candidate { path: path.to_path_buf(), size, sha256: hex::encode(sha), sha, summary })
        }
        Ok(Verdict::Rejected { reason }) => Checked::Skipped(reason),
        Err(_) => Checked::Failed("zrax crashed on this file".into()),
    }
}

// ----------------------------------------------------------------- upload

/// How one attempt at a file ended, when not with a final outcome.
enum Flow {
    Done(Outcome),
    /// The server lost the upload (it restarted): send the file again.
    Restart(String),
    /// The server took the file but could not post it.
    ServerFailed(String),
}

type Step<T> = std::result::Result<T, Flow>;

async fn donate(ctx: Arc<Ctx>, c: Candidate, slot: OwnedSemaphorePermit) {
    let mut slot = Some(slot);
    let mut server_failures = 0;
    let outcome = loop {
        if ctx.stopped() {
            break Outcome::Stopped;
        }
        let permit = match slot.take() {
            Some(permit) => permit,
            None => ctx.slots.clone().acquire_owned().await.expect("semaphore closed"),
        };
        match upload_once(&ctx, &c, permit).await {
            Ok(outcome) | Err(Flow::Done(outcome)) => break outcome,
            Err(Flow::Restart(why)) => eprintln!("{}: {why}; sending it again", c.path.display()),
            Err(Flow::ServerFailed(why)) => {
                server_failures += 1;
                if server_failures >= SERVER_FAILURE_ATTEMPTS {
                    break Outcome::Failed(format!("the server could not post it: {why}"));
                }
                eprintln!("{}: the server could not post it ({why}); trying again", c.path.display());
                tokio::time::sleep(MAX_BACKOFF).await;
            }
        }
    };
    ctx.counts.to_upload.fetch_sub(1, Ordering::SeqCst);
    ctx.finish(&c.path, c.size, Some(&c.summary), outcome);
}

async fn upload_once(ctx: &Ctx, c: &Candidate, slot: OwnedSemaphorePermit) -> Step<Outcome> {
    let uploading = Gauge::new(&ctx.counts.uploading);
    let session = admit(ctx, c).await?;
    let status = {
        let _receiving = ctx.receiving(&session.id);
        send_chunks(ctx, c, &session).await?;
        complete(ctx, c, &session.id).await?
    };
    drop(uploading);
    // The server gives this address its upload slot back once the file is
    // complete. Without waiting, the next file starts now and this one waits
    // for Telegram on its own.
    let _slot = if ctx.wait_posted {
        Some(slot)
    } else {
        drop(slot);
        None
    };
    let _at_server = Gauge::new(&ctx.counts.at_server);
    await_post(ctx, c, &session.id, status).await
}

/// Proof of work and upload admission.
async fn admit(ctx: &Ctx, c: &Candidate) -> Step<InitResponse> {
    let name = c.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "firmware.bin".into());
    let mut attempt = 0;
    let mut quick_retry = true;
    loop {
        if ctx.stopped() {
            return Err(Flow::Done(Outcome::Stopped));
        }
        let challenge = ctx.persist(|| ctx.api.challenge()).await.map_err(|e| Flow::Done(Outcome::Failed(e.to_string())))?;
        let nonce = {
            let (token, sha) = (challenge.token.clone(), c.sha);
            tokio::task::spawn_blocking(move || solve(&token, &sha, challenge.bits))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| format!("{e:#}")))
                .map_err(|e| Flow::Done(Outcome::Failed(format!("proof of work failed: {e}"))))?
        };
        let req = InitRequest {
            name: &name,
            size: c.size,
            sha256: &c.sha256,
            username: &ctx.name,
            token: &challenge.token,
            nonce,
            zrax_rev: zrax_rev(),
        };
        match ctx.api.init(&req).await {
            Ok(session) => {
                ctx.notices.recovered();
                return Ok(session);
            }
            Err(e) if e.is("duplicate") => return Err(Flow::Done(Outcome::Duplicate(e.message))),
            Err(e) if e.is("stale_client") => {
                ctx.halt("the server no longer accepts this zrax revision; rebuild fwdonate from the current fwdonor source");
                return Err(Flow::Done(Outcome::Stopped));
            }
            Err(e) if e.banned() => {
                ctx.halt(&format!("the server refuses uploads from this address for now ({})", e.message));
                return Err(Flow::Done(Outcome::Stopped));
            }
            Err(e) if e.is("size") => return Err(Flow::Done(Outcome::Skipped(e.message))),
            // The challenge may have expired while we waited: once right away.
            Err(e) if e.is("pow") && quick_retry => quick_retry = false,
            Err(e) if e.transient() || e.is("pow") => {
                ctx.wait(&e, attempt).await;
                attempt += 1;
            }
            Err(e) => return Err(Flow::Done(Outcome::Failed(e.to_string()))),
        }
    }
}

/// First nonce whose work hash has `bits` leading zero bits (src/pow.rs).
fn solve(token_b64: &str, sha: &[u8; 32], bits: u8) -> Result<u64> {
    let token = URL_SAFE_NO_PAD.decode(token_b64).context("bad challenge token")?;
    let seed = seed(&token, sha);
    let bits = u32::from(bits);
    (0u64..).find(|&n| leading_zero_bits(&work_hash(&seed, n)) >= bits).context("no proof of work found")
}

/// Give up on a session that is still receiving.
async fn abandon(ctx: &Ctx, id: &str, why: String) -> Flow {
    let _ = ctx.api.cancel(id).await;
    Flow::Done(Outcome::Failed(why))
}

async fn send_chunks(ctx: &Ctx, c: &Candidate, session: &InitResponse) -> Step<()> {
    let mut file = match tokio::fs::File::open(&c.path).await {
        Ok(file) => file,
        Err(e) => return Err(abandon(ctx, &session.id, format!("read failed: {e}")).await),
    };
    let mut hasher = Sha256::new();
    for index in 0..session.chunks {
        let len = session.chunk_size.min(c.size - index * session.chunk_size) as usize;
        let mut buf = vec![0u8; len];
        if let Err(e) = file.read_exact(&mut buf).await {
            return Err(abandon(ctx, &session.id, format!("read failed: {e}")).await);
        }
        hasher.update(&buf);
        let data = Bytes::from(buf);
        let (mut attempt, mut damaged) = (0, 0);
        loop {
            match ctx.api.put_chunk(&session.id, index, data.clone()).await {
                Ok(()) => break,
                Err(e) if e.not_found() || e.is("state") => return Err(after_restart(ctx, c).await),
                Err(e) if e.transient() => {
                    ctx.wait(&e, attempt).await;
                    attempt += 1;
                }
                // A chunk that arrived cut short: send it again, a few times.
                Err(e) if e.status == Some(StatusCode::BAD_REQUEST) && damaged < 3 => {
                    damaged += 1;
                    tokio::time::sleep(backoff(damaged, None)).await;
                }
                Err(e) => return Err(abandon(ctx, &session.id, e.to_string()).await),
            }
        }
    }
    // The server verifies the hash and counts a mismatch against this
    // address, so never complete a file that changed since it was checked.
    if hex::encode(hasher.finalize()) != c.sha256 {
        let why = "the file changed since it was checked; run again to donate the new version".to_string();
        return Err(abandon(ctx, &session.id, why).await);
    }
    Ok(())
}

async fn complete(ctx: &Ctx, c: &Candidate, id: &str) -> Step<Status> {
    let mut attempt = 0;
    loop {
        match ctx.api.complete(id).await {
            Ok(status) => return Ok(status),
            Err(e) if e.not_found() => return Err(after_restart(ctx, c).await),
            Err(e) if e.is("incomplete") => return Err(Flow::Restart("the server is missing parts of it".into())),
            Err(e) if e.transient() => {
                ctx.wait(&e, attempt).await;
                attempt += 1;
            }
            Err(e) => return Err(Flow::Done(Outcome::Failed(e.to_string()))),
        }
    }
}

/// Follow verification and posting until the file is in the group.
async fn await_post(ctx: &Ctx, c: &Candidate, id: &str, mut status: Status) -> Step<Outcome> {
    loop {
        match status.state.as_str() {
            "posted" => return Ok(Outcome::Donated),
            "rejected" => return Ok(Outcome::Rejected(status.reason.unwrap_or_default())),
            "failed" => return Err(Flow::ServerFailed(status.reason.unwrap_or_default())),
            "receiving" => return Err(Flow::Restart("the server restarted".into())),
            _ => {}
        }
        tokio::time::sleep(poll_interval(status.position)).await;
        let mut attempt = 0;
        status = loop {
            match ctx.api.status(id).await {
                Ok(status) => break status,
                Err(e) if e.not_found() => return Err(after_restart(ctx, c).await),
                Err(e) if e.transient() => {
                    ctx.wait(&e, attempt).await;
                    attempt += 1;
                }
                Err(e) => return Err(Flow::Done(Outcome::Failed(e.to_string()))),
            }
        };
    }
}

/// Every 2 s near the front of the Telegram queue, up to 30 s further back
/// (the group takes a post every few seconds).
fn poll_interval(position: Option<usize>) -> Duration {
    Duration::from_secs(position.unwrap_or(0).clamp(2, 30) as u64)
}

/// The server no longer knows the upload: did it post the file before it
/// restarted, is the file still on its way, or does it have to be sent again?
async fn after_restart(ctx: &Ctx, c: &Candidate) -> Flow {
    let one = [c.sha256.as_str()];
    let mut attempt = 0;
    loop {
        match ctx.persist(|| ctx.api.known(&one)).await {
            Ok(known) => match known.get(&c.sha256) {
                Some(k) if k.posted_at.is_some() => return Flow::Done(Outcome::Donated),
                Some(_) => {
                    tokio::time::sleep(backoff(attempt, None)).await;
                    attempt += 1;
                }
                None => return Flow::Restart("the server lost the upload (it restarted)".into()),
            },
            Err(e) => return Flow::Done(Outcome::Failed(e.to_string())),
        }
    }
}

// ----------------------------------------------------------------- output

async fn progress(ctx: Arc<Ctx>) {
    let mut last = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let c = &ctx.counts;
        let load = |n: &AtomicU64| n.load(Ordering::SeqCst);
        let mut line = format!("{} found, {} checked", load(&c.found), load(&c.checked));
        if ctx.dry_run {
            line += &format!(", {} new", load(&c.new));
        } else {
            let (uploading, at_server) = (load(&c.uploading), load(&c.at_server));
            line += &format!(
                ", {} waiting to upload, {uploading} uploading, {at_server} with the server, {} donated",
                load(&c.to_upload).saturating_sub(uploading + at_server),
                load(&c.donated)
            );
        }
        line += &format!(", {} known, {} skipped, {} failed", load(&c.duplicate), load(&c.skipped), load(&c.failed));
        if line != last {
            eprintln!("[{}] {line}", fmt_duration(ctx.started.elapsed()));
            last = line;
        }
    }
}

fn describe(s: &Summary, size: u64) -> String {
    let mut out = s.format_name.clone();
    if let Some(isa) = &s.isa_name {
        out += " · ";
        out += isa;
        if s.bitwidth > 0 {
            out += &format!(" {}-bit", s.bitwidth);
        }
    }
    out + &format!(" · {}", fmt_size(size))
}

fn fmt_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, secs % 3600 / 60),
    }
}

fn short(rev: &str) -> &str {
    &rev[..rev.len().min(7)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_server_rule() {
        assert_eq!(donor_name("@some_handle").unwrap(), "some_handle");
        assert_eq!(donor_name(" a.b-c_1 ").unwrap(), "a.b-c_1");
        assert!(donor_name("has space").is_err());
        assert!(donor_name("").is_err());
        assert!(donor_name(&"x".repeat(33)).is_err());
    }

    #[test]
    fn solves_the_shared_vector() {
        // src/pow.rs `shared_test_vector`: token 41 × 0x11, file hash 32 × 0x22.
        let token = URL_SAFE_NO_PAD.encode([0x11u8; 41]);
        assert_eq!(solve(&token, &[0x22; 32], 12).unwrap(), 449);
    }

    #[test]
    fn polls_slower_further_back_in_the_queue() {
        assert_eq!(poll_interval(None), Duration::from_secs(2));
        assert_eq!(poll_interval(Some(1)), Duration::from_secs(2));
        assert_eq!(poll_interval(Some(12)), Duration::from_secs(12));
        assert_eq!(poll_interval(Some(400)), Duration::from_secs(30));
    }

    #[test]
    fn sizes_and_durations() {
        assert_eq!(fmt_size(512), "512 B");
        assert_eq!(fmt_size(3 * 1024 * 1024 / 2), "1.5 MiB");
        assert_eq!(fmt_duration(Duration::from_secs(75)), "1m15s");
    }
}
