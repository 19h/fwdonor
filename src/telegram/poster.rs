//! Sequential poster: sends each verified job to the group as a document
//! with a metadata caption, records it, then deletes the spooled file (the
//! copy in the firmware store stays and is told where it was posted).
//!
//! It also edits the captions of posts whose file was classified anew
//! (src/reclassify.rs). Posts and edits share one pace; new donations go
//! first, but while both are waiting every fifth turn is an edit.
//!
//! Web donations come before background ones (fwdonate's, src/jobs.rs),
//! which are posted from the store's copy with the record's current
//! classification. On shutdown the poster finishes the post it is sending
//! and stops; a job it was only waiting on is posted after the restart.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use super::caption;
use super::client::{TdClient, TdError};
use crate::analyze::Summary;
use crate::firmwares::{Edit, Firmwares, Posted};
use crate::jobs::{Job, Next, PostQueue, Queued};
use crate::ledger::{Entry, Ledger};
use crate::uploads::{unix_now, UploadState, Uploads};

const MAX_ATTEMPTS: u32 = 5;
/// Bots get roughly 20 messages a minute per group; stay well below.
const MIN_INTERVAL: Duration = Duration::from_secs(3);
/// How long to wait before retrying when the bot cannot write to the chat.
const CHAT_RETRY: Duration = Duration::from_secs(60);
/// While posts and edits are both waiting, an edit after this many posts.
const POSTS_PER_EDIT: u32 = 4;
/// Tries per edit in one run (transient errors); then the next start.
const EDIT_ATTEMPTS: u32 = 3;
/// Failed posts of a background job (each after MAX_ATTEMPTS sends) before
/// it is given up; it goes back to the end of its donor's turn in between.
const BACKGROUND_ATTEMPTS: u32 = 3;
const EDIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Errors about the chat rather than the file: retrying another file would
/// fail the same way, so the job must be kept, never discarded.
fn chat_level(err: &TdError) -> bool {
    let m = err.message.to_ascii_lowercase();
    err.code == 403
        || [
            "write access",
            "not enough rights",
            "chat_write_forbidden",
            "chat not found",
            "kicked",
            "channel_private",
            "chat_restricted",
            "banned",
        ]
        .iter()
        .any(|p| m.contains(p))
}

/// Primary ISA first, then the other ISAs found in slices, once each.
fn distinct_isas(s: &Summary) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for isa in s.isa.iter().chain(s.slices.iter().filter_map(|sl| sl.isa.as_ref())) {
        if !out.contains(isa) {
            out.push(isa.clone());
        }
    }
    out
}

/// Posts whose caption should be edited (by sha256), once each, and what
/// came of the edits so far.
#[derive(Default)]
pub struct EditQueue {
    queue: Mutex<(VecDeque<String>, HashSet<String>)>,
    notify: Notify,
    edited: AtomicUsize,
    already: AtomicUsize,
    refused: AtomicUsize,
    retry_later: AtomicUsize,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct EditCounts {
    pub pending: usize,
    /// Captions changed.
    pub edited: usize,
    /// The post already showed the caption.
    pub already: usize,
    /// Telegram won't let them be edited (or the post is gone).
    pub refused: usize,
    /// Kept failing; tried again at the next start.
    pub retry_later: usize,
}

impl EditQueue {
    pub fn push(&self, sha256: String) {
        let mut q = self.queue.lock().unwrap();
        if q.1.insert(sha256.clone()) {
            q.0.push_back(sha256);
            drop(q);
            self.notify.notify_one();
        }
    }

    fn push_front(&self, sha256: String) {
        let mut q = self.queue.lock().unwrap();
        if q.1.insert(sha256.clone()) {
            q.0.push_front(sha256);
        }
    }

    pub(crate) fn pop(&self) -> Option<String> {
        let mut q = self.queue.lock().unwrap();
        let sha = q.0.pop_front()?;
        q.1.remove(&sha);
        Some(sha)
    }

    async fn next(&self) -> String {
        loop {
            if let Some(sha) = self.pop() {
                return sha;
            }
            self.notify.notified().await;
        }
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().0.len()
    }

    pub fn counts(&self) -> EditCounts {
        EditCounts {
            pending: self.len(),
            edited: self.edited.load(Ordering::Relaxed),
            already: self.already.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            retry_later: self.retry_later.load(Ordering::Relaxed),
        }
    }
}

/// What came of one edit.
enum Edited {
    /// Done, or nothing to do. `used_telegram`: it counts towards the pace.
    Done { used_telegram: bool },
    /// Flood wait or the chat refusing the bot: no edits for this long.
    Pause(Duration),
    /// A transient error: try again later in this run.
    Again,
}

enum Work {
    Post(Next),
    Edit(String),
}

enum PostError {
    Failed(String),
    /// The service is stopping: the job stays queued for the restart.
    Stopping,
}

pub struct Poster {
    pub client: Option<Arc<TdClient>>,
    pub chat_id: i64,
    pub queue: Arc<PostQueue>,
    pub uploads: Arc<Uploads>,
    pub ledger: Arc<Ledger>,
    pub firmwares: Arc<Firmwares>,
    pub edits: Arc<EditQueue>,
    /// True once the service is stopping.
    pub stop: watch::Receiver<bool>,
}

impl Poster {
    pub async fn run(mut self) {
        let mut posts_in_a_row = 0;
        let mut edits_from = Instant::now();
        let mut attempts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut stop = self.stop.clone();
        loop {
            let edits_ready = Instant::now() >= edits_from;
            let turn = (posts_in_a_row >= POSTS_PER_EDIT && edits_ready).then(|| self.edits.pop()).flatten();
            let work = match turn {
                Some(sha) => Work::Edit(sha),
                None => tokio::select! {
                    biased;
                    _ = stop.wait_for(|s| *s) => return,
                    next = self.queue.next() => Work::Post(next),
                    sha = self.edits.next(), if edits_ready => Work::Edit(sha),
                    _ = tokio::time::sleep_until(edits_from), if !edits_ready => continue,
                },
            };
            if self.stopping() {
                // Taken just now: still queued on disk, posted after the restart.
                return;
            }
            let started = Instant::now();
            match work {
                Work::Post(next) => {
                    let (job, background) = match next {
                        Next::Web(job) => (job, None),
                        Next::Background(queued) => match self.ready(queued.clone()).await {
                            Some(job) => (job, Some(queued)),
                            None => continue,
                        },
                    };
                    posts_in_a_row += 1;
                    if !self.post_job(job, background).await || !self.pause_until(started + MIN_INTERVAL).await {
                        return;
                    }
                }
                Work::Edit(sha) => {
                    posts_in_a_row = 0;
                    match self.edit(&sha).await {
                        Edited::Done { used_telegram } => {
                            attempts.remove(&sha);
                            if used_telegram && !self.pause_until(started + MIN_INTERVAL).await {
                                return;
                            }
                        }
                        Edited::Pause(wait) => {
                            edits_from = Instant::now() + wait;
                            self.edits.push_front(sha);
                        }
                        Edited::Again => {
                            let n = attempts.entry(sha.clone()).or_default();
                            *n += 1;
                            if *n < EDIT_ATTEMPTS {
                                self.edits.push(sha);
                            } else {
                                attempts.remove(&sha);
                                self.edits.retry_later.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(sha256 = %sha, "editing the post keeps failing; trying again at the next start");
                            }
                            if !self.pause_until(started + MIN_INTERVAL * 2).await {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    /// Wait until `at`, or less when the service stops. False: stopping.
    async fn pause_until(&self, at: Instant) -> bool {
        let mut stop = self.stop.clone();
        tokio::select! {
            biased;
            _ = stop.wait_for(|s| *s) => false,
            _ = tokio::time::sleep_until(at) => true,
        }
    }

    /// A background job as a post: staged from the store under its name,
    /// with the record's current classification. None: nothing to post (it
    /// was posted already, or the stored copy is gone).
    async fn ready(&self, queued: Queued) -> Option<Job> {
        let (uploads, firmwares, ledger, q) =
            (self.uploads.clone(), self.firmwares.clone(), self.ledger.clone(), queued.clone());
        let staged = tokio::task::spawn_blocking(move || -> Result<Job, String> {
            if ledger.contains(&q.sha256) {
                return Err("it is posted already".into());
            }
            let record = firmwares.record(&q.sha256).map_err(|e| format!("reading its record failed: {e}"))?;
            let summary = record.and_then(|r| r.zrax).ok_or("its record is gone")?;
            let file = firmwares.stage(&q.sha256, &q.id, &q.name).map_err(|e| format!("staging the stored copy failed: {e}"))?;
            let job = Job {
                id: q.id,
                name: q.name,
                size: q.size,
                sha256: q.sha256,
                username: q.username,
                summary,
                file,
                created_at: q.created_at,
            };
            uploads.begin_posting(&job);
            Ok(job)
        })
        .await
        .unwrap_or_else(|e| Err(format!("panicked: {e}")));
        match staged {
            Ok(job) => {
                self.queue.release(&job.id);
                Some(job)
            }
            Err(why) => {
                tracing::warn!(id = %queued.id, sha256 = %queued.sha256, "dropping a background job: {why}");
                let (uploads, id) = (self.uploads.clone(), queued.id);
                let _ = tokio::task::spawn_blocking(move || uploads.drop_background(&id)).await;
                None
            }
        }
    }

    /// False: the service is stopping (the job stays queued on disk).
    async fn post_job(&mut self, job: Job, background: Option<Queued>) -> bool {
        self.uploads.set_state(&job.id, UploadState::Posting);
        match self.post(&job).await {
            Ok(message_id) => {
                let entry = Entry {
                    sha256: job.sha256.clone(),
                    name: job.name.clone(),
                    size: job.size,
                    username: job.username.clone(),
                    format: job.summary.format.clone(),
                    isa: job.summary.isa.clone(),
                    isas: distinct_isas(&job.summary),
                    message_id,
                    posted_at: unix_now(),
                };
                if let Err(e) = self.ledger.record(&entry) {
                    tracing::error!(id = %job.id, "ledger write failed: {e:#}");
                }
                self.firmwares.catalog().posted(&entry, self.chat_id);
                let mut posted = Posted::new(self.chat_id, message_id, entry.posted_at);
                posted.shows = Some(caption::job_key(&job));
                let (store, sha) = (self.firmwares.clone(), job.sha256.clone());
                match tokio::task::spawn_blocking(move || store.mark_posted(&sha, posted)).await {
                    Ok(Ok(Some(false))) => {}
                    // Classified anew while it waited (a zrax update).
                    Ok(Ok(Some(true))) => self.edits.push(job.sha256.clone()),
                    Ok(Ok(None)) => tracing::warn!(id = %job.id, "posted, but no copy of it is kept"),
                    Ok(Err(e)) => tracing::error!(id = %job.id, "noting the post in the firmware record failed: {e}"),
                    Err(e) => tracing::error!(id = %job.id, "noting the post panicked: {e}"),
                }
                tracing::info!(id = %job.id, name = %job.name, message_id, background = background.is_some(), "posted");
                self.uploads.finish(&job.id, UploadState::Posted);
            }
            Err(PostError::Stopping) => {
                tracing::info!(id = %job.id, "stopping before it was posted; posting it after the restart");
                return false;
            }
            Err(PostError::Failed(reason)) => match background.filter(|q| q.attempts + 1 < BACKGROUND_ATTEMPTS) {
                Some(queued) => {
                    tracing::warn!(id = %job.id, name = %job.name, %reason, "posting failed; trying again after the others");
                    let uploads = self.uploads.clone();
                    let requeued = tokio::task::spawn_blocking(move || uploads.requeue_background(queued)).await;
                    if !matches!(requeued, Ok(Ok(()))) {
                        tracing::error!(id = %job.id, "queueing it again failed, discarding");
                        self.uploads.finish(&job.id, UploadState::Failed { reason });
                    }
                }
                None => {
                    tracing::error!(id = %job.id, name = %job.name, %reason, "posting failed, discarding");
                    self.uploads.finish(&job.id, UploadState::Failed { reason });
                }
            },
        }
        true
    }

    async fn post(&mut self, job: &Job) -> Result<i64, PostError> {
        let caption = caption::for_job(job);
        let Some(client) = &self.client else {
            tracing::info!(id = %job.id, "dry run, would post {}:\n{}", job.file.display(), caption.text);
            tokio::time::sleep(Duration::from_millis(500)).await;
            return Ok(0);
        };
        if !job.file.exists() {
            return Err(PostError::Failed("spooled file vanished".into()));
        }
        let request = |chat_id: i64| json!({
            "@type": "sendMessage",
            "chat_id": chat_id,
            "input_message_content": {
                "@type": "inputMessageDocument",
                "document": {
                    "@type": "inputDocument",
                    "document": {"@type": "inputFileLocal", "path": job.file},
                    "disable_content_type_detection": true,
                },
                "caption": caption.to_formatted_text(),
            },
        });
        let confirm_timeout = Duration::from_secs(120 + 10 * job.size.div_ceil(1 << 20));
        let mut failures = 0;
        loop {
            let err = match self.send_once(client, &request(self.chat_id), confirm_timeout).await {
                Ok(id) => return Ok(id),
                Err(e) => e,
            };
            if chat_level(&err) {
                if let Some(new) = client.follow_upgrade(self.chat_id).await {
                    tracing::warn!(
                        "chat {} was upgraded to a supergroup; posting to {new} from now on. Set telegram.chat_id = {new} in fwdonor.toml",
                        self.chat_id
                    );
                    self.chat_id = new;
                    continue;
                }
                tracing::error!(id = %job.id, "cannot post to chat {} ({err}); holding the queue, retrying in {CHAT_RETRY:?}", self.chat_id);
                if !self.pause_until(Instant::now() + CHAT_RETRY).await {
                    return Err(PostError::Stopping);
                }
                continue;
            }
            // Flood waits are Telegram pacing us, not failures.
            if let Some(wait) = err.retry_after() {
                tracing::warn!(id = %job.id, "flood wait {wait}s");
                if !self.pause_until(Instant::now() + Duration::from_secs(wait + 1)).await {
                    return Err(PostError::Stopping);
                }
                continue;
            }
            failures += 1;
            if failures >= MAX_ATTEMPTS {
                return Err(PostError::Failed(format!("telegram: {}", err.message)));
            }
            let backoff = Duration::from_secs(5 * 2u64.pow(failures));
            tracing::warn!(id = %job.id, failures, "send failed ({err}), retrying in {backoff:?}");
            if !self.pause_until(Instant::now() + backoff).await {
                return Err(PostError::Stopping);
            }
        }
    }

    async fn send_once(&self, client: &TdClient, request: &Value, timeout: Duration) -> Result<i64, TdError> {
        let message = client.request(request.clone()).await?;
        let temp_id = message["id"].as_i64().unwrap_or(0);
        if message["sending_state"].is_null() {
            return Ok(temp_id);
        }
        match client.wait_sent(self.chat_id, temp_id, timeout).await {
            Ok(sent) => Ok(sent["id"].as_i64().unwrap_or(temp_id)),
            Err(e) => {
                if e.code == -2 {
                    // Never leave a half-sent copy behind before retrying.
                    let _ = client
                        .request(json!({"@type": "deleteMessages", "chat_id": self.chat_id, "message_ids": [temp_id], "revoke": true}))
                        .await;
                }
                Err(e)
            }
        }
    }

    async fn note(&self, sha: &str, message_id: i64, edit: Edit) {
        let counter = match &edit {
            Edit::Shows(_) => None,
            Edit::Refused(reason) => {
                tracing::info!(sha256 = %sha, message_id, %reason, "the post can't be edited");
                Some(&self.edits.refused)
            }
        };
        if let Some(c) = counter {
            c.fetch_add(1, Ordering::Relaxed);
        }
        let (store, sha) = (self.firmwares.clone(), sha.to_string());
        match tokio::task::spawn_blocking(move || store.note_edit(&sha, message_id, edit)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("noting the edit in the firmware record failed: {e}"),
            Err(e) => tracing::error!("noting the edit panicked: {e}"),
        }
    }

    /// Bring the caption of `sha256`'s post up to date with its record.
    async fn edit(&self, sha: &str) -> Edited {
        let record = {
            let (store, owned) = (self.firmwares.clone(), sha.to_string());
            match tokio::task::spawn_blocking(move || store.record(&owned)).await {
                Ok(Ok(Some(r))) => r,
                Ok(Ok(None)) => return Edited::Done { used_telegram: false },
                Ok(Err(e)) => {
                    tracing::error!(sha256 = %sha, "reading the record failed: {e}");
                    return Edited::Done { used_telegram: false };
                }
                Err(_) => return Edited::Done { used_telegram: false },
            }
        };
        let (Some(post), true) = (record.telegram.clone(), record.post_stale()) else {
            return Edited::Done { used_telegram: false };
        };
        let (Some(caption), Some(key)) = (caption::for_record(&record), caption::record_key(&record)) else {
            return Edited::Done { used_telegram: false };
        };
        if !post.editable() {
            self.note(sha, post.message_id, Edit::Refused("posted before the group became a supergroup, so it can't be edited".into()))
                .await;
            return Edited::Done { used_telegram: false };
        }
        let Some(client) = &self.client else {
            tracing::info!(sha256 = %sha, "dry run, would edit {}/{}:\n{}", post.chat_id, post.message_id, caption.text);
            self.edits.edited.fetch_add(1, Ordering::Relaxed);
            self.note(sha, post.message_id, Edit::Shows(key)).await;
            return Edited::Done { used_telegram: false };
        };
        let (chat, id) = (post.chat_id, post.message_id);
        let message = match client.request_timeout(json!({"@type": "getMessage", "chat_id": chat, "message_id": id}), EDIT_TIMEOUT).await {
            Ok(m) => m,
            Err(e) => return self.edit_failed(sha, id, "fetching the post", &e).await,
        };
        let shown = message["content"]["caption"]["text"].as_str().unwrap_or("");
        if message["content"]["@type"] != "messageDocument" || !shown.contains(sha) {
            self.note(sha, id, Edit::Refused("the message is not this file's post".into())).await;
            return Edited::Done { used_telegram: true };
        }
        if shown == caption.text {
            self.edits.already.fetch_add(1, Ordering::Relaxed);
            self.note(sha, id, Edit::Shows(key)).await;
            return Edited::Done { used_telegram: true };
        }
        match client.request_timeout(json!({"@type": "getMessageProperties", "chat_id": chat, "message_id": id}), EDIT_TIMEOUT).await {
            Ok(p) if p["can_be_edited"] == false => {
                self.note(sha, id, Edit::Refused("Telegram doesn't allow editing it".into())).await;
                return Edited::Done { used_telegram: true };
            }
            Ok(_) => {}
            Err(e) => return self.edit_failed(sha, id, "checking the post", &e).await,
        }
        let request = json!({
            "@type": "editMessageCaption",
            "chat_id": chat,
            "message_id": id,
            "caption": caption.to_formatted_text(),
        });
        match client.request_timeout(request, EDIT_TIMEOUT).await {
            Ok(_) => {}
            Err(e) if e.message.contains("MESSAGE_NOT_MODIFIED") => {}
            Err(e) => return self.edit_failed(sha, id, "editing the post", &e).await,
        }
        tracing::info!(sha256 = %sha, message_id = id, "edited the caption");
        self.edits.edited.fetch_add(1, Ordering::Relaxed);
        self.note(sha, id, Edit::Shows(key)).await;
        Edited::Done { used_telegram: true }
    }

    async fn edit_failed(&self, sha: &str, message_id: i64, what: &str, e: &TdError) -> Edited {
        match edit_error(e) {
            EditError::Chat => {
                tracing::warn!(sha256 = %sha, "{what}: {e}; no edits for {CHAT_RETRY:?}");
                Edited::Pause(CHAT_RETRY)
            }
            EditError::Flood(wait) => {
                tracing::info!(sha256 = %sha, "flood wait {wait}s while {what}; posts continue");
                Edited::Pause(Duration::from_secs(wait + 1))
            }
            EditError::Final => {
                self.note(sha, message_id, Edit::Refused(format!("{what}: {}", e.message))).await;
                Edited::Done { used_telegram: true }
            }
            EditError::Transient => {
                tracing::warn!(sha256 = %sha, "{what}: {e}");
                Edited::Again
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum EditError {
    /// The bot can't act in the chat now (no rights, kicked): pause.
    Chat,
    Flood(u64),
    /// The post is gone or can't be edited: don't try again.
    Final,
    Transient,
}

fn edit_error(e: &TdError) -> EditError {
    if chat_level(e) {
        EditError::Chat
    } else if let Some(wait) = e.retry_after() {
        EditError::Flood(wait)
    } else if matches!(e.code, 400 | 404) {
        EditError::Final
    } else {
        EditError::Transient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_level_errors_are_recognized() {
        let e = |code, message: &str| TdError { code, message: message.into() };
        assert!(chat_level(&e(400, "Have no write access to the chat")));
        assert!(chat_level(&e(400, "Not enough rights to send documents to the chat")));
        assert!(chat_level(&e(403, "Forbidden: bot was kicked from the group chat")));
        assert!(!chat_level(&e(400, "FILE_PARTS_INVALID")));
        assert!(!chat_level(&e(-2, "upload confirmation timed out")));
    }

    #[test]
    fn edit_errors_are_sorted() {
        let e = |code, message: &str| edit_error(&TdError { code, message: message.into() });
        assert_eq!(e(404, "Message not found"), EditError::Final);
        assert_eq!(e(400, "Message can't be edited"), EditError::Final);
        assert_eq!(e(403, "Forbidden: bot is not a member of the supergroup chat"), EditError::Chat);
        assert_eq!(e(400, "Not enough rights to edit messages in the chat"), EditError::Chat);
        assert_eq!(e(429, "Too Many Requests: retry after 17"), EditError::Flood(17));
        assert_eq!(e(-2, "TDLib request timed out"), EditError::Transient);
        assert_eq!(e(500, "Internal Server Error"), EditError::Transient);
    }

    #[test]
    fn the_edit_queue_holds_each_post_once() {
        let q = EditQueue::default();
        q.push("a".into());
        q.push("b".into());
        q.push("a".into());
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop().as_deref(), Some("a"));
        q.push_front("c".into());
        assert_eq!(q.pop().as_deref(), Some("c"));
        assert_eq!(q.pop().as_deref(), Some("b"));
        assert_eq!(q.pop(), None);
        q.push("a".into());
        assert_eq!(q.len(), 1, "popped posts can be queued again");
    }
}
