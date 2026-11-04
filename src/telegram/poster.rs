//! Sequential poster: sends each verified job to the group as a document
//! with a metadata caption, records it, then deletes the spooled file (the
//! copy in the firmware store stays and is told where it was posted).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::client::{TdClient, TdError};
use crate::analyze::Summary;
use crate::firmwares::{Firmwares, Posted};
use crate::jobs::{Job, PostQueue};
use crate::ledger::{Entry, Ledger};
use crate::uploads::{unix_now, UploadState, Uploads};

const CAPTION_MAX: usize = 1024;
const MAX_ATTEMPTS: u32 = 5;
/// Bots get roughly 20 messages a minute per group; stay well below.
const MIN_INTERVAL: Duration = Duration::from_secs(3);
/// How long to wait before retrying when the bot cannot write to the chat.
const CHAT_RETRY: Duration = Duration::from_secs(60);

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

pub struct Caption {
    pub text: String,
    /// (utf16 offset, utf16 length) of code spans.
    pub code: Vec<(usize, usize)>,
}

impl Caption {
    pub fn to_formatted_text(&self) -> Value {
        let entities: Vec<Value> = self
            .code
            .iter()
            .map(|(offset, length)| {
                json!({"@type": "textEntity", "offset": offset, "length": length, "type": {"@type": "textEntityTypeCode"}})
            })
            .collect();
        json!({"@type": "formattedText", "text": self.text, "entities": entities})
    }
}

struct Builder {
    text: String,
    code: Vec<(usize, usize)>,
}

impl Builder {
    fn utf16_len(&self) -> usize {
        self.text.encode_utf16().count()
    }
    fn push(&mut self, s: &str) {
        self.text.push_str(s);
    }
    fn code(&mut self, s: &str) {
        let offset = self.utf16_len();
        let length = s.encode_utf16().count();
        self.text.push_str(s);
        if length > 0 {
            self.code.push((offset, length));
        }
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
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

fn hashtag(raw: &str) -> Option<String> {
    let tag: String = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    (!tag.is_empty() && !tag.chars().all(|c| c.is_ascii_digit())).then(|| format!("#{tag}"))
}

/// zrax sometimes reports a Rust debug rendering or the format name itself as
/// the variant; neither adds anything to the post.
pub fn clean_variant<'a>(variant: &'a str, format_name: &str) -> Option<&'a str> {
    let v = variant.trim();
    (!v.is_empty() && !v.contains('{') && !v.eq_ignore_ascii_case(format_name)).then_some(v)
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

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Build the post caption. Optional lines (slices, metadata) are shortened
/// first so the essentials always fit within 1024 code points.
pub fn build_caption(job: &Job) -> Caption {
    let s: &Summary = &job.summary;
    let name = truncate_chars(&job.name, 160);

    let classification = match (&s.isa_name, s.basis.as_str()) {
        (Some(isa), _) => {
            let mut line = isa.clone();
            if s.bitwidth > 0 {
                line.push_str(&format!(" · {}-bit", s.bitwidth));
            }
            if !s.endianness.is_empty() {
                line.push_str(&format!(" {}", s.endianness));
            }
            line.push_str(&format!(" · {:.1}% ({})", s.confidence * 100.0, s.source.replace('_', " ")));
            line
        }
        _ => "firmware container, no ISA resolved".to_string(),
    };
    let mut format_line = s.format_name.clone();
    if let Some(variant) = s.format_variant.as_deref().and_then(|v| clean_variant(v, &s.format_name)) {
        format_line.push_str(&format!(" ({variant})"));
    }
    if let Some(variant) = s.variant.as_deref().filter(|v| !v.is_empty()) {
        format_line.push_str(&format!(" · {variant}"));
    }

    let tags: Vec<String> = [s.isa_tag.as_deref(), Some(s.format.as_str())]
        .into_iter()
        .flatten()
        .filter_map(hashtag)
        .chain(std::iter::once("#fwdonor".to_string()))
        .collect();
    let footer = format!("zrax {}  {}", s.zrax, tags.join(" "));

    let slices: Vec<String> = s
        .slices
        .iter()
        .map(|sl| {
            let isa = sl.isa_name.as_deref().unwrap_or("?");
            match sl.label.as_deref().filter(|l| !l.is_empty()) {
                Some(label) => format!("{label}: {isa}"),
                None => isa.to_string(),
            }
        })
        .collect();
    let meta: Vec<String> = s.metadata.iter().map(|m| format!("{} {}", m.label, m.value)).collect();

    let build = |budget: usize| -> Caption {
        let mut b = Builder { text: String::new(), code: Vec::new() };
        b.push("📦 ");
        b.code(&name);
        b.push("\ndonated by ");
        b.code(&job.username);
        b.push(&format!("\n{format_line}\n{classification}\n{} · sha256 ", human_size(job.size)));
        b.code(&job.sha256);
        let optional = [("slices", &slices), ("meta", &meta)];
        for (label, items) in optional {
            if items.is_empty() || budget == 0 {
                continue;
            }
            let line = truncate_chars(&format!("{label}: {}", items.join(", ")), budget);
            b.push(&format!("\n{line}"));
        }
        b.push(&format!("\n{footer}"));
        Caption { text: b.text, code: b.code }
    };

    let mut budget = 400;
    loop {
        let caption = build(budget);
        if caption.text.chars().count() <= CAPTION_MAX || budget == 0 {
            return caption;
        }
        budget = budget.saturating_sub(50);
    }
}

pub struct Poster {
    pub client: Option<Arc<TdClient>>,
    pub chat_id: i64,
    pub queue: Arc<PostQueue>,
    pub uploads: Arc<Uploads>,
    pub ledger: Arc<Ledger>,
    pub firmwares: Arc<Firmwares>,
}

impl Poster {
    pub async fn run(mut self) {
        loop {
            let job = self.queue.next().await;
            self.uploads.set_state(&job.id, UploadState::Posting);
            let started = tokio::time::Instant::now();
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
                    let posted = Posted { chat_id: self.chat_id, message_id, posted_at: entry.posted_at };
                    let (store, sha) = (self.firmwares.clone(), job.sha256.clone());
                    match tokio::task::spawn_blocking(move || store.mark_posted(&sha, posted)).await {
                        Ok(Ok(true)) => {}
                        Ok(Ok(false)) => tracing::warn!(id = %job.id, "posted, but no copy of it is kept"),
                        Ok(Err(e)) => tracing::error!(id = %job.id, "noting the post in the firmware record failed: {e}"),
                        Err(e) => tracing::error!(id = %job.id, "noting the post panicked: {e}"),
                    }
                    tracing::info!(id = %job.id, name = %job.name, message_id, "posted");
                    self.uploads.finish(&job.id, UploadState::Posted);
                }
                Err(reason) => {
                    tracing::error!(id = %job.id, name = %job.name, %reason, "posting failed, discarding");
                    self.uploads.finish(&job.id, UploadState::Failed { reason });
                }
            }
            tokio::time::sleep_until(started + MIN_INTERVAL).await;
        }
    }

    async fn post(&mut self, job: &Job) -> Result<i64, String> {
        let caption = build_caption(job);
        let Some(client) = &self.client else {
            tracing::info!(id = %job.id, "dry run, would post {}:\n{}", job.file.display(), caption.text);
            tokio::time::sleep(Duration::from_millis(500)).await;
            return Ok(0);
        };
        if !job.file.exists() {
            return Err("spooled file vanished".into());
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
                tokio::time::sleep(CHAT_RETRY).await;
                continue;
            }
            // Flood waits are Telegram pacing us, not failures.
            if let Some(wait) = err.retry_after() {
                tracing::warn!(id = %job.id, "flood wait {wait}s");
                tokio::time::sleep(Duration::from_secs(wait + 1)).await;
                continue;
            }
            failures += 1;
            if failures >= MAX_ATTEMPTS {
                return Err(format!("telegram: {}", err.message));
            }
            let backoff = Duration::from_secs(5 * 2u64.pow(failures));
            tracing::warn!(id = %job.id, failures, "send failed ({err}), retrying in {backoff:?}");
            tokio::time::sleep(backoff).await;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{MetaSummary, SliceSummary};

    #[test]
    fn chat_level_errors_are_recognized() {
        let e = |code, message: &str| TdError { code, message: message.into() };
        assert!(chat_level(&e(400, "Have no write access to the chat")));
        assert!(chat_level(&e(400, "Not enough rights to send documents to the chat")));
        assert!(chat_level(&e(403, "Forbidden: bot was kicked from the group chat")));
        assert!(!chat_level(&e(400, "FILE_PARTS_INVALID")));
        assert!(!chat_level(&e(-2, "upload confirmation timed out")));
    }

    fn job(name: &str, slices: usize) -> Job {
        Job {
            id: "00".repeat(12),
            name: name.into(),
            size: 5 * 1024 * 1024 + 123,
            sha256: "ab".repeat(32),
            username: "donor_1".into(),
            summary: Summary {
                format: "uimage".into(),
                format_name: "U-Boot uImage".into(),
                format_variant: Some("kernel".into()),
                isa: Some("arm".into()),
                isa_name: Some("ARM (32-bit)".into()),
                isa_tag: Some("arm".into()),
                bitwidth: 32,
                endianness: "little".into(),
                confidence: 0.973,
                source: "file_format".into(),
                variant: None,
                slices: (0..slices)
                    .map(|i| SliceSummary {
                        label: Some(format!("member-{i}-with-a-long-name")),
                        isa: Some("arm".into()),
                        isa_name: Some("ARM (32-bit)".into()),
                        bitwidth: 32,
                        offset: 0,
                        size: 0,
                    })
                    .collect(),
                metadata: vec![MetaSummary { label: "Entry point".into(), value: "0x8000".into() }],
                basis: "isa".into(),
                zrax: "0.1.0@d3f4a7a".into(),
            },
            file: "/tmp/x".into(),
            created_at: 0,
        }
    }

    #[test]
    fn caption_has_code_entities_at_utf16_offsets() {
        let c = build_caption(&job("rüter 🛜.bin", 2));
        let utf16: Vec<u16> = c.text.encode_utf16().collect();
        let spans: Vec<String> =
            c.code.iter().map(|(o, l)| String::from_utf16(&utf16[*o..*o + *l]).unwrap()).collect();
        assert_eq!(spans, vec!["rüter 🛜.bin".to_string(), "donor_1".into(), "ab".repeat(32)]);
        assert!(c.text.contains("#arm #uimage #fwdonor"), "{}", c.text);
        assert!(c.text.contains("5.0 MiB"));
    }

    #[test]
    fn caption_fits_limit() {
        let c = build_caption(&job(&"😀".repeat(200), 400));
        assert!(c.text.chars().count() <= CAPTION_MAX, "{}", c.text.chars().count());
        assert!(c.text.contains("sha256"));
        assert!(c.text.ends_with("#fwdonor"));
    }
}
