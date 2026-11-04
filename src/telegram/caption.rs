//! Post captions, built from a donation or from a store record, and the
//! caption key: a hash of what a caption says about the file, leaving out the
//! confidence and the zrax version. A post is edited only when the key of
//! what it shows differs from the key of what the record says now.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::analyze::Summary;
use crate::firmwares::Record;
use crate::jobs::Job;

pub const CAPTION_MAX: usize = 1024;

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

/// The file a caption is about.
pub struct Subject<'a> {
    /// The file name the donor gave.
    pub name: &'a str,
    /// The donor name the post credits.
    pub donor: &'a str,
    pub size: u64,
    pub sha256: &'a str,
}

impl<'a> Subject<'a> {
    pub fn of_job(job: &'a Job) -> Self {
        Self { name: &job.name, donor: &job.username, size: job.size, sha256: &job.sha256 }
    }

    pub fn of_record(r: &'a Record) -> Self {
        Self { name: &r.original_name, donor: &r.name, size: r.size, sha256: &r.sha256 }
    }
}

/// What a post says about a file.
pub enum State<'a> {
    Classified(&'a Summary),
    /// The current zrax no longer accepts it; `earlier` is what one before it found.
    Unclassified { earlier: Option<&'a Summary>, zrax: &'a str, reason: &'a str },
}

impl<'a> State<'a> {
    /// What the post of a record should show; None when there is nothing to
    /// say (the image was never classified, e.g. recovered from the group
    /// while zrax failed on it).
    pub fn of_record(r: &'a Record) -> Option<Self> {
        match (&r.unclassified, &r.zrax) {
            (Some(u), earlier) => Some(State::Unclassified {
                earlier: earlier.as_ref(),
                zrax: r.checked.as_ref().map_or(u.zrax.as_str(), |c| c.zrax.as_str()),
                reason: &u.reason,
            }),
            (None, Some(z)) => Some(State::Classified(z)),
            (None, None) => None,
        }
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

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// "U-Boot uImage (kernel) · variant".
fn format_line(s: &Summary) -> String {
    let mut line = s.format_name.clone();
    if let Some(variant) = s.format_variant.as_deref().and_then(|v| clean_variant(v, &s.format_name)) {
        line.push_str(&format!(" ({variant})"));
    }
    if let Some(variant) = s.variant.as_deref().filter(|v| !v.is_empty()) {
        line.push_str(&format!(" · {variant}"));
    }
    line
}

/// "ARM (32-bit) · 32-bit little · 97.3% (file format)".
fn classification_line(s: &Summary) -> String {
    match &s.isa_name {
        Some(isa) => {
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
        None => "firmware container, no ISA resolved".to_string(),
    }
}

/// Build the caption. Optional lines (slices, metadata, the earlier
/// classification) are shortened first so the essentials always fit within
/// 1024 code points.
pub fn build(subject: &Subject, state: &State) -> Caption {
    let name = truncate_chars(subject.name, 160);
    let (status_lines, tags, zrax, optional): (String, Vec<String>, &str, Vec<(&str, Vec<String>)>) = match state {
        State::Classified(s) => {
            let tags: Vec<String> =
                [s.isa_tag.as_deref(), Some(s.format.as_str())].into_iter().flatten().filter_map(hashtag).collect();
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
            (format!("{}\n{}", format_line(s), classification_line(s)), tags, s.zrax.as_str(), vec![("slices", slices), ("meta", meta)])
        }
        State::Unclassified { earlier, zrax, reason } => {
            let earlier: Vec<String> =
                earlier.iter().map(|s| format!("{} · {}", format_line(s), classification_line(s))).collect();
            (
                format!("no longer classified by zrax {zrax}: {}", truncate_chars(reason, 200)),
                vec!["#unclassified".to_string()],
                *zrax,
                vec![("earlier", earlier)],
            )
        }
    };
    let footer = {
        let mut tags = tags;
        tags.push("#fwdonor".to_string());
        format!("zrax {zrax}  {}", tags.join(" "))
    };

    let build = |budget: usize| -> Caption {
        let mut b = Builder { text: String::new(), code: Vec::new() };
        b.push("📦 ");
        b.code(&name);
        b.push("\ndonated by ");
        b.code(subject.donor);
        b.push(&format!("\n{status_lines}\n{} · sha256 ", human_size(subject.size)));
        b.code(subject.sha256);
        for (label, items) in &optional {
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

pub fn for_job(job: &Job) -> Caption {
    build(&Subject::of_job(job), &State::Classified(&job.summary))
}

pub fn for_record(r: &Record) -> Option<Caption> {
    Some(build(&Subject::of_record(r), &State::of_record(r)?))
}

/// The caption with the confidence and the zrax version left out.
fn masked(subject: &Subject, state: &State) -> String {
    let strip = |s: &Summary| Summary { confidence: 0.0, zrax: String::new(), ..s.clone() };
    match state {
        State::Classified(s) => build(subject, &State::Classified(&strip(s))).text,
        State::Unclassified { earlier, reason, .. } => {
            let earlier = earlier.map(strip);
            build(subject, &State::Unclassified { earlier: earlier.as_ref(), zrax: "", reason }).text
        }
    }
}

fn key_of(text: &str) -> String {
    hex::encode(&Sha256::digest(text.as_bytes())[..8])
}

pub fn key(subject: &Subject, state: &State) -> String {
    key_of(&masked(subject, state))
}

pub fn job_key(job: &Job) -> String {
    key(&Subject::of_job(job), &State::Classified(&job.summary))
}

/// None: the record has nothing for a post to show.
pub fn record_key(r: &Record) -> Option<String> {
    Some(key(&Subject::of_record(r), &State::of_record(r)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{MetaSummary, SliceSummary};
    use crate::firmwares::{Checked, Unclassified};

    pub(crate) fn summary(slices: usize) -> Summary {
        Summary {
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
        }
    }

    fn job(name: &str, slices: usize) -> Job {
        Job {
            id: "00".repeat(12),
            name: name.into(),
            size: 5 * 1024 * 1024 + 123,
            sha256: "ab".repeat(32),
            username: "donor_1".into(),
            summary: summary(slices),
            file: "/tmp/x".into(),
            created_at: 0,
        }
    }

    fn record(z: Option<Summary>) -> Record {
        Record {
            sha256: "ab".repeat(32),
            size: 5 * 1024 * 1024 + 123,
            name: "donor_1".into(),
            original_name: "rüter 🛜.bin".into(),
            zrax: z,
            unclassified: None,
            checked: None,
            received_at: 0,
            source: "upload".into(),
            telegram: None,
        }
    }

    #[test]
    fn caption_has_code_entities_at_utf16_offsets() {
        let c = for_job(&job("rüter 🛜.bin", 2));
        let utf16: Vec<u16> = c.text.encode_utf16().collect();
        let spans: Vec<String> =
            c.code.iter().map(|(o, l)| String::from_utf16(&utf16[*o..*o + *l]).unwrap()).collect();
        assert_eq!(spans, vec!["rüter 🛜.bin".to_string(), "donor_1".into(), "ab".repeat(32)]);
        assert!(c.text.contains("#arm #uimage #fwdonor"), "{}", c.text);
        assert!(c.text.contains("5.0 MiB"));
    }

    #[test]
    fn caption_fits_limit() {
        let c = for_job(&job(&"😀".repeat(200), 400));
        assert!(c.text.chars().count() <= CAPTION_MAX, "{}", c.text.chars().count());
        assert!(c.text.contains("sha256"));
        assert!(c.text.ends_with("#fwdonor"));
    }

    #[test]
    fn a_record_and_its_job_make_the_same_caption() {
        let j = job("rüter 🛜.bin", 2);
        let r = record(Some(j.summary.clone()));
        assert_eq!(for_record(&r).unwrap().text, for_job(&j).text);
        assert_eq!(record_key(&r).unwrap(), job_key(&j));
    }

    #[test]
    fn the_key_ignores_confidence_and_zrax_version_only() {
        let base = record_key(&record(Some(summary(1)))).unwrap();
        let same = |f: &dyn Fn(&mut Summary)| {
            let mut s = summary(1);
            f(&mut s);
            record_key(&record(Some(s))).unwrap() == base
        };
        assert!(same(&|s| s.confidence = 0.5));
        assert!(same(&|s| s.zrax = "0.1.0@42df78c".into()));
        assert!(!same(&|s| s.bitwidth = 64));
        assert!(!same(&|s| s.format_variant = Some("ramdisk".into())));
        assert!(!same(&|s| s.isa_name = Some("Thumb".into())));
        assert!(!same(&|s| s.slices.clear()));
        assert!(!same(&|s| s.metadata.clear()));
        assert_eq!(record_key(&record(None)), None, "never classified: nothing to show");
    }

    #[test]
    fn unclassified_caption() {
        let mut r = record(Some(summary(400)));
        r.original_name = "😀".repeat(200);
        r.unclassified = Some(Unclassified { zrax: "0.1.0@42df78c".into(), reason: "unrecognized by zrax".into(), since: 1 });
        let c = for_record(&r).unwrap();
        assert!(c.text.chars().count() <= CAPTION_MAX, "{}", c.text.chars().count());
        assert!(c.text.contains("no longer classified by zrax 0.1.0@42df78c: unrecognized by zrax"), "{}", c.text);
        assert!(c.text.contains("earlier: U-Boot uImage (kernel) · ARM (32-bit)"), "{}", c.text);
        assert!(c.text.ends_with("zrax 0.1.0@42df78c  #unclassified #fwdonor"), "{}", c.text);
        assert!(!c.text.contains("#arm"));
        // A later zrax that still rejects it, for the same reason: the post stays.
        let key = record_key(&r).unwrap();
        r.checked = Some(Checked { zrax: "0.1.0@ffffff0".into(), at: 2, error: None });
        assert!(for_record(&r).unwrap().text.contains("zrax 0.1.0@ffffff0  #unclassified"));
        assert_eq!(record_key(&r).unwrap(), key);
        r.unclassified.as_mut().unwrap().reason = "no ISA found in elf".into();
        assert_ne!(record_key(&r).unwrap(), key);
        assert_ne!(key, record_key(&record(Some(summary(400)))).unwrap());
    }
}
