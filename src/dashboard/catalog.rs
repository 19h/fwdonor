//! The dashboard's index: one row per donated image, built from the ledger
//! (`posted.jsonl`, which knows every post) and the firmware store (whose
//! records have everything zrax found). It lives in memory so that filtering,
//! facet counts, the tree, histograms and sorting are one pass over the rows,
//! a few milliseconds even for hundreds of thousands of files.
//!
//! Rows are never removed, so a row's index stays valid (exports walk them in
//! batches without holding the lock).

use std::cmp::Ordering as CmpOrdering;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

use serde_json::{json, Value};

use super::families;
use super::kind::{self, Kind, KINDS};
use crate::analyze::isa_display_name;
use crate::firmwares::Record;
use crate::ledger::Entry;

/// The key of "no value" in every dimension (never a valid name, ISA,
/// format or extension).
pub const NONE: &str = "(none)";

const ORIGINS: [(&str, &str); 3] = [("upload", "uploaded"), ("telegram", "from Telegram"), ("ledger", "ledger only")];
const STATUSES: [(&str, &str); 4] = [
    ("stored", "stored"),
    ("queued", "not posted yet"),
    ("pending", "not in the store yet"),
    ("unrecovered", "recovery failed"),
];
const ORIGIN_UPLOAD: u8 = 0;
const ORIGIN_TELEGRAM: u8 = 1;
const ORIGIN_LEDGER: u8 = 2;

/// Search text kept per row (name, donor, format, ISAs, metadata).
const SEARCH_CAP: usize = 1024;
/// Values listed per facet, children per tree node, matrix rows and columns.
const FACET_CAP: usize = 250;
const TREE_CAP: usize = 400;
const MATRIX_ROWS: usize = 40;
const MATRIX_COLS: usize = 24;
pub const MAX_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dim {
    Isa,
    Family,
    Format,
    Variant,
    Donor,
    Ext,
    Bits,
    Endian,
    Class,
    Basis,
    Origin,
    Status,
    Zrax,
    Kind,
    Month,
    Day,
}

impl Dim {
    pub const FACETS: [Dim; 14] = [
        Dim::Kind,
        Dim::Isa,
        Dim::Family,
        Dim::Format,
        Dim::Variant,
        Dim::Donor,
        Dim::Ext,
        Dim::Bits,
        Dim::Endian,
        Dim::Class,
        Dim::Basis,
        Dim::Origin,
        Dim::Status,
        Dim::Zrax,
    ];
    const ALL: [Dim; 16] = [
        Dim::Isa,
        Dim::Family,
        Dim::Format,
        Dim::Variant,
        Dim::Donor,
        Dim::Ext,
        Dim::Bits,
        Dim::Endian,
        Dim::Class,
        Dim::Basis,
        Dim::Origin,
        Dim::Status,
        Dim::Zrax,
        Dim::Kind,
        Dim::Month,
        Dim::Day,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Dim::Isa => "isa",
            Dim::Family => "family",
            Dim::Format => "format",
            Dim::Variant => "variant",
            Dim::Donor => "donor",
            Dim::Ext => "ext",
            Dim::Bits => "bits",
            Dim::Endian => "endian",
            Dim::Class => "class",
            Dim::Basis => "basis",
            Dim::Origin => "origin",
            Dim::Status => "status",
            Dim::Zrax => "zrax",
            Dim::Kind => "kind",
            Dim::Month => "month",
            Dim::Day => "day",
        }
    }

    pub fn parse(s: &str) -> Option<Dim> {
        Dim::ALL.into_iter().find(|d| d.key() == s)
    }

    fn bit(self) -> u32 {
        1 << self as u32
    }

    fn is_time(self) -> bool {
        matches!(self, Dim::Month | Dim::Day)
    }
}

// Filter groups beyond the dimensions (bits 0..15).
const _: () = assert!((Dim::Day as u32) < 16);
const TEXT: u32 = 1 << 16;
const SIZE: u32 = 1 << 17;
const TIME: u32 = 1 << 18;
const CONF: u32 = 1 << 19;
const MULTI: u32 = 1 << 20;
const SHAS: u32 = 1 << 21;

// ------------------------------------------------------------------ rows

struct Dict {
    keys: Vec<Box<str>>,
    labels: Vec<Box<str>>,
    ids: HashMap<Box<str>, u32>,
}

impl Dict {
    fn new() -> Self {
        Self { keys: vec![NONE.into()], labels: vec!["none".into()], ids: HashMap::from([(NONE.into(), 0)]) }
    }

    fn id(&mut self, key: &str) -> u32 {
        if key.is_empty() {
            return 0;
        }
        if let Some(&id) = self.ids.get(key) {
            return id;
        }
        let id = self.keys.len() as u32;
        self.keys.push(key.into());
        self.labels.push(key.into());
        self.ids.insert(key.into(), id);
        id
    }

    fn find(&self, key: &str) -> Option<u32> {
        self.ids.get(key).copied()
    }

    fn label(&mut self, id: u32, label: &str) {
        if id != 0 && !label.is_empty() {
            self.labels[id as usize] = label.into();
        }
    }
}

struct Row {
    sha: [u8; 32],
    size: u64,
    name: Box<str>,
    /// Lower-case name, donor, format, ISAs, slice labels and metadata.
    search: Box<str>,
    received_at: u64,
    /// 0: not posted (yet).
    posted_at: u64,
    chat_id: i64,
    message_id: i64,
    /// Negative: unknown (ledger-only rows).
    confidence: f32,
    slices: u32,
    isa: u32,
    /// Distinct concrete ISAs, primary first, then those of the slices.
    isas: Box<[u32]>,
    families: Box<[u32]>,
    format: u32,
    variant: u32,
    donor: u32,
    ext: u32,
    endian: u32,
    class: u32,
    basis: u32,
    zrax: u32,
    bits: u8,
    origin: u8,
    /// `Kind as u8`: firmware, or a program, library, object or package.
    kind: u8,
    stored: bool,
    /// Built from a store record (not only from the ledger).
    has_record: bool,
    unrecovered: Option<Box<str>>,
}

impl Row {
    fn status(&self) -> u32 {
        match (self.stored, self.posted_at > 0, self.unrecovered.is_some()) {
            (true, true, _) => 0,
            (true, false, _) => 1,
            (false, _, false) => 2,
            (false, _, true) => 3,
        }
    }
}

fn parse_sha(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str.trim()).ok()?.try_into().ok()
}

/// The extension of an original file name: up to 10 letters or digits.
fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext))
            if !stem.is_empty() && (1..=10).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            ext.to_ascii_lowercase()
        }
        _ => String::new(),
    }
}

fn cap(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Telegram link of a post in a supergroup (`-100…` ids); basic groups have none.
pub fn telegram_url(chat_id: i64, message_id: i64) -> Option<String> {
    if message_id <= 0 || chat_id > -1_000_000_000_000 {
        return None;
    }
    Some(format!("https://t.me/c/{}/{}", -(chat_id + 1_000_000_000_000), message_id >> 20))
}

// Civil dates (Howard Hinnant's algorithms), for the month and day dimensions.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn month_index(unix: u64) -> u32 {
    let (y, m, _) = civil((unix / 86_400) as i64);
    (y * 12 + m as i64 - 1).max(0) as u32
}

fn month_range(index: u32) -> (u64, u64, String) {
    let (y, m) = ((index / 12) as i64, index % 12 + 1);
    let start = days_from_civil(y, m, 1);
    let end = if m == 12 { days_from_civil(y + 1, 1, 1) } else { days_from_civil(y, m + 1, 1) };
    (start as u64 * 86_400, end as u64 * 86_400, format!("{y:04}-{m:02}"))
}

// ------------------------------------------------------------------ index

struct Index {
    rows: Vec<Row>,
    by_sha: HashMap<[u8; 32], u32>,
    isa: Dict,
    family: Dict,
    format: Dict,
    variant: Dict,
    donor: Dict,
    ext: Dict,
    endian: Dict,
    class: Dict,
    basis: Dict,
    zrax: Dict,
    /// Family id of each ISA id.
    isa_family: Vec<u32>,
}

static ZERO: [u32; 1] = [0];

impl Index {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            by_sha: HashMap::new(),
            isa: Dict::new(),
            family: Dict::new(),
            format: Dict::new(),
            variant: Dict::new(),
            donor: Dict::new(),
            ext: Dict::new(),
            endian: Dict::new(),
            class: Dict::new(),
            basis: Dict::new(),
            zrax: Dict::new(),
            isa_family: vec![0],
        }
    }

    fn isa_id(&mut self, key: &str) -> u32 {
        let id = self.isa.id(key);
        if id as usize >= self.isa_family.len() {
            let label = isa_display_name(key).unwrap_or(key).to_string();
            self.isa.label(id, &label);
            let (fkey, flabel) = families::family(key);
            let fid = self.family.id(fkey);
            self.family.label(fid, flabel);
            self.isa_family.push(fid);
        }
        id
    }

    fn isa_set(&mut self, keys: impl IntoIterator<Item = String>) -> (Box<[u32]>, Box<[u32]>) {
        let mut isas: Vec<u32> = Vec::new();
        for key in keys {
            let id = self.isa_id(&key);
            if id != 0 && !isas.contains(&id) {
                isas.push(id);
            }
        }
        let mut fams: Vec<u32> = Vec::new();
        for &id in &isas {
            let f = self.isa_family[id as usize];
            if !fams.contains(&f) {
                fams.push(f);
            }
        }
        (isas.into(), fams.into())
    }

    fn search_text(&self, row: &Row, extra: &[&str]) -> Box<str> {
        let mut s = String::new();
        let mut push = |t: &str| {
            if !t.is_empty() && t != NONE {
                s.push_str(&t.to_lowercase());
                s.push('\n');
            }
        };
        push(&row.name);
        push(&self.donor.keys[row.donor as usize]);
        for (dict, id) in [(&self.format, row.format), (&self.variant, row.variant)] {
            push(&dict.keys[id as usize]);
            push(&dict.labels[id as usize]);
        }
        for &i in row.isas.iter() {
            push(&self.isa.keys[i as usize]);
            push(&self.isa.labels[i as usize]);
        }
        for t in extra {
            push(t);
        }
        cap(s, SEARCH_CAP).into_boxed_str()
    }

    /// A row from a store record; `prev` is what the ledger knew.
    fn row_from_record(&mut self, r: &Record, sha: [u8; 32], prev: Option<&Row>, kind: Kind) -> Row {
        let mut extra: Vec<String> = Vec::new();
        let mut row = Row {
            sha,
            size: r.size,
            name: r.original_name.as_str().into(),
            search: "".into(),
            received_at: r.received_at,
            posted_at: 0,
            chat_id: 0,
            message_id: 0,
            confidence: -1.0,
            slices: 0,
            isa: 0,
            isas: Box::new([]),
            families: Box::new([]),
            format: 0,
            variant: 0,
            donor: self.donor.id(&r.name),
            ext: 0,
            endian: 0,
            class: 0,
            basis: 0,
            zrax: 0,
            bits: 0,
            origin: if r.source == "telegram" { ORIGIN_TELEGRAM } else { ORIGIN_UPLOAD },
            kind: kind as u8,
            stored: true,
            has_record: true,
            unrecovered: None,
        };
        let ext = ext_of(&r.original_name);
        row.ext = self.ext.id(&ext);
        match &r.zrax {
            Some(z) => {
                row.format = self.format.id(&z.format);
                self.format.label(row.format, &z.format_name);
                row.variant = self.variant.id(z.format_variant.as_deref().unwrap_or(""));
                row.isa = self.isa_id(z.isa.as_deref().unwrap_or(""));
                let keys = z.isa.iter().cloned().chain(z.slices.iter().filter_map(|s| s.isa.clone()));
                (row.isas, row.families) = self.isa_set(keys.collect::<Vec<_>>());
                row.bits = z.bitwidth;
                row.endian = self.endian.id(&z.endianness);
                row.confidence = z.confidence as f32;
                row.class = self.class.id(&z.source);
                row.basis = self.basis.id(&z.basis);
                row.zrax = self.zrax.id(&z.zrax);
                row.slices = z.slices.len() as u32;
                extra.extend(z.slices.iter().filter_map(|s| s.label.clone()));
                extra.extend(z.metadata.iter().map(|m| format!("{} {}", m.label, m.value)));
            }
            // The current zrax no longer accepts it: keep what the ledger knew.
            None => {
                if let Some(p) = prev {
                    row.format = p.format;
                    row.isa = p.isa;
                    row.isas = p.isas.clone();
                    row.families = p.families.clone();
                }
            }
        }
        match (&r.telegram, prev) {
            (Some(t), _) => {
                row.posted_at = t.posted_at.max(1);
                row.chat_id = t.chat_id;
                row.message_id = t.message_id;
            }
            (None, Some(p)) => {
                row.posted_at = p.posted_at;
                row.chat_id = p.chat_id;
                row.message_id = p.message_id;
            }
            (None, None) => {}
        }
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        row.search = self.search_text(&row, &extra);
        row
    }

    fn row_from_entry(&mut self, e: &Entry, sha: [u8; 32], chat_id: i64) -> Row {
        let keys: Vec<String> = if e.isas.is_empty() { e.isa.iter().cloned().collect() } else { e.isas.clone() };
        let isa = self.isa_id(e.isa.as_deref().unwrap_or(""));
        let (isas, families) = self.isa_set(keys);
        let mut row = Row {
            sha,
            size: e.size,
            name: e.name.as_str().into(),
            search: "".into(),
            received_at: e.posted_at,
            posted_at: e.posted_at.max(1),
            chat_id,
            message_id: e.message_id,
            confidence: -1.0,
            slices: 0,
            isa,
            isas,
            families,
            format: self.format.id(&e.format),
            variant: 0,
            donor: self.donor.id(&e.username),
            ext: 0,
            endian: 0,
            class: 0,
            basis: 0,
            zrax: 0,
            bits: 0,
            origin: ORIGIN_LEDGER,
            kind: kind::classify(None, &e.format, "", &e.name).kind as u8,
            stored: false,
            has_record: false,
            unrecovered: None,
        };
        row.ext = self.ext.id(&ext_of(&e.name));
        row.search = self.search_text(&row, &[]);
        row
    }

    fn insert(&mut self, row: Row) {
        match self.by_sha.get(&row.sha) {
            Some(&i) => self.rows[i as usize] = row,
            None => {
                self.by_sha.insert(row.sha, self.rows.len() as u32);
                self.rows.push(row);
            }
        }
    }

    fn get(&self, sha: &[u8; 32]) -> Option<&Row> {
        self.by_sha.get(sha).map(|&i| &self.rows[i as usize])
    }

    /// The single value of a row in `dim` (the primary ISA for ISA and family).
    fn value(&self, row: &Row, dim: Dim) -> u32 {
        match dim {
            Dim::Isa => row.isa,
            Dim::Family => self.isa_family[row.isa as usize],
            Dim::Format => row.format,
            Dim::Variant => row.variant,
            Dim::Donor => row.donor,
            Dim::Ext => row.ext,
            Dim::Bits => row.bits as u32,
            Dim::Endian => row.endian,
            Dim::Class => row.class,
            Dim::Basis => row.basis,
            Dim::Origin => row.origin as u32,
            Dim::Kind => row.kind as u32,
            Dim::Status => row.status(),
            Dim::Zrax => row.zrax,
            Dim::Month => month_index(row.received_at),
            Dim::Day => (row.received_at / 86_400) as u32,
        }
    }

    /// All values of a row in `dim`: every contained ISA (and family) when
    /// `any`, else one value.
    fn values<'a>(&self, row: &'a Row, dim: Dim, any: bool, buf: &'a mut [u32; 1]) -> &'a [u32] {
        match dim {
            Dim::Isa if any => {
                if row.isas.is_empty() {
                    &ZERO
                } else {
                    &row.isas
                }
            }
            Dim::Family if any => {
                if row.families.is_empty() {
                    &ZERO
                } else {
                    &row.families
                }
            }
            _ => {
                buf[0] = self.value(row, dim);
                let b: &'a [u32; 1] = buf;
                b
            }
        }
    }

    fn dict(&self, dim: Dim) -> Option<&Dict> {
        Some(match dim {
            Dim::Isa => &self.isa,
            Dim::Family => &self.family,
            Dim::Format => &self.format,
            Dim::Variant => &self.variant,
            Dim::Donor => &self.donor,
            Dim::Ext => &self.ext,
            Dim::Endian => &self.endian,
            Dim::Class => &self.class,
            Dim::Basis => &self.basis,
            Dim::Zrax => &self.zrax,
            _ => return None,
        })
    }

    fn cardinality(&self, dim: Dim) -> usize {
        match dim {
            Dim::Bits => 256,
            Dim::Origin => ORIGINS.len(),
            Dim::Kind => KINDS.len(),
            Dim::Status => STATUSES.len(),
            Dim::Month | Dim::Day => 0,
            d => self.dict(d).map_or(0, |d| d.keys.len()),
        }
    }

    fn key_label(&self, dim: Dim, id: u32) -> (String, String) {
        match dim {
            Dim::Bits if id == 0 => (NONE.into(), "unknown".into()),
            Dim::Bits => (id.to_string(), format!("{id}-bit")),
            Dim::Origin => (ORIGINS[id as usize].0.into(), ORIGINS[id as usize].1.into()),
            Dim::Kind => (KINDS[id as usize].0.into(), KINDS[id as usize].1.into()),
            Dim::Status => (STATUSES[id as usize].0.into(), STATUSES[id as usize].1.into()),
            Dim::Month => {
                let (_, _, label) = month_range(id);
                (label.clone(), label)
            }
            Dim::Day => {
                let label = crate::ledger::date(id as u64 * 86_400);
                (label.clone(), label)
            }
            d => {
                let dict = self.dict(d).expect("a dictionary dimension");
                (dict.keys[id as usize].to_string(), dict.labels[id as usize].to_string())
            }
        }
    }

    /// The id of a filter value, None when nothing has it.
    fn resolve(&self, dim: Dim, key: &str) -> Option<u32> {
        match dim {
            Dim::Bits if key == NONE => Some(0),
            Dim::Bits => key.parse::<u8>().ok().map(u32::from),
            Dim::Origin => ORIGINS.iter().position(|(k, _)| *k == key).map(|i| i as u32),
            Dim::Kind => KINDS.iter().position(|(k, _)| *k == key).map(|i| i as u32),
            Dim::Status => STATUSES.iter().position(|(k, _)| *k == key).map(|i| i as u32),
            Dim::Month | Dim::Day => None,
            d => self.dict(d)?.find(key),
        }
    }

    fn row_json(&self, row: &Row) -> Value {
        let k = |d: &Dict, id: u32| if id == 0 { Value::Null } else { Value::from(&*d.keys[id as usize]) };
        let fam = self.isa_family[row.isa as usize];
        json!({
            "sha256": hex::encode(row.sha),
            "name": &*row.name,
            "size": row.size,
            "ext": k(&self.ext, row.ext),
            "donor": &*self.donor.keys[row.donor as usize],
            "format": k(&self.format, row.format),
            "format_name": if row.format == 0 { Value::Null } else { Value::from(&*self.format.labels[row.format as usize]) },
            "variant": k(&self.variant, row.variant),
            "isa": k(&self.isa, row.isa),
            "isa_name": if row.isa == 0 { Value::Null } else { Value::from(&*self.isa.labels[row.isa as usize]) },
            "isas": row.isas.iter().map(|&i| &*self.isa.keys[i as usize]).collect::<Vec<_>>(),
            "family": k(&self.family, fam),
            "family_name": if fam == 0 { Value::Null } else { Value::from(&*self.family.labels[fam as usize]) },
            "bits": if row.bits == 0 { Value::Null } else { Value::from(row.bits) },
            "endian": k(&self.endian, row.endian),
            "confidence": if row.confidence < 0.0 { Value::Null } else { Value::from((row.confidence as f64 * 1e4).round() / 1e4) },
            "class": k(&self.class, row.class),
            "basis": k(&self.basis, row.basis),
            "slices": row.slices,
            "origin": ORIGINS[row.origin as usize].0,
            "kind": KINDS[row.kind as usize].0,
            "status": STATUSES[row.status() as usize].0,
            "received_at": row.received_at,
            "posted_at": if row.posted_at == 0 { Value::Null } else { Value::from(row.posted_at) },
            "message_id": if row.message_id == 0 { Value::Null } else { Value::from(row.message_id) },
            "telegram": telegram_url(row.chat_id, row.message_id),
            "zrax": k(&self.zrax, row.zrax),
            "reason": row.unrecovered.as_deref(),
        })
    }

    /// Ranks of a dictionary's ids by label (case-insensitive), for sorting.
    fn ranks(&self, dim: Dim) -> Vec<u32> {
        let Some(dict) = self.dict(dim) else { return Vec::new() };
        let mut ids: Vec<u32> = (0..dict.keys.len() as u32).collect();
        ids.sort_by_cached_key(|&i| if i == 0 { String::from("\u{10FFFF}") } else { dict.labels[i as usize].to_lowercase() });
        let mut rank = vec![0; ids.len()];
        for (r, id) in ids.into_iter().enumerate() {
            rank[id as usize] = r as u32;
        }
        rank
    }
}

// ------------------------------------------------------------------ queries

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortKey {
    Name,
    Size,
    Time,
    Posted,
    Conf,
    Slices,
    Sha,
    Dim(Dim),
}

impl SortKey {
    fn parse(s: &str) -> Option<SortKey> {
        Some(match s {
            "name" => SortKey::Name,
            "size" => SortKey::Size,
            "time" | "received" => SortKey::Time,
            "posted" => SortKey::Posted,
            "conf" | "confidence" => SortKey::Conf,
            "slices" => SortKey::Slices,
            "sha" | "sha256" => SortKey::Sha,
            other => match Dim::parse(other)? {
                d if d.is_time() => SortKey::Time,
                d => SortKey::Dim(d),
            },
        })
    }
}

#[derive(Debug, Clone, Default)]
struct Filter {
    dim: Option<Dim>,
    include: Vec<String>,
    exclude: Vec<String>,
}

/// A parsed `query?…` (also used for exports).
#[derive(Debug, Clone)]
pub struct Query {
    words: Vec<String>,
    filters: Vec<Filter>,
    pub isa_any: bool,
    multi: bool,
    size: (u64, u64),
    time: (u64, u64),
    conf: (f64, f64),
    shas: Option<HashSet<[u8; 32]>>,
    pub sort: Vec<(SortKey, bool)>,
    pub offset: usize,
    pub limit: usize,
    tree: Vec<Dim>,
    matrix: Option<(Dim, Dim)>,
    facets: bool,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            words: Vec::new(),
            filters: Vec::new(),
            isa_any: true,
            multi: false,
            size: (0, u64::MAX),
            time: (0, u64::MAX),
            conf: (f64::NEG_INFINITY, f64::INFINITY),
            shas: None,
            sort: vec![(SortKey::Time, true)],
            offset: 0,
            limit: 100,
            tree: Vec::new(),
            matrix: None,
            facets: false,
        }
    }
}

fn range<T: std::str::FromStr + Copy>(raw: &str, lo: T, hi: T, what: &str) -> Result<(T, T), String> {
    let (a, b) = raw.split_once("..").ok_or_else(|| format!("{what} must be a range like a..b"))?;
    let parse = |s: &str, default: T| -> Result<T, String> {
        if s.trim().is_empty() {
            Ok(default)
        } else {
            s.trim().parse().map_err(|_| format!("{what}: {s} is not a number"))
        }
    };
    Ok((parse(a, lo)?, parse(b, hi)?))
}

impl Query {
    /// From the query string. Ranges are `a..b` (inclusive, either end
    /// optional); filter values are comma-separated, `!` excludes.
    pub fn parse(params: &HashMap<String, String>) -> Result<Query, String> {
        let mut q = Query::default();
        for (name, raw) in params {
            let raw = raw.trim();
            match name.as_str() {
                "q" => q.words = raw.to_lowercase().split_whitespace().map(str::to_string).collect(),
                "isa_mode" => q.isa_any = raw != "primary",
                "multi" => q.multi = matches!(raw, "1" | "true"),
                "size" => q.size = range(raw, 0, u64::MAX, "size")?,
                "time" => q.time = range(raw, 0, u64::MAX, "time")?,
                "conf" => q.conf = range(raw, f64::NEG_INFINITY, f64::INFINITY, "conf")?,
                "sha" if !raw.is_empty() => {
                    let shas: Option<HashSet<[u8; 32]>> = raw.split(',').map(parse_sha).collect();
                    q.shas = Some(shas.ok_or("sha takes full SHA-256 values")?);
                }
                "sort" if !raw.is_empty() => {
                    q.sort = raw
                        .split(',')
                        .map(|part| {
                            let (key, dir) = part.split_once(':').unwrap_or((part, "asc"));
                            let key = SortKey::parse(key.trim()).ok_or(format!("cannot sort by {key}"))?;
                            Ok((key, dir.trim() == "desc"))
                        })
                        .collect::<Result<_, String>>()?;
                }
                "offset" => q.offset = raw.parse().map_err(|_| "offset must be a number")?,
                "limit" => q.limit = raw.parse::<usize>().map_err(|_| "limit must be a number")?.min(MAX_LIMIT),
                "tree" if !raw.is_empty() => {
                    q.tree = raw
                        .split(',')
                        .map(|d| Dim::parse(d.trim()).ok_or(format!("no dimension {d}")))
                        .collect::<Result<_, String>>()?;
                    q.tree.dedup();
                    q.tree.truncate(4);
                }
                "matrix" if !raw.is_empty() => {
                    let (a, b) = raw.split_once(',').ok_or("matrix takes two dimensions")?;
                    let a = Dim::parse(a.trim()).ok_or(format!("no dimension {a}"))?;
                    let b = Dim::parse(b.trim()).ok_or(format!("no dimension {b}"))?;
                    q.matrix = Some((a, b));
                }
                "facets" => q.facets = raw != "0",
                other => {
                    let Some(dim) = Dim::parse(other).filter(|d| !d.is_time()) else { continue };
                    let mut f = Filter { dim: Some(dim), ..Default::default() };
                    for v in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                        match v.strip_prefix('!') {
                            Some(x) => f.exclude.push(x.to_string()),
                            None => f.include.push(v.to_string()),
                        }
                    }
                    if !f.include.is_empty() || !f.exclude.is_empty() {
                        q.filters.push(f);
                    }
                }
            }
        }
        Ok(q)
    }

    /// The selected (`in`) and excluded (`out`) keys of a dimension.
    fn selection(&self, dim: Dim) -> (Vec<&str>, Vec<&str>) {
        let f = self.filters.iter().filter(|f| f.dim == Some(dim));
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for f in f {
            a.extend(f.include.iter().map(String::as_str));
            b.extend(f.exclude.iter().map(String::as_str));
        }
        (a, b)
    }
}

struct Resolved {
    dim: Dim,
    include: Vec<u32>,
    any_include: bool,
    exclude: Vec<u32>,
}

impl Resolved {
    fn matches(&self, vals: &[u32]) -> bool {
        (!self.any_include || vals.iter().any(|v| self.include.contains(v)))
            && !vals.iter().any(|v| self.exclude.contains(v))
    }
}

/// Text words; those of 6+ hex digits also match a SHA-256 prefix.
struct Words {
    text: Vec<String>,
    nibbles: Vec<Option<Vec<u8>>>,
}

impl Words {
    fn new(words: &[String]) -> Self {
        let nibbles = words
            .iter()
            .map(|w| {
                (w.len() >= 6 && w.len() <= 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| w.bytes().map(|b| (b as char).to_digit(16).unwrap() as u8).collect())
            })
            .collect();
        Self { text: words.to_vec(), nibbles }
    }

    fn matches(&self, row: &Row) -> bool {
        self.text.iter().zip(&self.nibbles).all(|(w, nib)| {
            row.search.contains(w.as_str())
                || nib.as_ref().is_some_and(|n| {
                    n.iter().enumerate().all(|(i, &x)| {
                        let byte = row.sha[i / 2];
                        (if i % 2 == 0 { byte >> 4 } else { byte & 15 }) == x
                    })
                })
        })
    }
}

#[derive(Default, Clone, Copy)]
struct Tally {
    files: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }
}

type Path4 = (u8, [u32; 4]);

pub enum ExportKind {
    Csv,
    Ndjson,
    Sha256sum,
    Rsync,
}

pub const CSV_HEADER: &str = "sha256,name,size,donor,kind,isa,isas,family,format,variant,bits,endian,confidence,class,basis,slices,origin,status,received_at,posted_at,telegram,zrax\n";

pub const CSV_COLUMNS: [&str; 22] = [
    "sha256", "name", "size", "donor", "kind", "isa", "isas", "family", "format", "variant", "bits", "endian", "confidence", "class",
    "basis", "slices", "origin", "status", "received_at", "posted_at", "telegram", "zrax",
];

/// One CSV line of a row's JSON (as `Index::row_json` makes it).
pub fn csv_line(row: &Value) -> String {
    csv_row(row, &CSV_COLUMNS)
}

/// One CSV line with these columns of a row's JSON.
pub fn csv_row(row: &Value, cols: &[&str]) -> String {
    let field = |v: &Value| -> String {
        let s = match v {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
            other => other.to_string(),
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    let mut line = cols.iter().map(|c| field(&row[*c])).collect::<Vec<_>>().join(",");
    line.push('\n');
    line
}

// ------------------------------------------------------------------ catalog

pub struct Catalog {
    index: RwLock<Index>,
    version: AtomicU64,
    ready: AtomicBool,
    load_done: AtomicUsize,
    load_total: AtomicUsize,
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

impl Catalog {
    pub fn new() -> Self {
        Self {
            index: RwLock::new(Index::new()),
            version: AtomicU64::new(1),
            ready: AtomicBool::new(false),
            load_done: AtomicUsize::new(0),
            load_total: AtomicUsize::new(0),
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.load_done.load(Ordering::Relaxed), self.load_total.load(Ordering::Relaxed))
    }

    fn bump(&self) {
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    /// A record was written to the store (a donation kept, posted, or
    /// recovered). Always wins over what the index had.
    pub fn put(&self, record: &Record, file: &Path) {
        let Some(sha) = parse_sha(&record.sha256) else { return };
        let kind = record_kind(record, file);
        let mut ix = self.index.write().unwrap();
        let prev = ix.get(&sha).map(clone_meta);
        let row = ix.row_from_record(record, sha, prev.as_ref(), kind);
        ix.insert(row);
        drop(ix);
        self.bump();
    }

    /// An image was posted (the ledger entry). Adds what the store record
    /// may lack, or a ledger-only row when nothing was kept.
    pub fn posted(&self, entry: &Entry, chat_id: i64) {
        let Some(sha) = parse_sha(&entry.sha256) else { return };
        let mut ix = self.index.write().unwrap();
        match ix.by_sha.get(&sha).copied() {
            Some(i) => {
                let row = &mut ix.rows[i as usize];
                if row.posted_at == 0 {
                    row.posted_at = entry.posted_at.max(1);
                    row.chat_id = chat_id;
                    row.message_id = entry.message_id;
                }
            }
            None => {
                let row = ix.row_from_entry(entry, sha, chat_id);
                ix.insert(row);
            }
        }
        drop(ix);
        self.bump();
    }

    /// The backfill could not get this image back (this time).
    pub fn unrecovered(&self, sha256: &str, reason: &str) {
        let Some(sha) = parse_sha(sha256) else { return };
        let mut ix = self.index.write().unwrap();
        if let Some(i) = ix.by_sha.get(&sha).copied() {
            let row = &mut ix.rows[i as usize];
            if !row.stored {
                row.unrecovered = Some(cap(reason.to_string(), 500).into());
            }
        }
        drop(ix);
        self.bump();
    }

    pub fn contains(&self, sha256: &str) -> bool {
        parse_sha(sha256).is_some_and(|sha| self.index.read().unwrap().by_sha.contains_key(&sha))
    }

    /// Blocking. Build the index from the ledger (`chat_ids[i]`: the chat of
    /// entry i, 0 when unknown) and the store's records. Only adds what live
    /// updates haven't already brought in.
    pub fn load(&self, entries: &[Entry], chat_ids: &[i64], firmware_dir: &Path) {
        let started = std::time::Instant::now();
        let files: Vec<std::path::PathBuf> = std::fs::read_dir(firmware_dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect()
            })
            .unwrap_or_default();
        self.load_total.store(entries.len() + files.len(), Ordering::Relaxed);
        for (chunk_no, chunk) in entries.chunks(2000).enumerate() {
            let mut ix = self.index.write().unwrap();
            for (j, e) in chunk.iter().enumerate() {
                let Some(sha) = parse_sha(&e.sha256) else { continue };
                let chat = chat_ids.get(chunk_no * 2000 + j).copied().unwrap_or(0);
                match ix.by_sha.get(&sha).copied() {
                    Some(i) => {
                        let row = &mut ix.rows[i as usize];
                        if row.posted_at == 0 {
                            row.posted_at = e.posted_at.max(1);
                            row.chat_id = chat;
                            row.message_id = e.message_id;
                        }
                    }
                    None => {
                        let row = ix.row_from_entry(e, sha, chat);
                        ix.insert(row);
                    }
                }
            }
            drop(ix);
            self.load_done.fetch_add(chunk.len(), Ordering::Relaxed);
        }
        let mut bad = 0;
        for chunk in files.chunks(500) {
            // Parse outside the lock.
            let records: Vec<(Record, Kind)> = chunk
                .iter()
                .filter_map(|p| match std::fs::read(p).map(|b| serde_json::from_slice::<Record>(&b)) {
                    Ok(Ok(r)) => {
                        let kind = record_kind(&r, &p.with_extension(""));
                        Some((r, kind))
                    }
                    _ => {
                        bad += 1;
                        None
                    }
                })
                .collect();
            let mut ix = self.index.write().unwrap();
            for (r, kind) in &records {
                let Some(sha) = parse_sha(&r.sha256) else { continue };
                let prev = match ix.get(&sha) {
                    Some(p) if p.has_record => continue,
                    Some(p) => Some(clone_meta(p)),
                    None => None,
                };
                let row = ix.row_from_record(r, sha, prev.as_ref(), *kind);
                ix.insert(row);
            }
            drop(ix);
            self.load_done.fetch_add(chunk.len(), Ordering::Relaxed);
        }
        self.bump();
        self.ready.store(true, Ordering::SeqCst);
        let n = self.index.read().unwrap().rows.len();
        tracing::info!(
            "dashboard: indexed {n} images ({} ledger entries, {} records{}) in {:.1} s",
            entries.len(),
            files.len(),
            if bad > 0 { format!(", {bad} unreadable") } else { String::new() },
            started.elapsed().as_secs_f64()
        );
    }

    /// Totals for the dashboard's header.
    pub fn summary(&self, now: u64, current_zrax: &str) -> Value {
        let ix = self.index.read().unwrap();
        let (mut total, mut stored, mut queued, mut pending, mut unrecovered) =
            (Tally::default(), Tally::default(), 0u64, Tally::default(), 0u64);
        let (mut hour, mut day, mut older) = (0u64, 0u64, 0u64);
        let (mut first, mut last) = (u64::MAX, 0u64);
        let mut donors = HashSet::new();
        let mut isas = HashSet::new();
        let mut formats = HashSet::new();
        let mut kinds = [0u64; KINDS.len()];
        let current = ix.zrax.find(current_zrax).unwrap_or(u32::MAX);
        for r in &ix.rows {
            total.add(r.size);
            kinds[r.kind as usize] += 1;
            match r.status() {
                0 => stored.add(r.size),
                1 => {
                    stored.add(r.size);
                    queued += 1;
                }
                2 => pending.add(r.size),
                _ => {
                    pending.add(r.size);
                    unrecovered += 1;
                }
            }
            if r.received_at + 3600 >= now {
                hour += 1;
            }
            if r.received_at + 86_400 >= now {
                day += 1;
            }
            if r.has_record && r.zrax != 0 && r.zrax != current {
                older += 1;
            }
            first = first.min(r.received_at);
            last = last.max(r.received_at);
            donors.insert(r.donor);
            isas.extend(r.isas.iter().copied());
            formats.insert(r.format);
        }
        formats.remove(&0);
        let named = donors.iter().filter(|&&d| &*ix.donor.keys[d as usize] != "anonymous").count();
        let wanted: Vec<Value> = crate::analyze::raw_isas()
            .iter()
            .filter(|r| ix.isa.find(&r.key).is_none_or(|id| !isas.contains(&id)))
            .map(|r| json!({ "isa": r.key, "name": r.name, "family": families::family(&r.key).0 }))
            .collect();
        let (done, all) = self.progress();
        json!({
            "ready": self.ready(),
            "progress": { "done": done, "total": all },
            "version": self.version(),
            "files": total.files,
            "bytes": total.bytes,
            "stored": { "files": stored.files, "bytes": stored.bytes },
            "queued": queued,
            "pending": { "files": pending.files, "bytes": pending.bytes },
            "unrecovered": unrecovered,
            "donors": donors.len(),
            "named_donors": named,
            "isas": isas.len(),
            "formats": formats.len(),
            "kinds": KINDS.iter().zip(kinds).map(|((k, _), n)| (k.to_string(), Value::from(n))).collect::<serde_json::Map<_, _>>(),
            "last_hour": hour,
            "last_day": day,
            "first_at": (first != u64::MAX).then_some(first),
            "last_at": (last > 0).then_some(last),
            "older_zrax": older,
            "zrax": current_zrax,
            "wanted": wanted,
        })
    }

    /// One image: its row, and other images with the same original name.
    pub fn detail(&self, sha256: &str) -> Option<(Value, Vec<Value>)> {
        let sha = parse_sha(sha256)?;
        let ix = self.index.read().unwrap();
        let row = ix.get(&sha)?;
        let same: Vec<Value> = ix
            .rows
            .iter()
            .filter(|r| r.name == row.name && r.sha != row.sha)
            .take(50)
            .map(|r| ix.row_json(r))
            .collect();
        Some((ix.row_json(row), same))
    }

    /// The original name of a stored image, None if it isn't in the store.
    pub fn stored_name(&self, sha256: &str) -> Option<String> {
        let sha = parse_sha(sha256)?;
        let ix = self.index.read().unwrap();
        ix.get(&sha).filter(|r| r.stored).map(|r| r.name.to_string())
    }

    fn resolve(ix: &Index, q: &Query) -> Vec<Resolved> {
        q.filters
            .iter()
            .filter_map(|f| {
                let dim = f.dim?;
                Some(Resolved {
                    dim,
                    // Unknown keys match nothing.
                    include: f.include.iter().map(|k| ix.resolve(dim, k).unwrap_or(u32::MAX)).collect(),
                    any_include: !f.include.is_empty(),
                    exclude: f.exclude.iter().filter_map(|k| ix.resolve(dim, k)).collect(),
                })
            })
            .collect()
    }

    fn fails(ix: &Index, row: &Row, q: &Query, filters: &[Resolved], words: &Words) -> u32 {
        let mut fails = 0;
        for f in filters {
            let mut buf = [0];
            if !f.matches(ix.values(row, f.dim, q.isa_any, &mut buf)) {
                fails |= f.dim.bit();
            }
        }
        if !words.text.is_empty() && !words.matches(row) {
            fails |= TEXT;
        }
        if row.size < q.size.0 || row.size > q.size.1 {
            fails |= SIZE;
        }
        if row.received_at < q.time.0 || row.received_at > q.time.1 {
            fails |= TIME;
        }
        if q.conf.0.is_finite() || q.conf.1.is_finite() {
            let c = row.confidence as f64;
            if row.confidence < 0.0 || c < q.conf.0 - 1e-6 || c > q.conf.1 + 1e-6 {
                fails |= CONF;
            }
        }
        if q.multi && row.isas.len() < 2 {
            fails |= MULTI;
        }
        if q.shas.as_ref().is_some_and(|s| !s.contains(&row.sha)) {
            fails |= SHAS;
        }
        fails
    }

    fn sort(ix: &Index, ids: &mut [u32], keys: &[(SortKey, bool)]) {
        let ranks: HashMap<Dim, Vec<u32>> = keys
            .iter()
            .filter_map(|(k, _)| match k {
                SortKey::Dim(d) if ix.dict(*d).is_some() => Some((*d, ix.ranks(*d))),
                _ => None,
            })
            .collect();
        let cmp_key = |a: &Row, b: &Row, key: SortKey| -> CmpOrdering {
            match key {
                SortKey::Name => a.name.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.name.bytes().map(|c| c.to_ascii_lowercase())),
                SortKey::Size => a.size.cmp(&b.size),
                SortKey::Time => a.received_at.cmp(&b.received_at),
                SortKey::Posted => a.posted_at.cmp(&b.posted_at),
                SortKey::Conf => a.confidence.total_cmp(&b.confidence),
                SortKey::Slices => a.slices.cmp(&b.slices),
                SortKey::Sha => a.sha.cmp(&b.sha),
                SortKey::Dim(d) => match ranks.get(&d) {
                    Some(r) => r[ix.value(a, d) as usize].cmp(&r[ix.value(b, d) as usize]),
                    None => ix.value(a, d).cmp(&ix.value(b, d)),
                },
            }
        };
        ids.sort_by(|&x, &y| {
            let (a, b) = (&ix.rows[x as usize], &ix.rows[y as usize]);
            for &(key, desc) in keys {
                let o = cmp_key(a, b, key);
                if o != CmpOrdering::Equal {
                    return if desc { o.reverse() } else { o };
                }
            }
            b.received_at.cmp(&a.received_at).then(a.sha.cmp(&b.sha))
        });
    }

    /// Every matching row id, sorted (for exports).
    pub fn matching(&self, q: &Query) -> Vec<u32> {
        let ix = self.index.read().unwrap();
        let filters = Self::resolve(&ix, q);
        let words = Words::new(&q.words);
        let mut ids: Vec<u32> = (0..ix.rows.len() as u32)
            .filter(|&i| Self::fails(&ix, &ix.rows[i as usize], q, &filters, &words) == 0)
            .collect();
        Self::sort(&ix, &mut ids, &q.sort);
        ids
    }

    /// Rows for an export batch: (sha256, stored, row JSON).
    pub fn export_rows(&self, ids: &[u32]) -> Vec<(String, bool, Value)> {
        let ix = self.index.read().unwrap();
        ids.iter()
            .filter_map(|&i| ix.rows.get(i as usize))
            .map(|r| (hex::encode(r.sha), r.stored, ix.row_json(r)))
            .collect()
    }

    /// The dashboard's main query: a page of rows, plus facet counts,
    /// histograms, the tree and the matrix the query asks for.
    pub fn query(&self, q: &Query) -> Value {
        let ix = self.index.read().unwrap();
        let filters = Self::resolve(&ix, q);
        let words = Words::new(&q.words);
        let tree_mask = q.tree.iter().fold(0, |m, d| m | d.bit());
        let matrix_mask = q.matrix.map_or(0, |(a, b)| a.bit() | b.bit());

        let mut ids = Vec::new();
        let mut total = Tally::default();
        let mut facets: Vec<(Dim, Vec<Tally>)> = if q.facets {
            Dim::FACETS.iter().map(|&d| (d, vec![Tally::default(); ix.cardinality(d)])).collect()
        } else {
            Vec::new()
        };
        let mut size_hist = [Tally::default(); 65];
        let mut conf_hist = [Tally::default(); 10];
        let mut times: Vec<(u64, u64)> = Vec::new();
        let mut tree: HashMap<Path4, Tally> = HashMap::new();
        let mut matrix: HashMap<(u32, u32), u64> = HashMap::new();
        let mut matrix_a: HashMap<u32, u64> = HashMap::new();
        let mut matrix_b: HashMap<u32, u64> = HashMap::new();

        for (i, row) in ix.rows.iter().enumerate() {
            let fails = Self::fails(&ix, row, q, &filters, &words);
            if fails == 0 {
                ids.push(i as u32);
                total.add(row.size);
            }
            for (dim, counts) in &mut facets {
                if fails & !dim.bit() == 0 {
                    let mut buf = [0];
                    for &v in ix.values(row, *dim, q.isa_any, &mut buf) {
                        counts[v as usize].add(row.size);
                    }
                }
            }
            if q.facets {
                if fails & !SIZE == 0 {
                    size_hist[(64 - row.size.leading_zeros()) as usize].add(row.size);
                }
                if fails & !TIME == 0 {
                    times.push((row.received_at, row.size));
                }
                if fails & !CONF == 0 && row.confidence >= 0.0 {
                    conf_hist[((row.confidence * 10.0) as usize).min(9)].add(row.size);
                }
            }
            if !q.tree.is_empty() && fails & !tree_mask == 0 {
                Self::tree_add(&ix, row, &q.tree, q.isa_any, &mut tree);
            }
            if let Some((a, b)) = q.matrix {
                if fails & !matrix_mask == 0 {
                    let (mut ba, mut bb) = ([0], [0]);
                    let va = ix.values(row, a, q.isa_any, &mut ba);
                    let vb = ix.values(row, b, q.isa_any, &mut bb);
                    for &x in va {
                        *matrix_a.entry(x).or_default() += 1;
                    }
                    for &y in vb {
                        *matrix_b.entry(y).or_default() += 1;
                    }
                    for &x in va {
                        for &y in vb {
                            *matrix.entry((x, y)).or_default() += 1;
                        }
                    }
                }
            }
        }

        Self::sort(&ix, &mut ids, &q.sort);
        let page: Vec<Value> =
            ids.iter().skip(q.offset).take(q.limit).map(|&i| ix.row_json(&ix.rows[i as usize])).collect();

        let mut out = json!({
            "version": self.version(),
            "total": total.files,
            "bytes": total.bytes,
            "offset": q.offset,
            "limit": q.limit,
            "rows": page,
        });
        if q.facets {
            let mut fj = serde_json::Map::new();
            for (dim, counts) in &facets {
                fj.insert(dim.key().into(), Self::facet_json(&ix, q, *dim, counts));
            }
            out["facets"] = Value::Object(fj);
            out["hist"] = json!({
                "size": Self::size_hist_json(&size_hist),
                "time": Self::time_hist_json(&mut times),
                "conf": conf_hist.iter().enumerate().map(|(i, t)| json!({
                    "lo": i as f64 / 10.0, "hi": (i + 1) as f64 / 10.0, "files": t.files, "bytes": t.bytes
                })).collect::<Vec<_>>(),
            });
        }
        if !q.tree.is_empty() {
            let mut children: HashMap<(usize, [u32; 4]), Vec<(u32, Tally)>> = HashMap::new();
            for ((len, path), t) in &tree {
                let depth = *len as usize - 1;
                let mut parent = *path;
                parent[depth..].fill(0);
                children.entry((depth, parent)).or_default().push((path[depth], *t));
            }
            out["tree"] = json!({
                "levels": q.tree.iter().map(|d| d.key()).collect::<Vec<_>>(),
                "nodes": Self::tree_json(&ix, &q.tree, &mut children, 0, [0; 4]),
            });
        }
        if let Some((a, b)) = q.matrix {
            out["matrix"] = Self::matrix_json(&ix, a, b, &matrix, &matrix_a, &matrix_b);
        }
        out
    }

    fn facet_json(ix: &Index, q: &Query, dim: Dim, counts: &[Tally]) -> Value {
        let (inc, exc) = q.selection(dim);
        let mut vals: Vec<(usize, Tally)> = counts.iter().copied().enumerate().filter(|(_, t)| t.files > 0).collect();
        // Selected values stay listed (with 0) so they can be removed.
        for key in inc.iter().chain(&exc) {
            if let Some(id) = ix.resolve(dim, key) {
                if !vals.iter().any(|(i, _)| *i == id as usize) {
                    vals.push((id as usize, Tally::default()));
                }
            }
        }
        vals.sort_by(|a, b| b.1.files.cmp(&a.1.files).then(a.0.cmp(&b.0)));
        let more = vals.len().saturating_sub(FACET_CAP);
        let list: Vec<Value> = vals
            .iter()
            .take(FACET_CAP)
            .map(|&(id, t)| {
                let (key, label) = ix.key_label(dim, id as u32);
                let sel = if inc.contains(&key.as_str()) {
                    Some("in")
                } else if exc.contains(&key.as_str()) {
                    Some("out")
                } else {
                    None
                };
                json!({ "key": key, "label": label, "files": t.files, "bytes": t.bytes, "sel": sel })
            })
            .collect();
        json!({ "values": list, "more": more })
    }

    fn size_hist_json(h: &[Tally; 65]) -> Value {
        let used: Vec<usize> = (0..65).filter(|&i| h[i].files > 0).collect();
        let (Some(&lo), Some(&hi)) = (used.first(), used.last()) else { return json!([]) };
        (lo..=hi)
            .map(|i| {
                let (a, b) = if i == 0 { (0u64, 0u64) } else { (1u64 << (i - 1), (1u128 << i) as u64 - 1) };
                json!({ "lo": a, "hi": b, "files": h[i].files, "bytes": h[i].bytes })
            })
            .collect()
    }

    fn time_hist_json(times: &mut [(u64, u64)]) -> Value {
        let (Some(lo), Some(hi)) = (times.iter().map(|t| t.0).min(), times.iter().map(|t| t.0).max()) else {
            return json!({ "step": 3600, "start": 0, "buckets": [] });
        };
        let span = hi - lo;
        let step = if span <= 3 * 86_400 {
            3600
        } else if span <= 150 * 86_400 {
            86_400
        } else {
            7 * 86_400
        };
        let start = lo / step * step;
        let n = ((hi - start) / step + 1) as usize;
        let mut buckets = vec![Tally::default(); n];
        for &(t, size) in times.iter() {
            buckets[((t - start) / step) as usize].add(size);
        }
        json!({
            "step": step,
            "start": start,
            "buckets": buckets.iter().map(|b| json!([b.files, b.bytes])).collect::<Vec<_>>(),
        })
    }

    fn tree_add(ix: &Index, row: &Row, levels: &[Dim], any: bool, tree: &mut HashMap<Path4, Tally>) {
        let isa_based = levels.iter().any(|d| matches!(d, Dim::Isa | Dim::Family));
        let primary = [row.isa];
        let isas: &[u32] = if !isa_based || !any || row.isas.is_empty() { &primary } else { &row.isas };
        let mut seen: Vec<Path4> = Vec::with_capacity(levels.len() * isas.len());
        for &isa in isas {
            let mut path = [0u32; 4];
            for (k, &dim) in levels.iter().enumerate() {
                path[k] = match dim {
                    Dim::Isa => isa,
                    Dim::Family => ix.isa_family[isa as usize],
                    d => ix.value(row, d),
                };
                let mut prefix = [0u32; 4];
                prefix[..=k].copy_from_slice(&path[..=k]);
                let key = ((k + 1) as u8, prefix);
                if !seen.contains(&key) {
                    seen.push(key);
                    tree.entry(key).or_default().add(row.size);
                }
            }
        }
    }

    fn tree_json(
        ix: &Index,
        levels: &[Dim],
        children: &mut HashMap<(usize, [u32; 4]), Vec<(u32, Tally)>>,
        depth: usize,
        parent: [u32; 4],
    ) -> Value {
        let dim = levels[depth];
        let mut kids = children.remove(&(depth, parent)).unwrap_or_default();
        if dim.is_time() {
            kids.sort_by(|a, b| b.0.cmp(&a.0));
        } else {
            kids.sort_by(|a, b| b.1.files.cmp(&a.1.files).then(a.0.cmp(&b.0)));
        }
        let more = kids.len().saturating_sub(TREE_CAP);
        let mut nodes: Vec<Value> = kids
            .iter()
            .take(TREE_CAP)
            .map(|&(id, t)| {
                let (key, label) = ix.key_label(dim, id);
                let mut node = json!({ "key": key, "label": label, "files": t.files, "bytes": t.bytes });
                match dim {
                    Dim::Month => {
                        let (a, b, _) = month_range(id);
                        node["range"] = json!([a, b - 1]);
                    }
                    Dim::Day => {
                        let a = id as u64 * 86_400;
                        node["range"] = json!([a, a + 86_399]);
                    }
                    _ => {}
                }
                if depth + 1 < levels.len() {
                    let mut path = parent;
                    path[depth] = id;
                    node["children"] = Self::tree_json(ix, levels, children, depth + 1, path);
                }
                node
            })
            .collect();
        if more > 0 {
            nodes.push(json!({ "more": more }));
        }
        Value::Array(nodes)
    }

    fn matrix_json(
        ix: &Index,
        a: Dim,
        b: Dim,
        cells: &HashMap<(u32, u32), u64>,
        ta: &HashMap<u32, u64>,
        tb: &HashMap<u32, u64>,
    ) -> Value {
        let top = |t: &HashMap<u32, u64>, n: usize| {
            let mut v: Vec<(u32, u64)> = t.iter().map(|(k, c)| (*k, *c)).collect();
            v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
            let more = v.len().saturating_sub(n);
            v.truncate(n);
            (v, more)
        };
        let (rows, more_rows) = top(ta, MATRIX_ROWS);
        let (cols, more_cols) = top(tb, MATRIX_COLS);
        let head = |dim: Dim, v: &[(u32, u64)]| -> Vec<Value> {
            v.iter()
                .map(|(id, n)| {
                    let (key, label) = ix.key_label(dim, *id);
                    json!({ "key": key, "label": label, "files": n })
                })
                .collect()
        };
        let grid: Vec<Vec<u64>> =
            rows.iter().map(|(r, _)| cols.iter().map(|(c, _)| cells.get(&(*r, *c)).copied().unwrap_or(0)).collect()).collect();
        json!({
            "a": a.key(), "b": b.key(),
            "rows": head(a, &rows), "cols": head(b, &cols), "cells": grid,
            "more_rows": more_rows, "more_cols": more_cols,
        })
    }
}

/// The numeric and id fields of a row (for merging a record with what the
/// ledger knew).
/// The kind of a stored image (blocking: may read the file's headers).
pub fn record_kind(r: &Record, file: &Path) -> Kind {
    record_verdict(r, file).kind
}

pub fn record_verdict(r: &Record, file: &Path) -> kind::Verdict {
    let (format, variant) = r.zrax.as_ref().map_or(("", ""), |z| (z.format.as_str(), z.format_variant.as_deref().unwrap_or("")));
    kind::classify(Some(file), format, variant, &r.original_name)
}

fn clone_meta(p: &Row) -> Row {
    Row {
        sha: p.sha,
        size: p.size,
        name: p.name.clone(),
        search: p.search.clone(),
        received_at: p.received_at,
        posted_at: p.posted_at,
        chat_id: p.chat_id,
        message_id: p.message_id,
        confidence: p.confidence,
        slices: p.slices,
        isa: p.isa,
        isas: p.isas.clone(),
        families: p.families.clone(),
        format: p.format,
        variant: p.variant,
        donor: p.donor,
        ext: p.ext,
        endian: p.endian,
        class: p.class,
        basis: p.basis,
        zrax: p.zrax,
        bits: p.bits,
        origin: p.origin,
        kind: p.kind,
        stored: p.stored,
        has_record: p.has_record,
        unrecovered: p.unrecovered.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{SliceSummary, Summary};
    use crate::firmwares::Posted;

    fn summary(format: &str, isa: Option<&str>, slices: &[&str]) -> Summary {
        Summary {
            format: format.into(),
            format_name: format.to_uppercase(),
            format_variant: None,
            isa: isa.map(Into::into),
            isa_name: None,
            isa_tag: None,
            bitwidth: 32,
            endianness: "little".into(),
            confidence: 0.9,
            source: "heuristic".into(),
            variant: None,
            slices: slices
                .iter()
                .map(|s| SliceSummary {
                    label: Some(format!("{s} slice")),
                    isa: Some(s.to_string()),
                    isa_name: None,
                    bitwidth: 32,
                    offset: 0,
                    size: 1,
                })
                .collect(),
            metadata: vec![crate::analyze::MetaSummary { label: "Machine Type".into(), value: "EM_ARM".into() }],
            basis: "isa".into(),
            zrax: "0.1.0@abc".into(),
        }
    }

    fn record(n: u8, donor: &str, size: u64, z: Option<Summary>, at: u64) -> Record {
        Record {
            sha256: hex::encode([n; 32]),
            size,
            name: donor.into(),
            original_name: format!("fw{n}.bin"),
            zrax: z,
            received_at: at,
            source: "upload".into(),
            telegram: None,
        }
    }

    fn entry(n: u8, isa: &str, at: u64) -> Entry {
        Entry {
            sha256: hex::encode([n; 32]),
            name: format!("old{n}.img"),
            size: 100 * n as u64,
            username: "anonymous".into(),
            format: "raw".into(),
            isa: Some(isa.into()),
            isas: Vec::new(),
            message_id: (n as i64) << 20,
            posted_at: at,
        }
    }

    fn q(pairs: &[(&str, &str)]) -> Query {
        Query::parse(&pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()).unwrap()
    }

    fn shas(v: &Value) -> Vec<String> {
        v["rows"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap().to_string()).collect()
    }

    fn catalog() -> Catalog {
        let c = Catalog::new();
        c.put(&record(1, "kenan", 1000, Some(summary("elf", Some("arm"), &["arm", "tricore"])), 100), Path::new("/nonexistent"));
        c.put(&record(2, "kenan", 50, Some(summary("raw", Some("i8051"), &[])), 200), Path::new("/nonexistent"));
        c.put(&record(3, "anonymous", 7000, Some(summary("raw", Some("a_arch64"), &[])), 300), Path::new("/nonexistent"));
        c.posted(&entry(4, "mips", 50), -1003917356862);
        c
    }

    #[test]
    fn merging_ledger_and_records() {
        let dir = tempfile::tempdir().unwrap();
        let c = Catalog::new();
        // A live record arrives before the loader reads an older copy of it.
        let mut live = record(5, "kenan", 10, Some(summary("elf", Some("arm"), &[])), 50);
        live.telegram = Some(Posted { chat_id: -1003917356862, message_id: 9 << 20, posted_at: 60 });
        c.put(&live, Path::new("/nonexistent"));
        let stale = record(5, "kenan", 10, Some(summary("elf", Some("arm"), &[])), 50);
        std::fs::write(dir.path().join(format!("{}.json", stale.sha256)), serde_json::to_vec(&stale).unwrap()).unwrap();
        // One recovered record whose ledger entry is also loaded.
        let mut rec6 = record(6, "anonymous", 600, None, 70);
        rec6.source = "telegram".into();
        std::fs::write(dir.path().join(format!("{}.json", rec6.sha256)), serde_json::to_vec(&rec6).unwrap()).unwrap();
        let entries = vec![entry(6, "hexagon", 70), entry(7, "z80", 80)];
        c.load(&entries, &[-1003917356862, 0], dir.path());
        assert!(c.ready());

        let (five, _) = c.detail(&hex::encode([5u8; 32])).unwrap();
        assert_eq!(five["telegram"], "https://t.me/c/3917356862/9", "the live record wins");
        let (six, _) = c.detail(&hex::encode([6u8; 32])).unwrap();
        assert_eq!((six["origin"].as_str(), six["status"].as_str()), (Some("telegram"), Some("stored")));
        assert_eq!(six["isa"], "hexagon", "zrax rejected it now: the ledger's ISA stays");
        assert_eq!(six["message_id"], 6 << 20);
        let (seven, _) = c.detail(&hex::encode([7u8; 32])).unwrap();
        assert_eq!((seven["origin"].as_str(), seven["status"].as_str()), (Some("ledger"), Some("pending")));
        assert!(seven["telegram"].is_null(), "basic group (chat unknown): no link");

        c.unrecovered(&hex::encode([7u8; 32]), "chat -5599544901: not found");
        let (seven, _) = c.detail(&hex::encode([7u8; 32])).unwrap();
        assert_eq!(seven["status"], "unrecovered");
        // Recovered after all.
        c.put(&record(7, "anonymous", 700, Some(summary("raw", Some("z80"), &[])), 80), Path::new("/nonexistent"));
        let (seven, _) = c.detail(&hex::encode([7u8; 32])).unwrap();
        assert_eq!(seven["status"], "stored");
        assert!(seven["reason"].is_null());
        assert_eq!(seven["posted_at"], 80);
    }

    #[test]
    fn filters_facets_and_sorting() {
        let c = catalog();
        let all = c.query(&q(&[("facets", "1")]));
        assert_eq!(all["total"], 4);
        assert_eq!(shas(&all), ["fw3.bin", "fw2.bin", "fw1.bin", "old4.img"], "newest first by default");

        // Any contained ISA vs the primary one.
        assert_eq!(c.query(&q(&[("isa", "tricore")]))["total"], 1);
        assert_eq!(c.query(&q(&[("isa", "tricore"), ("isa_mode", "primary")]))["total"], 0);
        assert_eq!(c.query(&q(&[("family", "arm")]))["total"], 2);
        assert_eq!(c.query(&q(&[("isa", "!arm,!mips")]))["total"], 2);
        assert_eq!(c.query(&q(&[("isa", "nonsense")]))["total"], 0);
        assert_eq!(c.query(&q(&[("multi", "1")]))["total"], 1);
        assert_eq!(c.query(&q(&[("status", "pending")]))["total"], 1);
        assert_eq!(c.query(&q(&[("origin", "ledger")]))["total"], 1);
        assert_eq!(c.query(&q(&[("ext", "img")]))["total"], 1);
        assert_eq!(c.query(&q(&[("bits", "(none)")]))["total"], 1);
        assert_eq!(c.query(&q(&[("size", "100..5000")]))["total"], 2);
        assert_eq!(c.query(&q(&[("time", "150..")]))["total"], 2);
        assert_eq!(c.query(&q(&[("conf", "0.5..1")]))["total"], 3);
        assert_eq!(c.query(&q(&[("q", "em_arm kenan")]))["total"], 2, "metadata and donor are searchable");
        assert_eq!(c.query(&q(&[("q", &hex::encode([2u8; 4])[..7])]))["total"], 1, "sha prefix");

        // Facets ignore their own dimension: other donors stay countable.
        let v = c.query(&q(&[("donor", "kenan"), ("facets", "1")]));
        assert_eq!(v["total"], 2);
        let donors = &v["facets"]["donor"]["values"];
        assert_eq!(donors.as_array().unwrap().len(), 2);
        assert_eq!(donors[0]["key"], "kenan");
        assert_eq!(donors[0]["sel"], "in");
        // …but the other facets follow the filter.
        let mut isas: Vec<&str> =
            v["facets"]["isa"]["values"].as_array().unwrap().iter().map(|x| x["key"].as_str().unwrap()).collect();
        isas.sort();
        assert_eq!(isas, ["arm", "i8051", "tricore"]);

        // Sorting, several keys, paging.
        let by_size = c.query(&q(&[("sort", "size:desc"), ("limit", "2")]));
        assert_eq!(shas(&by_size), ["fw3.bin", "fw1.bin"]);
        let page2 = c.query(&q(&[("sort", "size:desc"), ("limit", "2"), ("offset", "2")]));
        assert_eq!(shas(&page2), ["old4.img", "fw2.bin"]);
        let by_donor = c.query(&q(&[("sort", "donor,size")]));
        assert_eq!(shas(&by_donor), ["old4.img", "fw3.bin", "fw2.bin", "fw1.bin"]);
        let by_isa = c.query(&q(&[("sort", "isa")]));
        assert_eq!(shas(&by_isa)[0], "fw3.bin", "AArch64 sorts first by name");
        assert!(Query::parse(&HashMap::from([("sort".to_string(), "bogus".to_string())])).is_err());
    }

    #[test]
    fn tree_histograms_and_matrix() {
        let c = catalog();
        let v = c.query(&q(&[("tree", "family,isa"), ("matrix", "isa,format"), ("facets", "1")]));
        let nodes = v["tree"]["nodes"].as_array().unwrap();
        let arm = nodes.iter().find(|n| n["key"] == "arm").unwrap();
        assert_eq!(arm["files"], 2);
        let kids: Vec<&str> = arm["children"].as_array().unwrap().iter().map(|n| n["key"].as_str().unwrap()).collect();
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&"arm") && kids.contains(&"a_arch64"));
        // A file with an ARM and a TriCore slice counts in both families.
        assert_eq!(nodes.iter().find(|n| n["key"] == "infineon").unwrap()["files"], 1);
        // A tree level ignores its own filter (siblings stay visible).
        let v2 = c.query(&q(&[("tree", "family,isa"), ("isa", "i8051")]));
        assert!(v2["tree"]["nodes"].as_array().unwrap().len() >= 3);
        assert_eq!(v2["total"], 1);

        let sizes = v["hist"]["size"].as_array().unwrap();
        assert_eq!(sizes.iter().map(|b| b["files"].as_u64().unwrap()).sum::<u64>(), 4);
        assert_eq!(v["hist"]["time"]["step"], 3600);
        let m = &v["matrix"];
        assert_eq!(m["rows"].as_array().unwrap().len(), 5);
        let cells: u64 = m["cells"].as_array().unwrap().iter().flat_map(|r| r.as_array().unwrap()).map(|x| x.as_u64().unwrap()).sum();
        assert_eq!(cells, 5, "five (ISA, format) pairs over four files");

        let months = c.query(&q(&[("tree", "month")]));
        assert_eq!(months["tree"]["nodes"][0]["key"], "1970-01");
        assert_eq!(months["tree"]["nodes"][0]["range"], json!([0, 31 * 86_400 - 1]));
    }

    #[test]
    fn kinds() {
        let c = catalog();
        let mut lib = record(9, "kenan", 300, Some(summary("elf", Some("hexagon"), &[])), 400);
        lib.original_name = "libdsp_skel.so".into();
        c.put(&lib, Path::new("/nonexistent"));
        let v = c.query(&q(&[("facets", "1"), ("kind", "firmware")]));
        assert_eq!(v["total"], 4);
        let kinds = &v["facets"]["kind"]["values"];
        assert_eq!(kinds[0]["key"], "firmware");
        assert_eq!(kinds[0]["sel"], "in");
        assert_eq!(kinds[1]["key"], "library");
        assert_eq!(kinds[1]["label"], "shared library");
        assert_eq!(kinds[1]["files"], 1, "the facet ignores its own filter");
        let other = c.query(&q(&[("kind", "!firmware")]));
        assert_eq!(shas(&other), ["libdsp_skel.so"]);
        assert_eq!(other["rows"][0]["kind"], "library");
        assert_eq!(c.summary(500, "")["kinds"], json!({"firmware": 4, "program": 0, "library": 1, "object": 0, "package": 0}));
        let tree = c.query(&q(&[("tree", "kind,isa")]));
        assert_eq!(tree["tree"]["nodes"][1]["children"][0]["key"], "hexagon");
        assert_eq!(shas(&c.query(&q(&[("sort", "kind:desc,name")])))[0], "libdsp_skel.so");
    }

    #[test]
    fn summary_exports_and_helpers() {
        let c = catalog();
        let s = c.summary(300, "0.1.0@abc");
        assert_eq!(s["files"], 4);
        assert_eq!(s["stored"]["files"], 3);
        assert_eq!(s["queued"], 3, "kept, not posted");
        assert_eq!(s["pending"]["files"], 1);
        assert_eq!(s["named_donors"], 1);
        assert_eq!(s["older_zrax"], 0);
        assert!(s["wanted"].as_array().unwrap().iter().all(|w| w["isa"] != "arm"));
        assert_eq!(c.summary(300, "0.2.0@def")["older_zrax"], 3);

        let ids = c.matching(&q(&[("sort", "name")]));
        let rows = c.export_rows(&ids);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].2["name"], "fw1.bin");
        let line = csv_line(&rows[0].2);
        assert!(line.starts_with(&format!("{},fw1.bin,1000,kenan,firmware,arm,arm tricore,arm,elf,", hex::encode([1u8; 32]))), "{line}");
        assert_eq!(line.matches(',').count(), CSV_HEADER.matches(',').count());
        assert!(csv_line(&json!({"name": "a,\"b\""})).starts_with(",\"a,\"\"b\"\"\","));

        assert_eq!(ext_of("router.BIN"), "bin");
        assert_eq!(ext_of("noext"), "");
        assert_eq!(ext_of(".bashrc"), "");
        assert_eq!(ext_of("a.tar.gz"), "gz");
        assert_eq!(telegram_url(-1003917356862, 7 << 20).as_deref(), Some("https://t.me/c/3917356862/7"));
        assert_eq!(telegram_url(-5599544901, 7 << 20), None);
        assert_eq!(telegram_url(-1003917356862, 0), None);
        for unix in [0u64, 951_782_400, 1_793_646_669] {
            let (start, end, label) = month_range(month_index(unix));
            assert!(start <= unix && unix < end, "{label}");
            assert_eq!(label, &crate::ledger::date(unix)[..7]);
        }
    }
}
