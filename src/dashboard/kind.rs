//! What kind of binary a donated image is: firmware, or something that runs
//! on an operating system (a program, a shared library, an object file or a
//! software package). Everything is welcome in the corpus; the dashboard only
//! keeps the two apart. Decided from the file's headers (ELF, PE, Mach-O),
//! the format zrax found and the original name.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Firmware = 0,
    Program = 1,
    Library = 2,
    Object = 3,
    Package = 4,
}

/// Key and label of each kind, indexed by `Kind as usize`.
pub const KINDS: [(&str, &str); 5] = [
    ("firmware", "firmware"),
    ("program", "program"),
    ("library", "shared library"),
    ("object", "object file"),
    ("package", "software package"),
];

impl Kind {
    pub fn key(self) -> &'static str {
        KINDS[self as usize].0
    }

    pub fn label(self) -> &'static str {
        KINDS[self as usize].1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub kind: Kind,
    /// Why, in a few words ("ELF, interpreter /system/bin/linker64").
    pub why: String,
}

fn verdict(kind: Kind, why: impl Into<String>) -> Verdict {
    Verdict { kind, why: why.into() }
}

/// Formats zrax names (`format_slug`) that are always programs for an
/// operating system or a VM.
const PROGRAM_FORMATS: [&str; 15] = [
    "dex", "pef", "ne", "le", "lx", "xbe", "xex", "nso", "nro", "wasm", "javaclass", "som", "xcoff", "ecoff", "aout",
];
/// ZIP variants (zrax labels) that are app packages.
const PACKAGE_VARIANTS: [&str; 3] = ["Android APK", "iOS IPA", "Java JAR"];

/// The kind of an image. `path` is the stored file (None: not in the store,
/// decided from the name and format alone).
pub fn classify(path: Option<&Path>, format: &str, variant: &str, name: &str) -> Verdict {
    // A record zrax no longer accepts has no format: go by the magic.
    let sniffed = if format.is_empty() { path.and_then(sniff) } else { None };
    let format = sniffed.unwrap_or(format);
    if format == "rpm" {
        return verdict(Kind::Package, "RPM package");
    }
    if format == "zip" && PACKAGE_VARIANTS.contains(&variant) {
        return verdict(Kind::Package, variant);
    }
    if PROGRAM_FORMATS.contains(&format) {
        return verdict(Kind::Program, format!("{format} executable"));
    }
    if format == "omf" {
        return verdict(Kind::Object, "OMF object");
    }
    if matches!(format, "elf" | "pe" | "mz" | "macho" | "machofat") {
        if let Some(file) = path.and_then(|p| File::open(p).ok()) {
            let r = Reader { file };
            let got = match format {
                "elf" => elf(&r, name),
                "pe" | "mz" => pe(&r),
                _ => macho(&r),
            };
            if let Some(v) = got {
                return v;
            }
        }
    }
    by_name(format, name)
}

fn sniff(path: &Path) -> Option<&'static str> {
    let mut magic = [0u8; 4];
    File::open(path).ok()?.read_exact_at(&mut magic, 0).ok()?;
    Some(match magic {
        [0x7f, b'E', b'L', b'F'] => "elf",
        [b'M', b'Z', ..] => "pe",
        [0xce | 0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xce | 0xcf] => "macho",
        _ => return None,
    })
}

/// Without the file: from the name (and format) only.
fn by_name(format: &str, name: &str) -> Verdict {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map_or("", |(_, e)| e);
    if (is_shared_name(&lower) && !is_split_image(&lower)) || matches!(ext, "dll" | "dylib") {
        return verdict(Kind::Library, "named as a shared library");
    }
    if matches!(ext, "o" | "ko" | "obj") {
        return verdict(Kind::Object, "named as an object file");
    }
    if matches!(format, "pe" | "mz") && ext == "exe" {
        return verdict(Kind::Program, "named as a program");
    }
    verdict(Kind::Firmware, "")
}

/// `.so`, `.so.1`, `.so.32-5` or `.so_zte_blade` names.
fn is_shared_name(lower: &str) -> bool {
    lower.match_indices(".so").any(|(i, _)| {
        let rest = &lower[i + 3..];
        rest.is_empty() || rest.starts_with(['.', '_', '-'])
    })
}

/// `lib…` (only a hint together with an ELF shared object).
fn lib_name(lower: &str) -> bool {
    let base = lower.rsplit('/').next().unwrap_or(lower);
    base.starts_with("lib") && base.len() > 3
}

/// Qualcomm split and signed images (`.mdt`, `.b00`…, `.mbn`, possibly with
/// a `_<digits>` suffix): firmware even when the ELF is a shared object
/// (TrustZone applications are).
fn is_split_image(lower: &str) -> bool {
    let stem = match lower.rsplit_once('_') {
        Some((s, digits)) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => s,
        _ => lower,
    };
    let Some((_, ext)) = stem.rsplit_once('.') else { return false };
    ext == "mdt" || ext == "mbn" || (ext.len() == 3 && ext.starts_with('b') && ext[1..].bytes().all(|b| b.is_ascii_digit()))
}

struct Reader {
    file: File,
}

impl Reader {
    /// Up to `len` bytes at `off` (fewer at the end of the file).
    fn read(&self, off: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        let mut got = 0;
        while got < len {
            match self.file.read_at(&mut buf[got..], off + got as u64) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        buf.truncate(got);
        buf
    }
}

#[derive(Clone, Copy)]
struct Endian {
    little: bool,
}

impl Endian {
    fn u16(self, b: &[u8], at: usize) -> Option<u16> {
        let x: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
        Some(if self.little { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) })
    }

    fn u32(self, b: &[u8], at: usize) -> Option<u32> {
        let x: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.little { u32::from_le_bytes(x) } else { u32::from_be_bytes(x) })
    }

    fn u64(self, b: &[u8], at: usize) -> Option<u64> {
        let x: [u8; 8] = b.get(at..at + 8)?.try_into().ok()?;
        Some(if self.little { u64::from_le_bytes(x) } else { u64::from_be_bytes(x) })
    }

    /// A 32- or 64-bit word.
    fn word(self, b: &[u8], at: usize, wide: bool) -> Option<u64> {
        if wide {
            self.u64(b, at)
        } else {
            self.u32(b, at).map(u64::from)
        }
    }
}

const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_SONAME: u64 = 14;

fn elf(r: &Reader, name: &str) -> Option<Verdict> {
    let h = r.read(0, 64);
    if h.len() < 52 || &h[..4] != b"\x7fELF" {
        return None;
    }
    let wide = h[4] == 2;
    let e = Endian { little: h[5] != 2 };
    let etype = e.u16(&h, 16)?;
    if etype == 1 {
        return Some(verdict(Kind::Object, "relocatable ELF"));
    }
    let (phoff, phentsize, phnum) = if wide {
        (e.u64(&h, 32)?, e.u16(&h, 54)?, e.u16(&h, 56)?)
    } else {
        (u64::from(e.u32(&h, 28)?), e.u16(&h, 42)?, e.u16(&h, 44)?)
    };
    let min_entry = if wide { 56 } else { 32 };
    let mut interp = None;
    let mut dynamic = None;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (vaddr, offset, filesz)
    let mut abi_tag = None;
    if phoff > 0 && usize::from(phentsize) >= min_entry && (1..=512).contains(&phnum) {
        let size = usize::from(phentsize);
        let table = r.read(phoff, size * usize::from(phnum));
        for ph in table.chunks_exact(size) {
            let ptype = e.u32(ph, 0)?;
            let (offset, vaddr, filesz) = if wide {
                (e.u64(ph, 8)?, e.u64(ph, 16)?, e.u64(ph, 32)?)
            } else {
                (u64::from(e.u32(ph, 4)?), u64::from(e.u32(ph, 8)?), u64::from(e.u32(ph, 16)?))
            };
            match ptype {
                1 => loads.push((vaddr, offset, filesz)),
                PT_INTERP => {
                    let bytes = r.read(offset, filesz.min(256) as usize);
                    let path = bytes.split(|&b| b == 0).next().unwrap_or_default();
                    interp = Some(String::from_utf8_lossy(path).into_owned());
                }
                PT_DYNAMIC => dynamic = Some((offset, filesz)),
                PT_NOTE if filesz <= 4096 => {
                    abi_tag = abi_tag.or_else(|| note_abi_tag(&r.read(offset, filesz as usize), e));
                }
                _ => {}
            }
        }
    }
    if let Some(path) = interp {
        let why = if path.is_empty() { "ELF with an interpreter".to_string() } else { format!("ELF, interpreter {path}") };
        return Some(verdict(Kind::Program, why));
    }
    let lower = name.to_ascii_lowercase();
    if let (3, Some((offset, filesz))) = (etype, dynamic) {
        if !is_split_image(&lower) {
            let d = dynamic_tags(r, e, wide, offset, filesz, &loads);
            if is_shared_name(&lower) || lib_name(&lower) || d.needed.is_some() || d.soname {
                let why = match d.needed {
                    Some(Some(lib)) => format!("ELF shared object, needs {lib}"),
                    _ => "ELF shared object".to_string(),
                };
                return Some(verdict(Kind::Library, why));
            }
        }
    }
    if let Some(os) = abi_tag {
        return Some(verdict(Kind::Program, format!("ELF with a {os} ABI tag")));
    }
    Some(verdict(Kind::Firmware, ""))
}

/// The OS of an ABI-tag note (type 1 from GNU, Android or a BSD), if any.
fn note_abi_tag(notes: &[u8], e: Endian) -> Option<&'static str> {
    let mut p = 0;
    while p + 12 <= notes.len() {
        let namesz = e.u32(notes, p)? as usize;
        let descsz = e.u32(notes, p + 4)? as usize;
        let ntype = e.u32(notes, p + 8)?;
        let name = notes.get(p + 12..p + 12 + namesz)?;
        let name = name.split(|&b| b == 0).next().unwrap_or_default();
        if ntype == 1 {
            for os in ["GNU", "Android", "FreeBSD", "NetBSD", "OpenBSD"] {
                if name == os.as_bytes() {
                    return Some(os);
                }
            }
        }
        p += 12 + namesz.div_ceil(4) * 4 + descsz.div_ceil(4) * 4;
    }
    None
}

struct DynamicTags {
    /// Some: has DT_NEEDED (with the first library's name when readable).
    needed: Option<Option<String>>,
    soname: bool,
}

fn dynamic_tags(r: &Reader, e: Endian, wide: bool, offset: u64, filesz: u64, loads: &[(u64, u64, u64)]) -> DynamicTags {
    let entry = if wide { 16 } else { 8 };
    let bytes = r.read(offset, filesz.min(64 * 1024) as usize);
    let mut first_needed = None;
    let mut strtab = None;
    let mut soname = false;
    for d in bytes.chunks_exact(entry) {
        let (Some(tag), Some(val)) = (e.word(d, 0, wide), e.word(d, entry / 2, wide)) else { break };
        match tag {
            0 => break,
            DT_NEEDED => first_needed = first_needed.or(Some(val)),
            DT_STRTAB => strtab = Some(val),
            DT_SONAME => soname = true,
            _ => {}
        }
    }
    let needed = first_needed.map(|name_off| {
        // DT_STRTAB is an address: find it in a loaded segment.
        let vaddr = strtab?.checked_add(name_off)?;
        let &(base, off, _) = loads.iter().find(|&&(v, _, s)| vaddr >= v && vaddr - v < s)?;
        let raw = r.read(off + (vaddr - base), 128);
        let lib = raw.split(|&b| b == 0).next()?;
        (!lib.is_empty() && lib.iter().all(|b| b.is_ascii_graphic())).then(|| String::from_utf8_lossy(lib).into_owned())
    });
    DynamicTags { needed, soname }
}

fn pe(r: &Reader) -> Option<Verdict> {
    let h = r.read(0, 64);
    if h.len() < 64 || &h[..2] != b"MZ" {
        return None;
    }
    let le = Endian { little: true };
    let lfanew = u64::from(le.u32(&h, 0x3c)?);
    let p = if lfanew >= 0x40 && lfanew < 1 << 24 { r.read(lfanew, 0x60) } else { Vec::new() };
    if p.len() < 0x5e || &p[..4] != b"PE\0\0" {
        return Some(verdict(Kind::Program, "DOS executable"));
    }
    let characteristics = le.u16(&p, 22)?;
    let subsystem = le.u16(&p, 24 + 68)?;
    let dll = characteristics & 0x2000 != 0;
    Some(match subsystem {
        0 => verdict(Kind::Firmware, ""),
        10 => verdict(Kind::Program, "PE, EFI application"),
        11..=13 => verdict(Kind::Firmware, "PE, EFI driver"),
        s => {
            let what = match s {
                1 => "native",
                2 => "Windows GUI",
                3 => "Windows console",
                5 => "OS/2",
                7 => "POSIX",
                9 => "Windows CE",
                14 => "Xbox",
                16 => "Windows boot",
                _ => "subsystem",
            };
            let what = if what == "subsystem" { format!("subsystem {s}") } else { what.to_string() };
            if dll {
                verdict(Kind::Library, format!("PE DLL, {what}"))
            } else {
                verdict(Kind::Program, format!("PE, {what}"))
            }
        }
    })
}

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_LOAD_DYLINKER: u32 = 0xe;

fn macho(r: &Reader) -> Option<Verdict> {
    let mut base = 0u64;
    let mut h = r.read(0, 32);
    if h.len() >= 8 && u32::from_be_bytes(h[..4].try_into().ok()?) == FAT_MAGIC {
        // The first architecture's slice.
        let arch = r.read(8, 20);
        base = u64::from(Endian { little: false }.u32(&arch, 8)?);
        h = r.read(base, 32);
    }
    if h.len() < 28 {
        return None;
    }
    let raw = u32::from_le_bytes(h[..4].try_into().ok()?);
    let (e, wide) = match raw {
        MH_MAGIC => (Endian { little: true }, false),
        MH_MAGIC_64 => (Endian { little: true }, true),
        _ => match raw.swap_bytes() {
            MH_MAGIC => (Endian { little: false }, false),
            MH_MAGIC_64 => (Endian { little: false }, true),
            _ => return None,
        },
    };
    let filetype = e.u32(&h, 12)?;
    let ncmds = e.u32(&h, 16)?;
    let sizeofcmds = e.u32(&h, 20)?;
    Some(match filetype {
        1 => verdict(Kind::Object, "Mach-O object"),
        6 | 7 | 8 | 0xb => verdict(Kind::Library, "Mach-O library"),
        2 => {
            let cmds = r.read(base + if wide { 32 } else { 28 }, sizeofcmds.min(1 << 20) as usize);
            let mut p = 0usize;
            let mut dylinker = false;
            for _ in 0..ncmds.min(4096) {
                let (Some(cmd), Some(size)) = (e.u32(&cmds, p), e.u32(&cmds, p + 4)) else { break };
                if cmd == LC_LOAD_DYLINKER {
                    dylinker = true;
                    break;
                }
                if size < 8 {
                    break;
                }
                p += size as usize;
            }
            if dylinker {
                verdict(Kind::Program, "Mach-O executable, dynamically linked")
            } else {
                verdict(Kind::Firmware, "")
            }
        }
        _ => verdict(Kind::Firmware, ""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    fn kind_of(bytes: &[u8], format: &str, name: &str) -> Verdict {
        let f = file(bytes);
        classify(Some(f.path()), format, "", name)
    }

    /// A little-endian ELF64 for AArch64 with the given type and program
    /// headers (type, offset, vaddr, filesz), followed by `tail` at 0x200.
    fn elf64(etype: u16, phdrs: &[(u32, u64, u64, u64)], tail: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&etype.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, &(t, off, vaddr, size)) in phdrs.iter().enumerate() {
            let at = 64 + i * 56;
            b[at..at + 4].copy_from_slice(&t.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            b[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            b[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
        }
        b.extend_from_slice(tail);
        b
    }

    /// A shared object: one PT_LOAD over the whole file, a dynamic section
    /// with DT_NEEDED → "libc.so" and DT_STRTAB.
    fn shared_object(needed: bool) -> Vec<u8> {
        let mut tail = Vec::new();
        let strtab = 0x200 + 0x40;
        for (tag, val) in [(if needed { DT_NEEDED } else { 0x6fff_fff0 }, 1u64), (DT_STRTAB, strtab), (0, 0)] {
            tail.extend_from_slice(&tag.to_le_bytes());
            tail.extend_from_slice(&val.to_le_bytes());
        }
        tail.resize(0x40, 0);
        tail.extend_from_slice(b"\0libc.so\0");
        let total = 0x200 + tail.len() as u64;
        elf64(3, &[(1, 0, 0, total), (PT_DYNAMIC, 0x200, 0x200, 48)], &tail)
    }

    #[test]
    fn elf_kinds() {
        assert_eq!(kind_of(&elf64(1, &[], &[]), "elf", "CanTrcv.o").kind, Kind::Object);
        let program = elf64(2, &[(PT_INTERP, 0x200, 0, 20)], b"/lib/ld-linux.so.3\0\0");
        assert_eq!(kind_of(&program, "elf", "tool").why, "ELF, interpreter /lib/ld-linux.so.3");
        assert_eq!(kind_of(&program, "elf", "tool").kind, Kind::Program);

        let so = shared_object(true);
        let v = kind_of(&so, "elf", "chre_pal");
        assert_eq!((v.kind, v.why.as_str()), (Kind::Library, "ELF shared object, needs libc.so"));
        // Named as a library, without DT_NEEDED.
        assert_eq!(kind_of(&shared_object(false), "elf", "skel.so.1").kind, Kind::Library);
        assert_eq!(kind_of(&shared_object(false), "elf", "fastrpc_shell_3").kind, Kind::Firmware);
        // Qualcomm TrustZone applications are shared objects too.
        assert_eq!(kind_of(&so, "elf", "widevine.mdt").kind, Kind::Firmware);
        assert_eq!(kind_of(&so, "elf", "widevine.b00_1677637693").kind, Kind::Firmware);
        assert_eq!(kind_of(&so, "elf", "cmnlib64.mbn").kind, Kind::Firmware);

        assert_eq!(kind_of(&elf64(2, &[(1, 0, 0, 0x200)], &[]), "elf", "modem.elf").kind, Kind::Firmware);
        let mut note = Vec::new();
        for x in [4u32, 16, 1] {
            note.extend_from_slice(&x.to_le_bytes());
        }
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0; 16]);
        let tagged = elf64(2, &[(PT_NOTE, 0x200, 0, note.len() as u64)], &note);
        assert_eq!(kind_of(&tagged, "elf", "busybox").why, "ELF with a GNU ABI tag");
        // Not an ELF after all, or not readable: by name.
        assert_eq!(kind_of(b"nope", "elf", "x.bin").kind, Kind::Firmware);
    }

    fn pe32(characteristics: u16, subsystem: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x80 + 22..0x80 + 24].copy_from_slice(&characteristics.to_le_bytes());
        b[0x80 + 24..0x80 + 26].copy_from_slice(&0x10bu16.to_le_bytes());
        b[0x80 + 24 + 68..0x80 + 24 + 70].copy_from_slice(&subsystem.to_le_bytes());
        b
    }

    #[test]
    fn pe_kinds() {
        assert_eq!(kind_of(&pe32(0x0102, 2), "pe", "a.exe").why, "PE, Windows GUI");
        assert_eq!(kind_of(&pe32(0x2102, 3), "pe", "a.dll").kind, Kind::Library);
        assert_eq!(kind_of(&pe32(0x2102, 10), "pe", "storcli.efi").kind, Kind::Program);
        assert_eq!(kind_of(&pe32(0x2102, 11), "pe", "dxe.efi").kind, Kind::Firmware);
        let mut dos = vec![0u8; 0x100];
        dos[..2].copy_from_slice(b"MZ");
        assert_eq!(kind_of(&dos, "mz", "DASH.EXE").why, "DOS executable");
    }

    fn macho64(filetype: u32, cmds: &[u32]) -> Vec<u8> {
        let mut b = Vec::new();
        for x in [MH_MAGIC_64, 0x0100_000c, 0, filetype, cmds.len() as u32, 16 * cmds.len() as u32, 0, 0] {
            b.extend_from_slice(&x.to_le_bytes());
        }
        for &c in cmds {
            for x in [c, 16, 0, 0] {
                b.extend_from_slice(&x.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn macho_kinds() {
        assert_eq!(kind_of(&macho64(6, &[]), "macho", "libz.dylib").kind, Kind::Library);
        assert_eq!(kind_of(&macho64(2, &[0x19, LC_LOAD_DYLINKER]), "macho", "ls").kind, Kind::Program);
        assert_eq!(kind_of(&macho64(2, &[0x19]), "macho", "rtkit").kind, Kind::Firmware);
        assert_eq!(kind_of(&macho64(1, &[]), "macho", "a.o").kind, Kind::Object);
    }

    #[test]
    fn formats_and_names() {
        assert_eq!(classify(None, "rpm", "RPM package", "bash.rpm").kind, Kind::Package);
        assert_eq!(classify(None, "zip", "Android APK", "app.apk").kind, Kind::Package);
        assert_eq!(classify(None, "zip", "Nordic DFU package", "dfu.zip").kind, Kind::Firmware);
        assert_eq!(classify(None, "dex", "", "classes.dex").kind, Kind::Program);
        assert_eq!(classify(None, "elf", "", "libfoo.so.1").kind, Kind::Library);
        assert_eq!(classify(None, "elf", "", "libfoo.so.mbn").kind, Kind::Firmware);
        assert_eq!(classify(None, "raw", "", "library.bin").kind, Kind::Firmware);
        assert_eq!(classify(None, "elf", "", "mod.ko").kind, Kind::Object);
        assert_eq!(classify(None, "pe", "", "setup.exe").kind, Kind::Program);
        assert_eq!(classify(None, "raw", "", "flash.bin").kind, Kind::Firmware);
        // No format (zrax no longer accepts it): by the magic.
        let f = file(&shared_object(true));
        assert_eq!(classify(Some(f.path()), "", "", "x").kind, Kind::Library);
        assert!(is_shared_name("storelib.so.32-5") && is_shared_name("gps.default.so_zte") && !is_shared_name("also.sorted"));
    }
}
