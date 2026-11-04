//! Default accept/deny format lists. Names are zrax `FileFormat` serde names
//! (lowercase variant names), exactly as they appear in `classify()` JSON.
//! Both lists are overridable in `fwdonor.toml` and published at
//! `/api/policy`, so the browser applies the identical rule.

/// Firmware, filesystem and boot containers: accepted even when zrax cannot
/// resolve an ISA for their contents.
pub const DEFAULT_ALLOW: &[&str] = &[
    // Automotive / ECU
    "ols", "epr", "sgo", "vbf", "frf", "bcf", "sox", "d10", "odx", "hondarwd", "toyotacuw",
    "mercedescff",
    // TI boot and image families
    "tic55xboot", "tiboot", "tiais", "tirprc", "timulticore", "timcelf", "tiimage", "tioad",
    "tix509", "tiasciihex", "titagged", "titekhex", "titxt",
    // MCU / record formats and update packages
    "mcuboot", "fip", "intelhex", "srec", "espfirmware", "espflash", "blackfinldr", "uf2",
    "dfuse", "dfusuffix", "gbl", "cyacd", "silabsebl", "nordicinitpacket", "ihex2fw", "huaweiupdate",
    "ffu",
    // FPGA
    "xilinxbit", "latticebitstream", "intelfpga", "xilinxbootbin",
    // SoC boot images
    "allwinneregon", "allwinnerimage", "rockchipimage", "mediatekpreloader", "mediatekimage",
    "qualcommmbn",
    "imximage", "nxpsb", "amlogicupgrade", "opteeimage", "bareboximage",
    // Kernels and device trees
    "zimage", "uimage", "fit", "dtb", "chromeoskernel",
    // Android
    "androidboot", "androidvendorboot", "androidbootloader", "androidsparse", "androidota",
    "androidsuper", "androiddtbo", "androidvbmeta",
    // Apple
    "ftab", "uarp", "img4", "im4p", "img3", "apple8900", "lzss",
    // PC firmware
    "pcioptionrom", "uefifv", "uefite", "ueficapsule", "intelifd", "intelme", "amdpsp",
    "intelmicrocode", "amdmicrocode", "fmap", "cbfs",
    // Router / appliance firmware
    "trx", "netgearchk", "seama", "tplink", "mikrotiknpk", "ubiquitifw", "qnxifs", "winceimage",
    // Embedded filesystems
    "squashfs", "cramfs", "romfs", "ubi", "ubifs", "jffs2", "ext", "erofs",
];

/// Rejected even when an ISA is found: private data, game content, music,
/// and application bundles that are not firmware.
pub const DEFAULT_DENY: &[&str] = &[
    // Memory dumps, certificates and VM disks may hold private data.
    "minidump", "windowskerneldump", "x509", "qcow2", "vmdk", "vhd", "vhdx", "vdi",
    // Console / handheld ROMs, discs and game executables
    "nesrom", "snesrom", "n64rom", "gbrom", "gbarom", "ndsrom", "genesisrom", "smsrom",
    "sega32xrom", "msxrom", "lynxrom", "atari7800rom", "wonderswanrom", "ngprom", "c64crt",
    "gamecubedisc", "wiidisc", "xboxdvd", "xbe", "xex", "selfps3", "selfps4", "selfps5", "nso",
    "nro", "dol", "rel", "cia", "ncsd", "xci", "pfs0", "psppbp", "wbfs", "cso", "gcz", "ciso",
    "xboxstfs", "n3dsncch", "n3ds3dsx", "wiiurpx", "psxexe", "dreamcastip", "saturnip",
    "segacdip",
    // Retro disk / tape media
    "d64", "d71", "d81", "t64", "adf", "amigahdf", "atr", "atarixex", "apple2dos", "prodos",
    "twoimg", "cpcdsk", "plus3dos", "amsdos", "zxtape", "zxsnapshot",
    // Chiptunes and sound programs
    "nsf", "sid", "gbs", "psf", "hes", "kss", "sap", "aytune", "sndh", "snesspc",
    // Bytecode and application bundles
    "javaclass", "jimage", "jmod", "wasm", "llvmbc", "pyinstaller", "asar", "dotnetbundle",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_disjoint_and_lowercase() {
        for name in DEFAULT_ALLOW.iter().chain(DEFAULT_DENY) {
            assert_eq!(*name, name.to_lowercase(), "{name}");
        }
        for name in DEFAULT_ALLOW {
            assert!(!DEFAULT_DENY.contains(name), "{name} is on both lists");
        }
    }
}
