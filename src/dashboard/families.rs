//! ISA families for the dashboard's tree, following the grouping in zrax's
//! own `Isa` enum (vendor/zrax/src/types.rs). ISAs zrax adds later land in
//! "other" until they are listed here.

use serde_json::Value;
use zrax::types::Isa;

/// `(key, label)` of the family an ISA (zrax serde name) belongs to.
pub fn family(isa_key: &str) -> (&'static str, &'static str) {
    let Ok(isa) = serde_json::from_value::<Isa>(Value::String(isa_key.to_string())) else {
        return OTHER;
    };
    of(&isa)
}

const OTHER: (&str, &str) = ("other", "Other");

fn of(isa: &Isa) -> (&'static str, &'static str) {
    use Isa::*;
    match isa {
        X86 | X86_64 => ("x86", "x86"),
        Arm | AArch64 => ("arm", "ARM"),
        RiscV32 | RiscV64 | RiscV128 => ("riscv", "RISC-V"),
        Mips | Mips64 => ("mips", "MIPS"),
        Ppc | Ppc64 | PpcVle | CellSpu => ("powerpc", "PowerPC / Cell"),
        S390 | S390x => ("s390", "IBM mainframe"),
        Sparc | Sparc64 => ("sparc", "SPARC"),
        M68k | ColdFire => ("m68k", "Motorola 68k / ColdFire"),
        Sh | Sh4 => ("superh", "SuperH"),
        LoongArch32 | LoongArch64 => ("loongarch", "LoongArch"),
        Hexagon => ("hexagon", "Qualcomm Hexagon"),
        Arc | ArcCompact | ArcCompact2 => ("arc", "Synopsys ARC"),
        Xtensa => ("xtensa", "Tensilica Xtensa"),
        MicroBlaze | Nios2 | OpenRisc => ("softcore", "FPGA soft cores / OpenRISC"),
        Lanai | Csky | Nds32 | Kvx | Elbrus | McstElbrus | Tile64 | TilePro | TileGx => ("risc", "Other RISC / VLIW"),
        V850 | Rh850 | K78k0r | Rl78 | Rx | H8300 | H8500 | M32r | M16c | R32c | M7700 | M740 => {
            ("renesas", "Renesas / NEC / Mitsubishi")
        }
        TiC6000 | TiC2000 | TiC28x | TiC5500 | TiC5400 | TiC3x | TiPru | Msp430 => ("ti", "Texas Instruments"),
        Blackfin | Sharc | Adsp21xx => ("adi", "Analog Devices DSP"),
        Dsp56k | Dsp96k | OakDsp | TriMedia => ("dsp", "Other DSP"),
        Tricore | C166 => ("infineon", "Infineon / Siemens"),
        Hcs12 | S12z | Hc11 | Hc05 | Hc08 | Hc16 | M6800 | M6809 => ("motorola8", "Motorola / NXP 8/16-bit"),
        I8051 | Xa | Mcs96 => ("mcs", "Intel MCS-51 / MCS-96"),
        Z80 | Z8 | Mcs6502 | W65816 | Spc700 => ("classic8", "Z80 / 6502 classics"),
        Avr | Avr32 | Pic => ("microchip", "Microchip / Atmel"),
        Stm8 | St7 | St9 | St20 => ("st", "STMicroelectronics"),
        Frv | Fr30 | Fr80 | F2mc16 => ("fujitsu", "Fujitsu"),
        Tlcs900 | Mn10200 | Cr16 | C39 | Unsp | Kr1878 => ("mcu", "Other microcontrollers"),
        AmdGpu | Cuda | VideoCore3 | VideoCore5 => ("gpu", "GPU / media processors"),
        Vax | Pdp11 | Alpha | Parisc | Ia64 | I860 | I960 => ("legacy", "Legacy workstation / mini"),
        Wasm | Jvm | Dalvik | Clr | Ebc | Bpf | Clemency => ("vm", "Bytecode / virtual machines"),
        _ => OTHER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_and_fallback() {
        assert_eq!(family("arm").0, "arm");
        assert_eq!(family("a_arch64").0, "arm");
        assert_eq!(family("i8051").0, "mcs");
        assert_eq!(family("mcs96").0, "mcs");
        assert_eq!(family("c166").0, "infineon");
        assert_eq!(family("nonsense"), OTHER);
        // Every ISA the raw-code model knows has a family of its own.
        for raw in crate::analyze::raw_isas() {
            assert_ne!(family(&raw.key), OTHER, "{} has no family", raw.key);
        }
    }
}
