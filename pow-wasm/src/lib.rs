//! Proof-of-work search for the donation page, as a small WASM module.
//!
//! The work hash is SHA-256(seed ‖ nonce_u64be) (see src/pow.rs): a 40-byte
//! message, so always exactly one 64-byte block. The search hashes eight
//! nonces per step: two independent groups of four SIMD lanes, interleaved
//! so the engine can overlap their dependency chains. The first nine rounds
//! depend only on the seed and the nonce's high word, so they are computed
//! once per call.
//!
//! Build: `cargo build --release` here (.cargo/config.toml selects the target
//! and SIMD); scripts/build.sh copies the result to dist/pow.wasm. The page
//! falls back to the JS search (web/sha256.js) without WASM SIMD.
//!
//! Exports, besides `memory`:
//!   pow_seed() -> ptr          32 bytes to write the seed into
//!   pow_search(hi, start, count, bits) -> i32
//!                              offset (from `start`) of the first nonce
//!                              hi:start+offset in `count` (a multiple of 8)
//!                              whose hash has `bits` (≤ 32) leading zero
//!                              bits, or -1

#![no_std]

#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
compile_error!("build for wasm32-unknown-unknown with +simd128 (see .cargo/config.toml)");

use core::arch::wasm32::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unreachable()
}

static mut SEED: [u8; 32] = [0; 32];

/// Groups of four nonces hashed side by side. Three or four were no faster
/// in V8 on arm64 and would spill registers on x86 (16 SIMD registers).
const STREAMS: usize = 2;

#[no_mangle]
pub extern "C" fn pow_seed() -> *mut u8 {
    core::ptr::addr_of_mut!(SEED).cast()
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

// Message words 10..15: padding for a 40-byte message.
const PAD: [u32; 6] = [0x8000_0000, 0, 0, 0, 0, 40 * 8];

fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// One scalar round on the state.
fn round(s: &mut [u32; 8], kw: u32) {
    let [a, b, c, d, e, f, g, h] = *s;
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ (!e & g);
    let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(kw);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    *s = [t1.wrapping_add(s0.wrapping_add(maj)), a, b, c, d.wrapping_add(t1), e, f, g];
}

#[inline(always)]
fn rotr(x: v128, n: u32) -> v128 {
    v128_or(u32x4_shr(x, n), u32x4_shl(x, 32 - n))
}

#[inline(always)]
fn add(a: v128, b: v128) -> v128 {
    u32x4_add(a, b)
}

#[inline(always)]
fn vsigma0(x: v128) -> v128 {
    v128_xor(v128_xor(rotr(x, 7), rotr(x, 18)), u32x4_shr(x, 3))
}

#[inline(always)]
fn vsigma1(x: v128) -> v128 {
    v128_xor(v128_xor(rotr(x, 17), rotr(x, 19)), u32x4_shr(x, 10))
}

#[no_mangle]
pub extern "C" fn pow_search(hi: u32, start: u32, count: u32, bits: u32) -> i32 {
    if bits == 0 {
        return 0;
    }
    // Top `bits` bits of the first digest word must be zero.
    let mask = u32x4_splat(if bits >= 32 { u32::MAX } else { !(u32::MAX >> bits) });

    // SAFETY: the page writes the seed before calling; nothing else aliases it.
    let seed = unsafe { core::ptr::read(core::ptr::addr_of!(SEED)) };
    let mut m = [0u32; 16];
    for (i, word) in m.iter_mut().take(8).enumerate() {
        *word = u32::from_be_bytes([seed[4 * i], seed[4 * i + 1], seed[4 * i + 2], seed[4 * i + 3]]);
    }
    m[8] = hi;
    m[10..16].copy_from_slice(&PAD);

    // Rounds 0..=8 don't involve the low nonce word.
    let mut pre = IV;
    for i in 0..9 {
        round(&mut pre, K[i].wrapping_add(m[i]));
    }
    // w[i] = σ1(w[i-2]) + w[i-7] + σ0(w[i-15]) + w[i-16]: w16 is a constant
    // plus the low nonce word, w17 doesn't involve it at all.
    let w16_base = small_sigma1(m[14]).wrapping_add(small_sigma0(m[1])).wrapping_add(m[0]);
    let w17 = small_sigma1(m[15]).wrapping_add(m[10]).wrapping_add(small_sigma0(m[2])).wrapping_add(m[1]);

    let mut offset = 0u32;
    while offset < count {
        let base = start.wrapping_add(offset);
        let mut lo = [u32x4_splat(0); STREAMS];
        for (j, l) in lo.iter_mut().enumerate() {
            *l = add(u32x4_splat(base.wrapping_add(4 * j as u32)), u32x4(0, 1, 2, 3));
        }
        let first = block(&pre, &m, w16_base, w17, lo);
        for (j, word) in first.iter().enumerate() {
            let hits = u32x4_bitmask(u32x4_eq(v128_and(*word, mask), u32x4_splat(0)));
            if hits != 0 {
                return (offset + 4 * j as u32 + hits.trailing_zeros()) as i32;
            }
        }
        offset += 4 * STREAMS as u32;
    }
    -1
}

/// Hash 4·N nonces (lanes of `lo`, interleaved so the engine can overlap the
/// independent dependency chains); returns the first digest word of each.
#[inline(always)]
fn block<const N: usize>(pre: &[u32; 8], m: &[u32; 16], w16_base: u32, w17: u32, lo: [v128; N]) -> [v128; N] {
    // Message schedule; words other than 9 and those derived from it are the
    // same in every lane.
    let mut w = [[u32x4_splat(0); N]; 64];
    for i in 0..16 {
        w[i] = [u32x4_splat(m[i]); N];
    }
    w[17] = [u32x4_splat(w17); N];
    for j in 0..N {
        w[9][j] = lo[j];
        w[16][j] = add(u32x4_splat(w16_base), lo[j]);
    }
    for i in 18..64 {
        for j in 0..N {
            w[i][j] = add(add(w[i - 16][j], vsigma0(w[i - 15][j])), add(w[i - 7][j], vsigma1(w[i - 2][j])));
        }
    }

    let mut st = [[u32x4_splat(0); N]; 8];
    for (k, v) in st.iter_mut().enumerate() {
        *v = [u32x4_splat(pre[k]); N];
    }
    for i in 9..64 {
        let k = u32x4_splat(K[i]);
        for j in 0..N {
            let [a, b, c, d, e, f, g, h] = [st[0][j], st[1][j], st[2][j], st[3][j], st[4][j], st[5][j], st[6][j], st[7][j]];
            let s1 = v128_xor(v128_xor(rotr(e, 6), rotr(e, 11)), rotr(e, 25));
            let ch = v128_xor(v128_and(e, f), v128_andnot(g, e));
            let t1 = add(add(h, s1), add(ch, add(k, w[i][j])));
            let s0 = v128_xor(v128_xor(rotr(a, 2), rotr(a, 13)), rotr(a, 22));
            let maj = v128_or(v128_and(a, b), v128_and(c, v128_or(a, b)));
            st[7][j] = g;
            st[6][j] = f;
            st[5][j] = e;
            st[4][j] = add(d, t1);
            st[3][j] = c;
            st[2][j] = b;
            st[1][j] = a;
            st[0][j] = add(t1, add(s0, maj));
        }
    }
    let mut first = [u32x4_splat(0); N];
    for j in 0..N {
        first[j] = add(st[0][j], u32x4_splat(IV[0]));
    }
    first
}
