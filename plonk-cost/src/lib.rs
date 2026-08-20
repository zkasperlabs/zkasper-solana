//! A BN254 PLONK verifier for Zisk's on-chain wrap, on Solana.
//!
//! This exists to answer one question with a number rather than a guess: what
//! does verifying a `cargo-zisk wrap --plonk` proof cost in compute units? The
//! Groth16 path `zkasper-solana-program` takes is a fixed three-pairing check
//! and lands at 86,699 CU. PLONK is a different shape — eighteen scalar
//! multiplications, eighteen point additions, a two-pair pairing, and about
//! ninety `Fr` multiplications with no syscall behind them — and nothing in the
//! tree said what that came to.
//!
//! It is a line-for-line transliteration of the snarkjs verifier Zisk ships as
//! `zisk-contracts/PlonkVerifier.sol`, so the operation count is the real one
//! and not a model of one. Where the Solidity reaches for a precompile this
//! reaches for the matching `alt_bn128` syscall; where it uses `mulmod` this
//! uses `ark_bn254::Fr`, which is what an implementer would actually write.
//!
//! The [`Mode`] dispatch exists so the total can be decomposed: each mode is a
//! separate transaction, and the difference between two of them is the cost of
//! what changed.

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
pub mod vk;

use ark_bn254::{Fq, Fr};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, Zero};
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
};
use solana_program::keccak;
use vk::G1;

/// `uint256[24]`: nine G1 commitments then six opening evaluations.
pub const PROOF_LEN: usize = 768;
/// `StreamFinalOutput`, the bytes the guest commits.
pub const PUBLICS_LEN: usize = 176;
/// Zisk's public window is a fixed 64 slots; v1.0.0-alpha views them as u32.
pub const PUBLIC_VALUES_LEN: usize = 256;

/// The guest whose proof this verifies. Pinned, exactly as the Groth16 program
/// pins its verifying key.
pub const PROGRAM_VK: [u8; 32] = [
    0xe4, 0x32, 0x2c, 0xd5, 0xd0, 0x1f, 0xeb, 0x7f, 0x23, 0x37, 0xeb, 0xb0, 0xa0, 0x6d, 0x93, 0x14,
    0x60, 0xf3, 0xc3, 0x29, 0x4f, 0xea, 0x88, 0x2e, 0x7f, 0x64, 0x7c, 0x0f, 0xfd, 0x70, 0xf2, 0xec,
];

/// `rootCVadcopFinal`, which names the VADCOP final verification key and so
/// pins the Zisk release as well as the guest.
pub const ROOT_C: [u8; 32] = [
    0xe3, 0xd9, 0x7c, 0x4d, 0xfb, 0xa6, 0xc9, 0xa6, 0x25, 0x3b, 0xa5, 0xa8, 0x66, 0xfe, 0x16, 0xcc,
    0x82, 0xc0, 0x91, 0x42, 0x98, 0x52, 0x4e, 0x94, 0x61, 0xe3, 0x03, 0xab, 0xde, 0xcd, 0x7f, 0xcc,
];

// ---------------------------------------------------------------------------
// Field and group helpers
// ---------------------------------------------------------------------------

/// Reduce a 256-bit big-endian value into `Fr`.
///
/// `from_be_bytes_mod_order` is the obvious call and costs about 6,000 units;
/// two `u128` halves and one multiplication is the same answer for a tenth of
/// that. Only the transcript needs it — everything else arrives canonical.
fn fr_reduce(bytes: &[u8]) -> Fr {
    let hi = u128::from_be_bytes(bytes[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(bytes[16..32].try_into().unwrap());
    Fr::from(hi) * (Fr::from(u128::MAX) + Fr::from(1u64)) + Fr::from(lo)
}

/// Parse a canonical field element, which is `checkField` and the parse in one:
/// `from_bigint` is `None` exactly when the value is not below the modulus.
fn fr_canonical(bytes: &[u8]) -> Option<Fr> {
    Fr::from_bigint(be_limbs(bytes))
}

fn fq_canonical(bytes: &[u8]) -> Option<Fq> {
    Fq::from_bigint(be_limbs(bytes))
}

fn be_limbs(bytes: &[u8]) -> BigInt<4> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().rev().enumerate() {
        *limb = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    BigInt(limbs)
}

/// The inverse, without the `Vec` that `to_bytes_be` allocates. Called once per
/// scalar multiplication, so eighteen times a verification.
fn fr_bytes(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in x.into_bigint().0.iter().rev().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// `y^2 == x^3 + 3` over the base field, with both coordinates canonical.
///
/// Redundant on Solana: every commitment in the proof is fed to an `alt_bn128`
/// syscall, and the syscall rejects a point that is not in the group. Kept so
/// its cost can be quoted separately.
fn on_curve(point: &G1) -> bool {
    let (Some(x), Some(y)) = (fq_canonical(&point[..32]), fq_canonical(&point[32..])) else {
        return false;
    };
    y * y == x * x * x + Fq::from(3u64)
}

fn g1_mul(point: &G1, scalar: &Fr) -> G1 {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(&fr_bytes(scalar));
    let out = alt_bn128_g1_multiplication_be(&input).expect("g1 mul");
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

fn g1_add(a: &G1, b: &G1) -> G1 {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);
    let out = alt_bn128_g1_addition_be(&input).expect("g1 add");
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// `(x, y)` becomes `(x, -y)`. Free — one field negation, no syscall.
fn g1_neg(point: &G1) -> G1 {
    let y = Fq::from_be_bytes_mod_order(&point[32..]);
    let mut out = *point;
    if !y.is_zero() {
        out[32..].copy_from_slice(&(-y).into_bigint().to_bytes_be());
    }
    out
}

/// `acc = acc + point * scalar`, the Solidity's `g1_mulAcc`.
fn g1_mul_acc(acc: &G1, point: &G1, scalar: &Fr) -> G1 {
    g1_add(acc, &g1_mul(point, scalar))
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

pub struct Proof<'a> {
    pub a: G1,
    pub b: G1,
    pub c: G1,
    pub z: G1,
    pub t1: G1,
    pub t2: G1,
    pub t3: G1,
    pub wxi: G1,
    pub wxiw: G1,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_s1: Fr,
    pub eval_s2: Fr,
    pub eval_zw: Fr,
    /// Borrowed rather than copied: the transcript hashes the wire bytes, not
    /// the field elements, and 768 bytes of proof plus 576 of points does not
    /// fit an SBF stack frame.
    raw: &'a [u8],
}

impl<'a> Proof<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let raw: &[u8; PROOF_LEN] = bytes.try_into().ok()?;
        let point = |i: usize| -> G1 {
            let mut p = [0u8; 64];
            p.copy_from_slice(&raw[i * 32..i * 32 + 64]);
            p
        };
        let word = |i: usize| -> [u8; 32] {
            let mut w = [0u8; 32];
            w.copy_from_slice(&raw[i * 32..i * 32 + 32]);
            w
        };
        Some(Self {
            a: point(0),
            b: point(2),
            c: point(4),
            z: point(6),
            t1: point(8),
            t2: point(10),
            t3: point(12),
            wxi: point(14),
            wxiw: point(16),
            eval_a: fr_canonical(&word(18))?,
            eval_b: fr_canonical(&word(19))?,
            eval_c: fr_canonical(&word(20))?,
            eval_s1: fr_canonical(&word(21))?,
            eval_s2: fr_canonical(&word(22))?,
            eval_zw: fr_canonical(&word(23))?,
            raw,
        })
    }

    fn commitments(&self) -> [&G1; 9] {
        [
            &self.a, &self.b, &self.c, &self.z, &self.t1, &self.t2, &self.t3, &self.wxi, &self.wxiw,
        ]
    }

    /// `checkProofData`. The evaluations were range-checked in
    /// [`Proof::parse`]; what is left is nine curve-membership tests.
    pub fn well_formed(&self) -> bool {
        self.commitments().iter().all(|p| on_curve(p))
    }
}

/// The single public input: `sha256(programVK || publicValues || rootC) mod r`,
/// over the 64-slot window with the guest's output zero-padded into it.
pub fn public_input(publics: &[u8]) -> Fr {
    let mut preimage = [0u8; 32 + PUBLIC_VALUES_LEN + 32];
    preimage[..32].copy_from_slice(&PROGRAM_VK);
    preimage[32..32 + publics.len()].copy_from_slice(publics);
    preimage[32 + PUBLIC_VALUES_LEN..].copy_from_slice(&ROOT_C);
    fr_reduce(solana_program::hash::hash(&preimage).as_ref())
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

struct Challenges {
    alpha: Fr,
    alpha2: Fr,
    beta: Fr,
    gamma: Fr,
    xi: Fr,
    xin: Fr,
    beta_xi: Fr,
    zh: Fr,
    v: [Fr; 5],
    u: Fr,
}

fn challenges(proof: &Proof, pi: &Fr) -> Challenges {
    let mut t = [0u8; 736];
    for (i, p) in [
        vk::QM,
        vk::QL,
        vk::QR,
        vk::QO,
        vk::QC,
        vk::S1,
        vk::S2,
        vk::S3,
    ]
    .iter()
    .enumerate()
    {
        t[i * 64..i * 64 + 64].copy_from_slice(p);
    }
    t[512..544].copy_from_slice(&fr_bytes(pi));
    t[544..608].copy_from_slice(&proof.a);
    t[608..672].copy_from_slice(&proof.b);
    t[672..736].copy_from_slice(&proof.c);
    let beta = fr_reduce(keccak::hash(&t).as_ref());

    let gamma = fr_reduce(keccak::hash(&fr_bytes(&beta)).as_ref());

    let mut t = [0u8; 128];
    t[..32].copy_from_slice(&fr_bytes(&beta));
    t[32..64].copy_from_slice(&fr_bytes(&gamma));
    t[64..].copy_from_slice(&proof.z);
    let alpha = fr_reduce(keccak::hash(&t).as_ref());

    let mut t = [0u8; 224];
    t[..32].copy_from_slice(&fr_bytes(&alpha));
    t[32..96].copy_from_slice(&proof.t1);
    t[96..160].copy_from_slice(&proof.t2);
    t[160..224].copy_from_slice(&proof.t3);
    let xi = fr_reduce(keccak::hash(&t).as_ref());

    let mut t = [0u8; 224];
    t[..32].copy_from_slice(&fr_bytes(&xi));
    t[32..224].copy_from_slice(&proof.raw[576..768]);
    let v1 = fr_reduce(keccak::hash(&t).as_ref());

    let mut t = [0u8; 128];
    t[..64].copy_from_slice(&proof.wxi);
    t[64..].copy_from_slice(&proof.wxiw);
    let u = fr_reduce(keccak::hash(&t).as_ref());

    let beta_xi = beta * xi;
    let mut xin = xi;
    for _ in 0..vk::POWER {
        xin = xin * xin;
    }
    let zh = xin - Fr::from(1u64);

    let v2 = v1 * v1;
    let v3 = v2 * v1;
    let v4 = v3 * v1;
    let v5 = v4 * v1;

    Challenges {
        alpha,
        alpha2: alpha * alpha,
        beta,
        gamma,
        xi,
        xin,
        beta_xi,
        zh,
        v: [v1, v2, v3, v4, v5],
        u,
    }
}

/// `L_1(xi) = zh / (n * (xi - 1))`, through the same two-element batch
/// inversion the Solidity does — one `Fr` inversion and three multiplications.
fn lagrange_1(c: &Challenges) -> Fr {
    let denominator = Fr::from(vk::N) * (c.xi - Fr::from(1u64));

    let mut acc = c.zh * denominator;
    // 50,139 units of software extended-Euclid, and there is no cheaper route:
    // `sol_big_mod_exp` would invert by Fermat for the 238 units its published
    // price implies, but an SBPF v3 program under agave 4.1.2 cannot reach it —
    // the call comes back "unsupported BPF instruction" even with mainnet's
    // feature set active.
    acc = acc.inverse().expect("the domain does not vanish at xi");
    let eval_l1_inv = acc * c.zh;
    // `zh_inv` is computed and, with one Lagrange polynomial, unused — the
    // batch costs the same either way, so the port keeps it.
    let _zh_inv = acc * denominator;

    eval_l1_inv * c.zh
}

fn eval_r0(proof: &Proof, c: &Challenges, pi: &Fr, eval_l1: &Fr) -> Fr {
    let e2 = *eval_l1 * c.alpha2;
    let e3a = proof.eval_a + c.beta * proof.eval_s1 + c.gamma;
    let e3b = proof.eval_b + c.beta * proof.eval_s2 + c.gamma;
    let e3c = proof.eval_c + c.gamma;
    let e3 = e3a * e3b * e3c * proof.eval_zw * c.alpha;
    *pi - e2 - e3
}

fn calculate_d(proof: &Proof, c: &Challenges, eval_l1: &Fr) -> G1 {
    let mut d = vk::QC;
    d = g1_mul_acc(&d, &vk::QM, &(proof.eval_a * proof.eval_b));
    d = g1_mul_acc(&d, &vk::QL, &proof.eval_a);
    d = g1_mul_acc(&d, &vk::QR, &proof.eval_b);
    d = g1_mul_acc(&d, &vk::QO, &proof.eval_c);

    let val1 = proof.eval_a + c.beta_xi + c.gamma;
    let val2 = proof.eval_b + c.beta_xi * Fr::from(vk::K1) + c.gamma;
    let val3 = proof.eval_c + c.beta_xi * Fr::from(vk::K2) + c.gamma;
    let d2 = g1_mul(
        &proof.z,
        &(val1 * val2 * val3 * c.alpha + *eval_l1 * c.alpha2 + c.u),
    );

    let val1 = proof.eval_a + c.beta * proof.eval_s1 + c.gamma;
    let val2 = proof.eval_b + c.beta * proof.eval_s2 + c.gamma;
    let val3 = c.alpha * c.beta * proof.eval_zw;
    let d3 = g1_mul(&vk::S3, &(val1 * val2 * val3));

    let mut d4 = proof.t1;
    d4 = g1_mul_acc(&d4, &proof.t2, &c.xin);
    d4 = g1_mul_acc(&d4, &proof.t3, &(c.xin * c.xin));
    let d4 = g1_mul(&d4, &c.zh);

    let d = g1_add(&d, &d2);
    let d = g1_add(&d, &g1_neg(&d3));
    g1_add(&d, &g1_neg(&d4))
}

fn calculate_f(proof: &Proof, c: &Challenges, d: &G1) -> G1 {
    let mut f = g1_mul_acc(d, &proof.a, &c.v[0]);
    f = g1_mul_acc(&f, &proof.b, &c.v[1]);
    f = g1_mul_acc(&f, &proof.c, &c.v[2]);
    f = g1_mul_acc(&f, &vk::S1, &c.v[3]);
    g1_mul_acc(&f, &vk::S2, &c.v[4])
}

fn calculate_e(proof: &Proof, c: &Challenges, r0: &Fr) -> G1 {
    let s = -*r0
        + proof.eval_a * c.v[0]
        + proof.eval_b * c.v[1]
        + proof.eval_c * c.v[2]
        + proof.eval_s1 * c.v[3]
        + proof.eval_s2 * c.v[4]
        + proof.eval_zw * c.u;
    g1_mul(&vk::G1_GEN, &s)
}

fn check_pairing(proof: &Proof, c: &Challenges, f: &G1, e: &G1) -> bool {
    let a1 = g1_neg(&g1_add(&g1_mul(&proof.wxiw, &c.u), &proof.wxi));

    let b1 = g1_mul(&proof.wxi, &c.xi);
    let b1 = g1_add(
        &b1,
        &g1_mul(
            &proof.wxiw,
            &(c.u * c.xi * fr_canonical(&vk::W1).expect("w1 is canonical")),
        ),
    );
    let b1 = g1_add(&b1, f);
    let b1 = g1_add(&b1, &g1_neg(e));

    let mut input = [0u8; 384];
    input[..64].copy_from_slice(&a1);
    input[64..192].copy_from_slice(&vk::X_2);
    input[192..256].copy_from_slice(&b1);
    input[256..].copy_from_slice(&vk::G2_GEN);
    match alt_bn128_pairing_be(&input) {
        Ok(out) => out.last() == Some(&1),
        Err(_) => false,
    }
}

/// Verify a wrapped Zisk proof against the guest output it claims.
pub fn verify(proof_bytes: &[u8], publics: &[u8]) -> bool {
    verify_with(proof_bytes, publics, true)
}

/// `check_membership` is the `checkProofData` the Solidity runs before anything
/// else. On Solana the syscalls do it, so it can be dropped; it is a parameter
/// rather than a deletion so both costs stay measurable.
pub fn verify_with(proof_bytes: &[u8], publics: &[u8], check_membership: bool) -> bool {
    let Some(proof) = Proof::parse(proof_bytes) else {
        return false;
    };
    if check_membership && !proof.well_formed() {
        return false;
    }
    let pi = public_input(publics);
    let c = challenges(&proof, &pi);
    let eval_l1 = lagrange_1(&c);
    // `PI(xi)` for one public input.
    let pi_xi = -(eval_l1 * pi);
    let r0 = eval_r0(&proof, &c, &pi_xi, &eval_l1);
    let d = calculate_d(&proof, &c, &eval_l1);
    let f = calculate_f(&proof, &c, &d);
    let e = calculate_e(&proof, &c, &r0);
    check_pairing(&proof, &c, &f, &e)
}
