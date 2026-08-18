//! Builds the Groth16 fixtures the on-chain tests and the demo script use.
//!
//! IMPORTANT: these are NOT zkasper proofs.
//!
//! zkasper's STARK-to-Groth16 wrap has never been run, so no real proof of
//! Ethereum finality exists yet in this format. What this binary produces is a
//! genuine Groth16 proof — real trusted setup, real BN254 arithmetic, a real
//! pairing check on chain — over a placeholder circuit that constrains nothing
//! about Ethereum. It exists so the verifier, the account plumbing and the
//! compute-unit measurement can be exercised end to end against real curve
//! operations.
//!
//! The proof cost of Groth16 verification does not depend on what the circuit
//! proves, only on the number of public inputs, so the measured compute-unit
//! figure carries over unchanged to real proofs.
//!
//! Swapping in real proofs means replacing `fixtures/*.bin`; the program does
//! not change. See "Going live" in the README.

use std::fs;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use sha2::{Digest as _, Sha256};

use zkasper_solana_program::state::{VK_IC_LEN, VK_LEN};
use zkasper_solana_program::wire::{public_inputs, FinalizationOutput};

/// Fixed so fixtures are byte-for-byte reproducible. A real deployment gets its
/// verifying key from zkasper's wrap ceremony, not from a seeded RNG.
const SETUP_SEED: u64 = 0x007a_6b61_7370_6572;

/// Stand-in for zkasper's finalization wrap.
///
/// The real circuit verifies a Zisk VADCOP final proof and exposes the same two
/// public inputs. This one exposes the two inputs and constrains only that they
/// sum to a private witness, which is enough to produce a well-formed R1CS with
/// exactly two public inputs — the only property the on-chain verifier depends
/// on.
#[derive(Clone, Copy)]
struct WrapStub {
    pi0: Fr,
    pi1: Fr,
}

impl ConstraintSynthesizer<Fr> for WrapStub {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_input_variable(|| Ok(self.pi0))?;
        let b = cs.new_input_variable(|| Ok(self.pi1))?;
        let sum = cs.new_witness_variable(|| Ok(self.pi0 + self.pi1))?;
        cs.enforce_constraint(lc!() + a + b, lc!() + Variable::One, lc!() + sum)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EIP-197 serialization
// ---------------------------------------------------------------------------

fn fq_be(v: &ark_bn254::Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = v.into_bigint().to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// `x || y`, each 32 bytes big-endian.
fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.infinity {
        return out;
    }
    out[..32].copy_from_slice(&fq_be(&p.x));
    out[32..].copy_from_slice(&fq_be(&p.y));
    out
}

/// `x.c1 || x.c0 || y.c1 || y.c0` — the imaginary part leads, as EIP-197 wants.
fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.infinity {
        return out;
    }
    out[0..32].copy_from_slice(&fq_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_be(&p.y.c0));
    out
}

fn vk_bytes(vk: &VerifyingKey<Bn254>) -> [u8; VK_LEN] {
    assert_eq!(
        vk.gamma_abc_g1.len(),
        VK_IC_LEN,
        "wrap circuit must expose exactly {} public inputs",
        VK_IC_LEN - 1
    );
    let mut out = [0u8; VK_LEN];
    out[0..64].copy_from_slice(&g1_bytes(&vk.alpha_g1));
    out[64..192].copy_from_slice(&g2_bytes(&vk.beta_g2));
    out[192..320].copy_from_slice(&g2_bytes(&vk.gamma_g2));
    out[320..448].copy_from_slice(&g2_bytes(&vk.delta_g2));
    for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
        out[448 + i * 64..512 + i * 64].copy_from_slice(&g1_bytes(ic));
    }
    out
}

// ---------------------------------------------------------------------------
// fixture values
// ---------------------------------------------------------------------------

fn label(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zkasper-solana fixture: ");
    h.update(s.as_bytes());
    h.finalize().into()
}

/// A plausible accumulator digest: four Goldilocks elements, each canonical.
fn goldilocks_digest(s: &str) -> [u8; 32] {
    const P: u64 = 0xffff_ffff_0000_0001;
    let raw = label(s);
    let mut out = [0u8; 32];
    for i in 0..4 {
        let w = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap()) % P;
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn prove(pk: &ProvingKey<Bn254>, inputs: &[[u8; 32]; 2], rng: &mut StdRng) -> [u8; 256] {
    let pi0 = Fr::from_be_bytes_mod_order(&inputs[0]);
    let pi1 = Fr::from_be_bytes_mod_order(&inputs[1]);
    let proof = Groth16::<Bn254>::prove(pk, WrapStub { pi0, pi1 }, rng).expect("prove");

    let mut out = [0u8; 256];
    out[0..64].copy_from_slice(&g1_bytes(&proof.a));
    out[64..192].copy_from_slice(&g2_bytes(&proof.b));
    out[192..256].copy_from_slice(&g1_bytes(&proof.c));
    out
}

fn main() {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fixtures".into())
        .into();
    fs::create_dir_all(&out_dir).expect("create fixtures dir");

    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        WrapStub {
            pi0: Fr::from(0u64),
            pi1: Fr::from(0u64),
        },
        &mut rng,
    )
    .expect("setup");
    let vk_ser = vk_bytes(&vk);

    // Stand-in for the Zisk verification key of the finalization guest.
    let program_vk = label("finalization guest program vk");

    let bootstrap_epoch: u64 = 300_000;
    let bootstrap_acc = goldilocks_digest("bootstrap accumulator");
    let bootstrap_root = label("bootstrap block root");
    let bootstrap_state_root = label("bootstrap state root");

    // Epoch 300_001 keeps the bootstrap accumulator; 300_002 and 300_003 advance
    // it, so the tests cover both the steady-state and the accumulator-advance
    // branch of `submit_finalization`.
    // A real chain: each finalization starts from the accumulator the previous
    // one ended at. The program enforces this, so fixtures that did not chain
    // would be rejected — which is the point of generating them this way.
    let outputs: Vec<FinalizationOutput> = (1..=3u64)
        .map(|i| {
            let start = if i == 1 {
                bootstrap_acc
            } else {
                goldilocks_digest(&format!("accumulator after epoch {}", bootstrap_epoch + i - 1))
            };
            FinalizationOutput {
                accumulator_commitment: start,
                next_accumulator_commitment: goldilocks_digest(&format!(
                    "accumulator after epoch {}",
                    bootstrap_epoch + i
                )),
                finalized_epoch: bootstrap_epoch + i,
                finalized_root: label(&format!("block root epoch {}", bootstrap_epoch + i)),
                finalized_state_root: label(&format!("state root epoch {}", bootstrap_epoch + i)),
            }
        })
        .collect();

    // fixtures/bootstrap.bin is the `Initialize` payload without its tag byte.
    let mut bootstrap = Vec::with_capacity(136 + VK_LEN);
    bootstrap.extend_from_slice(&bootstrap_acc);
    bootstrap.extend_from_slice(&bootstrap_state_root);
    bootstrap.extend_from_slice(&bootstrap_epoch.to_le_bytes());
    bootstrap.extend_from_slice(&bootstrap_root);
    bootstrap.extend_from_slice(&program_vk);
    bootstrap.extend_from_slice(&vk_ser);
    fs::write(out_dir.join("bootstrap.bin"), &bootstrap).expect("write bootstrap");
    fs::write(out_dir.join("vk.bin"), vk_ser).expect("write vk");

    let mut json = String::from("{\n");
    json.push_str("  \"warning\": \"PLACEHOLDER FIXTURES. Real Groth16 proofs over a circuit that proves nothing about Ethereum. See fixtures/README.md.\",\n");
    json.push_str(&format!(
        "  \"program_vk\": \"0x{}\",\n",
        hex::encode(program_vk)
    ));
    json.push_str(&format!("  \"vk\": \"0x{}\",\n", hex::encode(vk_ser)));
    json.push_str("  \"bootstrap\": {\n");
    json.push_str(&format!(
        "    \"accumulator_commitment\": \"0x{}\",\n",
        hex::encode(bootstrap_acc)
    ));
    json.push_str(&format!(
        "    \"latest_state_root\": \"0x{}\",\n",
        hex::encode(bootstrap_state_root)
    ));
    json.push_str(&format!("    \"finalized_epoch\": {bootstrap_epoch},\n"));
    json.push_str(&format!(
        "    \"finalized_root\": \"0x{}\"\n",
        hex::encode(bootstrap_root)
    ));
    json.push_str("  },\n  \"finalizations\": [\n");

    for (i, output) in outputs.iter().enumerate() {
        let inputs = public_inputs(&program_vk, output);
        let proof = prove(&pk, &inputs, &mut rng);

        // Self-check through the same code path the program runs, so a broken
        // fixture fails here rather than inside a transaction.
        zkasper_solana_program::verifier::verify(
            &vk_ser,
            proof[0..64].try_into().unwrap(),
            proof[64..192].try_into().unwrap(),
            proof[192..256].try_into().unwrap(),
            &inputs,
        )
        .expect("fixture proof must verify through the on-chain verifier");

        // fixtures/finalization_N.bin is the `SubmitFinalization` payload
        // without its tag byte.
        let mut blob = Vec::with_capacity(360);
        blob.extend_from_slice(&proof);
        blob.extend_from_slice(&output.public_bytes());
        fs::write(out_dir.join(format!("finalization_{i}.bin")), &blob).expect("write proof");

        json.push_str("    {\n");
        json.push_str(&format!(
            "      \"finalized_epoch\": {},\n",
            output.finalized_epoch
        ));
        json.push_str(&format!(
            "      \"finalized_root\": \"0x{}\",\n",
            hex::encode(output.finalized_root)
        ));
        json.push_str(&format!(
            "      \"finalized_state_root\": \"0x{}\",\n",
            hex::encode(output.finalized_state_root)
        ));
        json.push_str(&format!(
            "      \"accumulator_commitment\": \"0x{}\",\n",
            hex::encode(output.accumulator_commitment)
        ));
        json.push_str(&format!(
            "      \"public_inputs\": [\"0x{}\", \"0x{}\"],\n",
            hex::encode(inputs[0]),
            hex::encode(inputs[1])
        ));
        json.push_str(&format!("      \"proof\": \"0x{}\"\n", hex::encode(proof)));
        json.push_str(if i + 1 == outputs.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    json.push_str("  ]\n}\n");
    fs::write(out_dir.join("fixtures.json"), json).expect("write json");

    println!(
        "wrote {} fixtures to {}",
        outputs.len() + 2,
        out_dir.display()
    );
}
