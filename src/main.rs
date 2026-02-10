use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer};
use rand::rngs::OsRng; // random number generator
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use ark_ff::{BigInteger, PrimeField}; // Needed for into_bigint()
use std::fs;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use std::str::FromStr; // Needed to parse the large numbers
use std::io::Read;
use zerocopy::IntoBytes;

/// Build merkle tree by hashing binary leaves with Poseidon 
fn poseidon_merkle_root(mut leaves: Vec<Fr>) -> Fr {
    if leaves.is_empty() {
        return Fr::from(0);
    }

    // Zero-Pad to the next power of 2
    let next_pow2 = leaves.len().next_power_of_two();
    leaves.resize(next_pow2, Fr::from(0));

    while leaves.len() > 1 {
        leaves = leaves
            .chunks(2)
            .map(|pair| poseidon_hash(pair[0], pair[1]))
            .collect();
    }

    leaves[0]
}

fn poseidon_hash(a: Fr, b: Fr) -> Fr {    
    // Create the hasher
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    
    // Hash the inputs
    poseidon.hash(&[a, b]).unwrap()
}

/// Sign merkle root hash with ECDSA

fn sign_merkle_root_hash(signing_key: &SigningKey, root_hash: &[u8; 32],
) -> Signature {
    let sig: Signature = signing_key
        .sign_prehash(root_hash)
        .expect("ECDSA signing failed");
    
    let r = sig.r().to_bytes();
    let s = sig.s().to_bytes();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);

    fs::write("signature.sig", out.as_bytes()).unwrap();
    //fs::write("signature.sig", out).unwrap();

    sig
}

/// Sign merkle root, forcing ECDSA signing function to NOT hash the root again, before signing
fn sign_merkle_root_raw(
    signing_key: &SigningKey,
    root_bytes: &[u8; 32],
) -> [u8; 64] {
    let sig: Signature = signing_key.sign_prehash(root_bytes).expect("ECDSA signing failed");

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.r().to_bytes());
    out[32..].copy_from_slice(&sig.s().to_bytes());

    fs::write("signature.sig", out.as_bytes()).unwrap();

    out
}

/// Sign merkle root with ECDSA 
/// Warning: --------------------- UNUSED ------ didnt match verification inside Noir
fn sign_merkle_root(sk: &SigningKey, root: Fr) -> Signature {
    let mut bytes = [0u8; 32];
    root.into_bigint().to_bytes_be().iter().rev().enumerate().for_each(|(i, b)| {
        if i < 32 { // // prevent out of bounds if vector is > 32 bytes
            bytes[31 - i] = *b; // fill array from the back
        }
    });

    let sig: Signature = sk.sign(&bytes);
    // DER encoding written to file
    let der = sig.to_der();
    fs::write("signature.der", der.as_bytes()).unwrap();

    sk.sign(&bytes) // Result: Big Endian
}
// --------------------------------------------------------

fn main() {
    println!("Hello, Merkle poseidon root ecdsa!");
    // 1. Generate a random Private Key (SigningKey / secret key)
    let signing_key = SigningKey::random(&mut OsRng);
    // 2. Generate public key (VerifyingKey)
    let verifying_key = VerifyingKey::from(&signing_key);
    println!("pub key: \n{:?}", verifying_key);
    let encoded_vk = verifying_key.to_encoded_point(false); // uncompressed
    let bytes_vk = encoded_vk.as_bytes();

    fs::write("verifying_key.sec1", bytes_vk).unwrap();

    let rdf_leaves: Vec<Fr> = vec![
        Fr::from_str("4910744290370992967594783267190021468504474627849903460949550480278838140199").unwrap(),
        Fr::from_str("10194548762545774750915906808733983907201990848957491253134558847853880061861").unwrap(),
        Fr::from_str("8361791287903088380138808503792110151023699568954984532145283304862179688869").unwrap(),
        Fr::from_str("2902104138811596866383925023591303991501113627166467298658710052247721224774").unwrap(),
    ];
    let root: Fr = poseidon_merkle_root(rdf_leaves);
    println!("Root: \n{:?}", root);

    
    let root_bytes = root.into_bigint().to_bytes_be(); // convert Fr to bytes
    // it has to fit into 32 bytes
    let root_bytes: [u8; 32] = root_bytes 
        .try_into()
        .expect("root must be 32 bytes");

    // sign root bytes
    let signature_ecdsa_root = sign_merkle_root_raw(&signing_key, &root_bytes);
    println!("SIGN root bytes: {:02x?}", root_bytes);
    println!("\nECDSA Signature over root hash\n{:?}", signature_ecdsa_root);
}
