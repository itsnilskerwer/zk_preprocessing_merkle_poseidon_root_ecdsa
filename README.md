Work in progress: Not production-ready.

# Processing RDF for Noir ZK in Rust: Signing a merkle root over the dataset with ECDSA

## Calculate merkle tree root

Input: Concatenated and hashed RDF terms, mapped into BN254 scalar field.

TODO: Lexicographically sort the input. We want to be working with a bag / multiset, similar to RDF quads inside RDF datasets.

For a fixed-tree depth of 2, we construct a binary merkle tree using the Poseidon hash function, giving us a merkle tree root.

TODO Insert: Image of root construction

The root is encoded as 32 bytes (Field -> BigInt -> 32-byte big endian ?).

## Sign root

We create an ECDSA (secp256k1 curve) keypair and sign the merkle root with the private key.
Note: We use sign_prehash(root_bytes), meaning that the root bytes are signed directly without further hashing in order to match Noir's ECDSA signature verification.

We save the root, signature and public key (verifying key).

# How to run

```rust
cargo run
````
