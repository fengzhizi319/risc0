// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ecdsa_methods::{ECDSA_VERIFY_ELF, ECDSA_VERIFY_ID};
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use rand_core::OsRng;
use risc0_zkvm::{ExecutorEnv, Receipt};
use risc0_zkvm::host::server::prove::get_local_prover;

/// Given an secp256k1 verifier key (i.e. public key), message and signature,
/// runs the ECDSA verifier inside the zkVM and returns a receipt, including a
/// journal and seal attesting to the fact that the prover knows a valid
/// signature from the committed public key over the committed message.
fn prove_ecdsa_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Receipt {
    let input = (verifying_key.to_encoded_point(true), message, signature);
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = get_local_prover().unwrap();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove(env, ECDSA_VERIFY_ELF).unwrap().receipt
}

fn main() {
    // Generate a random secp256k1 keypair and sign the message.
    use std::time::Instant;

    let start = Instant::now();
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let duration = start.elapsed();
    println!("Time taken to generate signing key: {:?}", duration);

    let message = b"This is a message that will be signed, and verified within the zkVM";

    let start = Instant::now();
    let signature: Signature = signing_key.sign(message);
    let duration = start.elapsed();
    println!("Time taken to sign message: {:?}", duration);

    // Run signature verified in the zkVM guest and get the resulting receipt.
    let start = Instant::now();
    let receipt = prove_ecdsa_verification(signing_key.verifying_key(), message, &signature);
    let duration = start.elapsed();
    println!("Time taken to prove ECDSA verification: {:?}", duration);

    // Verify the receipt and then access the journal.
    let start = Instant::now();
    receipt.verify(ECDSA_VERIFY_ID).unwrap();
    let duration = start.elapsed();
    println!("Time taken to verify receipt: {:?}", duration);

    let (receipt_verifying_key, receipt_message): (EncodedPoint, Vec<u8>) =
        receipt.journal.decode().unwrap();

    println!(
        "Verified the signature over message {:?} with key {}",
        std::str::from_utf8(&receipt_message[..]).unwrap(),
        receipt_verifying_key,
    );
}
