use anyhow::{Result, bail};
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::config::IdentityConfig;

pub fn generate_identity(algo: &str) -> Result<IdentityConfig> {
    if algo != "ed25519" {
        bail!("unsupported key algorithm: {algo}");
    }

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let public_key = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
    let private_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.to_keypair_bytes().as_ref());

    let mut hash_output = [0_u8; 128];
    blake3::Hasher::new()
        .update(verifying_key.as_bytes())
        .finalize_xof()
        .fill(&mut hash_output);
    let id = hash_output
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(IdentityConfig {
        algo: algo.to_owned(),
        public_key,
        private_key,
        id,
    })
}
