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

    let hash_output = blake3::hash(verifying_key.as_bytes());
    let id = hash_output
        .as_bytes()
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

#[cfg(test)]
mod tests {
    use super::generate_identity;

    #[test]
    fn generated_identity_id_is_256_bit_hex() {
        let identity = generate_identity("ed25519").expect("identity generation must succeed");

        assert_eq!(identity.id.len(), 64);
        assert!(identity.id.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}
