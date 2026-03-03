use std::error::Error;
use std::fmt::{Display, Formatter};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait, SharedSecret,
};
use sha2::Sha256;

use super::PeerLinksMode;

pub const HANDSHAKE_V1_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressMode {
    PublicOnly = 0,
    GrayOnly = 1,
    All = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeConfig {
    pub protocol_version: u8,
    pub mux_mode: PeerLinksMode,
    pub address_mode: AddressMode,
    pub pow_difficulty: u8,
    pub node_id: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub config: HandshakeConfig,
    pub kem_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub config: HandshakeConfig,
    pub kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    pub verify_tag: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

#[derive(Debug)]
pub struct ClientHandshakeState {
    client_config: HandshakeConfig,
    client_public_key: Vec<u8>,
    client_secret_key: mlkem768::SecretKey,
}

#[derive(Debug, Clone)]
pub struct ServerHandshakeState {
    keys: SessionKeys,
    transcript_hash: [u8; 32],
}

#[derive(Debug)]
pub enum HandshakeError {
    UnsupportedVersion(u8),
    InvalidSignature,
    InvalidKexMaterial,
    InvalidFinished,
    Kdf,
    Aead,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported handshake version: {v}"),
            Self::InvalidSignature => write!(f, "invalid handshake signature"),
            Self::InvalidKexMaterial => write!(f, "invalid KEM material"),
            Self::InvalidFinished => write!(f, "invalid handshake finished tag"),
            Self::Kdf => write!(f, "failed to derive session keys via HKDF"),
            Self::Aead => write!(f, "failed AEAD operation"),
        }
    }
}

impl Error for HandshakeError {}

pub fn build_client_hello(
    client_signing: &SigningKey,
    client_config: HandshakeConfig,
) -> Result<(ClientHandshakeState, ClientHello), HandshakeError> {
    validate_version(client_config.protocol_version)?;

    let (pk, sk) = mlkem768::keypair();
    let kem_public_key = pk.as_bytes().to_vec();

    let sig_input = client_hello_signature_payload(&client_config, &kem_public_key);
    let signature = client_signing.sign(&sig_input).to_bytes().to_vec();

    Ok((
        ClientHandshakeState {
            client_config: client_config.clone(),
            client_public_key: kem_public_key.clone(),
            client_secret_key: sk,
        },
        ClientHello {
            config: client_config,
            kem_public_key,
            signature,
        },
    ))
}

pub fn handle_client_hello(
    hello: &ClientHello,
    expected_client_signing_key: &VerifyingKey,
    server_signing: &SigningKey,
    server_config: HandshakeConfig,
) -> Result<(ServerHandshakeState, ServerHello), HandshakeError> {
    validate_version(hello.config.protocol_version)?;
    validate_version(server_config.protocol_version)?;

    let sig_payload = client_hello_signature_payload(&hello.config, &hello.kem_public_key);
    verify_signature(expected_client_signing_key, &sig_payload, &hello.signature)?;

    let client_kem_public = mlkem768::PublicKey::from_bytes(&hello.kem_public_key)
        .map_err(|_| HandshakeError::InvalidKexMaterial)?;
    let (shared_secret, ciphertext) = mlkem768::encapsulate(&client_kem_public);

    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let transcript_hash = transcript_hash(
        &hello.config,
        &server_config,
        &hello.kem_public_key,
        &ciphertext_bytes,
    );

    let key_material = derive_key_material(shared_secret.as_bytes(), &transcript_hash)?;
    let keys = SessionKeys {
        send_key: key_material.server_to_client,
        recv_key: key_material.client_to_server,
    };
    let server_sig_payload =
        server_hello_signature_payload(&server_config, &ciphertext_bytes, &transcript_hash);
    let signature = server_signing.sign(&server_sig_payload).to_bytes().to_vec();

    Ok((
        ServerHandshakeState {
            keys,
            transcript_hash,
        },
        ServerHello {
            config: server_config,
            kem_ciphertext: ciphertext_bytes,
            signature,
        },
    ))
}

pub fn handle_server_hello(
    client_state: ClientHandshakeState,
    hello: &ServerHello,
    expected_server_signing_key: &VerifyingKey,
) -> Result<(SessionKeys, Finished), HandshakeError> {
    validate_version(hello.config.protocol_version)?;

    let kem_ciphertext = mlkem768::Ciphertext::from_bytes(&hello.kem_ciphertext)
        .map_err(|_| HandshakeError::InvalidKexMaterial)?;
    let shared_secret = mlkem768::decapsulate(&kem_ciphertext, &client_state.client_secret_key);

    let transcript_hash = transcript_hash(
        &client_state.client_config,
        &hello.config,
        &client_state.client_public_key,
        &hello.kem_ciphertext,
    );

    let sig_payload =
        server_hello_signature_payload(&hello.config, &hello.kem_ciphertext, &transcript_hash);
    verify_signature(expected_server_signing_key, &sig_payload, &hello.signature)?;

    let key_material = derive_key_material(shared_secret.as_bytes(), &transcript_hash)?;
    let keys = SessionKeys {
        send_key: key_material.client_to_server,
        recv_key: key_material.server_to_client,
    };
    let finished = Finished {
        verify_tag: finished_tag(&transcript_hash),
    };

    Ok((keys, finished))
}

pub fn verify_finished(
    server_state: &ServerHandshakeState,
    finished: &Finished,
) -> Result<(), HandshakeError> {
    if finished.verify_tag != finished_tag(&server_state.transcript_hash) {
        return Err(HandshakeError::InvalidFinished);
    }
    Ok(())
}

pub fn server_session_keys(state: &ServerHandshakeState) -> SessionKeys {
    state.keys.clone()
}

#[derive(Debug, Clone)]
pub struct EncryptedFrame {
    pub key_id: u32,
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_frame(
    keys: &SessionKeys,
    key_id: u32,
    seq: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedFrame, HandshakeError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.send_key));
    let nonce = build_nonce(key_id, seq);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| HandshakeError::Aead)?;

    Ok(EncryptedFrame {
        key_id,
        seq,
        ciphertext,
    })
}

pub fn decrypt_frame(
    keys: &SessionKeys,
    frame: &EncryptedFrame,
    aad: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.recv_key));
    let nonce = build_nonce(frame.key_id, frame.seq);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &frame.ciphertext,
                aad,
            },
        )
        .map_err(|_| HandshakeError::Aead)
}

fn validate_version(version: u8) -> Result<(), HandshakeError> {
    if version != HANDSHAKE_V1_VERSION {
        return Err(HandshakeError::UnsupportedVersion(version));
    }
    Ok(())
}

fn client_hello_signature_payload(config: &HandshakeConfig, kem_public_key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + kem_public_key.len());
    bytes.extend_from_slice(b"dsn-handshake-client-hello-v1");
    bytes.extend_from_slice(&serialize_config(config));
    bytes.extend_from_slice(kem_public_key);
    bytes
}

fn server_hello_signature_payload(
    config: &HandshakeConfig,
    kem_ciphertext: &[u8],
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96 + kem_ciphertext.len());
    bytes.extend_from_slice(b"dsn-handshake-server-hello-v1");
    bytes.extend_from_slice(&serialize_config(config));
    bytes.extend_from_slice(kem_ciphertext);
    bytes.extend_from_slice(transcript_hash);
    bytes
}

fn serialize_config(config: &HandshakeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.push(config.protocol_version);
    out.push(match config.mux_mode {
        PeerLinksMode::SingleMux => 0,
        PeerLinksMode::MultiConn => 1,
    });
    out.push(config.address_mode as u8);
    out.push(config.pow_difficulty);
    out.extend_from_slice(&config.node_id);
    out
}

fn transcript_hash(
    client_cfg: &HandshakeConfig,
    server_cfg: &HandshakeConfig,
    client_kem_public_key: &[u8],
    kem_ciphertext: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"dsn-handshake-transcript-v1");
    h.update(&serialize_config(client_cfg));
    h.update(&serialize_config(server_cfg));
    h.update(client_kem_public_key);
    h.update(kem_ciphertext);
    *h.finalize().as_bytes()
}

struct KeyMaterial {
    client_to_server: [u8; 32],
    server_to_client: [u8; 32],
}

fn derive_key_material(
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<KeyMaterial, HandshakeError> {
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    let mut client_to_server = [0u8; 32];
    let mut server_to_client = [0u8; 32];

    hk.expand(b"dsn/client_to_server", &mut client_to_server)
        .map_err(|_| HandshakeError::Kdf)?;
    hk.expand(b"dsn/server_to_client", &mut server_to_client)
        .map_err(|_| HandshakeError::Kdf)?;

    Ok(KeyMaterial {
        client_to_server,
        server_to_client,
    })
}

fn finished_tag(transcript_hash: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(transcript_hash, b"dsn-finished-v1").as_bytes()
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    sig_bytes: &[u8],
) -> Result<(), HandshakeError> {
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| HandshakeError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    key.verify(payload, &signature)
        .map_err(|_| HandshakeError::InvalidSignature)
}

fn build_nonce(key_id: u32, seq: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&key_id.to_be_bytes());
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn config(node: u8) -> HandshakeConfig {
        HandshakeConfig {
            protocol_version: HANDSHAKE_V1_VERSION,
            mux_mode: PeerLinksMode::SingleMux,
            address_mode: AddressMode::PublicOnly,
            pow_difficulty: 7,
            node_id: node_id(node),
        }
    }

    #[test]
    fn mitm_mutation_breaks_handshake_signature() {
        let client_sign = SigningKey::from_bytes(&[1u8; 32]);
        let client_verify = client_sign.verifying_key();
        let server_sign = SigningKey::from_bytes(&[2u8; 32]);

        let (_state, mut hello) = build_client_hello(&client_sign, config(0x11)).expect("hello");

        // MITM tampers transcript input.
        hello.config.pow_difficulty = 42;

        let err = handle_client_hello(&hello, &client_verify, &server_sign, config(0x22))
            .expect_err("tamper must fail");
        assert!(matches!(err, HandshakeError::InvalidSignature));
    }

    #[test]
    fn encrypted_frame_roundtrip_works() {
        let client_sign = SigningKey::from_bytes(&[3u8; 32]);
        let client_verify = client_sign.verifying_key();
        let server_sign = SigningKey::from_bytes(&[4u8; 32]);
        let server_verify = server_sign.verifying_key();

        let (client_state, client_hello) =
            build_client_hello(&client_sign, config(0x33)).expect("client hello");
        let (server_state, server_hello) =
            handle_client_hello(&client_hello, &client_verify, &server_sign, config(0x44))
                .expect("server hello");
        let (client_keys, finished) =
            handle_server_hello(client_state, &server_hello, &server_verify)
                .expect("client accept hello");
        verify_finished(&server_state, &finished).expect("finished must verify");

        let server_keys = server_session_keys(&server_state);

        let aad = b"frame-aad";
        let enc = encrypt_frame(&client_keys, 1, 1, b"secret-payload", aad).expect("encrypt");
        let dec = decrypt_frame(&server_keys, &enc, aad).expect("decrypt");
        assert_eq!(dec, b"secret-payload");
    }
}
