use std::error::Error;
use std::fmt::{Display, Formatter};

pub const CONTROL_PROTOCOL_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlMsgType {
    Ping = 0,
    Pong = 1,
    FindNode = 2,
    FindValue = 3,
    Store = 4,
    Delete = 5,
    NodeContact = 6,
    SessionChangeRequest = 7,
    SessionChangeAck = 8,
}

impl ControlMsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ping),
            1 => Some(Self::Pong),
            2 => Some(Self::FindNode),
            3 => Some(Self::FindValue),
            4 => Some(Self::Store),
            5 => Some(Self::Delete),
            6 => Some(Self::NodeContact),
            7 => Some(Self::SessionChangeRequest),
            8 => Some(Self::SessionChangeAck),
            _ => None,
        }
    }
}

pub const REKEY_ACK_OK: u16 = 0;
pub const REKEY_ACK_REJECTED: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub request_id: u64,
    pub sender_node_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub request_id: u64,
    pub responder_node_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNode {
    pub request_id: u64,
    pub namespace_id: u32,
    pub target_node_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindValue {
    pub request_id: u64,
    pub namespace_id: u32,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    pub request_id: u64,
    pub namespace_id: u32,
    pub flags: u16,
    pub error_code: u16,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub request_id: u64,
    pub namespace_id: u32,
    pub flags: u16,
    pub error_code: u16,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeContact {
    pub request_id: u64,
    pub flags: u16,
    pub error_code: u16,
    pub node_id_contact: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChangeRequest {
    pub request_id: u64,
    pub new_key_id: u32,
    pub requester_node_id: [u8; 32],
    pub kem_payload: Vec<u8>,
    pub sign: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChangeAck {
    pub request_id: u64,
    pub key_id: u32,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Ping(Ping),
    Pong(Pong),
    FindNode(FindNode),
    FindValue(FindValue),
    Store(Store),
    Delete(Delete),
    NodeContact(NodeContact),
    SessionChangeRequest(SessionChangeRequest),
    SessionChangeAck(SessionChangeAck),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCodecError {
    UnexpectedEof,
    UnsupportedVersion(u8),
    UnknownMessageType(u8),
    InvalidLength,
}

impl Display for ControlCodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF while decoding control message"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported control protocol version: {v}"),
            Self::UnknownMessageType(t) => write!(f, "unknown control message type: {t}"),
            Self::InvalidLength => write!(f, "invalid control message length"),
        }
    }
}

impl Error for ControlCodecError {}

impl ControlMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(CONTROL_PROTOCOL_V1);

        match self {
            Self::Ping(msg) => {
                out.push(ControlMsgType::Ping as u8);
                put_u16(&mut out, 0); // flags
                put_u16(&mut out, 0); // error_code
                put_u64(&mut out, msg.request_id);
                out.extend_from_slice(&msg.sender_node_id);
            }
            Self::Pong(msg) => {
                out.push(ControlMsgType::Pong as u8);
                put_u16(&mut out, 0);
                put_u16(&mut out, 0);
                put_u64(&mut out, msg.request_id);
                out.extend_from_slice(&msg.responder_node_id);
            }
            Self::FindNode(msg) => {
                out.push(ControlMsgType::FindNode as u8);
                put_u16(&mut out, 0);
                put_u16(&mut out, 0);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.namespace_id);
                out.extend_from_slice(&msg.target_node_id);
            }
            Self::FindValue(msg) => {
                out.push(ControlMsgType::FindValue as u8);
                put_u16(&mut out, 0);
                put_u16(&mut out, 0);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.namespace_id);
                put_u16(&mut out, msg.key.len() as u16);
                out.extend_from_slice(&msg.key);
            }
            Self::Store(msg) => {
                out.push(ControlMsgType::Store as u8);
                put_u16(&mut out, msg.flags);
                put_u16(&mut out, msg.error_code);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.namespace_id);
                put_u16(&mut out, msg.key.len() as u16);
                out.extend_from_slice(&msg.key);
                put_u16(&mut out, msg.value.len() as u16);
                out.extend_from_slice(&msg.value);
                put_u16(&mut out, msg.signature.len() as u16); // sig_len u16
                out.extend_from_slice(&msg.signature);
            }
            Self::Delete(msg) => {
                out.push(ControlMsgType::Delete as u8);
                put_u16(&mut out, msg.flags);
                put_u16(&mut out, msg.error_code);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.namespace_id);
                put_u16(&mut out, msg.key.len() as u16);
                out.extend_from_slice(&msg.key);
                put_u16(&mut out, msg.value.len() as u16);
                out.extend_from_slice(&msg.value);
                put_u16(&mut out, msg.signature.len() as u16); // sig_len u16
                out.extend_from_slice(&msg.signature);
            }
            Self::NodeContact(msg) => {
                out.push(ControlMsgType::NodeContact as u8);
                put_u16(&mut out, msg.flags);
                put_u16(&mut out, msg.error_code);
                put_u64(&mut out, msg.request_id);
                out.extend_from_slice(&msg.node_id_contact);
                out.extend_from_slice(&msg.nonce);
            }
            Self::SessionChangeRequest(msg) => {
                out.push(ControlMsgType::SessionChangeRequest as u8);
                put_u16(&mut out, 0);
                put_u16(&mut out, 0);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.new_key_id);
                out.extend_from_slice(&msg.requester_node_id);
                put_u16(&mut out, msg.kem_payload.len() as u16);
                out.extend_from_slice(&msg.kem_payload);
                put_u16(&mut out, msg.sign.len() as u16);
                out.extend_from_slice(&msg.sign);
            }
            Self::SessionChangeAck(msg) => {
                out.push(ControlMsgType::SessionChangeAck as u8);
                put_u16(&mut out, msg.status);
                put_u16(&mut out, 0);
                put_u64(&mut out, msg.request_id);
                put_u32(&mut out, msg.key_id);
            }
        }

        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, ControlCodecError> {
        let mut rd = Reader::new(input);
        let version = rd.read_u8()?;
        if version != CONTROL_PROTOCOL_V1 {
            return Err(ControlCodecError::UnsupportedVersion(version));
        }

        let msg_type = rd.read_u8()?;
        let flags = rd.read_u16()?;
        let error_code = rd.read_u16()?;
        let request_id = rd.read_u64()?;

        let parsed = match ControlMsgType::from_u8(msg_type) {
            Some(ControlMsgType::Ping) => {
                let sender_node_id = rd.read_fixed32()?;
                Self::Ping(Ping {
                    request_id,
                    sender_node_id,
                })
            }
            Some(ControlMsgType::Pong) => {
                let responder_node_id = rd.read_fixed32()?;
                Self::Pong(Pong {
                    request_id,
                    responder_node_id,
                })
            }
            Some(ControlMsgType::FindNode) => {
                let namespace_id = rd.read_u32()?;
                let target_node_id = rd.read_fixed32()?;
                Self::FindNode(FindNode {
                    request_id,
                    namespace_id,
                    target_node_id,
                })
            }
            Some(ControlMsgType::FindValue) => {
                let namespace_id = rd.read_u32()?;
                let key = rd.read_vec_u16()?;
                Self::FindValue(FindValue {
                    request_id,
                    namespace_id,
                    key,
                })
            }
            Some(ControlMsgType::Store) => {
                let namespace_id = rd.read_u32()?;
                let key = rd.read_vec_u16()?;
                let value = rd.read_vec_u16()?;
                let signature = rd.read_vec_u16()?;
                Self::Store(Store {
                    request_id,
                    namespace_id,
                    flags,
                    error_code,
                    key,
                    value,
                    signature,
                })
            }
            Some(ControlMsgType::Delete) => {
                let namespace_id = rd.read_u32()?;
                let key = rd.read_vec_u16()?;
                let value = rd.read_vec_u16()?;
                let signature = rd.read_vec_u16()?;
                Self::Delete(Delete {
                    request_id,
                    namespace_id,
                    flags,
                    error_code,
                    key,
                    value,
                    signature,
                })
            }
            Some(ControlMsgType::NodeContact) => {
                let node_id_contact = rd.read_fixed32()?;
                let nonce = rd.read_fixed32()?;
                Self::NodeContact(NodeContact {
                    request_id,
                    flags,
                    error_code,
                    node_id_contact,
                    nonce,
                })
            }
            Some(ControlMsgType::SessionChangeRequest) => {
                let new_key_id = rd.read_u32()?;
                let requester_node_id = rd.read_fixed32()?;
                let kem_payload = rd.read_vec_u16()?;
                let sign = rd.read_vec_u16()?;
                Self::SessionChangeRequest(SessionChangeRequest {
                    request_id,
                    new_key_id,
                    requester_node_id,
                    kem_payload,
                    sign,
                })
            }
            Some(ControlMsgType::SessionChangeAck) => {
                let key_id = rd.read_u32()?;
                Self::SessionChangeAck(SessionChangeAck {
                    request_id,
                    key_id,
                    status: flags,
                })
            }
            None => return Err(ControlCodecError::UnknownMessageType(msg_type)),
        };

        if !rd.is_exhausted() {
            return Err(ControlCodecError::InvalidLength);
        }

        Ok(parsed)
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

struct Reader<'a> {
    input: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, off: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.off == self.input.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], ControlCodecError> {
        let end = self
            .off
            .checked_add(len)
            .ok_or(ControlCodecError::InvalidLength)?;
        if end > self.input.len() {
            return Err(ControlCodecError::UnexpectedEof);
        }
        let slice = &self.input[self.off..end];
        self.off = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, ControlCodecError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ControlCodecError> {
        let b = self.read_exact(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ControlCodecError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, ControlCodecError> {
        let b = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_fixed32(&mut self) -> Result<[u8; 32], ControlCodecError> {
        let b = self.read_exact(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_vec_u16(&mut self) -> Result<Vec<u8>, ControlCodecError> {
        let len = self.read_u16()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_PROTOCOL_V1, ControlCodecError, ControlMessage, Delete, FindNode, FindValue,
        NodeContact, Ping, Pong, Store,
    };

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn roundtrip_all_message_types() {
        let vectors = vec![
            ControlMessage::Ping(Ping {
                request_id: 1,
                sender_node_id: id(1),
            }),
            ControlMessage::Pong(Pong {
                request_id: 2,
                responder_node_id: id(2),
            }),
            ControlMessage::FindNode(FindNode {
                request_id: 3,
                namespace_id: 10,
                target_node_id: id(3),
            }),
            ControlMessage::FindValue(FindValue {
                request_id: 4,
                namespace_id: 11,
                key: b"key".to_vec(),
            }),
            ControlMessage::Store(Store {
                request_id: 5,
                namespace_id: 12,
                flags: 0x0001,
                error_code: 0x0000,
                key: b"k".to_vec(),
                value: b"v".to_vec(),
                signature: vec![9, 8, 7],
            }),
            ControlMessage::Delete(Delete {
                request_id: 6,
                namespace_id: 13,
                flags: 0x0002,
                error_code: 0x0003,
                key: b"dk".to_vec(),
                value: b"dv".to_vec(),
                signature: vec![6, 5, 4, 3],
            }),
            ControlMessage::NodeContact(NodeContact {
                request_id: 7,
                flags: 0x0100,
                error_code: 0,
                node_id_contact: id(4),
                nonce: id(5),
            }),
        ];

        for msg in vectors {
            let encoded = msg.encode();
            let decoded = ControlMessage::decode(&encoded).expect("decode must succeed");
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn garbage_input_returns_error_without_panic() {
        let garbage = [0xFFu8, 0x00, 0xAB, 0xCD, 0xEF];
        let err = ControlMessage::decode(&garbage).expect_err("garbage must fail");
        assert!(matches!(
            err,
            ControlCodecError::UnsupportedVersion(_) | ControlCodecError::UnexpectedEof
        ));
    }

    #[test]
    fn unknown_type_and_trailing_data_are_rejected() {
        let mut unknown = vec![CONTROL_PROTOCOL_V1, 250];
        unknown.extend_from_slice(&0u16.to_be_bytes());
        unknown.extend_from_slice(&0u16.to_be_bytes());
        unknown.extend_from_slice(&1u64.to_be_bytes());
        let err = ControlMessage::decode(&unknown).expect_err("unknown type must fail");
        assert!(matches!(err, ControlCodecError::UnknownMessageType(250)));

        let mut valid = ControlMessage::Ping(Ping {
            request_id: 9,
            sender_node_id: id(9),
        })
        .encode();
        valid.push(0xEE);
        let err = ControlMessage::decode(&valid).expect_err("trailing data must fail");
        assert!(matches!(err, ControlCodecError::InvalidLength));
    }
}
