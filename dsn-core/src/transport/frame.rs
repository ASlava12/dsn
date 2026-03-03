use std::error::Error;
use std::fmt::{Display, Formatter};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FRAME_V1_MAGIC: u16 = 0x4453;
pub const FRAME_V1_VERSION: u8 = 1;
const FRAME_V1_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameClass {
    Control = 0,
    Net = 1,
    Data = 2,
}

impl FrameClass {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Control),
            1 => Some(Self::Net),
            2 => Some(Self::Data),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameV1 {
    pub class: FrameClass,
    pub msg_type: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    pub control_max_len: u32,
    pub net_max_len: u32,
    pub data_max_len: u32,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            control_max_len: 64 * 1024,
            net_max_len: 256 * 1024,
            data_max_len: 1024 * 1024,
        }
    }
}

impl FrameLimits {
    pub fn max_len_for_class(self, class: FrameClass) -> u32 {
        match class {
            FrameClass::Control => self.control_max_len,
            FrameClass::Net => self.net_max_len,
            FrameClass::Data => self.data_max_len,
        }
    }
}

#[derive(Debug)]
pub enum FrameIoError {
    Io(std::io::Error),
    InvalidMagic(u16),
    UnsupportedVersion(u8),
    UnknownClass(u8),
    PayloadTooLarge {
        class: FrameClass,
        actual: u32,
        max_allowed: u32,
    },
}

impl Display for FrameIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error while processing frame: {err}"),
            Self::InvalidMagic(value) => write!(f, "invalid frame magic: 0x{value:04x}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported frame version: {version}")
            }
            Self::UnknownClass(value) => write!(f, "unknown frame class: {value}"),
            Self::PayloadTooLarge {
                class,
                actual,
                max_allowed,
            } => write!(
                f,
                "payload too large for class {class:?}: {actual} > {max_allowed}"
            ),
        }
    }
}

impl Error for FrameIoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrameIoError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &FrameV1,
    limits: FrameLimits,
) -> Result<(), FrameIoError> {
    let payload_len =
        u32::try_from(frame.payload.len()).map_err(|_| FrameIoError::PayloadTooLarge {
            class: frame.class,
            actual: u32::MAX,
            max_allowed: limits.max_len_for_class(frame.class),
        })?;

    validate_payload_len(frame.class, payload_len, limits)?;

    let mut header = [0u8; FRAME_V1_HEADER_LEN];
    header[0..2].copy_from_slice(&FRAME_V1_MAGIC.to_be_bytes());
    header[2] = FRAME_V1_VERSION;
    header[3] = frame.class as u8;
    header[4..6].copy_from_slice(&frame.msg_type.to_be_bytes());
    header[6..8].copy_from_slice(&frame.flags.to_be_bytes());
    header[8..12].copy_from_slice(&payload_len.to_be_bytes());

    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;

    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: FrameLimits,
) -> Result<FrameV1, FrameIoError> {
    let mut header = [0u8; FRAME_V1_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let magic = u16::from_be_bytes([header[0], header[1]]);
    if magic != FRAME_V1_MAGIC {
        return Err(FrameIoError::InvalidMagic(magic));
    }

    let version = header[2];
    if version != FRAME_V1_VERSION {
        return Err(FrameIoError::UnsupportedVersion(version));
    }

    let class_raw = header[3];
    let class = FrameClass::from_u8(class_raw).ok_or(FrameIoError::UnknownClass(class_raw))?;

    let msg_type = u16::from_be_bytes([header[4], header[5]]);
    let flags = u16::from_be_bytes([header[6], header[7]]);
    let payload_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);

    validate_payload_len(class, payload_len, limits)?;

    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload).await?;

    Ok(FrameV1 {
        class,
        msg_type,
        flags,
        payload,
    })
}

fn validate_payload_len(
    class: FrameClass,
    payload_len: u32,
    limits: FrameLimits,
) -> Result<(), FrameIoError> {
    let max_allowed = limits.max_len_for_class(class);
    if payload_len > max_allowed {
        return Err(FrameIoError::PayloadTooLarge {
            class,
            actual: payload_len,
            max_allowed,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FRAME_V1_MAGIC, FRAME_V1_VERSION, FrameClass, FrameIoError, FrameLimits, FrameV1,
        read_frame, write_frame,
    };
    use tokio::io::{self, AsyncWriteExt};

    #[tokio::test]
    async fn frame_roundtrip_works() {
        let limits = FrameLimits::default();
        let frame = FrameV1 {
            class: FrameClass::Control,
            msg_type: 42,
            flags: 0b101,
            payload: b"hello-v1".to_vec(),
        };

        let (mut tx, mut rx) = io::duplex(1024);

        write_frame(&mut tx, &frame, limits)
            .await
            .expect("frame write must succeed");

        let decoded = read_frame(&mut rx, limits)
            .await
            .expect("frame read must succeed");

        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn invalid_version_returns_controlled_error() {
        let limits = FrameLimits::default();
        let (mut tx, mut rx) = io::duplex(128);

        let mut raw = Vec::new();
        raw.extend_from_slice(&FRAME_V1_MAGIC.to_be_bytes());
        raw.push(FRAME_V1_VERSION + 1);
        raw.push(FrameClass::Control as u8);
        raw.extend_from_slice(&7u16.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());

        tx.write_all(&raw).await.expect("raw write must succeed");

        let err = read_frame(&mut rx, limits)
            .await
            .expect_err("invalid version must fail");

        match err {
            FrameIoError::UnsupportedVersion(v) => assert_eq!(v, FRAME_V1_VERSION + 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn payload_limit_protects_from_oom() {
        let limits = FrameLimits {
            control_max_len: 8,
            net_max_len: 16,
            data_max_len: 32,
        };
        let (mut tx, mut rx) = io::duplex(128);

        let mut raw = Vec::new();
        raw.extend_from_slice(&FRAME_V1_MAGIC.to_be_bytes());
        raw.push(FRAME_V1_VERSION);
        raw.push(FrameClass::Control as u8);
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&9u32.to_be_bytes());
        tx.write_all(&raw).await.expect("raw write must succeed");

        let err = read_frame(&mut rx, limits)
            .await
            .expect_err("oversized payload must fail");

        assert!(matches!(err, FrameIoError::PayloadTooLarge { .. }));
    }
}
