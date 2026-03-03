use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowScope {
    NodeContact,
    Metrics,
    RouteCreate,
}

impl PowScope {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::NodeContact => b"dsn/pow/node_contact/v1",
            Self::Metrics => b"dsn/pow/metrics/v1",
            Self::RouteCreate => b"dsn/pow/route_create/v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowError {
    ErrPowInvalid,
    ErrRateLimited,
}

impl PowError {
    pub const ERR_POW_INVALID: &'static str = "ERR_POW_INVALID";
    pub const ERR_RATE_LIMITED: &'static str = "ERR_RATE_LIMITED";

    pub fn code(self) -> &'static str {
        match self {
            Self::ErrPowInvalid => Self::ERR_POW_INVALID,
            Self::ErrRateLimited => Self::ERR_RATE_LIMITED,
        }
    }
}

impl Display for PowError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl Error for PowError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowChallenge {
    pub scope: PowScope,
    pub peer_id: [u8; 32],
    pub request_id: u64,
    pub target_id: [u8; 32],
    pub challenge_seed: [u8; 32],
    pub nonce: u64,
    pub difficulty: u8,
}

pub fn make_pow_tag(challenge: PowChallenge) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(challenge.scope.domain());
    hasher.update(&challenge.peer_id);
    hasher.update(&challenge.request_id.to_be_bytes());
    hasher.update(&challenge.target_id);
    hasher.update(&challenge.challenge_seed);
    hasher.update(&challenge.nonce.to_be_bytes());
    *hasher.finalize().as_bytes()
}

pub fn verify_pow(challenge: PowChallenge) -> Result<(), PowError> {
    let tag = make_pow_tag(challenge);
    let lz = leading_zero_bits(&tag);
    if lz >= challenge.difficulty as u16 {
        return Ok(());
    }

    Err(PowError::ErrPowInvalid)
}

pub fn leading_zero_bits(bytes: &[u8]) -> u16 {
    let mut zeros = 0u16;
    for byte in bytes {
        if *byte == 0 {
            zeros += 8;
            continue;
        }
        zeros += byte.leading_zeros() as u16;
        break;
    }
    zeros
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill_us: u64,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_sec: u32, now_us: u64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec: refill_per_sec as f64,
            tokens: capacity as f64,
            last_refill_us: now_us,
        }
    }

    pub fn try_consume(&mut self, now_us: u64, cost: u32) -> Result<(), PowError> {
        self.refill(now_us);
        let cost = cost as f64;
        if self.tokens < cost {
            return Err(PowError::ErrRateLimited);
        }
        self.tokens -= cost;
        Ok(())
    }

    fn refill(&mut self, now_us: u64) {
        if now_us <= self.last_refill_us {
            return;
        }

        let elapsed_sec = (now_us - self.last_refill_us) as f64 / 1_000_000f64;
        self.tokens = (self.tokens + elapsed_sec * self.refill_per_sec).min(self.capacity);
        self.last_refill_us = now_us;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PowChallenge, PowError, PowScope, TokenBucket, leading_zero_bits, make_pow_tag, verify_pow,
    };

    fn arr(v: u8) -> [u8; 32] {
        [v; 32]
    }

    fn mine_nonce(mut c: PowChallenge) -> PowChallenge {
        for nonce in 0..10_000_000u64 {
            c.nonce = nonce;
            let tag = make_pow_tag(c);
            if leading_zero_bits(&tag) >= c.difficulty as u16 {
                return c;
            }
        }
        panic!("unable to mine nonce in bounded search")
    }

    #[test]
    fn invalid_nonce_returns_pow_invalid() {
        let challenge = PowChallenge {
            scope: PowScope::NodeContact,
            peer_id: arr(1),
            request_id: 42,
            target_id: arr(2),
            challenge_seed: arr(9),
            nonce: 0,
            difficulty: 20,
        };

        let err = verify_pow(challenge).expect_err("nonce must be rejected");
        assert_eq!(err.code(), PowError::ERR_POW_INVALID);
    }

    #[test]
    fn valid_nonce_passes_for_metrics_and_route_create() {
        let base = PowChallenge {
            scope: PowScope::Metrics,
            peer_id: arr(3),
            request_id: 100,
            target_id: arr(4),
            challenge_seed: arr(8),
            nonce: 0,
            difficulty: 14,
        };

        let mined_metrics = mine_nonce(base);
        verify_pow(mined_metrics).expect("metrics pow must verify");

        let mined_route = mine_nonce(PowChallenge {
            scope: PowScope::RouteCreate,
            ..base
        });
        verify_pow(mined_route).expect("route_create pow must verify");
    }

    #[test]
    fn token_bucket_limits_and_refills() {
        let mut bucket = TokenBucket::new(3, 2, 0);

        bucket.try_consume(0, 1).expect("token #1");
        bucket.try_consume(0, 1).expect("token #2");
        bucket.try_consume(0, 1).expect("token #3");

        let err = bucket
            .try_consume(0, 1)
            .expect_err("must be rate limited when empty");
        assert_eq!(err.code(), PowError::ERR_RATE_LIMITED);

        // 1 second * 2 tokens/sec => 2 tokens refill.
        bucket.try_consume(1_000_000, 1).expect("refilled token #1");
        bucket.try_consume(1_000_000, 1).expect("refilled token #2");
        let err = bucket
            .try_consume(1_000_000, 1)
            .expect_err("bucket should be empty again");
        assert_eq!(err.code(), PowError::ERR_RATE_LIMITED);
    }
}
