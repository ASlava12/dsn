use std::collections::{HashMap, VecDeque};
use std::time::Duration;

pub const REKEY_BYTES_THRESHOLD_V1: u64 = 64 * 1024 * 1024 * 1024;
pub const REKEY_AGE_THRESHOLD_US_V1: u64 = 24 * 60 * 60 * 1_000_000;

#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    pub rekey_bytes_threshold: u64,
    pub rekey_age_threshold_us: u64,
    pub grace_window_us: u64,
    pub session_timeout_us: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            rekey_bytes_threshold: REKEY_BYTES_THRESHOLD_V1,
            rekey_age_threshold_us: REKEY_AGE_THRESHOLD_US_V1,
            grace_window_us: 30_000_000,
            session_timeout_us: 300_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionChangeRequest {
    pub request_id: u64,
    pub next_key_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionChangeAck {
    pub request_id: u64,
    pub accepted_key_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub request_id: u64,
    pub ts_mono_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub request_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRekey {
    request_id: u64,
    next_key_id: u32,
    requested_at_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreviousKeyGrace {
    key_id: u32,
    until_us: u64,
}

#[derive(Debug)]
pub struct SessionState {
    policy: SessionPolicy,
    active_key_id: u32,
    active_key_since_us: u64,
    bytes_on_active_key: u64,
    pending_rekey: Option<PendingRekey>,
    previous_key_grace: Option<PreviousKeyGrace>,
    last_pong_us: u64,
    pending_pings: HashMap<u64, u64>,
    rtt_ring_us: VecDeque<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyReason {
    Bytes,
    Age,
}

impl SessionState {
    pub fn new(policy: SessionPolicy, initial_key_id: u32, now_us: u64) -> Self {
        Self {
            policy,
            active_key_id: initial_key_id,
            active_key_since_us: now_us,
            bytes_on_active_key: 0,
            pending_rekey: None,
            previous_key_grace: None,
            last_pong_us: now_us,
            pending_pings: HashMap::new(),
            rtt_ring_us: VecDeque::with_capacity(5),
        }
    }

    pub fn active_key_id(&self) -> u32 {
        self.active_key_id
    }

    pub fn should_rekey(&self, now_us: u64) -> bool {
        self.rekey_reason(now_us).is_some()
    }

    pub fn rekey_reason(&self, now_us: u64) -> Option<RekeyReason> {
        if self.pending_rekey.is_some() {
            return None;
        }
        if self.bytes_on_active_key >= self.policy.rekey_bytes_threshold {
            return Some(RekeyReason::Bytes);
        }
        if now_us.saturating_sub(self.active_key_since_us) >= self.policy.rekey_age_threshold_us {
            return Some(RekeyReason::Age);
        }
        None
    }

    pub fn on_bytes_sent(&mut self, bytes: usize) {
        self.bytes_on_active_key = self.bytes_on_active_key.saturating_add(bytes as u64);
    }

    pub fn build_session_change_request(
        &mut self,
        request_id: u64,
        next_key_id: u32,
        now_us: u64,
    ) -> SessionChangeRequest {
        self.pending_rekey = Some(PendingRekey {
            request_id,
            next_key_id,
            requested_at_us: now_us,
        });

        SessionChangeRequest {
            request_id,
            next_key_id,
        }
    }

    pub fn accept_session_change_request(&self, req: SessionChangeRequest) -> SessionChangeAck {
        SessionChangeAck {
            request_id: req.request_id,
            accepted_key_id: req.next_key_id,
        }
    }

    pub fn handle_session_change_ack(
        &mut self,
        ack: SessionChangeAck,
        now_us: u64,
    ) -> Result<(), &'static str> {
        let Some(pending) = self.pending_rekey else {
            return Err("unexpected SESSION_CHANGE_ACK without pending rekey");
        };

        if pending.request_id != ack.request_id {
            return Err("SESSION_CHANGE_ACK request_id mismatch");
        }
        if pending.next_key_id != ack.accepted_key_id {
            return Err("SESSION_CHANGE_ACK key_id mismatch");
        }

        let old_key = self.active_key_id;
        self.active_key_id = pending.next_key_id;
        self.active_key_since_us = now_us;
        self.bytes_on_active_key = 0;
        self.pending_rekey = None;
        self.previous_key_grace = Some(PreviousKeyGrace {
            key_id: old_key,
            until_us: now_us.saturating_add(self.policy.grace_window_us),
        });

        Ok(())
    }

    pub fn can_accept_key_id(&self, key_id: u32, now_us: u64) -> bool {
        if key_id == self.active_key_id {
            return true;
        }

        match self.previous_key_grace {
            Some(grace) if grace.key_id == key_id && now_us <= grace.until_us => true,
            _ => false,
        }
    }

    pub fn switch_to_remote_key(&mut self, new_key_id: u32, now_us: u64) {
        let old_key = self.active_key_id;
        self.active_key_id = new_key_id;
        self.active_key_since_us = now_us;
        self.bytes_on_active_key = 0;
        self.pending_rekey = None;
        self.previous_key_grace = Some(PreviousKeyGrace {
            key_id: old_key,
            until_us: now_us.saturating_add(self.policy.grace_window_us),
        });
    }

    pub fn track_ping(&mut self, request_id: u64, now_us: u64) -> Ping {
        self.pending_pings.insert(request_id, now_us);
        Ping {
            request_id,
            ts_mono_us: now_us,
        }
    }

    pub fn respond_pong(&self, ping: Ping) -> Pong {
        Pong {
            request_id: ping.request_id,
        }
    }

    pub fn handle_pong(&mut self, pong: Pong, now_us: u64) -> Result<u64, &'static str> {
        let Some(sent_at) = self.pending_pings.remove(&pong.request_id) else {
            return Err("unexpected PONG request_id");
        };

        let rtt_us = now_us.saturating_sub(sent_at);
        self.last_pong_us = now_us;
        self.rtt_ring_us.push_back(rtt_us);
        if self.rtt_ring_us.len() > 5 {
            let _ = self.rtt_ring_us.pop_front();
        }

        Ok(rtt_us)
    }

    pub fn rtt_ring_us(&self) -> Vec<u64> {
        self.rtt_ring_us.iter().copied().collect()
    }

    pub fn is_timed_out(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.last_pong_us) > self.policy.session_timeout_us
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_micros(self.policy.session_timeout_us)
    }
}

#[cfg(test)]
mod tests {
    use super::{REKEY_AGE_THRESHOLD_US_V1, REKEY_BYTES_THRESHOLD_V1, SessionPolicy, SessionState};

    #[test]
    fn rekey_triggers_by_bytes_or_age() {
        let mut state = SessionState::new(SessionPolicy::default(), 10, 1_000);

        assert!(!state.should_rekey(2_000));

        state.on_bytes_sent(REKEY_BYTES_THRESHOLD_V1 as usize);
        assert!(state.should_rekey(3_000));

        let state2 = SessionState::new(SessionPolicy::default(), 10, 1_000);
        assert!(state2.should_rekey(1_000 + REKEY_AGE_THRESHOLD_US_V1));
    }

    #[test]
    fn switch_happens_after_ack_with_grace_window() {
        let policy = SessionPolicy {
            grace_window_us: 50,
            ..SessionPolicy::default()
        };
        let mut state = SessionState::new(policy, 7, 0);

        let req = state.build_session_change_request(1, 8, 10);
        let ack = state.accept_session_change_request(req);

        assert_eq!(state.active_key_id(), 7);
        state
            .handle_session_change_ack(ack, 20)
            .expect("ack must switch key");

        assert_eq!(state.active_key_id(), 8);
        assert!(state.can_accept_key_id(8, 21));
        assert!(state.can_accept_key_id(7, 60));
        assert!(!state.can_accept_key_id(7, 80));
    }

    #[test]
    fn ping_pong_tracks_rtt_ring_of_five() {
        let mut state = SessionState::new(SessionPolicy::default(), 1, 100);

        for i in 0..7u64 {
            let ping = state.track_ping(i, 1_000 + i * 10);
            let pong = state.respond_pong(ping);
            let _ = state
                .handle_pong(pong, 1_003 + i * 10)
                .expect("pong should be tracked");
        }

        let ring = state.rtt_ring_us();
        assert_eq!(ring.len(), 5);
        assert_eq!(ring, vec![3, 3, 3, 3, 3]);
    }

    #[test]
    fn no_pong_invalidates_link_by_timeout() {
        let policy = SessionPolicy {
            session_timeout_us: 100,
            ..SessionPolicy::default()
        };
        let mut state = SessionState::new(policy, 1, 1_000);

        let ping = state.track_ping(55, 1_010);
        let _ = ping;

        assert!(!state.is_timed_out(1_100));
        assert!(state.is_timed_out(1_101));

        let pong = state.respond_pong(ping);
        let _ = state
            .handle_pong(pong, 1_102)
            .expect("pong should recover liveness");
        assert!(!state.is_timed_out(1_150));
    }
}
