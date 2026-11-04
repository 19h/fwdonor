//! Per-client admission limits.
//!
//! Clients are keyed by IPv4 address or IPv6 /64. The size an upload declares
//! is charged when the upload is admitted and is never refunded, so rejected
//! or abandoned uploads still count against the client.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Limits;

const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey(u128);

impl ClientKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => ClientKey(u128::from(u32::from(v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ClientKey(u128::from(u32::from(v4))),
                None => ClientKey((u128::from(v6) >> 64 << 64) | 1),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    Banned { retry_after: u64 },
    Concurrent,
    Files { retry_after: u64 },
    Bytes { retry_after: u64 },
}

impl Denied {
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Denied::Concurrent => Some(5),
            Denied::Banned { retry_after }
            | Denied::Files { retry_after }
            | Denied::Bytes { retry_after } => Some(*retry_after),
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Denied::Banned { .. } => "too many rejected uploads from this address",
            Denied::Concurrent => "too many uploads in progress from this address",
            Denied::Files { .. } => "hourly file limit reached for this address",
            Denied::Bytes { .. } => "hourly upload volume reached for this address",
        }
    }
}

#[derive(Default)]
struct Client {
    active: u32,
    admitted: VecDeque<(Instant, u64)>,
    rejections: VecDeque<Instant>,
    banned_until: Option<Instant>,
}

#[derive(Default)]
struct State {
    clients: HashMap<ClientKey, Client>,
}

pub struct Limiter {
    limits: Limits,
    state: Mutex<State>,
}

fn secs_until(when: Instant, now: Instant) -> u64 {
    when.saturating_duration_since(now).as_secs().max(1)
}

impl Limiter {
    pub fn new(limits: Limits) -> Self {
        Self { limits, state: Mutex::new(State::default()) }
    }

    /// Admit an upload of `size` bytes, taking a concurrency slot.
    pub fn admit(&self, key: ClientKey, size: u64) -> Result<(), Denied> {
        let now = Instant::now();
        let l = &self.limits;
        let mut state = self.state.lock().unwrap();
        let client = state.clients.entry(key).or_default();
        if let Some(until) = client.banned_until {
            if until > now {
                return Err(Denied::Banned { retry_after: secs_until(until, now) });
            }
            client.banned_until = None;
        }
        while client.admitted.front().is_some_and(|(t, _)| now.duration_since(*t) >= HOUR) {
            client.admitted.pop_front();
        }
        if client.active >= l.per_ip_concurrent {
            return Err(Denied::Concurrent);
        }
        let oldest = client.admitted.front().map(|(t, _)| secs_until(*t + HOUR, now)).unwrap_or(60);
        if client.admitted.len() >= l.per_ip_files_per_hour as usize {
            return Err(Denied::Files { retry_after: oldest });
        }
        let bytes: u64 = client.admitted.iter().map(|(_, b)| b).sum();
        if bytes + size > l.per_ip_bytes_per_hour {
            return Err(Denied::Bytes { retry_after: oldest });
        }
        client.active += 1;
        client.admitted.push_back((now, size));
        Ok(())
    }

    /// Give back the concurrency slot (bytes and file counts stay charged).
    pub fn release(&self, key: ClientKey) {
        if let Some(client) = self.state.lock().unwrap().clients.get_mut(&key) {
            client.active = client.active.saturating_sub(1);
        }
    }

    /// A file the browser claimed was firmware failed server verification.
    pub fn record_rejection(&self, key: ClientKey) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.limits.ban_secs);
        let mut state = self.state.lock().unwrap();
        let client = state.clients.entry(key).or_default();
        while client.rejections.front().is_some_and(|t| now.duration_since(*t) >= window) {
            client.rejections.pop_front();
        }
        client.rejections.push_back(now);
        if client.rejections.len() >= self.limits.ban_after_rejections as usize {
            client.banned_until = Some(now + window);
            return true;
        }
        false
    }

    /// Drop idle client records.
    pub fn prune(&self) {
        let now = Instant::now();
        self.state.lock().unwrap().clients.retain(|_, c| {
            c.active > 0
                || c.banned_until.is_some_and(|u| u > now)
                || c.admitted.back().is_some_and(|(t, _)| now.duration_since(*t) < HOUR)
                || c.rejections.back().is_some()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits { per_ip_concurrent: 2, per_ip_files_per_hour: 3, ..Limits::default() }
    }

    #[test]
    fn concurrency_and_hourly_counts() {
        let limiter = Limiter::new(limits());
        let a = ClientKey::from_ip("10.0.0.1".parse().unwrap());
        assert!(limiter.admit(a, 1).is_ok());
        assert!(limiter.admit(a, 1).is_ok());
        assert_eq!(limiter.admit(a, 1), Err(Denied::Concurrent));
        limiter.release(a);
        assert!(limiter.admit(a, 1).is_ok());
        limiter.release(a);
        assert!(matches!(limiter.admit(a, 1), Err(Denied::Files { .. })));
    }

    #[test]
    fn bytes_and_bans() {
        let limiter = Limiter::new(Limits { per_ip_bytes_per_hour: 100, ban_after_rejections: 2, ..limits() });
        let a = ClientKey::from_ip("10.0.0.2".parse().unwrap());
        assert!(matches!(limiter.admit(a, 101), Err(Denied::Bytes { .. })));
        assert!(!limiter.record_rejection(a));
        assert!(limiter.record_rejection(a));
        assert!(matches!(limiter.admit(a, 1), Err(Denied::Banned { .. })));
    }

    #[test]
    fn ipv6_groups_by_64() {
        let a = ClientKey::from_ip("2001:db8:1:2::1".parse().unwrap());
        let b = ClientKey::from_ip("2001:db8:1:2:ffff::9".parse().unwrap());
        let c = ClientKey::from_ip("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(
            ClientKey::from_ip("::ffff:10.0.0.1".parse().unwrap()),
            ClientKey::from_ip("10.0.0.1".parse().unwrap())
        );
    }
}
