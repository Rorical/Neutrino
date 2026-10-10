//! Bounded reconnect state for explicitly configured bootstrap addresses.

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, swarm::ConnectionId};
use neutrino_primitives::blake3_256;
use std::time::Duration;
use tokio::time::Instant;

const MAX_BOOTNODES: usize = 64;
const MAX_ADDRESS_BYTES: usize = 2048;
const MAX_BACKOFF_MILLIS: u64 = 60_000;

struct Bootnode {
    address: Multiaddr,
    expected_peer: Option<PeerId>,
    connected_peer: Option<PeerId>,
    pending: Option<ConnectionId>,
    failures: u8,
    attempts: u64,
    retry_at: Instant,
    disabled: bool,
}

/// Tracks only operator-supplied addresses, never an expanding peer inventory.
#[derive(Default)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "reconnect state is an internal service implementation, not a public network API"
)]
pub(crate) struct Bootnodes {
    entries: Vec<Bootnode>,
    jitter_seed: Vec<u8>,
}

impl Bootnodes {
    pub(crate) fn configured(
        local_peer: PeerId,
        addresses: Vec<Multiaddr>,
        now: Instant,
    ) -> Result<Self, String> {
        if addresses.len() > MAX_BOOTNODES {
            return Err(format!(
                "at most {MAX_BOOTNODES} bootnodes may be configured"
            ));
        }
        let mut entries = Vec::<Bootnode>::new();
        for address in addresses {
            if address.is_empty() || address.len() > MAX_ADDRESS_BYTES {
                return Err("bootnode addresses must contain 1..=2048 bytes".into());
            }
            let expected_peer = match address.iter().last() {
                Some(Protocol::P2p(peer)) => Some(peer),
                _ => None,
            };
            if expected_peer == Some(local_peer) {
                return Err("a bootnode must not name the local peer identity".into());
            }
            if transport_address(&address).is_empty() {
                return Err("a bootnode must include a transport address".into());
            }
            if entries.iter().any(|entry| entry.address == address) {
                continue;
            }
            entries.push(Bootnode {
                address,
                expected_peer,
                connected_peer: None,
                pending: None,
                failures: 0,
                attempts: 0,
                retry_at: now,
                disabled: false,
            });
        }
        Ok(Self {
            entries,
            jitter_seed: local_peer.to_bytes(),
        })
    }

    fn can_start(&self, index: usize) -> bool {
        let entry = &self.entries[index];
        if entry.disabled || entry.connected_peer.is_some() || entry.pending.is_some() {
            return false;
        }
        !entry.expected_peer.is_some_and(|peer| {
            self.entries.iter().any(|other| {
                other.expected_peer == Some(peer)
                    && (other.pending.is_some() || other.connected_peer.is_some())
            })
        })
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, _)| self.can_start(*index))
            .map(|(_, entry)| entry.retry_at)
            .min()
    }

    pub(crate) fn next_due(&self, now: Instant) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find(|(index, entry)| entry.retry_at <= now && self.can_start(*index))
            .map(|(index, _)| index)
    }

    pub(crate) fn address(&self, index: usize) -> &Multiaddr {
        &self.entries[index].address
    }

    pub(crate) fn expected_peer(&self, index: usize) -> Option<PeerId> {
        self.entries[index].expected_peer
    }

    pub(crate) fn manual_target(&self, address: &Multiaddr) -> Option<usize> {
        let transport = transport_address(address);
        self.entries.iter().position(|entry| {
            entry.address == *address
                || (entry.expected_peer.is_none() && transport_address(&entry.address) == transport)
        })
    }

    pub(crate) fn start(&mut self, index: usize, connection: ConnectionId) -> bool {
        if !self.can_start(index) {
            return false;
        }
        let entry = &mut self.entries[index];
        entry.pending = Some(connection);
        entry.attempts = entry.attempts.saturating_add(1);
        true
    }

    pub(crate) fn failed(
        &mut self,
        connection: ConnectionId,
        now: Instant,
        self_dial: bool,
    ) -> bool {
        let mut matched = false;
        for entry in &mut self.entries {
            if entry.pending != Some(connection) {
                continue;
            }
            entry.pending = None;
            matched = true;
            if self_dial {
                entry.disabled = true;
            } else if entry.connected_peer.is_none() {
                schedule_retry(entry, &self.jitter_seed, now);
            }
        }
        matched
    }

    pub(crate) fn states(&self, now: Instant) -> [u64; 6] {
        let mut states = [0; 6];
        for (index, entry) in self.entries.iter().enumerate() {
            let state = if entry.disabled {
                4
            } else if entry.connected_peer.is_some() {
                0
            } else if entry.pending.is_some() {
                1
            } else if !self.can_start(index) {
                5
            } else if entry.retry_at > now {
                2
            } else {
                3
            };
            states[state] += 1;
        }
        states
    }

    pub(crate) fn connected(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        address: &Multiaddr,
    ) {
        let transport = transport_address(address);
        for entry in &mut self.entries {
            if entry.pending == Some(connection)
                || entry.expected_peer == Some(peer)
                || entry.connected_peer == Some(peer)
                || (entry.expected_peer.is_none() && transport_address(&entry.address) == transport)
            {
                entry.connected_peer = Some(peer);
                entry.pending = None;
                entry.failures = 0;
            }
        }
    }

    pub(crate) fn disconnected(&mut self, peer: PeerId, remaining: u32, now: Instant) {
        if remaining != 0 {
            return;
        }
        for entry in &mut self.entries {
            if entry.connected_peer == Some(peer) {
                entry.connected_peer = None;
                schedule_retry(entry, &self.jitter_seed, now);
            }
        }
    }

    pub(crate) fn local_address(&mut self, address: &Multiaddr) {
        let transport = transport_address(address);
        for entry in &mut self.entries {
            if transport_address(&entry.address) == transport {
                entry.disabled = true;
            }
        }
    }
}

fn transport_address(address: &Multiaddr) -> Multiaddr {
    let mut transport = address.clone();
    if matches!(transport.iter().last(), Some(Protocol::P2p(_))) {
        let _ = transport.pop();
    }
    transport
}

fn schedule_retry(entry: &mut Bootnode, seed: &[u8], now: Instant) {
    entry.failures = entry.failures.saturating_add(1);
    let exponent = u32::from(entry.failures.saturating_sub(1).min(6));
    let nominal = (1000_u64 << exponent).min(MAX_BACKOFF_MILLIS);
    let minimum = (nominal / 2).max(1000);
    let mut entropy = seed.to_vec();
    entropy.extend_from_slice(&entry.address.to_vec());
    entropy.extend_from_slice(&entry.attempts.to_le_bytes());
    entropy.push(entry.failures);
    let digest = blake3_256(&entropy);
    let random = u64::from_le_bytes(digest[..8].try_into().expect("eight hash bytes"));
    let millis = minimum + random % (nominal - minimum + 1);
    entry.retry_at = now + Duration::from_millis(millis);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(port: u16, peer: Option<PeerId>) -> Multiaddr {
        let mut result: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
        if let Some(peer) = peer {
            result.push(Protocol::P2p(peer));
        }
        result
    }

    #[test]
    fn fake_time_retries_back_off_with_bounded_jitter_and_ignore_stale_failures() {
        let now = Instant::now();
        let mut state =
            Bootnodes::configured(PeerId::random(), vec![address(1, None)], now).unwrap();
        assert_eq!(state.next_due(now), Some(0));
        for attempt in 0..100 {
            let at = state.next_deadline().unwrap();
            let connection = ConnectionId::new_unchecked(attempt);
            assert!(state.start(0, connection));
            assert_eq!(state.next_deadline(), None);
            assert!(!state.start(0, ConnectionId::new_unchecked(1000)));
            state.failed(ConnectionId::new_unchecked(1000), at, false);
            assert_eq!(state.next_deadline(), None);
            state.failed(connection, at, false);
            let next = state.next_deadline().unwrap();
            let nominal = (1000_u64 << attempt.min(6)).min(MAX_BACKOFF_MILLIS);
            let delay = next.duration_since(at);
            assert!(delay >= Duration::from_millis((nominal / 2).max(1000)));
            assert!(delay <= Duration::from_millis(nominal));
            assert_eq!(state.next_due(next - Duration::from_nanos(1)), None);
            assert_eq!(state.next_due(next), Some(0));
        }
    }

    #[test]
    fn same_peer_addresses_share_pending_and_connected_state_until_last_connection_closes() {
        let now = Instant::now();
        let peer = PeerId::random();
        let addresses = vec![address(1, Some(peer)), address(2, Some(peer))];
        let mut state = Bootnodes::configured(PeerId::random(), addresses.clone(), now).unwrap();
        let first = ConnectionId::new_unchecked(1);
        assert!(state.start(0, first));
        assert_eq!(state.next_deadline(), None);
        state.failed(first, now, false);
        assert_eq!(state.next_due(now), Some(1));
        let second = ConnectionId::new_unchecked(2);
        assert!(state.start(1, second));
        state.connected(peer, second, &addresses[1]);
        assert_eq!(state.next_deadline(), None);
        state.disconnected(peer, 1, now);
        assert_eq!(state.next_deadline(), None);
        state.disconnected(peer, 0, now);
        assert!(state.next_deadline().unwrap() > now);
        assert!(state.next_deadline().unwrap() <= now + Duration::from_secs(1));
    }

    #[test]
    fn bare_address_can_reconnect_to_a_restarted_peer_with_a_new_identity() {
        let now = Instant::now();
        let address = address(1, None);
        let mut state =
            Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
        let first_peer = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        assert!(state.start(0, first));
        state.connected(first_peer, first, &address);
        assert_eq!(state.next_deadline(), None);
        state.disconnected(first_peer, 0, now);
        let second_peer = PeerId::random();
        let second = ConnectionId::new_unchecked(2);
        assert!(state.start(0, second));
        state.connected(second_peer, second, &address);
        state.failed(first, now, false);
        assert_eq!(state.entries[0].connected_peer, Some(second_peer));
        assert_eq!(state.entries[0].failures, 0);
    }

    #[test]
    fn only_configured_addresses_are_tracked_and_self_dials_are_disabled() {
        let now = Instant::now();
        let address = address(1, None);
        let mut state =
            Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
        state.connected(
            PeerId::random(),
            ConnectionId::new_unchecked(9),
            &super::tests::address(2, None),
        );
        assert_eq!(state.next_due(now), Some(0));
        let pending = ConnectionId::new_unchecked(1);
        assert!(state.start(0, pending));
        state.failed(pending, now, true);
        assert_eq!(state.next_deadline(), None);
        let mut local =
            Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
        local.local_address(&address);
        assert_eq!(local.next_deadline(), None);
    }

    #[test]
    fn configuration_is_bounded_deduplicated_and_rejects_local_identity() {
        let now = Instant::now();
        let local = PeerId::random();
        let address = address(1, None);
        let state =
            Bootnodes::configured(local, vec![address.clone(), address.clone()], now).unwrap();
        assert_eq!(state.entries.len(), 1);
        assert!(Bootnodes::configured(local, vec![address; MAX_BOOTNODES + 1], now).is_err());
        assert!(Bootnodes::configured(local, vec![self::address(1, Some(local))], now).is_err());
        assert!(Bootnodes::configured(local, vec![Multiaddr::empty()], now).is_err());
        let only_peer: Multiaddr = format!("/p2p/{}", PeerId::random()).parse().unwrap();
        assert!(Bootnodes::configured(local, vec![only_peer], now).is_err());
    }
}
