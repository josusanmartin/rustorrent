// BEP 55 (ut_holepunch): a peer connected to two others introduces them so
// that both open a uTP connection at the same time. The simultaneous
// outgoing packets open both NATs, which lets two peers that cannot accept
// incoming connections still reach each other.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Our extension message ID for ut_holepunch in the extended handshake.
pub const EXT_ID: u8 = 3;

const MSG_RENDEZVOUS: u8 = 0;
const MSG_CONNECT: u8 = 1;
const MSG_ERROR: u8 = 2;

// BEP 55 error 1 (no such peer) is folded into "not connected": we only
// know the peers we are connected to.
pub const ERR_NOT_CONNECTED: u32 = 2;
pub const ERR_NO_SUPPORT: u32 = 3;
pub const ERR_NO_SELF: u32 = 4;

/// Each relay learned from PEX is remembered for this many targets.
const MAX_RELAYS: usize = 2048;
const MAX_PENDING_CONNECTS: usize = 64;
const MAX_OUTBOX: usize = 32;
/// A target is introduced at most once per this interval, in either role.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Msg {
    Rendezvous(SocketAddr),
    Connect(SocketAddr),
    Error(SocketAddr, u32),
}

pub fn encode(msg: Msg) -> Vec<u8> {
    let (kind, addr, code) = match msg {
        Msg::Rendezvous(addr) => (MSG_RENDEZVOUS, addr, 0),
        Msg::Connect(addr) => (MSG_CONNECT, addr, 0),
        Msg::Error(addr, code) => (MSG_ERROR, addr, code),
    };
    let mut out = Vec::with_capacity(24);
    out.push(kind);
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(0);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out
}

pub fn decode(payload: &[u8]) -> Option<Msg> {
    let (&kind, rest) = payload.split_first()?;
    let (&family, rest) = rest.split_first()?;
    let (ip, rest): (IpAddr, &[u8]) = match family {
        0 => {
            let (octets, rest) = rest.split_first_chunk::<4>()?;
            (IpAddr::from(*octets), rest)
        }
        1 => {
            let (octets, rest) = rest.split_first_chunk::<16>()?;
            (IpAddr::from(*octets), rest)
        }
        _ => return None,
    };
    let (port, rest) = rest.split_first_chunk::<2>()?;
    let addr = SocketAddr::new(ip, u16::from_be_bytes(*port));
    // The error code is only meaningful in error messages but always sent.
    let code = rest
        .first_chunk::<4>()
        .map_or(0, |code| u32::from_be_bytes(*code));
    match kind {
        MSG_RENDEZVOUS => Some(Msg::Rendezvous(addr)),
        MSG_CONNECT => Some(Msg::Connect(addr)),
        MSG_ERROR => Some(Msg::Error(addr, code)),
        _ => None,
    }
}

/// One spelling per address: a dual-stack listener reports IPv4 peers as
/// IPv4-mapped IPv6, while PEX and holepunch messages name them as IPv4.
fn canon(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn canon_msg(msg: Msg) -> Msg {
    match msg {
        Msg::Rendezvous(addr) => Msg::Rendezvous(canon(addr)),
        Msg::Connect(addr) => Msg::Connect(canon(addr)),
        Msg::Error(addr, code) => Msg::Error(canon(addr), code),
    }
}

struct Peer {
    /// The peer's ID for ut_holepunch; None when it does not support it.
    ext_id: Option<u8>,
    /// Listening port from the peer's extended handshake ("p"), which is how
    /// other peers know an incoming connection.
    listen_port: Option<u16>,
    outbox: Vec<Msg>,
}

#[derive(Default)]
struct State {
    peers: HashMap<SocketAddr, Peer>,
    /// target -> the peer that told us about it over PEX.
    relays: HashMap<SocketAddr, SocketAddr>,
    connects: Vec<SocketAddr>,
    recent: HashMap<SocketAddr, Instant>,
}

/// Holepunch state for one torrent, shared by its peer connections.
#[derive(Default)]
pub struct Holepunch {
    state: Mutex<State>,
    /// Queued messages across all outboxes, so peer loops skip the lock.
    queued: AtomicUsize,
}

impl Holepunch {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn register(&self, addr: SocketAddr) {
        let addr = canon(addr);
        self.lock().peers.insert(
            addr,
            Peer {
                ext_id: None,
                listen_port: None,
                outbox: Vec::new(),
            },
        );
    }

    pub fn unregister(&self, addr: SocketAddr) {
        let addr = canon(addr);
        if let Some(peer) = self.lock().peers.remove(&addr) {
            self.queued.fetch_sub(peer.outbox.len(), Ordering::SeqCst);
        }
    }

    /// Records what the peer's extended handshake said.
    pub fn set_caps(&self, addr: SocketAddr, ext_id: Option<u8>, listen_port: Option<u16>) {
        let addr = canon(addr);
        if let Some(peer) = self.lock().peers.get_mut(&addr) {
            peer.ext_id = ext_id.filter(|&id| id != 0);
            peer.listen_port = listen_port.filter(|&port| port != 0);
        }
    }

    /// Messages to send to `addr`, with the peer's extension ID.
    pub fn take_outbox(&self, addr: SocketAddr) -> Option<(u8, Vec<Msg>)> {
        if self.queued.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut state = self.lock();
        let peer = state.peers.get_mut(&canon(addr))?;
        let ext_id = peer.ext_id?;
        if peer.outbox.is_empty() {
            return None;
        }
        let messages = std::mem::take(&mut peer.outbox);
        self.queued.fetch_sub(messages.len(), Ordering::SeqCst);
        Some((ext_id, messages))
    }

    /// Remembers that `relay` is connected to these peers (it told us about
    /// them over PEX), in case we cannot reach them directly.
    pub fn note_pex(&self, relay: SocketAddr, targets: &[SocketAddr]) {
        let relay = canon(relay);
        let mut state = self.lock();
        for target in targets.iter().copied().map(canon) {
            if state.relays.len() >= MAX_RELAYS && !state.relays.contains_key(&target) {
                break;
            }
            state.relays.insert(target, relay);
        }
    }

    /// Initiator role: after a failed connection to `target`, asks the peer
    /// that knows it to introduce us. True when a request was queued.
    pub fn request(&self, target: SocketAddr, now: Instant) -> bool {
        let target = canon(target);
        let mut state = self.lock();
        let Some(&relay) = state.relays.get(&target) else {
            return false;
        };
        if !mark_recent(&mut state.recent, target, now) {
            return false;
        }
        let queued = queue(&mut state.peers, relay, Msg::Rendezvous(target));
        if queued {
            self.queued.fetch_add(1, Ordering::SeqCst);
        }
        queued
    }

    /// Handles a ut_holepunch message from `from`.
    pub fn on_message(&self, from: SocketAddr, msg: Msg, now: Instant) {
        let (from, msg) = (canon(from), canon_msg(msg));
        let mut state = self.lock();
        match msg {
            Msg::Rendezvous(target) => {
                let mut added = 0;
                match relay_target(&state.peers, from, target) {
                    Ok(target_conn) => {
                        // Introduce each to the other by the address we
                        // see it on, which is where its NAT will answer.
                        if queue(&mut state.peers, from, Msg::Connect(target)) {
                            added += 1;
                        }
                        if queue(&mut state.peers, target_conn, Msg::Connect(from)) {
                            added += 1;
                        }
                    }
                    Err(code) => {
                        if queue(&mut state.peers, from, Msg::Error(target, code)) {
                            added += 1;
                        }
                    }
                }
                self.queued.fetch_add(added, Ordering::SeqCst);
            }
            Msg::Connect(target) => {
                if state.peers.contains_key(&target)
                    || state.connects.len() >= MAX_PENDING_CONNECTS
                    || state.connects.contains(&target)
                {
                    return;
                }
                // The relay has already told the target to connect, so a
                // recent attempt of our own does not hold this one back.
                state.recent.insert(target, now);
                state.connects.push(target);
            }
            // The relay could not introduce us; the normal retry schedule
            // for the target still applies.
            Msg::Error(..) => {}
        }
    }

    /// Peers a relay asked us to connect to now.
    pub fn take_connects(&self) -> Vec<SocketAddr> {
        let mut state = self.lock();
        if state.connects.is_empty() {
            return Vec::new();
        }
        std::mem::take(&mut state.connects)
    }
}

fn mark_recent(
    recent: &mut HashMap<SocketAddr, Instant>,
    target: SocketAddr,
    now: Instant,
) -> bool {
    recent.retain(|_, at| now.saturating_duration_since(*at) < RETRY_INTERVAL);
    if recent.contains_key(&target) || recent.len() >= MAX_RELAYS {
        return false;
    }
    recent.insert(target, now);
    true
}

fn queue(peers: &mut HashMap<SocketAddr, Peer>, to: SocketAddr, msg: Msg) -> bool {
    match peers.get_mut(&to) {
        Some(peer) if peer.ext_id.is_some() && peer.outbox.len() < MAX_OUTBOX => {
            peer.outbox.push(msg);
            true
        }
        _ => false,
    }
}

/// The connection that `target` names, or the BEP 55 error for the request.
fn relay_target(
    peers: &HashMap<SocketAddr, Peer>,
    from: SocketAddr,
    target: SocketAddr,
) -> Result<SocketAddr, u32> {
    if target == from {
        return Err(ERR_NO_SELF);
    }
    let found = peers.get_key_value(&target).or_else(|| {
        peers.iter().find(|(addr, peer)| {
            addr.ip() == target.ip() && peer.listen_port == Some(target.port())
        })
    });
    match found {
        None => Err(ERR_NOT_CONNECTED),
        Some((&addr, _)) if addr == from => Err(ERR_NO_SELF),
        Some((_, peer)) if peer.ext_id.is_none() => Err(ERR_NO_SUPPORT),
        Some((&addr, _)) => Ok(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn messages_round_trip_in_bep55_layout() {
        let v4 = Msg::Rendezvous(addr("1.2.3.4:6881"));
        assert_eq!(
            encode(v4),
            [0, 0, 1, 2, 3, 4, 0x1a, 0xe1, 0, 0, 0, 0].to_vec()
        );
        let v6 = Msg::Error(addr("[2001:db8::1]:51413"), ERR_NOT_CONNECTED);
        let bytes = encode(v6);
        assert_eq!(bytes.len(), 1 + 1 + 16 + 2 + 4);
        assert_eq!(decode(&bytes), Some(v6));
        assert_eq!(
            decode(&encode(Msg::Connect(addr("5.6.7.8:1")))),
            Some(Msg::Connect(addr("5.6.7.8:1")))
        );
        assert_eq!(decode(&[9, 0, 1, 2, 3, 4, 0, 1]), None);
        assert_eq!(decode(&[0, 0, 1, 2]), None);
    }

    #[test]
    fn relay_introduces_both_peers_or_reports_why_not() {
        let hp = Holepunch::default();
        let (a, b, c) = (
            addr("1.1.1.1:1000"),
            addr("2.2.2.2:40000"),
            addr("3.3.3.3:3000"),
        );
        let now = Instant::now();
        for peer in [a, b, c] {
            hp.register(peer);
        }
        hp.set_caps(a, Some(7), None);
        hp.set_caps(b, Some(9), Some(6881));

        // b connected in from an ephemeral port; a names its listen port.
        hp.on_message(a, Msg::Rendezvous(addr("2.2.2.2:6881")), now);
        assert_eq!(
            hp.take_outbox(a),
            Some((7, vec![Msg::Connect(addr("2.2.2.2:6881"))]))
        );
        assert_eq!(hp.take_outbox(b), Some((9, vec![Msg::Connect(a)])));

        hp.on_message(a, Msg::Rendezvous(c), now);
        hp.on_message(a, Msg::Rendezvous(addr("4.4.4.4:1")), now);
        hp.on_message(a, Msg::Rendezvous(a), now);
        assert_eq!(
            hp.take_outbox(a),
            Some((
                7,
                vec![
                    Msg::Error(c, ERR_NO_SUPPORT),
                    Msg::Error(addr("4.4.4.4:1"), ERR_NOT_CONNECTED),
                    Msg::Error(a, ERR_NO_SELF),
                ]
            ))
        );
        assert_eq!(hp.queued.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dual_stack_addresses_match_their_ipv4_form() {
        let hp = Holepunch::default();
        let (a, b) = (addr("[::ffff:1.1.1.1]:1000"), addr("[::ffff:2.2.2.2]:2000"));
        let now = Instant::now();
        for peer in [a, b] {
            hp.register(peer);
            hp.set_caps(peer, Some(5), None);
        }
        hp.on_message(a, Msg::Rendezvous(addr("2.2.2.2:2000")), now);
        assert_eq!(
            hp.take_outbox(addr("1.1.1.1:1000")),
            Some((5, vec![Msg::Connect(addr("2.2.2.2:2000"))]))
        );
        assert_eq!(
            hp.take_outbox(b),
            Some((5, vec![Msg::Connect(addr("1.1.1.1:1000"))]))
        );
        assert_eq!(
            encode(Msg::Connect(addr("1.1.1.1:1000")))[1],
            0,
            "IPv4 peers are introduced as IPv4"
        );
    }

    #[test]
    fn initiator_asks_the_pex_source_once_and_connects_when_told() {
        let hp = Holepunch::default();
        let (relay, target) = (addr("1.1.1.1:1000"), addr("2.2.2.2:2000"));
        let now = Instant::now();
        hp.register(relay);
        hp.set_caps(relay, Some(4), None);
        assert!(!hp.request(target, now), "no relay known yet");
        hp.note_pex(relay, &[target]);
        assert!(hp.request(target, now));
        assert!(
            !hp.request(target, now + Duration::from_secs(1)),
            "rate limited"
        );
        assert_eq!(
            hp.take_outbox(relay),
            Some((4, vec![Msg::Rendezvous(target)]))
        );
        assert!(hp.request(target, now + RETRY_INTERVAL));

        hp.on_message(relay, Msg::Connect(target), now);
        hp.on_message(relay, Msg::Connect(target), now);
        hp.on_message(relay, Msg::Connect(relay), now);
        assert_eq!(hp.take_connects(), vec![target]);
        assert!(hp.take_connects().is_empty());

        hp.unregister(relay);
        assert_eq!(hp.queued.load(Ordering::SeqCst), 0);
    }
}
