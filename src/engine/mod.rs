//! Core Neighbor Discovery responder engine and packet scheduling state machine.

mod rate;
use rate::TokenBucket;

use crate::{
    config::Config,
    packet::{self, MacAddress, NeighborSolicitation},
};
use std::{
    collections::{HashMap, VecDeque},
    net::Ipv6Addr,
    sync::{Arc, Weak},
    time::Duration,
};

/// Operational state of a local network interface used by the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    /// Interface name (e.g. `eth0`).
    pub name: String,
    /// Kernel interface index (`ifindex`).
    pub index: u32,
    /// Hardware Ethernet MAC address.
    pub mac: MacAddress,
    /// Selected link-local IPv6 address (`fe80::/10`).
    pub link_local: Ipv6Addr,
}

/// Internal engine tracking state for an active interface.
struct InterfaceLinkState {
    interface: NetworkInterface,
    lease: Arc<()>,
    rx: TokenBucket,
    tx: TokenBucket,
}

/// Outgoing Ethernet frame queued for or ready for transmission.
#[derive(Debug, Clone)]
pub struct OutgoingTransmission {
    /// Target network interface name.
    pub interface: String,
    /// Complete Ethernet frame bytes.
    pub frame: Vec<u8>,
    /// Expiration timestamp after which this frame will be dropped.
    expires: Duration,
    /// Weak reference to the interface lease; invalid once the interface drops or changes.
    link: Weak<()>,
}

impl OutgoingTransmission {
    /// Checks whether this transmission is still within its timeout and its interface is active.
    pub fn is_valid(&self, now: Duration) -> bool {
        self.expires > now && self.link.strong_count() > 0
    }
}

/// Packet and queue counters maintained by the engine.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResponderStats {
    /// Total Neighbor Solicitation frames received.
    pub received: u64,
    /// Malformed or unparseable frames dropped.
    pub invalid: u64,
    /// Frames dropped due to receive or transmit rate limits.
    pub limited: u64,
    /// Neighbor Advertisements successfully transmitted.
    pub transmitted: u64,
    /// Transmit errors reported by the socket layer.
    pub send_errors: u64,
    /// Queued replies dropped due to timeout, capacity, or interface change.
    pub queue_dropped: u64,
}

/// State machine that processes solicitations, enforces rate limits, and queues replies.
pub struct ResponderEngine {
    config: Config,
    interfaces: HashMap<String, InterfaceLinkState>,
    deferred: VecDeque<OutgoingTransmission>,
    /// Accumulated runtime counters.
    pub stats: ResponderStats,
}

impl ResponderEngine {
    /// Constructs a responder engine with the given configuration.
    pub fn new(config: Config) -> std::io::Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            interfaces: HashMap::new(),
            deferred: VecDeque::new(),
            stats: ResponderStats::default(),
        })
    }

    /// Updates the active network interface set.
    ///
    /// Preserves rate limit tokens for interfaces whose configuration has not changed.
    /// Dropping modified or removed interfaces drops their lease, which invalidates
    /// any queued replies bound to that incarnation of the interface.
    pub fn update_interfaces(&mut self, interfaces: Vec<NetworkInterface>) {
        let mut next = HashMap::new();
        for interface in interfaces {
            let link = self
                .interfaces
                .remove(&interface.name)
                .filter(|link| link.interface == interface)
                .unwrap_or_else(|| InterfaceLinkState {
                    interface: interface.clone(),
                    lease: Arc::new(()),
                    rx: TokenBucket::new(self.config.limits.burst),
                    tx: TokenBucket::new(self.config.limits.burst),
                });
            next.insert(interface.name, link);
        }
        self.interfaces = next;
        self.prune_queue(Duration::ZERO);
    }

    /// Checks the token bucket for either receiving (`transmit = false`) or sending (`transmit = true`).
    fn check_rate_limit(&mut self, name: &str, now: Duration, transmit: bool) -> bool {
        let limits = &self.config.limits;
        let link = self.interfaces.get_mut(name).unwrap();
        let bucket = if transmit { &mut link.tx } else { &mut link.rx };
        if bucket.try_consume(now, limits.packets_per_second, limits.burst) {
            true
        } else {
            self.stats.limited += 1;
            false
        }
    }

    /// Returns the number of transmissions currently queued in the engine.
    pub fn queued_count(&self) -> usize {
        self.deferred.len()
    }

    /// Removes expired or invalidated transmissions from the queue.
    fn prune_queue(&mut self, now: Duration) {
        let before = self.deferred.len();
        self.deferred.retain(|tx| tx.is_valid(now));
        self.stats.queue_dropped += (before - self.deferred.len()) as u64;
    }

    /// Creates a weak lease reference for an interface.
    fn lease_link(&self, name: &str) -> Weak<()> {
        Arc::downgrade(&self.interfaces[name].lease)
    }

    /// Enqueues a transmission if capacity allows and no duplicate is already queued.
    fn enqueue_transmission(&mut self, tx: OutgoingTransmission, now: Duration) {
        self.prune_queue(now);
        if !tx.is_valid(now) {
            self.stats.queue_dropped += 1;
            return;
        }
        // Deduplicate identical pending frames on the same interface generation.
        if self.deferred.iter().any(|other| {
            other.interface == tx.interface
                && other.frame == tx.frame
                && other.link.ptr_eq(&tx.link)
        }) {
            return;
        }
        if self.deferred.len() >= self.config.limits.max_queued {
            self.stats.queue_dropped += 1;
            return;
        }
        self.deferred.push_back(tx);
    }

    /// Records a successful frame transmission.
    pub fn record_sent(&mut self) {
        self.stats.transmitted += 1;
    }

    /// Records a failed send attempt, re-queuing the transmission if `retry` is true.
    pub fn record_send_failure(&mut self, tx: OutgoingTransmission, retry: bool, now: Duration) {
        self.stats.send_errors += 1;
        if retry {
            self.enqueue_transmission(tx, now);
        } else {
            self.stats.queue_dropped += 1;
        }
    }

    /// Transmits immediately if the interface queue is empty and rate allows; defers otherwise.
    fn dispatch_transmission(
        &mut self,
        tx: OutgoingTransmission,
        now: Duration,
    ) -> Option<OutgoingTransmission> {
        if !self
            .deferred
            .iter()
            .any(|queued| queued.interface == tx.interface)
            && self.check_rate_limit(&tx.interface, now, true)
        {
            Some(tx)
        } else {
            self.enqueue_transmission(tx, now);
            None
        }
    }

    /// Constructs and schedules a Neighbor Advertisement in response to a solicitation.
    fn enqueue_reply(
        &mut self,
        name: &str,
        request: NeighborSolicitation,
        now: Duration,
    ) -> Option<OutgoingTransmission> {
        let interface = &self.interfaces[name].interface;
        let (destination, mac) = if request.source.is_unspecified() {
            (
                packet::ALL_NODES_ADDR,
                packet::compute_multicast_mac(packet::ALL_NODES_ADDR),
            )
        } else {
            (request.source, request.source_mac)
        };
        let frame = packet::build_neighbor_advertisement(
            interface.mac,
            interface.link_local,
            mac,
            destination,
            request.target,
        );
        self.dispatch_transmission(
            OutgoingTransmission {
                interface: name.into(),
                frame,
                expires: now
                    .saturating_add(Duration::from_millis(self.config.limits.reply_timeout_ms)),
                link: self.lease_link(name),
            },
            now,
        )
    }

    /// Processes an incoming raw Ethernet frame on the specified interface.
    ///
    /// Validates framing, checks rate limits, matches target against configured
    /// prefix rules, and returns an immediate reply when transmission capacity is available.
    pub fn receive_frame(
        &mut self,
        name: &str,
        frame: &[u8],
        now: Duration,
    ) -> Option<OutgoingTransmission> {
        if !self.interfaces.contains_key(name) {
            return None;
        }
        self.stats.received += 1;
        if !self.check_rate_limit(name, now, false) {
            return None;
        }
        let Some(packet) = packet::parse_solicitation_frame(frame) else {
            self.stats.invalid += 1;
            return None;
        };
        // Ignore frames sent from our own MAC addresses, and ignore unicast frames
        // addressed to someone else's MAC.
        if self
            .interfaces
            .values()
            .any(|i| i.interface.mac == packet.source_mac)
            || (!packet.destination.is_multicast()
                && packet.destination_mac != self.interfaces[name].interface.mac)
        {
            return None;
        }
        self.prune_queue(now);
        if self
            .config
            .responder
            .iter()
            .any(|rule| rule.interface == name && rule.prefix.contains(&packet.target))
        {
            self.enqueue_reply(name, packet, now)
        } else {
            None
        }
    }

    /// Advances the engine timer, draining queued transmissions that now have rate capacity.
    pub fn process_timer_tick(&mut self, now: Duration) -> Vec<OutgoingTransmission> {
        self.prune_queue(now);
        let mut output = Vec::new();
        for _ in 0..self.deferred.len() {
            let tx = self.deferred.pop_front().unwrap();
            if self.check_rate_limit(&tx.interface, now, true) {
                output.push(tx);
            } else {
                self.deferred.push_back(tx);
            }
        }
        output
    }
}
