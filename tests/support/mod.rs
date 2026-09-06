//! Test fixtures, synthetic frame encoding/decoding, and simulation world.

#![allow(dead_code)]
use ndp_responder_lite::{
    config::{Config, ResourceLimits, ResponderRule},
    engine::{NetworkInterface, OutgoingTransmission, ResponderEngine},
};
use std::{net::Ipv6Addr, time::Duration};

pub type Mac = [u8; 6];
pub const UP: Mac = [2, 0, 0, 0, 0, 1];
pub const DOWN: Mac = [2, 0, 0, 0, 0, 2];
pub const A: Mac = [2, 0, 0, 0, 0, 10];
pub const B: Mac = [2, 0, 0, 0, 0, 11];
pub const C: Mac = [2, 0, 0, 0, 0, 12];

pub fn ip(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

pub fn target() -> Ipv6Addr {
    ip("2001:db8:1::100:2")
}

pub fn group(t: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from((u128::from(ip("ff02::1:ff00:0")) & !0xffffff) | (u128::from(t) & 0xffffff))
}

pub fn multicast(ip: Ipv6Addr) -> Mac {
    let b = ip.octets();
    [0x33, 0x33, b[12], b[13], b[14], b[15]]
}

pub fn config() -> Config {
    Config {
        limits: ResourceLimits::default(),
        responder: vec![ResponderRule {
            prefix: "2001:db8:1::100:0/112".parse().unwrap(),
            interface: "up".into(),
        }],
    }
}

pub fn port(name: &str, index: u32, mac: Mac, local: &str) -> NetworkInterface {
    NetworkInterface {
        name: name.into(),
        index,
        mac,
        link_local: ip(local),
    }
}

pub fn ports() -> Vec<NetworkInterface> {
    vec![
        port("up", 1, UP, "fe80::1"),
        port("down", 2, DOWN, "fe80::2"),
    ]
}

/// Decoded representation of a raw wire packet for testing comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wire {
    pub source_mac: Mac,
    pub destination_mac: Mac,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub target: Ipv6Addr,
    pub kind: u8,
    pub flags: u8,
    pub options: Vec<u8>,
}

impl Wire {
    pub fn ns(mac: Mac, source: &str, target: Ipv6Addr) -> Self {
        let source = ip(source);
        let destination = group(target);
        let options = if source.is_unspecified() {
            vec![]
        } else {
            [vec![1, 1], mac.to_vec()].concat()
        };
        Self {
            source_mac: mac,
            destination_mac: multicast(destination),
            source,
            destination,
            target,
            kind: 135,
            flags: 0,
            options,
        }
    }

    pub fn na(
        mac: Mac,
        source: &str,
        destination_mac: Mac,
        destination: &str,
        target: Ipv6Addr,
        flags: u8,
    ) -> Self {
        Self {
            source_mac: mac,
            destination_mac,
            source: ip(source),
            destination: ip(destination),
            target,
            kind: 136,
            flags,
            options: [vec![2, 1], mac.to_vec()].concat(),
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut frame = vec![0; 78];
        frame[..6].copy_from_slice(&self.destination_mac);
        frame[6..12].copy_from_slice(&self.source_mac);
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[20] = 58;
        frame[21] = 255;
        frame[22..38].copy_from_slice(&self.source.octets());
        frame[38..54].copy_from_slice(&self.destination.octets());
        frame[54] = self.kind;
        frame[58] = self.flags;
        frame[62..78].copy_from_slice(&self.target.octets());
        frame.extend_from_slice(&self.options);
        let length = (frame.len() - 54) as u16;
        frame[18..20].copy_from_slice(&length.to_be_bytes());
        repair(&mut frame);
        frame
    }

    pub fn read(frame: &[u8]) -> Self {
        assert!(frame.len() >= 78);
        assert_eq!(&frame[12..15], &[0x86, 0xdd, 0x60]);
        assert_eq!(&frame[20..22], &[58, 255]);
        assert_eq!(
            usize::from(u16::from_be_bytes(frame[18..20].try_into().unwrap())) + 54,
            frame.len()
        );
        assert_eq!(
            u16::from_be_bytes(frame[56..58].try_into().unwrap()),
            wire_checksum(frame),
            "incorrect checksum"
        );
        assert_eq!(frame[55], 0);
        assert_eq!(&frame[59..62], &[0, 0, 0]);
        Self {
            source_mac: frame[6..12].try_into().unwrap(),
            destination_mac: frame[..6].try_into().unwrap(),
            source: Ipv6Addr::from(<[u8; 16]>::try_from(&frame[22..38]).unwrap()),
            destination: Ipv6Addr::from(<[u8; 16]>::try_from(&frame[38..54]).unwrap()),
            target: Ipv6Addr::from(<[u8; 16]>::try_from(&frame[62..78]).unwrap()),
            kind: frame[54],
            flags: frame[58],
            options: frame[78..].to_vec(),
        }
    }
}

pub fn wire_checksum(frame: &[u8]) -> u16 {
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[22..38]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[38..54]).unwrap());
    let packet = pnet_packet::icmpv6::Icmpv6Packet::new(&frame[54..]).unwrap();
    pnet_packet::icmpv6::checksum(&packet, &source, &destination)
}

pub fn repair(frame: &mut [u8]) {
    frame[56..58].fill(0);
    let c = wire_checksum(frame);
    frame[56..58].copy_from_slice(&c.to_be_bytes());
}

pub fn answer() -> Wire {
    Wire::na(B, "2001:db8:1::100:2", DOWN, "fe80::2", target(), 0x60)
}

pub fn assert_tx(tx: &[OutgoingTransmission], expected: &[(&str, Wire)]) {
    let mut actual: Vec<_> = tx
        .iter()
        .map(|t| (t.interface.clone(), Wire::read(&t.frame)))
        .collect();
    assert_eq!(actual.len(), expected.len(), "{actual:?}");
    for (name, packet) in expected {
        let position = actual
            .iter()
            .position(|(n, p)| n == name && p == packet)
            .unwrap_or_else(|| panic!("missing {name}: {packet:?}; actual {actual:?}"));
        actual.remove(position);
    }
}

/// Simulated test harness containing an engine and simulated virtual interfaces.
pub struct World {
    pub engine: ResponderEngine,
    pub interfaces: Vec<NetworkInterface>,
    pub now: Duration,
}

impl World {
    pub fn new(config: Config) -> Self {
        let interfaces = ports();
        let mut engine = ResponderEngine::new(config).unwrap();
        engine.update_interfaces(interfaces.clone());
        Self {
            engine,
            interfaces,
            now: Duration::ZERO,
        }
    }

    pub fn receive(&mut self, interface: &str, p: &Wire) -> Vec<OutgoingTransmission> {
        self.engine
            .receive_frame(interface, &p.bytes(), self.now)
            .into_iter()
            .collect()
    }

    pub fn at(&mut self, now: Duration) {
        assert!(now >= self.now);
        self.now = now;
    }

    pub fn tick(&mut self, millis: u64) -> Vec<OutgoingTransmission> {
        self.at(Duration::from_millis(millis));
        self.engine.process_timer_tick(self.now)
    }

    pub fn refresh(&mut self) {
        self.engine.update_interfaces(self.interfaces.clone());
    }
}
