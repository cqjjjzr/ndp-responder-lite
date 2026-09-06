//! Ethernet, IPv6, and ICMPv6 packet parsing and encoding for Neighbor Discovery.

use etherparse::{Ethernet2Header, Ipv6Header};
use std::net::Ipv6Addr;

/// Six-byte Ethernet MAC address.
pub type MacAddress = [u8; 6];

/// IPv6 link-local all-nodes multicast address (`ff02::1`).
pub const ALL_NODES_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Parsed fields of an incoming IPv6 Neighbor Solicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborSolicitation {
    /// Source MAC address from the Ethernet header.
    pub source_mac: MacAddress,
    /// Destination MAC address from the Ethernet header.
    pub destination_mac: MacAddress,
    /// Source IPv6 address from the IPv6 header (`::` for DAD).
    pub source: Ipv6Addr,
    /// Destination IPv6 address from the IPv6 header.
    pub destination: Ipv6Addr,
    /// Target IPv6 address being resolved from the ICMPv6 payload.
    pub target: Ipv6Addr,
}

/// Computes the solicited-node multicast address (`ff02::1:ffxx:xxxx`) for a target address.
pub fn compute_solicited_node_address(target: Ipv6Addr) -> Ipv6Addr {
    let t = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(t[13]),
        u16::from_be_bytes([t[14], t[15]]),
    )
}

/// Maps an IPv6 multicast address to its Ethernet multicast MAC address (`33:33:xx:xx:xx:xx`).
pub fn compute_multicast_mac(address: Ipv6Addr) -> MacAddress {
    let a = address.octets();
    [0x33, 0x33, a[12], a[13], a[14], a[15]]
}

/// Returns true if the MAC address is a non-zero unicast address.
pub fn is_unicast_mac(mac: MacAddress) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6]
}

/// Parses an Ethernet frame containing an IPv6 ICMPv6 Neighbor Solicitation.
///
/// Validates Ethernet framing, IPv6 header fields (hop limit 255), extension headers,
/// ICMPv6 type 135 (Neighbor Solicitation) with code 0, checksum, target address,
/// and option formatting according to RFC 4861 and RFC 6980.
pub fn parse_solicitation_frame(frame: &[u8]) -> Option<NeighborSolicitation> {
    let (eth, ip_bytes) = Ethernet2Header::from_slice(frame).ok()?;
    if eth.ether_type.0 != 0x86dd || !is_unicast_mac(eth.source) {
        return None;
    }
    let (ip, payload) = Ipv6Header::from_slice(ip_bytes).ok()?;
    // IPv6 version must be 6; RFC 4861 requires hop limit 255.
    if ip_bytes[0] >> 4 != 6 || ip.hop_limit != 255 {
        return None;
    }
    let source = Ipv6Addr::from(ip.source);
    let destination = Ipv6Addr::from(ip.destination);
    if source.is_multicast() || destination.is_unspecified() {
        return None;
    }
    if destination.is_multicast() {
        if eth.destination != compute_multicast_mac(destination) {
            return None;
        }
    } else if !is_unicast_mac(eth.destination) {
        return None;
    }

    let mut body = payload.get(..usize::from(ip.payload_length))?;
    let mut next = ip.next_header.0;
    let mut extensions = 0;
    // Walk Hop-by-Hop (0) and Destination Options (60) headers.
    while next == 0 || next == 60 {
        if extensions == 8 || (next == 0 && extensions != 0) {
            return None;
        }
        let size = (usize::from(*body.get(1)?) + 1) * 8;
        let header = body.get(..size)?;
        let mut options = &header[2..];
        while let Some(&kind) = options.first() {
            if kind == 0 {
                options = &options[1..];
                continue;
            }
            if kind & 0xc0 != 0 {
                return None;
            }
            let len = usize::from(*options.get(1)?) + 2;
            options = options.get(len..)?;
        }
        next = header[0];
        body = &body[size..];
        extensions += 1;
    }

    // RFC 6980 forbids fragmented Neighbor Discovery messages.
    // ICMPv6 next-header is 58, code must be 0, and minimum payload is 24 bytes.
    if next != 58
        || body.len() < 24
        || body[0] != 135
        || body[1] != 0
        || compute_icmpv6_checksum(source, destination, body) != 0
    {
        return None;
    }

    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&body[8..24]).ok()?);
    if target.is_multicast() || target.is_unspecified() {
        return None;
    }

    let mut remaining = &body[24..];
    let mut has_lla = false;
    while let Some(&option) = remaining.first() {
        let size = usize::from(*remaining.get(1)?) * 8;
        if size == 0 {
            return None;
        }
        let value = remaining.get(..size)?;
        if option == 1 {
            // Source link-layer address option (type 1) must be 8 bytes for Ethernet.
            if size != 8 || value[2..] != eth.source {
                return None;
            }
            has_lla = true;
        }
        remaining = &remaining[size..];
    }

    // Target and destination address matching rules from RFC 4861.
    if (!destination.is_multicast() && destination != target)
        || (destination.is_multicast() && destination != compute_solicited_node_address(target))
    {
        return None;
    }
    // DAD solicitations (unspecified source) must not include SLLA and must target solicited-node.
    if source.is_unspecified() && (has_lla || destination != compute_solicited_node_address(target))
    {
        return None;
    }
    // Multicast resolution from a configured host must include SLLA.
    if !source.is_unspecified() && destination.is_multicast() && !has_lla {
        return None;
    }

    Some(NeighborSolicitation {
        source_mac: eth.source,
        destination_mac: eth.destination,
        source,
        destination,
        target,
    })
}

/// Computes the ICMPv6 16-bit one's complement checksum including the IPv6 pseudo-header.
pub fn compute_icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> u16 {
    etherparse::checksum::Sum16BitWords::new()
        .add_16bytes(source.octets())
        .add_16bytes(destination.octets())
        .add_4bytes((body.len() as u32).to_be_bytes())
        .add_4bytes([0, 0, 0, 58])
        .add_slice(body)
        .ones_complement()
        .to_be()
}

/// Encodes an ICMPv6 Neighbor Advertisement frame.
///
/// Router and Override flags are cleared. The Solicited flag is set for unicast
/// replies and cleared for DAD replies sent to all-nodes multicast.
pub fn build_neighbor_advertisement(
    mac: MacAddress,
    source: Ipv6Addr,
    destination_mac: MacAddress,
    destination: Ipv6Addr,
    target: Ipv6Addr,
) -> Vec<u8> {
    let mut body = [0u8; 32];
    body[0] = 136;
    body[4] = if destination.is_multicast() { 0 } else { 0x40 };
    body[8..24].copy_from_slice(&target.octets());
    // Target Link-Layer Address option (type 2, length 1 = 8 bytes).
    body[24..26].copy_from_slice(&[2, 1]);
    body[26..].copy_from_slice(&mac);
    let sum = compute_icmpv6_checksum(source, destination, &body);
    body[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut frame = Vec::with_capacity(54 + body.len());
    frame.extend_from_slice(
        &Ethernet2Header {
            source: mac,
            destination: destination_mac,
            ether_type: 0x86dd.into(),
        }
        .to_bytes(),
    );
    frame.extend_from_slice(
        &Ipv6Header {
            payload_length: body.len() as u16,
            next_header: 58.into(),
            hop_limit: 255,
            source: source.octets(),
            destination: destination.octets(),
            ..Default::default()
        }
        .to_bytes(),
    );
    frame.extend_from_slice(&body);
    frame
}
