//! Linux interface discovery, link state inspection, and link-local address resolution.

use crate::{engine::NetworkInterface, packet};
use socket2::{Domain, Socket, Type};
use std::{io, net::SocketAddrV6, os::fd::AsRawFd};

/// Queries Linux network interfaces by name and returns operational Ethernet interfaces.
///
/// Ignores transient errors (such as missing devices or interfaces waiting for link-local
/// address configuration) so the caller can retry periodically.
pub fn query_interfaces(names: &[String]) -> io::Result<Vec<NetworkInterface>> {
    let mut result = Vec::new();
    for name in names {
        match query_interface(name) {
            Ok(Some(interface)) => result.push(interface),
            Ok(None) => {}
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(
                        libc::ENODEV
                            | libc::ENXIO
                            | libc::ENETDOWN
                            | libc::ENETUNREACH
                            | libc::EADDRNOTAVAIL
                    )
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(result)
}

/// Inspects a single network interface and returns its metadata if it is ready.
///
/// Returns `Ok(None)` if the interface is down, not Ethernet, or lacks a usable
/// link-local IPv6 address.
fn query_interface(name: &str) -> io::Result<Option<NetworkInterface>> {
    if name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, from) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *to = from as libc::c_char;
    }

    // Verify the interface is UP and RUNNING.
    call_ioctl(&socket, libc::SIOCGIFFLAGS, &mut request)?;
    let flags = i32::from(unsafe { request.ifr_ifru.ifru_flags });
    if flags & (libc::IFF_UP | libc::IFF_RUNNING) != (libc::IFF_UP | libc::IFF_RUNNING) {
        return Ok(None);
    }

    // Verify hardware type is Ethernet and MAC is a valid unicast address.
    call_ioctl(&socket, libc::SIOCGIFHWADDR, &mut request)?;
    let hardware = unsafe { request.ifr_ifru.ifru_hwaddr };
    let mac = std::array::from_fn(|i| hardware.sa_data[i] as u8);
    if hardware.sa_family != libc::ARPHRD_ETHER || !packet::is_unicast_mac(mac) {
        return Ok(None);
    }

    // Read interface index.
    call_ioctl(&socket, libc::SIOCGIFINDEX, &mut request)?;
    let index = unsafe { request.ifr_ifru.ifru_ifindex } as u32;

    // Connect to the all-nodes multicast address to select a link-local source address.
    // UDP connect triggers kernel route selection without transmitting any packets.
    socket.bind_device(Some(name.as_bytes()))?;
    let destination = SocketAddrV6::new(packet::ALL_NODES_ADDR, 9, 0, index);
    socket.connect(&destination.into())?;
    let Some(source) = socket.local_addr()?.as_socket_ipv6() else {
        return Ok(None);
    };
    if !source.ip().is_unicast_link_local() {
        return Ok(None);
    }

    Ok(Some(NetworkInterface {
        name: name.into(),
        index,
        mac,
        link_local: *source.ip(),
    }))
}

/// Executes a netdevice ioctl on the provided socket.
fn call_ioctl(
    socket: &Socket,
    operation: libc::c_ulong,
    request: &mut libc::ifreq,
) -> io::Result<()> {
    if unsafe { libc::ioctl(socket.as_raw_fd(), operation as _, request) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
