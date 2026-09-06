//! Raw `AF_PACKET` socket setup and classic BPF packet filter configuration.

use crate::engine::NetworkInterface;
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, os::fd::AsRawFd};

/// Creates and configures a non-blocking `AF_PACKET` raw socket bound to `interface`.
///
/// Joins `PACKET_MR_ALLMULTI` so the interface receives multicast traffic without
/// enabling promiscuous mode. Attaches a BPF filter matching incoming IPv6 Neighbor
/// Solicitations while dropping outgoing frames and unrelated traffic.
pub(super) fn create_packet_socket(interface: &NetworkInterface) -> io::Result<Socket> {
    let protocol = (libc::ETH_P_ALL as u16).to_be();
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from(i32::from(protocol))),
    )?;
    socket.set_nonblocking(true)?;

    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol,
        sll_ifindex: interface.index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    check_syscall(unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            size_of_val(&address) as libc::socklen_t,
        )
    })?;

    let membership = libc::packet_mreq {
        mr_ifindex: interface.index as i32,
        mr_type: libc::PACKET_MR_ALLMULTI as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    set_socket_option(
        &socket,
        libc::SOL_PACKET,
        libc::PACKET_ADD_MEMBERSHIP,
        &membership,
    )?;

    // BPF filter instructions:
    // 1. Drop outgoing frames to prevent looping frames generated locally.
    // 2. Accept Ethernet type 0x86dd (IPv6).
    // 3. Accept IPv6 hop limit 255 (RFC 4861 requirement).
    // 4. Accept next-header 58 (ICMPv6), 0 (Hop-by-Hop), or 60 (Destination Options).
    // 5. Accept ICMPv6 type 135 (Neighbor Solicitation).
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut filter = [
        instruction(0x20, 0, 0, (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32),
        instruction(0x15, 0, 1, u32::from(libc::PACKET_OUTGOING)),
        instruction(0x06, 0, 0, 0),
        instruction(0x28, 0, 0, 12), // Ethernet type offset.
        instruction(0x15, 0, 9, 0x86dd),
        instruction(0x30, 0, 0, 21), // IPv6 hop limit offset.
        instruction(0x15, 0, 7, 255),
        instruction(0x30, 0, 0, 20), // IPv6 next header offset.
        instruction(0x15, 2, 0, 58),
        instruction(0x15, 3, 0, 0),
        instruction(0x15, 2, 3, 60),
        instruction(0x30, 0, 0, 54), // ICMPv6 type offset.
        instruction(0x15, 0, 1, 135),
        instruction(0x06, 0, 0, 65535 + 54),
        instruction(0x06, 0, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    set_socket_option(&socket, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)?;
    Ok(socket)
}

/// Converts a libc return code (-1 on failure) into an `io::Result<()>`.
fn check_syscall(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Sets a socket option via `libc::setsockopt`.
fn set_socket_option<T>(socket: &Socket, level: i32, name: i32, value: &T) -> io::Result<()> {
    check_syscall(unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    })
}
