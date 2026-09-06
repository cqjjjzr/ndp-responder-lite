use super::harness::check_interrupt;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct Capture {
    socket: Socket,
    output: File,
}

impl Capture {
    pub fn socket() -> io::Result<Socket> {
        let protocol = (libc::ETH_P_IPV6 as u16).to_be();
        let socket = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::RAW,
            Some(Protocol::from(i32::from(protocol))),
        )?;
        // SAFETY: the interface name is NUL-terminated and sockaddr_ll is initialized in full.
        let index = unsafe { libc::if_nametoindex(c"eth1".as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol,
            sll_ifindex: index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    pub fn new(socket: Socket, path: &Path) -> Self {
        let mut output = File::create(path).unwrap();
        for word in [0xa1b2c3d4u32, 0x00040002, 0, 0, 65589, 1] {
            output.write_all(&word.to_le_bytes()).unwrap();
        }
        Self { socket, output }
    }

    pub fn send(&self, frame: &[u8]) {
        assert_eq!(self.socket.send(frame).unwrap(), frame.len());
    }

    pub fn collect(&mut self, millis: u64, predicate: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
        let end = Instant::now() + Duration::from_millis(millis);
        let mut buffer = [0u8; 65589];
        while Instant::now() < end {
            check_interrupt();
            let mut poll = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = end
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(50) as i32;
            // SAFETY: poll receives one initialized descriptor and a bounded timeout.
            let result = unsafe { libc::poll(&mut poll, 1, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("poll: {error}");
            }
            if result == 0 {
                continue;
            }
            let size = match (&self.socket).read(&mut buffer) {
                Ok(size) => size,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("packet receive: {e}"),
            };
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            for word in [
                stamp.as_secs() as u32,
                stamp.subsec_micros(),
                size as u32,
                size as u32,
            ] {
                self.output.write_all(&word.to_le_bytes()).unwrap();
            }
            self.output.write_all(&buffer[..size]).unwrap();
            if predicate(&buffer[..size]) {
                return Some(buffer[..size].to_vec());
            }
        }
        None
    }

    pub fn expect(&mut self, predicate: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        self.collect(1500, predicate)
            .expect("expected packet did not arrive")
    }
}
