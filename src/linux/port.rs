//! Asynchronous socket I/O management and background packet readers per interface.

use super::socket::create_packet_socket;
use crate::engine::{NetworkInterface, OutgoingTransmission, ResponderEngine};
use socket2::Socket;
use std::{
    collections::HashMap,
    io::{self, Read},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
    task::JoinHandle,
};

/// Event sent by the background reader task when a packet arrives on an interface.
pub(super) struct IncomingFrameEvent {
    /// Interface name the frame was received on.
    pub name: String,
    /// Generation number identifying the socket instance.
    pub generation: u64,
    /// Complete received Ethernet frame bytes.
    pub frame: Vec<u8>,
}

/// Active interface socket handle and associated background reader task.
pub(super) struct InterfacePort {
    /// Active interface configuration.
    pub interface: NetworkInterface,
    socket: Arc<AsyncFd<Socket>>,
    /// Handle to the background task reading incoming frames.
    pub reader: JoinHandle<()>,
    /// Monotonically increasing generation number for this interface instance.
    pub generation: u64,
}

impl Drop for InterfacePort {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Opens a raw packet socket on `interface` and spawns a background frame reader.
pub(super) fn open_interface_port(
    interface: NetworkInterface,
    generation: u64,
    events: mpsc::Sender<IncomingFrameEvent>,
) -> io::Result<InterfacePort> {
    let socket = Arc::new(AsyncFd::new(create_packet_socket(&interface)?)?);
    let receiver = socket.clone();
    let name = interface.name.clone();
    let reader = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535 + 54];
        loop {
            let result = receiver
                .async_io(Interest::READABLE, |mut socket| socket.read(&mut buffer))
                .await;
            match result {
                Ok(len) => {
                    if events
                        .send(IncomingFrameEvent {
                            name: name.clone(),
                            generation,
                            frame: buffer[..len].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    tracing::warn!(interface = name, %error, "packet receive failed");
                    break;
                }
            }
        }
    });
    Ok(InterfacePort {
        interface,
        socket,
        reader,
        generation,
    })
}

/// Transmits a batch of outgoing frames across the active interface ports.
///
/// Records successes and failures in the engine. Transient errors (`WouldBlock`,
/// `Interrupted`, `ENOBUFS`) trigger re-queueing; other errors cause the frame
/// to be dropped.
pub(super) fn send_transmissions(
    ports: &HashMap<String, InterfacePort>,
    engine: &mut ResponderEngine,
    transmissions: impl IntoIterator<Item = OutgoingTransmission>,
    now: Duration,
) {
    for tx in transmissions {
        let result = ports
            .get(&tx.interface)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
            .and_then(|port| {
                if port.socket.get_ref().send(&tx.frame)? == tx.frame.len() {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WriteZero.into())
                }
            });
        match result {
            Ok(()) => engine.record_sent(),
            Err(error) => {
                let retry = matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) || error.raw_os_error() == Some(libc::ENOBUFS);
                tracing::debug!(interface = tx.interface, %error, retry, "packet send failed");
                engine.record_send_failure(tx, retry, now);
            }
        }
    }
}
