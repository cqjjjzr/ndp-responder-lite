//! Linux event loop combining interface scanning, raw packet I/O, and signal handling.

mod interfaces;
mod port;
mod socket;

use crate::{config::Config, engine::ResponderEngine};
pub use interfaces::query_interfaces;
use port::{IncomingFrameEvent, InterfacePort, open_interface_port, send_transmissions};
use std::{
    collections::{HashMap, HashSet},
    io,
    time::Instant,
};
use tokio::{
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};

/// Runs the Neighbor Discovery responder daemon event loop until terminated by signal.
///
/// Spawns interface monitors for each configured interface, periodically checks
/// interface state, processes incoming solicitations, transmits advertisements,
/// and reports traffic counters.
pub async fn run_daemon(config: Config) -> io::Result<()> {
    let names = config.interface_names();
    let mut engine = ResponderEngine::new(config)?;
    let mut ports: HashMap<String, InterfacePort> = HashMap::new();
    let (events, mut incoming) = mpsc::channel::<IncomingFrameEvent>(256);
    let start = Instant::now();
    let mut generation = 0u64;

    // Periodic timers:
    // - scan: inspects interface operational status and addresses every second.
    // - tick: drains rate-limited queued transmissions every 50 milliseconds.
    // - report: logs accumulated packet counters every 30 seconds.
    let mut scan = time::interval(Duration::from_secs(1));
    let mut tick = time::interval(Duration::from_millis(50));
    let mut report = time::interval(Duration::from_secs(30));
    for timer in [&mut scan, &mut tick, &mut report] {
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    }

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut unavailable = HashSet::new();

    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = scan.tick() => {
                let current = query_interfaces(&names)?;
                ports.retain(|_, port| current.contains(&port.interface) && !port.reader.is_finished());
                for interface in current {
                    if let std::collections::hash_map::Entry::Vacant(entry) = ports.entry(interface.name.clone()) {
                        generation += 1;
                        match open_interface_port(interface.clone(), generation, events.clone()) {
                            Ok(port) => {
                                tracing::info!(interface = interface.name, "listening");
                                entry.insert(port);
                            }
                            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Err(error),
                            Err(error) => {
                                if !unavailable.contains(&interface.name) {
                                    tracing::warn!(interface = interface.name, %error, "cannot open interface");
                                }
                            }
                        }
                    }
                }
                let missing: HashSet<_> = names.iter().filter(|name| !ports.contains_key(*name)).cloned().collect();
                for name in missing.difference(&unavailable) {
                    tracing::warn!(interface = name, "waiting for Ethernet interface and usable link-local address");
                }
                unavailable = missing;
                engine.update_interfaces(ports.values().map(|port| port.interface.clone()).collect());
            }
            Some(event) = incoming.recv() => {
                if ports.get(&event.name).is_some_and(|port| port.generation == event.generation) {
                    let now = start.elapsed();
                    let transmissions = engine.receive_frame(&event.name, &event.frame, now);
                    send_transmissions(&ports, &mut engine, transmissions, now);
                }
            }
            _ = tick.tick() => {
                let now = start.elapsed();
                let transmissions = engine.process_timer_tick(now);
                send_transmissions(&ports, &mut engine, transmissions, now);
            }
            _ = report.tick() => {
                tracing::info!(
                    received = engine.stats.received,
                    invalid = engine.stats.invalid,
                    limited = engine.stats.limited,
                    transmitted = engine.stats.transmitted,
                    queued = engine.queued_count(),
                    send_errors = engine.stats.send_errors,
                    queue_dropped = engine.stats.queue_dropped,
                    "ND counters"
                );
            }
        }
    }
    tracing::info!("stopped");
    Ok(())
}
