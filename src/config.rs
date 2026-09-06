//! Configuration loading, parsing, and validation for `ndp-responder-lite`.

use ipnet::Ipv6Net;
use serde::Deserialize;
use std::{io, net::Ipv6Addr, path::Path};

/// Daemon configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Traffic limits and queue sizes.
    #[serde(default)]
    pub limits: ResourceLimits,
    /// Prefix reservation rules per interface.
    pub responder: Vec<ResponderRule>,
}

/// Queue and rate limits applied per interface or across the daemon.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum number of queued replies across all interfaces.
    pub max_queued: usize,
    /// Token bucket refill rate in packets per second.
    pub packets_per_second: u32,
    /// Token bucket burst capacity in packets.
    pub burst: u32,
    /// Lifetime of a queued reply in milliseconds before it is dropped.
    pub reply_timeout_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_queued: 4096,
            packets_per_second: 200,
            burst: 400,
            reply_timeout_ms: 3000,
        }
    }
}

/// Reservation rule associating an IPv6 prefix with a network interface.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponderRule {
    /// Advertised IPv6 prefix. Host bits must be zero.
    pub prefix: Ipv6Net,
    /// Name of the network interface that answers for this prefix.
    pub interface: String,
}

impl Config {
    /// Reads and validates configuration from the file at `path`.
    pub fn load_from_path(path: &Path) -> io::Result<Self> {
        Self::parse_from_str(&std::fs::read_to_string(path)?)
    }

    /// Parses and validates a TOML configuration string.
    pub fn parse_from_str(text: &str) -> io::Result<Self> {
        let config: Self = toml::from_str(text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates limits, prefix ranges, interface names, and prefix overlap.
    pub fn validate(&self) -> io::Result<()> {
        let invalid =
            |message: &'static str| Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        let l = &self.limits;
        if l.max_queued == 0 || l.packets_per_second == 0 || l.burst == 0 || l.reply_timeout_ms == 0
        {
            return invalid("limits must be greater than zero");
        }
        if self.responder.is_empty() {
            return invalid("configure at least one responder rule");
        }
        for (i, rule) in self.responder.iter().enumerate() {
            if rule.prefix != rule.prefix.trunc() {
                return invalid("prefix must have zero host bits");
            }
            if rule.prefix.network().is_unspecified()
                || rule.prefix.network().is_multicast()
                || rule.prefix.network().is_unicast_link_local()
                || rule.prefix.contains(&Ipv6Addr::LOCALHOST)
                || rule
                    .prefix
                    .contains(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0))
                || rule
                    .prefix
                    .contains(&Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0))
            {
                return invalid("prefix must contain only non-link-local unicast addresses");
            }
            let name = &rule.interface;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.len() >= libc::IFNAMSIZ
                || name
                    .bytes()
                    .any(|b| b == 0 || b == b'/' || b == b':' || b.is_ascii_whitespace())
            {
                return invalid("invalid interface name in rule");
            }
            for other in &self.responder[..i] {
                if rule.interface == other.interface
                    && (rule.prefix.contains(&other.prefix) || other.prefix.contains(&rule.prefix))
                {
                    return invalid("responder prefixes on the same interface must not overlap");
                }
            }
        }
        Ok(())
    }

    /// Returns a sorted, deduplicated list of configured interface names.
    pub fn interface_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self
            .responder
            .iter()
            .map(|p| &p.interface)
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }
}
