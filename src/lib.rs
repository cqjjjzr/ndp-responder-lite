#![cfg(target_os = "linux")]

//! Linux static IPv6 neighbor discovery responder.
//!
//! `ndp-responder-lite` answers IPv6 Neighbor Solicitations for configured prefixes
//! on designated network interfaces. It responds to Duplicate Address Detection (DAD)
//! queries and Neighbor Unreachability Detection (NUD) unicast resolution.

pub mod config;
pub mod engine;
pub mod linux;
pub mod packet;
