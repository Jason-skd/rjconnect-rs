//! Linux wired Ethernet platform backend.
//!
//! The native implementation uses AF_PACKET for bounded EAPOL capture and
//! transmission. Portable interface normalization remains testable on every
//! host; native symbols are exported only when targeting Linux.

#![deny(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod error;

#[cfg(any(target_os = "linux", test))]
mod normalize;
