use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    fs, io,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    ptr,
    time::{Duration, Instant},
};

use libc::{BPF_H, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, sock_filter};
use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{
    EthernetLink, FrameChannel, FrameChannelConfig, InterfaceId, InterfaceInfo, InterfaceKind,
    MAX_ETHERNET_FRAME_LENGTH, MIN_ETHERNET_FRAME_LENGTH, PlatformError, ReceiveOutcome, Result,
};

use crate::{
    error::map_io_error,
    normalize::{DeviceNature, DeviceSnapshot, normalize},
};

const EAPOL_ETHERTYPE: u32 = 0x888e;
#[cfg(test)]
const EAPOL_ETHERTYPE_WIRE: u16 = 0x888e;
const VLAN_TPID_8021Q: u32 = 0x8100;
#[cfg(test)]
const VLAN_TPID_8021Q_WIRE: u16 = 0x8100;
const VLAN_TPID_8021AD: u32 = 0x88a8;
#[cfg(test)]
const VLAN_TPID_8021AD_WIRE: u16 = 0x88a8;
const ETH_P_ALL: u16 = 0x0003;
const LOAD_ETHERTYPE: u16 = bpf_opcode(BPF_LD | BPF_H | libc::BPF_ABS);
const COMPARE_IMMEDIATE: u16 = bpf_opcode(BPF_JMP | BPF_JEQ | BPF_K);
const RETURN_IMMEDIATE: u16 = bpf_opcode(BPF_RET | BPF_K);

/// Linux `AF_PACKET` Ethernet provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEthernet;

/// Active bounded Linux Ethernet channel.
pub struct LinuxFrameChannel {
    socket: OwnedFd,
    interface: String,
    ifindex: i32,
    local_mac: MacAddress,
    snapshot_length: usize,
    read_timeout: Duration,
}

impl EthernetLink for LinuxEthernet {
    type Channel = LinuxFrameChannel;

    fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        enumerate_interfaces()
    }

    fn open(&self, interface: &InterfaceId, config: &FrameChannelConfig) -> Result<Self::Channel> {
        let interface_name = interface.as_str();
        let interface_info = enumerate_interfaces()?
            .into_iter()
            .find(|candidate| candidate.id == *interface)
            .ok_or_else(|| PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            })?;

        if interface_info.kind != InterfaceKind::Ethernet {
            return Err(PlatformError::UnsupportedCapability {
                capability: "non-physical Ethernet wired interface",
            });
        }
        let Some(local_mac) = interface_info.mac_address else {
            return Err(PlatformError::UnsupportedCapability {
                capability: "Ethernet interface without a MAC address",
            });
        };
        if !interface_info.is_up {
            return Err(PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            });
        }

        let interface_c =
            CString::new(interface_name).map_err(|_error| PlatformError::InvalidInterfaceId)?;
        // SAFETY: `interface_c` is a valid NUL-terminated interface name.
        let raw_ifindex = unsafe { libc::if_nametoindex(interface_c.as_ptr()) };
        if raw_ifindex == 0 {
            return Err(PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            });
        }
        let ifindex =
            i32::try_from(raw_ifindex).map_err(|_error| PlatformError::OperationFailed {
                operation: "resolve interface index",
                message: "interface index exceeds AF_PACKET range".to_owned(),
            })?;

        let socket = create_packet_socket(interface_name)?;
        bind_packet_socket(socket.as_raw_fd(), interface_name, ifindex)?;
        set_receive_timeout(socket.as_raw_fd(), interface_name, config.read_timeout())?;
        attach_eapol_filter(socket.as_raw_fd(), interface_name, config.snapshot_length())?;
        if config.promiscuous() {
            enable_promiscuous(socket.as_raw_fd(), interface_name, ifindex)?;
        }

        Ok(LinuxFrameChannel {
            socket,
            interface: interface_name.to_owned(),
            ifindex,
            local_mac,
            snapshot_length: config.snapshot_length(),
            read_timeout: config.read_timeout(),
        })
    }
}

impl FrameChannel for LinuxFrameChannel {
    fn receive(&mut self) -> Result<ReceiveOutcome> {
        let deadline = Instant::now().checked_add(self.read_timeout).ok_or(
            PlatformError::InvalidReadTimeout {
                actual: self.read_timeout,
                minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
                maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
            },
        )?;

        loop {
            let mut buffer = vec![0_u8; self.snapshot_length];
            let mut iovec = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut source: libc::sockaddr_ll = unsafe { zeroed() };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_name = (&raw mut source).cast();
            message.msg_namelen = socket_address_length::<libc::sockaddr_ll>("receive frame")?;
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;

            // SAFETY: all message pointers reference initialized storage for the
            // duration of the call, and the receive buffer is uniquely borrowed.
            let received = unsafe {
                libc::recvmsg(self.socket.as_raw_fd(), &raw mut message, libc::MSG_TRUNC)
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => {
                        if !self.reset_timeout(deadline)? {
                            return Ok(ReceiveOutcome::Timeout);
                        }
                        continue;
                    }
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return Ok(ReceiveOutcome::Timeout);
                    }
                    _ => {
                        return Err(map_native_io_error(
                            "receive frame",
                            &self.interface,
                            &error,
                        ));
                    }
                }
            }

            let received_length =
                usize::try_from(received).map_err(|_error| PlatformError::OperationFailed {
                    operation: "receive frame",
                    message: "received byte count exceeds platform range".to_owned(),
                })?;
            if message.msg_flags & libc::MSG_TRUNC != 0 || received_length > buffer.len() {
                return Err(PlatformError::OperationFailed {
                    operation: "receive frame",
                    message: "received frame exceeded configured snapshot length".to_owned(),
                });
            }
            buffer.truncate(received_length);

            let is_own_frame = buffer
                .get(6..12)
                .is_some_and(|source_mac| source_mac == self.local_mac.octets());
            if source.sll_pkttype == libc::PACKET_OUTGOING || is_own_frame {
                if !self.reset_timeout(deadline)? {
                    return Ok(ReceiveOutcome::Timeout);
                }
                continue;
            }

            return Ok(ReceiveOutcome::Frame(buffer));
        }
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        validate_outbound_frame_length(frame.len())?;

        let mut address: libc::sockaddr_ll = unsafe { zeroed() };
        address.sll_family =
            u16::try_from(libc::AF_PACKET).map_err(|_error| PlatformError::OperationFailed {
                operation: "send frame",
                message: "AF_PACKET address family is invalid".to_owned(),
            })?;
        address.sll_protocol = libc::htons(ETH_P_ALL);
        address.sll_ifindex = self.ifindex;
        // SAFETY: `frame` and `address` remain valid for the syscall duration.
        let sent = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                libc::MSG_NOSIGNAL,
                (&raw const address).cast(),
                socket_address_length::<libc::sockaddr_ll>("send frame")?,
            )
        };
        if sent < 0 {
            return Err(map_native_io_error(
                "send frame",
                &self.interface,
                &io::Error::last_os_error(),
            ));
        }
        if usize::try_from(sent).ok() != Some(frame.len()) {
            return Err(PlatformError::OperationFailed {
                operation: "send frame",
                message: "AF_PACKET accepted only part of the frame".to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_outbound_frame_length(length: usize) -> Result<()> {
    if (MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&length) {
        Ok(())
    } else {
        Err(PlatformError::InvalidFrameLength {
            actual: length,
            minimum: MIN_ETHERNET_FRAME_LENGTH,
            maximum: MAX_ETHERNET_FRAME_LENGTH,
        })
    }
}

impl LinuxFrameChannel {
    fn reset_timeout(&self, deadline: Instant) -> Result<bool> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        set_receive_timeout(
            self.socket.as_raw_fd(),
            &self.interface,
            deadline.duration_since(now),
        )?;
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct InterfaceBuilder {
    flags: u32,
    hardware_type: u16,
    mac_address: Option<MacAddress>,
}

fn enumerate_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mut head = ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `head` on success. The returned list is
    // guarded immediately and freed exactly once by `IfAddrsGuard::drop`.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(PlatformError::OperationFailed {
            operation: "enumerate interfaces",
            message: io::Error::last_os_error().to_string(),
        });
    }
    let guard = IfAddrsGuard(head);
    let mut builders = HashMap::<String, InterfaceBuilder>::new();
    let mut current = guard.0;

    while !current.is_null() {
        // SAFETY: every node belongs to the live getifaddrs list held by guard.
        // Null name/address pointers are checked before dereference.
        unsafe {
            let entry = &*current;
            if !entry.ifa_name.is_null()
                && let Ok(name) = CStr::from_ptr(entry.ifa_name).to_str()
            {
                let builder = builders.entry(name.to_owned()).or_default();
                builder.flags |= entry.ifa_flags;
                if !entry.ifa_addr.is_null()
                    && i32::from((*entry.ifa_addr).sa_family) == libc::AF_PACKET
                {
                    let link = entry.ifa_addr.cast::<libc::sockaddr_ll>();
                    builder.hardware_type = (*link).sll_hatype;
                    if (*link).sll_halen == 6 {
                        let mut octets = [0; 6];
                        octets.copy_from_slice(&(&(*link).sll_addr)[..6]);
                        builder.mac_address = Some(MacAddress::new(octets));
                    }
                }
            }
            current = entry.ifa_next;
        }
    }

    let mut interfaces = builders
        .into_iter()
        .map(|(name, builder)| {
            let is_loopback = builder.flags & interface_flag(libc::IFF_LOOPBACK) != 0
                || builder.hardware_type == libc::ARPHRD_LOOPBACK;
            let is_wireless = interface_is_wireless(&name);
            let is_point_to_point = builder.flags & interface_flag(libc::IFF_POINTOPOINT) != 0;
            let is_physical_ethernet = builder.hardware_type == libc::ARPHRD_ETHER
                && !is_wireless
                && !is_loopback
                && !is_point_to_point
                && interface_is_physical(&name);
            let is_up = builder.flags & interface_flag(libc::IFF_UP) != 0
                && builder.flags & interface_flag(libc::IFF_RUNNING) != 0;

            normalize(DeviceSnapshot {
                mac_address: builder.mac_address,
                name,
                nature: if is_loopback {
                    DeviceNature::Loopback
                } else if is_wireless {
                    DeviceNature::Wireless
                } else if is_point_to_point {
                    DeviceNature::PointToPoint
                } else if is_physical_ethernet {
                    DeviceNature::PhysicalEthernet
                } else {
                    DeviceNature::VirtualOrUnknown
                },
                is_up,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    interfaces.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(interfaces)
}

const fn interface_flag(flag: libc::c_int) -> u32 {
    flag.unsigned_abs()
}

fn interface_is_wireless(name: &str) -> bool {
    let interface_path = Path::new("/sys/class/net").join(name);
    interface_path.join("wireless").exists() || interface_path.join("phy80211").exists()
}

fn interface_is_physical(name: &str) -> bool {
    let interface_path = Path::new("/sys/class/net").join(name);
    fs::read_link(interface_path).is_ok_and(|target| {
        !target
            .components()
            .any(|component| component.as_os_str() == "virtual")
    })
}

fn create_packet_socket(interface: &str) -> Result<OwnedFd> {
    // SAFETY: socket arguments are constants; the returned fd is immediately
    // wrapped in an owning descriptor on success.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(libc::htons(ETH_P_ALL)),
        )
    };
    if descriptor < 0 {
        return Err(map_native_io_error(
            "create AF_PACKET socket",
            interface,
            &io::Error::last_os_error(),
        ));
    }
    // SAFETY: `descriptor` is newly owned and has not been transferred elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn bind_packet_socket(socket: libc::c_int, interface: &str, ifindex: i32) -> Result<()> {
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family =
        u16::try_from(libc::AF_PACKET).map_err(|_error| PlatformError::OperationFailed {
            operation: "bind AF_PACKET socket",
            message: "AF_PACKET address family is invalid".to_owned(),
        })?;
    address.sll_protocol = libc::htons(ETH_P_ALL);
    address.sll_ifindex = ifindex;

    // SAFETY: `address` is fully initialized for the selected address length.
    let result = unsafe {
        libc::bind(
            socket,
            (&raw const address).cast(),
            socket_address_length::<libc::sockaddr_ll>("bind AF_PACKET socket")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "bind AF_PACKET socket",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn set_receive_timeout(socket: libc::c_int, interface: &str, timeout: Duration) -> Result<()> {
    let seconds = libc::time_t::try_from(timeout.as_secs()).map_err(|_error| {
        PlatformError::InvalidReadTimeout {
            actual: timeout,
            minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
            maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
        }
    })?;
    let microseconds = libc::suseconds_t::from(timeout.subsec_micros());
    let value = libc::timeval {
        tv_sec: seconds,
        tv_usec: microseconds,
    };

    // SAFETY: `value` is a correctly sized timeval for SO_RCVTIMEO.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const value).cast(),
            socket_address_length::<libc::timeval>("configure receive timeout")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "configure receive timeout",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn attach_eapol_filter(socket: libc::c_int, interface: &str, snapshot_length: usize) -> Result<()> {
    let snapshot_length =
        u32::try_from(snapshot_length).map_err(|_error| PlatformError::InvalidSnapshotLength {
            actual: snapshot_length,
            minimum: FrameChannelConfig::MIN_SNAPSHOT_LENGTH,
            maximum: FrameChannelConfig::MAX_SNAPSHOT_LENGTH,
        })?;
    let mut program = eapol_filter_program(snapshot_length);
    let mut filter = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(|_error| PlatformError::OperationFailed {
            operation: "install EAPOL filter",
            message: "BPF program length exceeds sock_fprog range".to_owned(),
        })?,
        filter: program.as_mut_ptr(),
    };

    // SAFETY: `filter` points to a live instruction vector for this call.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw mut filter).cast(),
            socket_address_length::<libc::sock_fprog>("install EAPOL filter")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "install EAPOL filter",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn enable_promiscuous(socket: libc::c_int, interface: &str, ifindex: i32) -> Result<()> {
    let membership = libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: u16::try_from(libc::PACKET_MR_PROMISC).map_err(|_error| {
            PlatformError::OperationFailed {
                operation: "enable promiscuous capture",
                message: "promiscuous membership type exceeds packet_mreq range".to_owned(),
            }
        })?,
        mr_alen: 0,
        mr_address: [0; 8],
    };

    // SAFETY: `membership` is fully initialized and the kernel interprets it as
    // PACKET_ADD_MEMBERSHIP for the lifetime of this call.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (&raw const membership).cast(),
            socket_address_length::<libc::packet_mreq>("enable promiscuous capture")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "enable promiscuous capture",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn socket_address_length<T>(operation: &'static str) -> Result<libc::socklen_t> {
    libc::socklen_t::try_from(size_of::<T>()).map_err(|_error| PlatformError::OperationFailed {
        operation,
        message: "socket structure length exceeds platform range".to_owned(),
    })
}

fn map_native_io_error(
    operation: &'static str,
    interface: &str,
    error: &io::Error,
) -> PlatformError {
    if matches!(
        error.raw_os_error(),
        Some(libc::ENODEV | libc::ENXIO | libc::ENETDOWN)
    ) {
        PlatformError::InterfaceUnavailable {
            interface: interface.to_owned(),
        }
    } else {
        map_io_error(operation, interface, error)
    }
}

fn eapol_filter_program(snapshot_length: u32) -> Vec<sock_filter> {
    vec![
        instruction(LOAD_ETHERTYPE, 0, 0, 12),
        instruction(COMPARE_IMMEDIATE, 11, 0, EAPOL_ETHERTYPE),
        instruction(COMPARE_IMMEDIATE, 2, 0, VLAN_TPID_8021Q),
        instruction(COMPARE_IMMEDIATE, 1, 0, VLAN_TPID_8021AD),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(LOAD_ETHERTYPE, 0, 0, 16),
        instruction(COMPARE_IMMEDIATE, 6, 0, EAPOL_ETHERTYPE),
        instruction(COMPARE_IMMEDIATE, 2, 0, VLAN_TPID_8021Q),
        instruction(COMPARE_IMMEDIATE, 1, 0, VLAN_TPID_8021AD),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(LOAD_ETHERTYPE, 0, 0, 20),
        instruction(COMPARE_IMMEDIATE, 1, 0, EAPOL_ETHERTYPE),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(RETURN_IMMEDIATE, 0, 0, snapshot_length),
    ]
}

const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "classic BPF opcode constants fit in sock_filter::code"
)]
const fn bpf_opcode(code: u32) -> u16 {
    code as u16
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by one successful getifaddrs
            // call and this guard is its sole owner.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with_ether_type_at(offset: usize, ether_type: u16) -> Vec<u8> {
        let mut frame = vec![0; offset + 2];
        frame[offset..offset + 2].copy_from_slice(&ether_type.to_be_bytes());
        frame
    }

    fn run_filter(program: &[sock_filter], frame: &[u8]) -> bool {
        let mut pc = 0;
        let mut accumulator = 0_u32;
        for _ in 0..program.len() {
            let instruction = program[pc];
            match instruction.code {
                LOAD_ETHERTYPE => {
                    let Ok(offset) = usize::try_from(instruction.k) else {
                        return false;
                    };
                    accumulator = frame.get(offset..offset + 2).map_or(0, |bytes| {
                        u32::from(u16::from_be_bytes([bytes[0], bytes[1]]))
                    });
                    pc += 1;
                }
                COMPARE_IMMEDIATE => {
                    pc += if accumulator == instruction.k {
                        1 + usize::from(instruction.jt)
                    } else {
                        1 + usize::from(instruction.jf)
                    };
                }
                RETURN_IMMEDIATE => return instruction.k != 0,
                _ => return false,
            }
        }
        false
    }

    #[test]
    fn eapol_filter_accepts_untagged_and_vlan_tagged_frames() {
        let program = eapol_filter_program(4096);
        let untagged = frame_with_ether_type_at(12, EAPOL_ETHERTYPE_WIRE);
        let mut single_vlan = frame_with_ether_type_at(16, EAPOL_ETHERTYPE_WIRE);
        single_vlan[12..14].copy_from_slice(&VLAN_TPID_8021Q_WIRE.to_be_bytes());
        let mut double_vlan = frame_with_ether_type_at(20, EAPOL_ETHERTYPE_WIRE);
        double_vlan[12..14].copy_from_slice(&VLAN_TPID_8021AD_WIRE.to_be_bytes());
        double_vlan[16..18].copy_from_slice(&VLAN_TPID_8021Q_WIRE.to_be_bytes());

        assert!(run_filter(&program, &untagged));
        assert!(run_filter(&program, &single_vlan));
        assert!(run_filter(&program, &double_vlan));
    }

    #[test]
    fn eapol_filter_rejects_non_eapol_and_unsupported_encapsulation() {
        let program = eapol_filter_program(4096);
        let ipv4 = frame_with_ether_type_at(12, 0x0800);
        let non_eapol_in_vlan = frame_with_ether_type_at(16, 0x0800);

        assert!(!run_filter(&program, &ipv4));
        assert!(!run_filter(&program, &non_eapol_in_vlan));
    }

    #[test]
    fn native_enumeration_returns_unique_nonempty_ids() -> Result<()> {
        let interfaces = LinuxEthernet.interfaces()?;
        assert!(!interfaces.is_empty());

        let mut ids = std::collections::HashSet::new();
        for interface in &interfaces {
            assert!(!interface.id.as_str().is_empty());
            assert!(ids.insert(interface.id.as_str()));
        }
        assert!(
            interfaces
                .iter()
                .any(|interface| interface.kind == InterfaceKind::Loopback)
        );
        Ok(())
    }

    #[test]
    fn opening_loopback_is_rejected_before_socket_activation() -> Result<()> {
        let interfaces = LinuxEthernet.interfaces()?;
        let loopback = interfaces
            .iter()
            .find(|interface| interface.kind == InterfaceKind::Loopback)
            .ok_or_else(|| PlatformError::OperationFailed {
                operation: "test loopback lookup",
                message: "no loopback interface found".to_owned(),
            })?;

        assert!(matches!(
            LinuxEthernet.open(&loopback.id, &FrameChannelConfig::default()),
            Err(PlatformError::UnsupportedCapability {
                capability: "non-physical Ethernet wired interface",
            })
        ));
        Ok(())
    }

    #[test]
    fn outbound_frame_length_uses_the_shared_ethernet_boundary() {
        assert_eq!(
            validate_outbound_frame_length(MIN_ETHERNET_FRAME_LENGTH - 1),
            Err(PlatformError::InvalidFrameLength {
                actual: MIN_ETHERNET_FRAME_LENGTH - 1,
                minimum: MIN_ETHERNET_FRAME_LENGTH,
                maximum: MAX_ETHERNET_FRAME_LENGTH,
            })
        );
        assert!(validate_outbound_frame_length(MIN_ETHERNET_FRAME_LENGTH).is_ok());
        assert!(validate_outbound_frame_length(MAX_ETHERNET_FRAME_LENGTH).is_ok());
        assert!(validate_outbound_frame_length(MAX_ETHERNET_FRAME_LENGTH + 1).is_err());
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW and activates a real AF_PACKET socket"]
    fn packet_socket_completes_a_bounded_send_and_receive_timeout() -> Result<()> {
        let interface = "lo";
        let interface_c =
            CString::new(interface).map_err(|_error| PlatformError::OperationFailed {
                operation: "test interface name",
                message: "loopback interface name contains NUL".to_owned(),
            })?;
        // SAFETY: `interface_c` is a valid NUL-terminated interface name.
        let raw_ifindex = unsafe { libc::if_nametoindex(interface_c.as_ptr()) };
        let ifindex =
            i32::try_from(raw_ifindex).map_err(|_error| PlatformError::InterfaceUnavailable {
                interface: interface.to_owned(),
            })?;
        let socket = create_packet_socket(interface)?;
        bind_packet_socket(socket.as_raw_fd(), interface, ifindex)?;
        let timeout = Duration::from_millis(100);
        set_receive_timeout(socket.as_raw_fd(), interface, timeout)?;
        attach_eapol_filter(socket.as_raw_fd(), interface, 4096)?;
        let mut channel = LinuxFrameChannel {
            socket,
            interface: interface.to_owned(),
            ifindex,
            local_mac: MacAddress::new([2, 3, 4, 5, 6, 7]),
            snapshot_length: 4096,
            read_timeout: timeout,
        };
        let mut frame = vec![0; 60];
        frame[0..6].copy_from_slice(&MacAddress::PAE_GROUP.octets());
        frame[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE_WIRE.to_be_bytes());

        channel.send(&frame)?;
        assert_eq!(channel.receive()?, ReceiveOutcome::Timeout);
        Ok(())
    }
}
