use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{InterfaceId, InterfaceInfo, InterfaceKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub name: String,
    pub mac_address: Option<MacAddress>,
    pub is_loopback: bool,
    pub is_wireless: bool,
    pub is_point_to_point: bool,
    pub is_physical_ethernet: bool,
    pub is_up: bool,
}

pub fn normalize(snapshot: DeviceSnapshot) -> Result<InterfaceInfo> {
    let kind = if snapshot.is_loopback {
        InterfaceKind::Loopback
    } else if snapshot.is_wireless {
        InterfaceKind::Wifi
    } else if snapshot.is_point_to_point {
        InterfaceKind::Tunnel
    } else if snapshot.is_physical_ethernet {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Other
    };

    Ok(InterfaceInfo {
        id: InterfaceId::new(snapshot.name.clone())?,
        display_name: snapshot.name,
        kind,
        mac_address: snapshot.mac_address,
        is_up: snapshot.is_up,
    })
}

#[cfg(test)]
mod tests {
    use rjconnect_platform_api::InterfaceKind;

    use super::*;

    fn snapshot(name: &str) -> DeviceSnapshot {
        DeviceSnapshot {
            name: name.to_owned(),
            mac_address: Some(MacAddress::new([2, 3, 4, 5, 6, 7])),
            is_loopback: false,
            is_wireless: false,
            is_point_to_point: false,
            is_physical_ethernet: true,
            is_up: true,
        }
    }

    #[test]
    fn physical_ethernet_is_wired_eapol_candidate() -> Result<()> {
        let interface = normalize(snapshot("enp3s0"))?;

        assert_eq!(interface.kind, InterfaceKind::Ethernet);
        assert!(interface.supports_wired_eapol());
        Ok(())
    }

    #[test]
    fn non_physical_interfaces_are_classified_without_becoming_wired_candidates() -> Result<()> {
        let mut loopback = snapshot("lo");
        loopback.is_loopback = true;
        loopback.is_physical_ethernet = false;
        loopback.mac_address = None;

        let mut wireless = snapshot("wlan0");
        wireless.is_wireless = true;
        wireless.is_physical_ethernet = false;

        let mut tunnel = snapshot("tun0");
        tunnel.is_point_to_point = true;
        tunnel.is_physical_ethernet = false;
        tunnel.mac_address = None;

        let mut bridge = snapshot("br0");
        bridge.is_physical_ethernet = false;

        for (device, expected) in [
            (loopback, InterfaceKind::Loopback),
            (wireless, InterfaceKind::Wifi),
            (tunnel, InterfaceKind::Tunnel),
            (bridge, InterfaceKind::Other),
        ] {
            let interface = normalize(device)?;
            assert_eq!(interface.kind, expected);
            assert!(!interface.supports_wired_eapol());
        }
        Ok(())
    }
}
