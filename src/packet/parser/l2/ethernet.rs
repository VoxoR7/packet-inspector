use std::fmt::{self, Display};

use crate::{
    bytes_arch,
    osi_layer::{
        l2::{EthernetErrors, L2Protocols, L2ProtocolsError},
        OsiLayer, OsiLayerError,
    },
    packet::{
        self,
        parser::l3::{ipv4, ipv6},
    },
    sessions::Sessions,
};

const ETHERNET_LEN: usize = 14;

const IPV4: u16 = 0x0800;
const ARP: u16 = 0x0806;
const PPPOEDISCOVERY: u16 = 0x8864;
const IPV6: u16 = 0x86DD;

#[derive(Debug, Clone, PartialEq)]
pub struct Ethernet {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16,
}

impl Ethernet {
    pub fn parse_ethernet(
        packet: packet::SoloPacket,
        sessions: &mut Sessions,
    ) -> Result<(), OsiLayerError> {
        let (mut packet, sig) = packet;
        let Some(ethernet_bytes) = packet.get(ETHERNET_LEN) else {
            return Err(OsiLayerError::L2(L2ProtocolsError::Ethernet(
                EthernetErrors::NotEnoughBytes,
            )));
        };

        let ether_type = bytes_arch::as_u16_be(&ethernet_bytes[12..14]);

        let ethernet = Self {
            dst: *<&[u8; 6]>::try_from(&ethernet_bytes[0..6]).unwrap(),
            src: *<&[u8; 6]>::try_from(&ethernet_bytes[6..12]).unwrap(),
            ether_type,
        };

        packet.add_layer(OsiLayer::L2(L2Protocols::Ethernet(ethernet)));

        match ether_type {
            IPV4 => ipv4::IPv4::parse_ipv4((packet, sig), sessions),
            ARP => Ok(()),
            PPPOEDISCOVERY => Ok(()),
            IPV6 => ipv6::IPv6::parse_ipv6((packet, sig), sessions),
            _ => Err(OsiLayerError::L2(L2ProtocolsError::Ethernet(
                EthernetErrors::UnknowEtherType,
            ))),
        }
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, &str> {
        let Some(ethernet_bytes) = slice.get(..ETHERNET_LEN) else {
            return Err("Not enough bytes");
        };

        let ether_type = bytes_arch::as_u16_be(&ethernet_bytes[12..14]);

        Ok(Self {
            dst: *<&[u8; 6]>::try_from(&ethernet_bytes[0..6]).unwrap(),
            src: *<&[u8; 6]>::try_from(&ethernet_bytes[6..12]).unwrap(),
            ether_type,
        })
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.ether_type.to_be_bytes());
    }
}

impl Display for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[L2 - Ethernet]")?;
        writeln!(f, "\tdst:              {}", print_ethernet_addr(&self.dst))?;
        writeln!(f, "\tsrc:              {}", print_ethernet_addr(&self.src))?;
        writeln!(f, "\tether type:       {:#06X}", self.ether_type)?;

        Ok(())
    }
}

fn print_ethernet_addr(addr: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

impl Default for Ethernet {
    fn default() -> Self {
        Self {
            dst: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            src: [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            ether_type: IPV4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ethernet;

    #[test]
    fn test() {
        let ethernet = Ethernet::default();
        let mut ethernet_on_wire = Vec::new();
        ethernet.to_wire(&mut ethernet_on_wire);
        let ethernet_2 =
            Ethernet::new_from_slice(&ethernet_on_wire).expect("Couldn't create ethernet_2");
        println!("{}", ethernet);
        println!("{:?}", ethernet_on_wire);
        println!("{}", ethernet_2);
        assert_eq!(ethernet, ethernet_2);
    }
}
