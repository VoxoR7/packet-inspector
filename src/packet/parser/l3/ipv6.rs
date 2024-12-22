use std::fmt::Display;

use super::ipprot;
use crate::{
    bytes_arch::as_u16_be,
    osi_layer::{
        l3::{IPv6Errors, L3Protocols, L3ProtocolsError},
        OsiLayer, OsiLayerError,
    },
    packet::{
        self,
        parser::{l3::icmp::Icmp, l4::tcp::Tcp},
    },
    sessions::Sessions,
};

const IPV6_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq)]
pub struct IPv6 {
    ip_version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

impl IPv6 {
    pub fn parse_ipv6(
        packet: packet::SoloPacket,
        sessions: &mut Sessions,
    ) -> Result<(), OsiLayerError> {
        let (mut pkt, mut sig) = packet;
        let Some(ipv6_bytes) = pkt.get(IPV6_LEN) else {
            return Err(OsiLayerError::L3(L3ProtocolsError::IPv6(
                IPv6Errors::NotEnoughBytes,
            )));
        };

        let protocol = ipv6_bytes[6];

        let ipv6 = Self {
            ip_version: (ipv6_bytes[0] & 0xF0) >> 4,
            traffic_class: ((ipv6_bytes[0] & 0x0F) << 4) + ((ipv6_bytes[1] & 0xF0) >> 4),
            flow_label: (((ipv6_bytes[1] & 0x0F) as u32) << 16)
                + ((ipv6_bytes[2] as u32) << 8)
                + ipv6_bytes[3] as u32,
            payload_len: as_u16_be(&ipv6_bytes[4..6]),
            next_header: protocol,
            hop_limit: ipv6_bytes[7],
            src: *<&[u8; 16]>::try_from(&ipv6_bytes[8..24]).unwrap(),
            dst: *<&[u8; 16]>::try_from(&ipv6_bytes[24..40]).unwrap(),
        };

        sig.add_signature_two_way(&ipv6.src, &ipv6.dst);
        pkt.add_layer(OsiLayer::L3(L3Protocols::IPv6(ipv6)));

        match protocol {
            ipprot::ICMP => Icmp::parse_icmp((pkt, sig)),
            ipprot::TCP => Tcp::parse_tcp((pkt, sig), sessions.1),
            _ => Ok(()),
        }
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, &str> {
        let Some(ipv6_bytes) = slice.get(..IPV6_LEN) else {
            return Err("Not enough bytes");
        };

        Ok(Self {
            ip_version: (ipv6_bytes[0] & 0xF0) >> 4,
            traffic_class: ((ipv6_bytes[0] & 0x0F) << 4) + ((ipv6_bytes[1] & 0xF0) >> 4),
            flow_label: (((ipv6_bytes[1] & 0x0F) as u32) << 16)
                + ((ipv6_bytes[2] as u32) << 8)
                + ipv6_bytes[3] as u32,
            payload_len: as_u16_be(&ipv6_bytes[4..6]),
            next_header: ipv6_bytes[6],
            hop_limit: ipv6_bytes[7],
            src: *<&[u8; 16]>::try_from(&ipv6_bytes[8..24]).unwrap(),
            dst: *<&[u8; 16]>::try_from(&ipv6_bytes[24..40]).unwrap(),
        })
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) {
        let flow_label = self.flow_label.to_be_bytes();
        out.push(((self.ip_version & 0x0F) << 4) + (self.traffic_class & 0x0F));
        out.push(((self.traffic_class & 0xF0) << 4) + (flow_label[1] & 0x0F));
        out.push(flow_label[2]);
        out.push(flow_label[3]);
        out.extend_from_slice(&self.payload_len.to_be_bytes());
        out.push(self.next_header);
        out.push(self.hop_limit);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
    }
}

impl Display for IPv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[L3 - IPv6]")?;
        writeln!(f, "\tip_version:       {}", self.ip_version)?;
        writeln!(f, "\ttraffic class:    {}", self.traffic_class)?;
        writeln!(f, "\tflow label:       {}", self.flow_label)?;
        writeln!(f, "\tpayload len:      {}", self.payload_len)?;
        writeln!(f, "\tnext header:      {}", self.next_header)?;
        writeln!(f, "\thop limit:        {}", self.hop_limit)?;
        writeln!(f, "\tsrc:              {}", print_ipv6_addr(&self.src))?;
        writeln!(f, "\tdst:              {}", print_ipv6_addr(&self.dst))?;

        Ok(())
    }
}

impl Default for IPv6 {
    fn default() -> Self {
        Self {
            ip_version: 6,
            traffic_class: 0,
            flow_label: 0x1234,
            payload_len: 0,
            next_header: ipprot::TCP,
            hop_limit: 64,
            src: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            dst: [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        }
    }
}

fn print_ipv6_addr(addr: &[u8; 16]) -> String {
    format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}"
    , addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15])
}

#[cfg(test)]
mod tests {
    use super::IPv6;

    #[test]
    fn test() {
        let ipv6 = IPv6::default();
        let mut ipv6_on_wire = Vec::new();
        ipv6.to_wire(&mut ipv6_on_wire);
        let ipv6_2 = IPv6::new_from_slice(&ipv6_on_wire).expect("Couldn't create ipv6_2");
        println!("{}", ipv6);
        println!("{:?}", ipv6_on_wire);
        println!("{}", ipv6_2);
        assert_eq!(ipv6, ipv6_2);
    }
}
