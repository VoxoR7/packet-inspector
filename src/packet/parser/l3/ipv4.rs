use std::fmt::Display;

use log::warn;

use super::{icmp::Icmp, ipprot};
use crate::{
    bytes_arch::as_u16_be,
    osi_layer::{
        l3::{IPv4Errors, L3Protocols, L3ProtocolsError},
        OsiLayer, OsiLayerError,
    },
    packet::{self, parser::l4::tcp::Tcp},
    sessions::Sessions,
};

const IPV4_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct IPv4 {
    ip_version: u8,
    ihl: u8,
    dscp_ecn: u8,
    total_len: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src: [u8; 4],
    dst: [u8; 4],
    option: Option<Vec<u8>>,
}

impl IPv4 {
    pub fn parse_ipv4(
        packet: packet::SoloPacket,
        sessions: &mut Sessions,
    ) -> Result<(), OsiLayerError> {
        let (mut packet, mut sig) = packet;
        let Some(ipv4_bytes) = packet.get(IPV4_LEN) else {
            return Err(OsiLayerError::L3(L3ProtocolsError::IPv4(
                IPv4Errors::NotEnoughBytes,
            )));
        };

        let protocol = ipv4_bytes[9];

        let mut ipv4 = Self {
            ip_version: (ipv4_bytes[0] & 0xF0) >> 4,
            ihl: ipv4_bytes[0] & 0x0F,
            dscp_ecn: ipv4_bytes[1],
            total_len: as_u16_be(&ipv4_bytes[2..4]),
            identification: as_u16_be(&ipv4_bytes[4..6]),
            flags: (ipv4_bytes[6] & 0b11100000) >> 5,
            fragment_offset: (((ipv4_bytes[6] as u16) & 0b00011111) << 8) + (ipv4_bytes[7] as u16),
            ttl: ipv4_bytes[8],
            protocol,
            header_checksum: as_u16_be(&ipv4_bytes[10..12]),
            src: *<&[u8; 4]>::try_from(&ipv4_bytes[12..16]).unwrap(),
            dst: *<&[u8; 4]>::try_from(&ipv4_bytes[16..20]).unwrap(),
            option: None,
        };

        if ipv4.ip_version != 4 {
            return Err(OsiLayerError::L3(L3ProtocolsError::IPv4(
                IPv4Errors::InvalidIPVersion,
            )));
        }

        if ipv4.ihl < 5 || ipv4.ihl > 20 {
            return Err(OsiLayerError::L3(L3ProtocolsError::IPv4(
                IPv4Errors::InvalidIHL,
            )));
        }

        let ipv4_hdr_len = (ipv4.ihl - 5) * 4;

        if ipv4.ihl > 5 {
            let Some(ipv4_bytes) = packet.get(ipv4_hdr_len as usize) else {
                return Err(OsiLayerError::L3(L3ProtocolsError::IPv4(
                    IPv4Errors::NotEnoughBytes,
                )));
            };

            ipv4.option = Some(ipv4_bytes.to_vec());
        }

        if IPV4_LEN + ipv4_hdr_len as usize + packet.remaining_data_len() != ipv4.total_len as usize
        {
            if IPV4_LEN + ipv4_hdr_len as usize + packet.remaining_data_len()
                < ipv4.total_len as usize
            {
                warn!("{packet}");
                return Err(OsiLayerError::L3(L3ProtocolsError::IPv4(
                    IPv4Errors::TotalLenExceedPacketLen,
                )));
            } else {
                let remain = ipv4.total_len as usize - IPV4_LEN - ipv4_hdr_len as usize;
                packet.set_remaining_data_len(remain);
            }
        }

        let is_fragment = ipv4.get_more_fragment() || ipv4.get_fragement_offset() > 0;

        sig.add_signature_two_way(&ipv4.src, &ipv4.dst);
        packet.add_layer(OsiLayer::L3(L3Protocols::IPv4(ipv4)));

        let (ipv4_frag_sessions, tcp_sessions) = sessions;

        if is_fragment {
            ipv4_frag_sessions.add_packet((packet, sig), tcp_sessions);
            return Ok(());
        }

        match protocol {
            ipprot::ICMP => Icmp::parse_icmp((packet, sig)),
            ipprot::TCP => Tcp::parse_tcp((packet, sig), tcp_sessions),
            _ => Ok(()),
        }
    }

    pub fn get_ihl(&self) -> u8 {
        self.ihl
    }

    pub fn get_total_len(&self) -> u16 {
        self.total_len
    }

    pub fn set_total_len(&mut self, total_len: u16) {
        self.total_len = total_len;
    }

    pub fn get_identification(&self) -> u16 {
        self.identification
    }

    pub fn get_dont_fragment(&self) -> bool {
        (self.flags & 0x02) == 0x02
    }

    pub fn get_more_fragment(&self) -> bool {
        (self.flags & 0x01) == 0x01
    }

    pub fn set_more_fragement(&mut self, more_fragement: bool) {
        if more_fragement {
            self.flags |= 0x01;
        } else {
            self.flags &= 0xFE;
        }
    }

    pub fn get_fragement_offset(&self) -> u16 {
        self.fragment_offset
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, &str> {
        let Some(ipv4_bytes) = slice.get(..IPV4_LEN) else {
            return Err("Not enough bytes (base)");
        };

        let mut ipv4 = Self {
            ip_version: (ipv4_bytes[0] & 0xF0) >> 4,
            ihl: ipv4_bytes[0] & 0x0F,
            dscp_ecn: ipv4_bytes[1],
            total_len: as_u16_be(&ipv4_bytes[2..4]),
            identification: as_u16_be(&ipv4_bytes[4..6]),
            flags: (ipv4_bytes[6] & 0b11100000) >> 5,
            fragment_offset: (((ipv4_bytes[6] as u16) & 0b00011111) << 8) + (ipv4_bytes[7] as u16),
            ttl: ipv4_bytes[8],
            protocol: ipv4_bytes[9],
            header_checksum: as_u16_be(&ipv4_bytes[10..12]),
            src: *<&[u8; 4]>::try_from(&ipv4_bytes[12..16]).unwrap(),
            dst: *<&[u8; 4]>::try_from(&ipv4_bytes[16..20]).unwrap(),
            option: None,
        };

        if ipv4.ihl > 5 && ipv4.ihl < 20 {
            let Some(ipv4_bytes) =
                slice.get(IPV4_LEN..(IPV4_LEN + (((ipv4.ihl - 5) * 4) as usize)))
            else {
                return Err("Not enough bytes (options)");
            };

            ipv4.option = Some(ipv4_bytes.to_vec());
        }

        Ok(ipv4)
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) {
        let byte = ((self.ip_version & 0x0F) << 4) + self.ihl;
        out.push(byte);
        out.push(self.dscp_ecn);
        for byte in self.total_len.to_be_bytes() {
            out.push(byte);
        }
        for byte in self.identification.to_be_bytes() {
            out.push(byte);
        }
        let fragment_offset = self.fragment_offset.to_be_bytes();
        let byte = ((self.flags & 0x07) << 5) + (fragment_offset[0] & 0x1F);
        out.push(byte);
        out.push(fragment_offset[1]);
        out.push(self.ttl);
        out.push(self.protocol);
        for byte in self.header_checksum.to_be_bytes() {
            out.push(byte);
        }
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        if let Some(options) = &self.option {
            out.extend_from_slice(options);
        }
    }
}

impl Display for IPv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[L3 - IPv4]")?;
        writeln!(f, "\tip_version:       {}", self.ip_version)?;
        writeln!(f, "\tihl:              {}", self.ihl)?;
        writeln!(f, "\tdscp ecn:         {}", self.dscp_ecn)?;
        writeln!(f, "\ttotal len:        {}", self.total_len)?;
        writeln!(f, "\tidentification:   {}", self.identification)?;
        write!(f, "\tflags:           ")?;
        if self.get_dont_fragment() {
            write!(f, " DF")?;
        }
        if self.get_more_fragment() {
            write!(f, " MF")?;
        }
        writeln!(f, "\n\tfragment offset:  {}", self.fragment_offset)?;
        writeln!(f, "\tttl:              {}", self.ttl)?;
        writeln!(f, "\tprotocol:         {}", self.protocol)?;
        writeln!(f, "\theader checksum:  {:#06x}", self.header_checksum)?;
        writeln!(f, "\tsrc:              {}", print_ipv4_addr(&self.src))?;
        writeln!(f, "\tdst:              {}", print_ipv4_addr(&self.dst))?;
        if let Some(options) = &self.option {
            writeln!(f, "\toptions:          {:?}", options)?;
        } else {
            writeln!(f, "\toptions:          None")?;
        }

        Ok(())
    }
}

fn print_ipv4_addr(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

impl Default for IPv4 {
    fn default() -> Self {
        Self {
            ip_version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_len: 20,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: ipprot::TCP,
            header_checksum: 0x0000,
            src: [1, 2, 3, 4],
            dst: [5, 6, 7, 8],
            option: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IPv4;

    #[test]
    fn test() {
        let ipv4 = IPv4::default();
        let mut ipv4_on_wire = Vec::new();
        ipv4.to_wire(&mut ipv4_on_wire);
        let ipv4_2 = IPv4::new_from_slice(&ipv4_on_wire).expect("Couldn't create ipv4_2");
        println!("{}", ipv4);
        println!("{:?}", ipv4_on_wire);
        println!("{}", ipv4_2);
        assert_eq!(ipv4, ipv4_2);
    }
}
