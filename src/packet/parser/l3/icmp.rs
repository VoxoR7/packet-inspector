use std::fmt::Display;

use crate::{
    bytes_arch::{as_u16_be, as_u32_be},
    osi_layer::{
        l3::{IcmpErrors, L3Protocols, L3ProtocolsError},
        OsiLayer, OsiLayerError,
    },
    packet,
};

const ICMP_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct Icmp {
    msg_type: u8,
    code: u8,
    checksum: u16,
    content: u32,
}

impl Icmp {
    pub fn parse_icmp(packet: packet::SoloPacket) -> Result<(), OsiLayerError> {
        let (mut packet, _) = packet;
        let Some(icmp_bytes) = packet.get(ICMP_LEN) else {
            return Err(OsiLayerError::L3(L3ProtocolsError::Icmp(
                IcmpErrors::NotEnoughBytes,
            )));
        };

        let icmp = Self {
            msg_type: icmp_bytes[0],
            code: icmp_bytes[1],
            checksum: as_u16_be(&icmp_bytes[2..4]),
            content: as_u32_be(&icmp_bytes[4..8]),
        };

        packet.add_layer(OsiLayer::L3(L3Protocols::Icmp(icmp)));

        Ok(())
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, &str> {
        let Some(icmp_bytes) = slice.get(..ICMP_LEN) else {
            return Err("Not enough bytes");
        };

        Ok(Self {
            msg_type: icmp_bytes[0],
            code: icmp_bytes[1],
            checksum: as_u16_be(&icmp_bytes[2..4]),
            content: as_u32_be(&icmp_bytes[4..8]),
        })
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) {
        out.push(self.msg_type);
        out.push(self.code);
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.content.to_be_bytes());
    }
}

impl Display for Icmp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[L3 - ICMP]")?;
        writeln!(f, "\ttype:             {}", self.msg_type)?;
        writeln!(f, "\tcode:             {}", self.code)?;
        writeln!(f, "\tchecksum          {:#06x}", self.checksum)?;
        writeln!(f, "\tcontent           {}", self.content)?;

        Ok(())
    }
}

impl Default for Icmp {
    fn default() -> Self {
        Self {
            msg_type: 0,
            code: 1,
            checksum: 0x0203,
            content: 0x04050607,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Icmp;

    #[test]
    fn test() {
        let icmp = Icmp::default();
        let mut icmp_on_wire = Vec::new();
        icmp.to_wire(&mut icmp_on_wire);
        let icmp_2 = Icmp::new_from_slice(&icmp_on_wire).expect("Couldn't create icmp_2");
        println!("{}", icmp);
        println!("{:?}", icmp_on_wire);
        println!("{}", icmp_2);
        assert_eq!(icmp, icmp_2);
    }
}
