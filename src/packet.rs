use std::{fmt::Display, fs::File, io::Write, path::Path};

pub mod parser;
use chrono::{DateTime, Utc};
use parser::l3::ipv4;

use crate::{
    osi_layer::{l2::L2Protocols, l3::L3Protocols, l4::L4Protocols, OsiLayer},
    sessions::Sessions,
    signature::Signature,
};

#[derive(Debug, strum::Display, Clone, Copy)]
pub enum Protocol {
    Ethernet,
    IPv4,
    IPv6,
}

#[derive(Debug)]
pub struct Packet {
    unique_number: u64,
    data: Vec<u8>,
    time: DateTime<Utc>,
    first_protocol: Protocol,
    bytes_parsed: usize,
    layers: Vec<OsiLayer>,
}

pub type SoloPacket = (Packet, Signature);

impl Packet {
    pub fn new_from_scratch(
        first_protocol: Protocol,
        time: DateTime<Utc>,
        unique_number: u64,
    ) -> Self {
        Self {
            unique_number,
            data: Vec::new(),
            time,
            first_protocol,
            bytes_parsed: 0,
            layers: Vec::with_capacity(32),
        }
    }

    pub fn add_layer_and_create_data(&mut self, layer: OsiLayer) {
        let mut data = Vec::with_capacity(64);

        match layer {
            OsiLayer::L2(ref l2_protocols) => match l2_protocols {
                L2Protocols::Ethernet(ethernet) => {
                    ethernet.to_wire(&mut data);
                }
            },
            OsiLayer::L3(ref l3_protocols) => match l3_protocols {
                L3Protocols::Icmp(icmp) => icmp.to_wire(&mut data),
                L3Protocols::IPv4(ipv4) => ipv4.to_wire(&mut data),
                L3Protocols::IPv6(ipv6) => ipv6.to_wire(&mut data),
            },
            OsiLayer::L4(_) => panic!(),
        }

        self.data.extend_from_slice(&data);
        self.add_layer(layer);
        self.bytes_parsed = self.data.len();
    }

    pub fn add_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn new(
        packet: &[u8],
        first_protocol: Protocol,
        time: DateTime<Utc>,
        unique_number: u64,
    ) -> Self {
        Self {
            unique_number,
            data: packet.to_vec(),
            time,
            first_protocol,
            bytes_parsed: 0,
            layers: Vec::with_capacity(32),
        }
    }

    pub fn parse(self, sessions: &mut Sessions) {
        let signature = Signature::new();
        parser::Parser::parse_packet((self, signature), sessions);
    }

    pub fn get_first_protocol(&self) -> Protocol {
        self.first_protocol
    }

    pub fn get(&mut self, nr_bytes: usize) -> Option<&[u8]> {
        if self.data.len() - self.bytes_parsed < nr_bytes {
            return None;
        }

        let begin = self.bytes_parsed;
        self.bytes_parsed += nr_bytes;

        Some(&self.data[begin..self.bytes_parsed])
    }

    pub fn set_remaining_data_len(&mut self, remain: usize) {
        self.data.truncate(self.bytes_parsed + remain);
    }

    pub fn remaining_data_len(&self) -> usize {
        self.data.len() - self.bytes_parsed
    }

    pub fn remaining_data(&self) -> &[u8] {
        &self.data[self.bytes_parsed..]
    }

    pub fn add_layer(&mut self, layer: OsiLayer) {
        self.layers.push(layer);
    }

    pub fn get_time(&self) -> DateTime<Utc> {
        self.time
    }

    pub fn get_unique_number(&self) -> u64 {
        self.unique_number
    }

    pub fn get_last_layer_l3_ipv4(&self) -> Option<&ipv4::IPv4> {
        for osi in self.layers.iter() {
            if let OsiLayer::L3(L3Protocols::IPv4(ipv4)) = osi {
                return Some(ipv4);
            }
        }

        None
    }

    pub fn write_to_pcap(&self, path: &Path) {
        let mut file = File::create(path).unwrap();
        file.write_all(&[0xD4, 0xC3, 0xB2, 0xA1]).unwrap();

        let major: u16 = 2;
        let minor: u16 = 4;
        file.write_all(&major.to_le_bytes()).unwrap();
        file.write_all(&minor.to_le_bytes()).unwrap();

        let reserved = [0u8; 8];
        file.write_all(&reserved).unwrap();

        let snaplen: u32 = 2000;
        let link_type: u32 = 0x01000000;

        file.write_all(&snaplen.to_le_bytes()).unwrap();
        file.write_all(&link_type.to_be_bytes()).unwrap();

        let ts_s: u32 = 0;
        let ts_a: u32 = 0;
        file.write_all(&ts_s.to_le_bytes()).unwrap();
        file.write_all(&ts_a.to_le_bytes()).unwrap();

        let packet_len: u32 = self.data.len().try_into().unwrap();
        file.write_all(&packet_len.to_le_bytes()).unwrap();
        file.write_all(&packet_len.to_le_bytes()).unwrap();

        file.write_all(&self.data).unwrap();
    }
}

impl Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n[Packet info]")?;
        writeln!(f, "\tunique number:    {}", self.unique_number)?;
        writeln!(f, "\ttime:             {}", self.time)?;
        writeln!(f, "\tfirst protocol:   {}", self.first_protocol)?;

        for layer in self.layers.iter() {
            match layer {
                OsiLayer::L2(l2_protocols) => match l2_protocols {
                    L2Protocols::Ethernet(ethernet) => writeln!(f, "{ethernet}")?,
                },
                OsiLayer::L3(l3_protocols) => match l3_protocols {
                    L3Protocols::Icmp(icmp) => writeln!(f, "{icmp}")?,
                    L3Protocols::IPv4(ipv4) => writeln!(f, "{ipv4}")?,
                    L3Protocols::IPv6(ipv6) => writeln!(f, "{ipv6}")?,
                },
                OsiLayer::L4(l4_protocols) => match l4_protocols {
                    L4Protocols::Tcp(tcp) => writeln!(f, "{tcp}")?,
                },
            }
        }

        Ok(())
    }
}

impl<'a> IntoIterator for &'a Packet {
    type Item = &'a OsiLayer;
    type IntoIter = PacketIter<'a>;

    fn into_iter(self) -> PacketIter<'a> {
        PacketIter {
            packet: self,
            index: 0,
        }
    }
}

pub struct PacketIter<'a> {
    packet: &'a Packet,
    index: usize,
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = &'a OsiLayer;

    fn next(&mut self) -> Option<&'a OsiLayer> {
        let layer = self.packet.layers.get(self.index);
        self.index += 1;
        layer
    }
}
