use l2::ethernet;
use l3::{ipv4, ipv6};
use log::info;

use crate::{packet, sessions::Sessions};
pub mod layer;

pub struct Parser {}

impl Parser {
    pub fn parse_packet(packet: packet::SoloPacket, sessions: &mut Sessions) {
        if let Err(err) = match packet.0.get_first_protocol() {
            packet::Protocol::Ethernet => ethernet::Ethernet::parse_ethernet(packet, sessions),
            packet::Protocol::IPv4 => ipv4::IPv4::parse_ipv4(packet, sessions),
            packet::Protocol::IPv6 => ipv6::IPv6::parse_ipv6(packet, sessions),
        } {
            info!("{}", err);
        }
    }
}

pub mod l2 {
    pub mod ethernet;
}

pub mod l3 {
    pub mod icmp;
    pub mod ipprot;
    pub mod ipv4;
    pub mod ipv6;
}

pub mod l4 {
    pub mod tcp;
}
