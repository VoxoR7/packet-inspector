use crate::packet::parser::l3::{icmp, ipv4, ipv6};

#[derive(Debug, Clone)]
pub enum L3Protocols {
    Icmp(icmp::Icmp),
    IPv4(ipv4::IPv4),
    IPv6(ipv6::IPv6),
}

#[derive(Debug)]
pub enum IcmpErrors {
    NotEnoughBytes,
}

#[derive(Debug)]
pub enum IPv4Errors {
    NotEnoughBytes,
    InvalidIPVersion,
    InvalidIHL,
    TotalLenExceedPacketLen,
}

#[derive(Debug)]
pub enum IPv6Errors {
    NotEnoughBytes,
}

#[derive(Debug)]
pub enum L3ProtocolsError {
    Icmp(IcmpErrors),
    IPv4(IPv4Errors),
    IPv6(IPv6Errors),
}
