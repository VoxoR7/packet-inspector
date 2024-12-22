pub const ICMP: u8 = 0x01;
pub const TCP: u8 = 0x06;

#[derive(Debug, strum::Display, Clone, Copy)]
pub enum IPProtocols {
    Unknow(u8),
    Icmp,
    Tcp,
}

pub fn parse_network_number(network_number: u8) -> IPProtocols {
    match network_number {
        0x01 => IPProtocols::Icmp,
        0x06 => IPProtocols::Tcp,
        _ => IPProtocols::Unknow(network_number),
    }
}
