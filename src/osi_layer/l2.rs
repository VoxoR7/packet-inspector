use crate::packet::parser::l2::ethernet;

#[derive(Debug, Clone)]
pub enum L2Protocols {
    Ethernet(ethernet::Ethernet),
}

#[derive(Debug)]
pub enum EthernetErrors {
    NotEnoughBytes,
    UnknowEtherType,
}

#[derive(Debug)]
pub enum L2ProtocolsError {
    Ethernet(EthernetErrors),
}
