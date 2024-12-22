use crate::packet::parser::l4::tcp;

#[derive(Debug, Clone)]
pub enum L4Protocols {
    Tcp(tcp::Tcp),
}

#[derive(Debug)]
pub enum TCPErrors {
    NotEnoughBytes,
    InvalidDataOffset,
}

#[derive(Debug)]
pub enum L4ProtocolsError {
    Tcp(TCPErrors),
}
