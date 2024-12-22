use l2::{L2Protocols, L2ProtocolsError};
use l3::{L3Protocols, L3ProtocolsError};
use l4::{L4Protocols, L4ProtocolsError};

pub mod l2;
pub mod l3;
pub mod l4;

#[derive(Debug, strum::Display, Clone)]
pub enum OsiLayer {
    L2(L2Protocols),
    L3(L3Protocols),
    L4(L4Protocols),
}

#[derive(Debug, strum::Display)]
pub enum OsiLayerError {
    L2(L2ProtocolsError),
    L3(L3ProtocolsError),
    L4(L4ProtocolsError),
}
