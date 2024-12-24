use std::{cell::RefCell, fmt::Display, rc::Rc};

use crate::{
    bytes_arch::{as_u16_be, as_u32_be},
    osi_layer::{
        l4::{L4Protocols, L4ProtocolsError, TCPErrors},
        OsiLayer, OsiLayerError,
    },
    packet,
    sessions::tcp_sessions::{tcp_session::TCPSession, TCPSessions},
};

const TCP_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct Tcp {
    src: u16,
    dst: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    option: Option<Vec<u8>>,
}

impl Tcp {
    pub fn parse_tcp(
        packet: packet::SoloPacket,
        tcp_sessions: &mut TCPSessions,
    ) -> Result<(), OsiLayerError> {
        let (mut pkt, mut sig) = packet;
        let Some(tcp_bytes) = pkt.get(TCP_LEN) else {
            return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                TCPErrors::NotEnoughBytes,
            )));
        };

        let mut tcp = Self {
            src: as_u16_be(&tcp_bytes[0..2]),
            dst: as_u16_be(&tcp_bytes[2..4]),
            seq_number: as_u32_be(&tcp_bytes[4..8]),
            ack_number: as_u32_be(&tcp_bytes[8..12]),
            data_offset: (tcp_bytes[12] & 0xF0) >> 4,
            flags: tcp_bytes[13],
            window: as_u16_be(&tcp_bytes[14..16]),
            checksum: as_u16_be(&tcp_bytes[16..18]),
            urgent_pointer: as_u16_be(&tcp_bytes[18..20]),
            option: None,
        };

        if tcp.data_offset < 5 || tcp.data_offset > 20 {
            return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                TCPErrors::InvalidDataOffset,
            )));
        } else if tcp.data_offset > 5 {
            let Some(tcp_bytes) = pkt.get(((tcp.data_offset - 5) * 4) as usize) else {
                return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                    TCPErrors::NotEnoughBytes,
                )));
            };

            tcp.option = Some(tcp_bytes.to_vec());
        }

        sig.add_signature_two_way(&tcp.src.to_le_bytes(), &tcp.dst.to_le_bytes());
        pkt.add_layer(OsiLayer::L4(L4Protocols::Tcp(tcp)));

        tcp_sessions.add_packet((pkt, sig), false);

        Ok(())
    }

    pub fn parse_tcp_return_session(
        packet: packet::SoloPacket,
        crafted: bool,
        tcp_sessions: &mut TCPSessions,
    ) -> Result<&Rc<RefCell<TCPSession>>, OsiLayerError> {
        let (mut pkt, mut sig) = packet;
        let Some(tcp_bytes) = pkt.get(TCP_LEN) else {
            return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                TCPErrors::NotEnoughBytes,
            )));
        };

        let mut tcp = Self {
            src: as_u16_be(&tcp_bytes[0..2]),
            dst: as_u16_be(&tcp_bytes[2..4]),
            seq_number: as_u32_be(&tcp_bytes[4..8]),
            ack_number: as_u32_be(&tcp_bytes[8..12]),
            data_offset: (tcp_bytes[12] & 0xF0) >> 4,
            flags: tcp_bytes[13],
            window: as_u16_be(&tcp_bytes[14..16]),
            checksum: as_u16_be(&tcp_bytes[16..18]),
            urgent_pointer: as_u16_be(&tcp_bytes[18..20]),
            option: None,
        };

        if tcp.data_offset < 5 || tcp.data_offset > 20 {
            return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                TCPErrors::InvalidDataOffset,
            )));
        } else if tcp.data_offset > 5 {
            let Some(tcp_bytes) = pkt.get(((tcp.data_offset - 5) * 4) as usize) else {
                return Err(OsiLayerError::L4(L4ProtocolsError::Tcp(
                    TCPErrors::NotEnoughBytes,
                )));
            };

            tcp.option = Some(tcp_bytes.to_vec());
        }

        sig.add_signature_two_way(&tcp.src.to_le_bytes(), &tcp.dst.to_le_bytes());
        pkt.add_layer(OsiLayer::L4(L4Protocols::Tcp(tcp)));

        Ok(tcp_sessions.add_packet((pkt, sig), crafted))
    }

    pub fn get_cwr_bit(&self) -> bool {
        (self.flags & 0b10000000) == 0b10000000
    }

    pub fn get_ece_bit(&self) -> bool {
        (self.flags & 0b01000000) == 0b01000000
    }

    pub fn get_urg_bit(&self) -> bool {
        (self.flags & 0b00100000) == 0b00100000
    }

    pub fn get_ack_bit(&self) -> bool {
        (self.flags & 0b00010000) == 0b00010000
    }

    pub fn get_psh_bit(&self) -> bool {
        (self.flags & 0b00001000) == 0b00001000
    }

    pub fn get_rst_bit(&self) -> bool {
        (self.flags & 0b00000100) == 0b00000100
    }

    pub fn get_syn_bit(&self) -> bool {
        (self.flags & 0b00000010) == 0b00000010
    }

    pub fn get_fin_bit(&self) -> bool {
        (self.flags & 0b00000001) == 0b00000001
    }
}

impl Display for Tcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[L4 - TCP]")?;
        writeln!(f, "\tport src:         {}", self.src)?;
        writeln!(f, "\tport dst:         {}", self.dst)?;
        writeln!(f, "\tsequence number:  {}", self.seq_number)?;
        writeln!(f, "\tacknowled. number:{}", self.ack_number)?;
        writeln!(f, "\tdata offset:      {}", self.data_offset)?;
        write!(f, "\tflags:           ")?;
        if self.get_cwr_bit() {
            write!(f, " CWR")?;
        }
        if self.get_ece_bit() {
            write!(f, " ECE")?;
        }
        if self.get_urg_bit() {
            write!(f, " URG")?;
        }
        if self.get_ack_bit() {
            write!(f, " ACK")?;
        }
        if self.get_psh_bit() {
            write!(f, " PSH")?;
        }
        if self.get_rst_bit() {
            write!(f, " RST")?;
        }
        if self.get_syn_bit() {
            write!(f, " SYN")?;
        }
        if self.get_fin_bit() {
            write!(f, " FIN")?;
        }
        writeln!(f, "\n\twindow:           {}", self.window)?;
        writeln!(f, "\tchecksum:         {:#06x}", self.checksum)?;
        writeln!(f, "\turgent pointer:   {}", self.urgent_pointer)?;
        if let Some(options) = &self.option {
            writeln!(f, "\toptions:          {:?}", options)?;
        } else {
            writeln!(f, "\toptions:          None")?;
        }

        Ok(())
    }
}

impl Default for Tcp {
    fn default() -> Self {
        Self {
            src: 51254,
            dst: 80,
            seq_number: 0,
            ack_number: 0,
            data_offset: 0,
            flags: 0,
            window: 0,
            checksum: 0,
            urgent_pointer: 0,
            option: None,
        }
    }
}
