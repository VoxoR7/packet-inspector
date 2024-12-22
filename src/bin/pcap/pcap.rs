use chrono::DateTime;
use log::{info, warn};
use std::fs::File;
use std::io::Read;

use packet_inspector::bytes_arch;
use packet_inspector::packet;

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    UnableToOpenPcap(String),
    UnableToReadPcap(String),
    EndOfFile(String),
    WrongMagicNumber(String),
    FrameCheckSequenceNotSupported(String),
    LinkTypeNotSupported(String),
}

pub fn error_kind_to_string(err: ErrorKind) -> String {
    match err {
        ErrorKind::UnableToOpenPcap(s) => s,
        ErrorKind::UnableToReadPcap(s) => s,
        ErrorKind::EndOfFile(s) => s,
        ErrorKind::WrongMagicNumber(s) => s,
        ErrorKind::FrameCheckSequenceNotSupported(s) => s,
        ErrorKind::LinkTypeNotSupported(s) => s,
    }
}

#[derive(Debug)]
enum TimestampAccuracy {
    Micro,
    Nano,
}

#[derive(Debug, strum::Display)]
enum LinkType {
    BSDLoopbackEncapsulation,
    Ethernet,
}

#[derive(Debug)]
pub struct PcapReader {
    pcap_path: std::path::PathBuf,
    timestamp_accuracy: TimestampAccuracy,
    major_version: u16,
    minor_version: u16,
    link_type: LinkType,
    protocol: packet::Protocol,
    file: std::fs::File,
    buf: Vec<u8>,
    unique_number: u64,
}

impl PcapReader {
    pub fn new(
        pcap_path: &std::path::Path,
        force_protocol: Option<packet::Protocol>,
    ) -> Result<Self, ErrorKind> {
        let mut file = match File::open(pcap_path) {
            Ok(f) => f,
            Err(err) => {
                warn!("Unable to open pcap: {}", err);
                return Err(ErrorKind::UnableToOpenPcap(
                    format!("Unable to open pcap: {}", err).to_string(),
                ));
            }
        };
        let mut buffer = [0; 24];
        if let Err(err) = file.read_exact(&mut buffer) {
            warn!("Unable to read pcap: {}", err);
            return Err(ErrorKind::UnableToReadPcap(
                format!("Unable to read pcap: {}", err).to_string(),
            ));
        };

        let magic_number = &buffer[..4];
        let major_version = bytes_arch::as_u16_le(&buffer[4..6]);
        let minor_version = bytes_arch::as_u16_le(&buffer[6..8]);

        let timestamp_accuracy;
        if magic_number == [0xD4, 0xC3, 0xB2, 0xA1] {
            timestamp_accuracy = TimestampAccuracy::Micro;
        } else if magic_number == [0x4D, 0x3C, 0xB2, 0xA1] {
            timestamp_accuracy = TimestampAccuracy::Nano;
        } else {
            warn!(
                "pcap {} has wrong magic number! {:02X} {:02X} {:02X} {:02X}",
                pcap_path.display(),
                buffer[3],
                buffer[2],
                buffer[1],
                buffer[0]
            );
            return Err(ErrorKind::WrongMagicNumber(
                "Wrong magic number".to_string(),
            ));
        }

        // &buffer[8..12] reserved
        // &buffer[12..16] reserved

        let snaplen = bytes_arch::as_u32_le(buffer[16..20].try_into().unwrap());

        let fcsf = buffer[21];
        if fcsf & 0b0001000 != 0 {
            warn!(
                "pcap {} has Frame Check Sequence enabled, not supported yet!",
                pcap_path.display()
            );
            return Err(ErrorKind::FrameCheckSequenceNotSupported(
                "Frame check sequence not supported".to_string(),
            ));
        }

        let link_type = bytes_arch::as_u16_le(&buffer[22..24]);
        let link_type = match link_type {
            0 => LinkType::BSDLoopbackEncapsulation,
            1 => LinkType::Ethernet,
            _ => {
                warn!(
                    "pcap {} has link type {link_type}, not supported yet!",
                    pcap_path.display()
                );
                return Err(ErrorKind::LinkTypeNotSupported(
                    "Link type not supported".to_string(),
                ));
            }
        };

        let protocol = match link_type {
            LinkType::BSDLoopbackEncapsulation => {
                if let Some(forced_protocol) = force_protocol {
                    info!("protocol forced to {:?}", forced_protocol);
                    forced_protocol
                } else {
                    warn!("BSDLoopbackEncapsulation link type detected, defaulting to ethernet. This might cause issue if packets first protocol is not ethernet!");
                    packet::Protocol::Ethernet
                }
            }
            LinkType::Ethernet => {
                if force_protocol.is_some() {
                    warn!("link type ethernet detected, skiping forced protocol!");
                }
                packet::Protocol::Ethernet
            }
        };

        info!("protocol used: {:?}", protocol);

        Ok(Self {
            pcap_path: pcap_path.to_path_buf(),
            timestamp_accuracy,
            major_version,
            minor_version,
            file,
            link_type,
            protocol,
            buf: vec![0; snaplen as usize],
            unique_number: 0,
        })
    }

    pub fn get_packet(&mut self) -> Result<packet::Packet, ErrorKind> {
        let mut buffer = [0; 16];
        if let Err(err) = self.file.read_exact(&mut buffer) {
            return Err(ErrorKind::EndOfFile(
                format!("Unable to read pcap: {}", err).to_string(),
            ));
        };

        let timestamp_s = bytes_arch::as_u32_le(&buffer[0..4]);
        let timestamp_ms_ns = bytes_arch::as_u32_le(&buffer[4..8]);
        let captured_packet_len = bytes_arch::as_u32_le(&buffer[8..12]);

        let buffer = &mut self.buf[..captured_packet_len.try_into().unwrap()];

        if let Err(err) = self.file.read_exact(buffer) {
            warn!("Unable to read pcap: {}", err);
            return Err(ErrorKind::UnableToReadPcap(
                format!("Unable to read pcap: {}", err).to_string(),
            ));
        };

        let result = match self.timestamp_accuracy {
            TimestampAccuracy::Micro => Ok(packet::Packet::new(
                buffer,
                self.protocol,
                DateTime::from_timestamp(timestamp_s as i64, timestamp_ms_ns * 1000).unwrap(),
                self.unique_number,
            )),
            TimestampAccuracy::Nano => Ok(packet::Packet::new(
                buffer,
                self.protocol,
                DateTime::from_timestamp(timestamp_s as i64, timestamp_ms_ns).unwrap(),
                self.unique_number,
            )),
        };

        self.unique_number += 1;
        result
    }

    pub fn print_pcap_info(&self) {
        info!(
            "\nfile: {}\nversion: {}.{}\nlink type: {}",
            self.pcap_path.display(),
            self.major_version,
            self.minor_version,
            self.link_type
        );
    }
}
