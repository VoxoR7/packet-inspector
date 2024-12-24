use std::{cell::RefCell, rc::Rc};

use chrono::{DateTime, Utc};
use log::info;

use crate::{
    packet::Packet,
    signature::Signature,
};

#[derive(Debug)]
pub struct TCPSession {
    session_unique_number: u64,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    timer_index: usize,

    /// Theses are the packets received untouched  
    /// (e.g. ipv4 fragemented packets reassembled will not be shown here,  
    /// However fragments will be in this vec)  
    /// This Vec will be used in case of pcap writing
    packets: Vec<Rc<RefCell<Packet>>>,

    /// Theses are the packets to be analyzed.  
    /// They might not be the packets received  
    /// (In case of ipv4 fragmentation for example)
    reassembled_packet: Vec<Rc<RefCell<Packet>>>,
    signature: Signature,
}

impl TCPSession {
    pub fn new(unique_number: u64, time: DateTime<Utc>, sig: Signature) -> Self {
        Self {
            session_unique_number: unique_number,
            start_time: time,
            end_time: time,
            timer_index: usize::MAX,
            packets: Vec::new(),
            reassembled_packet: Vec::new(),
            signature: sig,
        }
    }

    pub fn get_timer_index(&self) -> usize {
        self.timer_index
    }

    pub fn set_timer_index(&mut self, timer_index: usize) {
        self.timer_index = timer_index;
    }

    pub fn session_add_packet(&mut self, packet: Packet, crafted: bool) {
        if self.end_time < packet.get_time() {
            self.end_time = packet.get_time();
        }

        let reference = Rc::new(RefCell::new(packet));

        if !crafted {
            self.packets.push(Rc::clone(&reference));
        }
        self.reassembled_packet.push(reference);
    }

    pub fn session_add_packet_for_pcap(&mut self, packet: Packet) {
        self.packets.push(Rc::new(RefCell::new(packet)));
    }

    pub fn print_session(&self) {
        let time_delta = self.end_time - self.start_time;
        let sec = time_delta.num_seconds();
        let min = sec / 60;
        let hours = sec / (60 * 60);
        let days = sec / (60 * 60 * 24);
        if self.reassembled_packet.len() > 0 {
            info!("\nInfo for session number {}\n\tStart start_time: {}\n\tEnd time:   {}\n\tDuration: {:>2}days{:>2}h{:>2}m{:>2}s\n\tNumber of packets: {}\n\tFirst packet: {}",
            self.session_unique_number, self.start_time, self.end_time, days, hours, min, sec, self.reassembled_packet.len(), self.reassembled_packet[0].borrow());
        } else {
            info!("\nInfo for session number {}\n\tStart start_time: {}\n\tEnd time:   {}\n\tDuration: {:>2}days{:>2}h{:>2}m{:>2}s\n\tNumber of packets: {}",
            self.session_unique_number, self.start_time, self.end_time, days, hours, min, sec, self.reassembled_packet.len());
        }
    }

    pub fn get_singature(&self) -> &Signature {
        &self.signature
    }
}
