use chrono::{DateTime, Utc};
use log::info;

use crate::{
    packet::{Packet, SoloPacket},
    signature::Signature,
};

#[derive(Debug)]
pub struct TCPSession {
    session_unique_number: u64,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    timer_index: usize,
    packets: Vec<Packet>,
    signature: Signature,
}

impl TCPSession {
    pub fn new(packet: SoloPacket, unique_number: u64) -> Self {
        let (packet, sig) = packet;
        Self {
            session_unique_number: unique_number,
            start_time: packet.get_time(),
            end_time: packet.get_time(),
            timer_index: usize::MAX,
            packets: vec![packet],
            signature: sig,
        }
    }

    pub fn get_timer_index(&self) -> usize {
        self.timer_index
    }

    pub fn set_timer_index(&mut self, timer_index: usize) {
        self.timer_index = timer_index;
    }

    pub fn session_add_packet(&mut self, packet: Packet) {
        if self.end_time < packet.get_time() {
            self.end_time = packet.get_time();
        }
        self.packets.push(packet);
    }

    pub fn print_session(&self) {
        let time_delta = self.end_time - self.start_time;
        let sec = time_delta.num_seconds();
        let min = sec / 60;
        let hours = sec / (60 * 60);
        let days = sec / (60 * 60 * 24);
        info!("\nInfo for session number {}\n\tStart start_time: {}\n\tEnd time:   {}\n\tDuration: {:>2}days{:>2}h{:>2}m{:>2}s\n\tNumber of packets: {}\n\tFirst packet: {}",
        self.session_unique_number, self.start_time, self.end_time, days, hours, min, sec, self.packets.len(), self.packets[0]);
    }

    pub fn get_singature(&self) -> &Signature {
        &self.signature
    }
}
