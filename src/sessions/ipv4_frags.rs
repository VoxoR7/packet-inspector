use std::{collections::HashMap, path::PathBuf, str::FromStr};

use log::error;

use crate::{
    osi_layer::{l3::L3Protocols, OsiLayer},
    packet::{
        self,
        parser::{
            l3::{icmp::Icmp, ipprot},
            l4::tcp::Tcp,
        },
        Packet, SoloPacket,
    },
    signature::Signature,
};

use super::tcp_sessions::TCPSessions;

#[derive(Default)]
pub struct Ipv4Frags {
    packets: HashMap<Signature, Vec<Packet>>,
}

impl Ipv4Frags {
    pub fn add_packet(&mut self, packet: SoloPacket, tcp_sessions: &mut TCPSessions) {
        let (packet, mut sig) = packet;

        let ipv4 = packet.get_last_layer_l3_ipv4().unwrap();
        /* if several packets are fragmented inside the same function,
        we must not mix them! And to do so, we add the identification number
        to the signature. Be careful to remove the identification number from
        the signature before sending the packet (sig.remove(2)) */
        sig.add_signature_one_way(&ipv4.get_identification().to_le_bytes());

        if let Some(fragments) = self.packets.get_mut(&sig) {
            fragments.push(packet);
            if check_fragments(fragments) {
                let fragments = self.packets.remove(&sig).unwrap();
                sig.remove(2);
                let new_packet = create_packet_from_fragments(&fragments);
                new_packet.write_to_pcap(&PathBuf::from_str("/tmp/test.pcap").unwrap());

                match new_packet.get_last_layer_l3_ipv4().unwrap().get_protocol() {
                    ipprot::ICMP => {
                        if let Err(err) = Icmp::parse_icmp((new_packet, sig)) {
                            error!("{err}");
                        }
                    }
                    ipprot::TCP => {
                        if let Ok(session) =
                            Tcp::parse_tcp_return_session((new_packet, sig), tcp_sessions)
                        {
                            for packet in fragments {
                                session.borrow_mut().session_add_packet(packet);
                            }
                        }
                    }
                    _ => (),
                }
                // Todo: send new packet and fragments to the correct place
            }
        } else {
            let mut vec = Vec::with_capacity(8);
            vec.push(packet);
            self.packets.insert(sig, vec);
        }
    }
}

fn check_fragments(packets: &[Packet]) -> bool {
    let mut next_fragment = 0;
    'outer: loop {
        for packet in packets.iter() {
            let ipv4 = packet.get_last_layer_l3_ipv4().unwrap();
            if ipv4.get_fragement_offset() == next_fragment {
                if !ipv4.get_more_fragment() {
                    return true;
                } else {
                    next_fragment = (packet.remaining_data_len() as u16) / 8;
                    continue 'outer;
                }
            }
        }

        return false;
    }
}

fn create_packet_from_fragments(packets: &[Packet]) -> Packet {
    let mut next_fragment = 0;
    let mut data: Vec<u8> = Vec::new();

    let mut new_packet = packet::Packet::new_from_scratch(
        packets[0].get_first_protocol(),
        packets[0].get_time(),
        packets[0].get_unique_number(),
    );

    let mut iter = packets[0].into_iter();
    let mut next_layer = iter.next();
    if next_layer.is_none() {
        panic!()
    }
    let mut layer;
    loop {
        layer = next_layer.unwrap().clone();
        next_layer = iter.next();

        if next_layer.is_none() {
            break;
        }

        new_packet.add_layer_and_create_data(layer);
    }

    // Here, we have pushed every layer into new_packet except the last one, which should be the fragement IP header
    // we keep it because we need to update some fields before pushing it into our new packet!

    let mut new_ipv4 = if let OsiLayer::L3(l3_protocol) = layer {
        if let L3Protocols::IPv4(ipv4) = l3_protocol {
            ipv4
        } else {
            panic!();
        }
    } else {
        panic!();
    };

    'outer: loop {
        for packet in packets.iter() {
            let ipv4 = packet.get_last_layer_l3_ipv4().unwrap();
            if ipv4.get_fragement_offset() == next_fragment {
                data.extend_from_slice(packet.remaining_data());
                if !ipv4.get_more_fragment() {
                    new_ipv4.set_more_fragement(false);
                    new_ipv4.set_total_len((new_ipv4.get_ihl() * 4) as u16 + (data.len() as u16));
                    new_packet.add_layer_and_create_data(OsiLayer::L3(L3Protocols::IPv4(new_ipv4)));
                    new_packet.add_data(&data);
                    return new_packet;
                } else {
                    next_fragment = (packet.remaining_data_len() as u16) / 8;
                    continue 'outer;
                }
            }
        }
    }
}
