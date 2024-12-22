use clap::Parser;
use log::{error, info};

use packet_inspector::{
    packet::Packet,
    sessions::{ipv4_frags::Ipv4Frags, tcp_sessions::TCPSessions},
    setup_logger,
};
mod pcap;
use pcap::{error_kind_to_string, PcapReader};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    pcap_path: std::path::PathBuf,
}

fn main() {
    setup_logger();

    info!("Welcome into packet inspector!");

    let args = Args::parse();

    let mut pcap_reader = PcapReader::new(&args.pcap_path, None).unwrap_or_else(|err| {
        error!("Coudn't create pcap handler: {}", error_kind_to_string(err));
        std::process::exit(1);
    });

    pcap_reader.print_pcap_info();

    let Some(packet) = get_packet(&mut pcap_reader) else {
        error!("The pcap is empty!");
        std::process::exit(1);
    };

    let mut tcp_sessions = TCPSessions::new(packet.get_time());
    let mut ipv4_frag_sessions = Ipv4Frags::default();

    let mut sessions = (&mut ipv4_frag_sessions, &mut tcp_sessions);

    packet.parse(&mut sessions);

    while let Some(packet) = get_packet(&mut pcap_reader) {
        packet.parse(&mut sessions);
    }

    tcp_sessions.print_state();

    info!("Exiting packet inspector!");
}

fn get_packet(pcap_reader: &mut PcapReader) -> Option<Packet> {
    let packet = pcap_reader.get_packet();

    if let Err(err) = packet {
        if let pcap::ErrorKind::EndOfFile(_) = err {
            return None;
        }

        error!("Coudn't get packet: {}", error_kind_to_string(err));
        std::process::exit(1);
    }

    Some(packet.unwrap())
}
