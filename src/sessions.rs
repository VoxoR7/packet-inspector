pub mod ipv4_frags;
pub mod tcp_sessions;

use ipv4_frags::Ipv4Frags;
use tcp_sessions::TCPSessions;

pub type Sessions<'a> = (&'a mut Ipv4Frags, &'a mut TCPSessions);
