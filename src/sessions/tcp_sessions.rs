pub mod tcp_session;

use std::{cell::RefCell, rc::Rc};

use chrono::{DateTime, Utc};
use log::{info, warn};
use tcp_session::TCPSession;

use crate::{packet, signature::Signature};

const TIME_ACCURACY_SEC: usize = 1;
const MAX_TIMER: usize = 65536;
const DEFAULT_SESSION_TIME_SEC: usize = 120;

#[derive(Debug)]
pub struct TCPSessions {
    session_unique_number: u64,
    hashmap: std::collections::HashMap<Signature, Rc<RefCell<TCPSession>>>,
    time_session: Vec<Vec<Rc<RefCell<TCPSession>>>>,
    timer: usize,
    next_time_wake_up: u64,
}

impl TCPSessions {
    pub fn new(time_start: DateTime<Utc>) -> Self {
        let mut time_session = Vec::new();
        for _ in 0..MAX_TIMER {
            time_session.push(Vec::new());
        }

        Self {
            session_unique_number: 0,
            hashmap: std::collections::HashMap::new(),
            time_session,
            timer: 0,
            next_time_wake_up: (time_start.timestamp() as u64) + (TIME_ACCURACY_SEC as u64),
        }
    }

    pub fn add_packet(&mut self, packet: packet::SoloPacket, crafted: bool) -> &Rc<RefCell<TCPSession>> {
        let (pkt, sig) = packet;
        let time = (pkt.get_time().timestamp()) as u64;
        while time >= self.next_time_wake_up {
            self.wake_up_session();
            self.timer += 1;
            self.timer %= MAX_TIMER;
            self.next_time_wake_up += TIME_ACCURACY_SEC as u64;
        }

        let index = self.compute_wake_up_session_in(DEFAULT_SESSION_TIME_SEC);

        if let Some(session) = self.hashmap.get(&sig) {
            session.borrow_mut().session_add_packet(pkt, crafted);
            session.borrow_mut().set_timer_index(index);
        } else {
            let mut session = TCPSession::new(
                self.session_unique_number,
                pkt.get_time(),
                sig.clone(), // only one clone will be made per session, performance cost is acceptable
            );
            session.session_add_packet(pkt, crafted);
            let session = Rc::new(RefCell::new(session));
            let session_clone = Rc::clone(&session);
            self.session_unique_number += 1;
            self.hashmap.insert(sig.clone(), session);
            session_clone.borrow_mut().set_timer_index(index);
            self.time_session[index].push(session_clone);
        }

        self.hashmap.get(&sig).unwrap()
    }

    fn compute_wake_up_session_in(&mut self, mut secs: usize) -> usize {
        if secs > (MAX_TIMER - 1) * TIME_ACCURACY_SEC {
            warn!(
                "Session is set to wake in {secs}secs, but maximum is {}. Setting to maximum.",
                (MAX_TIMER - 1) * TIME_ACCURACY_SEC
            );
            secs = (MAX_TIMER - 1) * TIME_ACCURACY_SEC;
        }

        (self.timer + (secs / TIME_ACCURACY_SEC)) % MAX_TIMER
    }

    fn wake_up_session(&mut self) {
        while let Some(session) = self.time_session[self.timer].pop() {
            let session_timer_index = session.borrow().get_timer_index();
            if session_timer_index != self.timer {
                self.time_session[session_timer_index].push(session);
                continue;
            }

            let session = self
                .hashmap
                .remove(session.borrow().get_singature())
                .expect("We should never reach this panic");

            info!("SESSION END!");
            session.borrow_mut().print_session();
        }
    }

    pub fn print_state(&self) {
        for session in self.hashmap.values() {
            session.borrow().print_session();
        }
    }
}
