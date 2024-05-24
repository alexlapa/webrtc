use std::{collections::HashMap, net::SocketAddr};

use tokio::time::Instant;

//  Channel number:
//    0x4000 through 0x7FFF: These values are the allowed channel
//    numbers (16,383 possible values).
const MIN_CHANNEL_NUMBER: u16 = 0x4000;
const MAX_CHANNEL_NUMBER: u16 = 0x7fff;

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum BindingState {
    Idle,
    Request,
    Ready,
    Refresh,
    Failed,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct Binding {
    pub(crate) number: u16,
    pub(crate) st: BindingState,
    pub(crate) addr: SocketAddr,
    pub(crate) refreshed_at: Instant,
}

impl Binding {
    pub(crate) fn set_state(&mut self, state: BindingState) {
        // atomic.StoreInt32((*int32)(&b.st), int32(state))
        self.st = state;
    }

    pub(crate) fn state(&self) -> BindingState {
        // return BindingState(atomic.LoadInt32((*int32)(&b.st)))
        self.st
    }

    pub(crate) fn set_refreshed_at(&mut self, at: Instant) {
        self.refreshed_at = at;
    }

    pub(crate) fn refreshed_at(&self) -> Instant {
        self.refreshed_at
    }
}
/// Thread-safe Binding map.
#[derive(Default)]
pub(crate) struct BindingManager {
    chan_map: HashMap<u16, String>,
    addr_map: HashMap<String, Binding>,
    next: u16,
}

impl BindingManager {
    pub(crate) fn new() -> Self {
        BindingManager {
            chan_map: HashMap::new(),
            addr_map: HashMap::new(),
            next: MIN_CHANNEL_NUMBER,
        }
    }

    pub(crate) fn assign_channel_number(&mut self) -> u16 {
        let n = self.next;
        if self.next == MAX_CHANNEL_NUMBER {
            self.next = MIN_CHANNEL_NUMBER;
        } else {
            self.next += 1;
        }
        n
    }

    pub(crate) fn create(&mut self, addr: SocketAddr) -> Option<&Binding> {
        let b = Binding {
            number: self.assign_channel_number(),
            st: BindingState::Idle,
            addr,
            refreshed_at: Instant::now(),
        };

        self.chan_map.insert(b.number, b.addr.to_string());
        self.addr_map.insert(b.addr.to_string(), b);
        self.addr_map.get(&addr.to_string())
    }

    pub(crate) fn find_by_addr(&self, addr: &SocketAddr) -> Option<&Binding> {
        self.addr_map.get(&addr.to_string())
    }

    pub(crate) fn get_by_addr(&mut self, addr: &SocketAddr) -> Option<&mut Binding> {
        self.addr_map.get_mut(&addr.to_string())
    }

    pub(crate) fn find_by_number(&self, number: u16) -> Option<&Binding> {
        if let Some(s) = self.chan_map.get(&number) {
            self.addr_map.get(s)
        } else {
            None
        }
    }

    pub(crate) fn delete_by_addr(&mut self, addr: &SocketAddr) -> bool {
        if let Some(b) = self.addr_map.remove(&addr.to_string()) {
            self.chan_map.remove(&b.number);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
impl BindingManager {
    pub(crate) fn delete_by_number(&mut self, number: u16) -> bool {
        if let Some(s) = self.chan_map.remove(&number) {
            self.addr_map.remove(&s);
            true
        } else {
            false
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.addr_map.len()
    }
}

#[cfg(test)]
mod binding_test {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::error::Result;

    #[test]
    fn test_binding_manager_number_assignment() -> Result<()> {
        let mut m = BindingManager::new();
        let mut n: u16;
        for i in 0..10 {
            n = m.assign_channel_number();
            assert_eq!(MIN_CHANNEL_NUMBER + i, n, "should match");
        }

        m.next = 0x7ff0;
        for i in 0..16 {
            n = m.assign_channel_number();
            assert_eq!(0x7ff0 + i, n, "should match");
        }
        // back to min
        n = m.assign_channel_number();
        assert_eq!(MIN_CHANNEL_NUMBER, n, "should match");

        Ok(())
    }

    #[test]
    fn test_binding_manager_method() -> Result<()> {
        let lo = Ipv4Addr::new(127, 0, 0, 1);
        let count = 100;
        let mut m = BindingManager::new();
        for i in 0..count {
            let addr = SocketAddr::V4(SocketAddrV4::new(lo, 10000 + i));
            let b0 = {
                let b = m.create(addr);
                *b.unwrap()
            };
            let b1 = m.find_by_addr(&addr);
            assert!(b1.is_some(), "should succeed");
            let b2 = m.find_by_number(b0.number);
            assert!(b2.is_some(), "should succeed");

            assert_eq!(b0, *b1.unwrap(), "should match");
            assert_eq!(b0, *b2.unwrap(), "should match");
        }

        assert_eq!(count, m.size() as u16, "should match");
        assert_eq!(count, m.addr_map.len() as u16, "should match");

        for i in 0..count {
            let addr = SocketAddr::V4(SocketAddrV4::new(lo, 10000 + i));
            if i % 2 == 0 {
                assert!(m.delete_by_addr(&addr), "should return true");
            } else {
                assert!(
                    m.delete_by_number(MIN_CHANNEL_NUMBER + i),
                    "should return true"
                );
            }
        }

        assert_eq!(0, m.size(), "should match");
        assert_eq!(0, m.addr_map.len(), "should match");

        Ok(())
    }

    #[test]
    fn test_binding_manager_failure() -> Result<()> {
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let addr = SocketAddr::V4(SocketAddrV4::new(ipv4, 7777));
        let mut m = BindingManager::new();
        let b = m.find_by_addr(&addr);
        assert!(b.is_none(), "should fail");
        let b = m.find_by_number(5555);
        assert!(b.is_none(), "should fail");
        let ok = m.delete_by_addr(&addr);
        assert!(!ok, "should fail");
        let ok = m.delete_by_number(5555);
        assert!(!ok, "should fail");

        Ok(())
    }
}
