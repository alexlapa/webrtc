use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use crate::stun::{self, attrs::*, msg::*, xoraddr::*};

/// `RelayedAddress` implements `XOR-RELAYED-ADDRESS` attribute.
///
/// It specifies the address and port that the server allocated to the
/// client. It is encoded in the same way as `XOR-MAPPED-ADDRESS`.
///
/// [RFC 5766 Section 14.5](https://www.rfc-editor.org/rfc/rfc5766#section-14.5).
#[derive(PartialEq, Eq, Debug)]
pub struct RelayedAddress {
    pub ip: IpAddr,
    pub port: u16,
}

impl Default for RelayedAddress {
    fn default() -> Self {
        RelayedAddress {
            ip: IpAddr::V4(Ipv4Addr::from(0)),
            port: 0,
        }
    }
}

impl fmt::Display for RelayedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(_) => write!(f, "{}:{}", self.ip, self.port),
            IpAddr::V6(_) => write!(f, "[{}]:{}", self.ip, self.port),
        }
    }
}

impl Setter for RelayedAddress {
    /// Adds `XOR-PEER-ADDRESS` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let a = XorMappedAddress {
            ip: self.ip,
            port: self.port,
        };
        a.add_to_as(m, ATTR_XOR_RELAYED_ADDRESS)
    }
}

impl Getter for RelayedAddress {
    /// Decodes `XOR-PEER-ADDRESS` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let mut a = XorMappedAddress::default();
        a.get_from_as(m, ATTR_XOR_RELAYED_ADDRESS)?;
        self.ip = a.ip;
        self.port = a.port;
        Ok(())
    }
}

/// `XorRelayedAddress` implements `XOR-RELAYED-ADDRESS` attribute.
///
/// It specifies the address and port that the server allocated to the
/// client. It is encoded in the same way as `XOR-MAPPED-ADDRESS`.
///
/// [RFC 5766 Section 14.5](https://www.rfc-editor.org/rfc/rfc5766#section-14.5).
pub type XorRelayedAddress = RelayedAddress;

#[cfg(test)]
mod relayaddr_test {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_relayed_address() -> Result<(), stun::Error> {
        // Simple tests because already tested in stun.
        let a = RelayedAddress {
            ip: IpAddr::V4(Ipv4Addr::new(111, 11, 1, 2)),
            port: 333,
        };

        assert_eq!(a.to_string(), "111.11.1.2:333", "invalid string");

        let mut m = Message::new();
        a.add_to(&mut m)?;
        m.write_header();

        let mut decoded = Message::new();
        decoded.write(&m.raw)?;

        let mut a_got = RelayedAddress::default();
        a_got.get_from(&decoded)?;

        Ok(())
    }
}
