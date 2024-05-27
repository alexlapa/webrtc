use crate::stun;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::stun::{attrs::*, error::*, msg::*};

pub(crate) const FAMILY_IPV4: u16 = 0x01;
pub(crate) const FAMILY_IPV6: u16 = 0x02;
pub(crate) const IPV4LEN: usize = 4;
pub(crate) const IPV6LEN: usize = 16;

/// MappedAddress represents MAPPED-ADDRESS attribute.
///
/// This attribute is used only by servers for achieving backwards
/// compatibility with RFC 3489 clients.
///
/// RFC 5389 Section 15.1
pub struct MappedAddress {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for MappedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };
        if family == FAMILY_IPV4 {
            write!(f, "{}:{}", self.ip, self.port)
        } else {
            write!(f, "[{}]:{}", self.ip, self.port)
        }
    }
}

impl Default for MappedAddress {
    fn default() -> Self {
        MappedAddress {
            ip: IpAddr::V4(Ipv4Addr::from(0)),
            port: 0,
        }
    }
}

impl Setter for MappedAddress {
    /// add_to adds MAPPED-ADDRESS to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        self.add_to_as(m, ATTR_MAPPED_ADDRESS)
    }
}

impl Getter for MappedAddress {
    /// get_from decodes MAPPED-ADDRESS from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        self.get_from_as(m, ATTR_MAPPED_ADDRESS)
    }
}

impl MappedAddress {
    /// get_from_as decodes MAPPED-ADDRESS value in message m as an attribute of
    /// type t.
    pub fn get_from_as(&mut self, m: &Message, t: AttrType) -> Result<(), stun::Error> {
        let v = m.get(t)?;
        if v.len() <= 4 {
            return Err(Error::ErrUnexpectedEof);
        }

        let family = u16::from_be_bytes([v[0], v[1]]);
        if family != FAMILY_IPV6 && family != FAMILY_IPV4 {
            return Err(Error::Other(format!("bad value {family}")));
        }
        self.port = u16::from_be_bytes([v[2], v[3]]);

        if family == FAMILY_IPV6 {
            let mut ip = [0; IPV6LEN];
            let l = std::cmp::min(ip.len(), v[4..].len());
            ip[..l].copy_from_slice(&v[4..4 + l]);
            self.ip = IpAddr::V6(Ipv6Addr::from(ip));
        } else {
            let mut ip = [0; IPV4LEN];
            let l = std::cmp::min(ip.len(), v[4..].len());
            ip[..l].copy_from_slice(&v[4..4 + l]);
            self.ip = IpAddr::V4(Ipv4Addr::from(ip));
        };

        Ok(())
    }

    /// add_to_as adds MAPPED-ADDRESS value to m as t attribute.
    pub fn add_to_as(&self, m: &mut Message, t: AttrType) -> Result<(), stun::Error> {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };

        let mut value = vec![0u8; 4];
        // value[0] = 0 // first 8 bits are zeroes
        value[0..2].copy_from_slice(&family.to_be_bytes());
        value[2..4].copy_from_slice(&self.port.to_be_bytes());

        match self.ip {
            IpAddr::V4(ipv4) => value.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => value.extend_from_slice(&ipv6.octets()),
        };

        m.add(t, &value);
        Ok(())
    }
}

#[cfg(test)]
mod addr_test {
    use super::*;

    #[test]
    fn test_mapped_address() {
        let mut m = Message::new();
        let addr = MappedAddress {
            ip: "122.12.34.5".parse().unwrap(),
            port: 5412,
        };
        assert_eq!(addr.to_string(), "122.12.34.5:5412", "bad string {addr}");

        //"add_to"
        {
            addr.add_to(&mut m).unwrap();

            //"GetFrom"
            {
                let mut got = MappedAddress::default();
                got.get_from(&m).unwrap();
                assert_eq!(got.ip, addr.ip, "got bad IP: {}", got.ip);

                //"Not found"
                {
                    let message = Message::new();
                    let result = got.get_from(&message);
                    if let Err(err) = result {
                        assert_eq!(
                            Error::ErrAttributeNotFound,
                            err,
                            "should be not found: {err}"
                        );
                    } else {
                        panic!("expected error, but got ok");
                    }
                }
                //"Bad family"
                {
                    let (mut v, _) = m.attributes.get(ATTR_MAPPED_ADDRESS);
                    v.value[0] = 32;
                    got.get_from(&m).unwrap()
                }
                //"Bad length"
                {
                    let mut message = Message::new();
                    message.add(ATTR_MAPPED_ADDRESS, &[1, 2, 3]);
                    let result = got.get_from(&message);
                    if let Err(err) = result {
                        assert_eq!(
                            Error::ErrUnexpectedEof,
                            err,
                            "<{}> should be <{}>",
                            err,
                            Error::ErrUnexpectedEof
                        );
                    } else {
                        panic!("expected error, but got ok");
                    }
                }
            }
        }
    }

    #[test]
    fn test_mapped_address_v6() {
        let mut m = Message::new();
        let addr = MappedAddress {
            ip: "::".parse().unwrap(),
            port: 5412,
        };

        //"add_to"
        {
            addr.add_to(&mut m).unwrap();

            //"GetFrom"
            {
                let mut got = MappedAddress::default();
                got.get_from(&m).unwrap();
                assert_eq!(got.ip, addr.ip, "got bad IP: {}", got.ip);

                //"Not found"
                {
                    let message = Message::new();
                    let result = got.get_from(&message);
                    if let Err(err) = result {
                        assert_eq!(
                            Error::ErrAttributeNotFound,
                            err,
                            "<{}> should be <{}>",
                            err,
                            Error::ErrAttributeNotFound,
                        );
                    } else {
                        panic!("expected error, but got ok");
                    }
                }
            }
        }
    }
}
