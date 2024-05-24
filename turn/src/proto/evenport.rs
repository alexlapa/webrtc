use std::fmt;

use crate::stun::{self, attributes::*, checks::*, message::*};

/// `EvenPort` represents `EVEN-PORT` attribute.
///
/// This attribute allows the client to request that the port in the
/// relayed transport address be even, and (optionally) that the server
/// reserve the next-higher port number.
///
/// [RFC 5766 Section 14.6](https://www.rfc-editor.org/rfc/rfc5766#section-14.6).
#[derive(Default, Debug, PartialEq, Eq)]
pub struct EvenPort {
    /// `reserve_port` means that the server is requested to reserve
    /// the next-higher port number (on the same IP address)
    /// for a subsequent allocation.
    reserve_port: bool,
}

impl fmt::Display for EvenPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reserve_port {
            write!(f, "reserve: true")
        } else {
            write!(f, "reserve: false")
        }
    }
}

const EVEN_PORT_SIZE: usize = 1;
const FIRST_BIT_SET: u8 = 0b10000000; // FIXME? (1 << 8) - 1;

impl Setter for EvenPort {
    /// Adds `EVEN-PORT` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let mut v = vec![0; EVEN_PORT_SIZE];
        if self.reserve_port {
            // Set first bit to 1.
            v[0] = FIRST_BIT_SET;
        }
        m.add(ATTR_EVEN_PORT, &v);
        Ok(())
    }
}

impl Getter for EvenPort {
    /// Decodes `EVEN-PORT` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let v = m.get(ATTR_EVEN_PORT)?;

        check_size(ATTR_EVEN_PORT, v.len(), EVEN_PORT_SIZE)?;

        if v[0] & FIRST_BIT_SET > 0 {
            self.reserve_port = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod evenport_test {
    use super::*;

    #[test]
    fn test_even_port_string() -> Result<(), stun::Error> {
        let mut p = EvenPort::default();
        assert_eq!(
            p.to_string(),
            "reserve: false",
            "bad value {p} for reselve: false"
        );

        p.reserve_port = true;
        assert_eq!(
            p.to_string(),
            "reserve: true",
            "bad value {p} for reselve: true"
        );

        Ok(())
    }

    #[test]
    fn test_even_port_false() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let p = EvenPort {
            reserve_port: false,
        };
        p.add_to(&mut m)?;
        m.write_header();

        let mut decoded = Message::new();
        let mut port = EvenPort::default();
        decoded.write(&m.raw)?;
        port.get_from(&m)?;
        assert_eq!(port, p);

        Ok(())
    }

    #[test]
    fn test_even_port_add_to() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let p = EvenPort { reserve_port: true };
        p.add_to(&mut m)?;
        m.write_header();
        //"GetFrom"
        {
            let mut decoded = Message::new();
            decoded.write(&m.raw)?;
            let mut port = EvenPort::default();
            port.get_from(&decoded)?;
            assert_eq!(port, p, "Decoded {port}, expected {p}");

            //"HandleErr"
            {
                let mut m = Message::new();
                let mut handle = EvenPort::default();
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        stun::Error::ErrAttributeNotFound,
                        err,
                        "{err} should be not found"
                    );
                }
                m.add(ATTR_EVEN_PORT, &[1, 2, 3]);
                if let Err(err) = handle.get_from(&m) {
                    assert!(
                        is_attr_size_invalid(&err),
                        "IsAttrSizeInvalid should be true"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
            }
        }

        Ok(())
    }
}
