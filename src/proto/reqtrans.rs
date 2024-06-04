use std::fmt;

use crate::stun::{self, attrs::*, checks::*, msg::*};

use super::*;

/// `RequestedTransport` represents `REQUESTED-TRANSPORT` attribute.
///
/// This attribute is used by the client to request a specific transport
/// protocol for the allocated transport address. RFC 5766 only allows the use
/// of codepoint 17 (User Datagram protocol).
///
/// [RFC 5766 Section 14.7](https://www.rfc-editor.org/rfc/rfc5766#section-14.7).
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RequestedTransport {
    pub protocol: Protocol,
}

impl fmt::Display for RequestedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol: {}", self.protocol)
    }
}

const REQUESTED_TRANSPORT_SIZE: usize = 4;

impl Setter for RequestedTransport {
    /// Adds `REQUESTED-TRANSPORT` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let mut v = vec![0; REQUESTED_TRANSPORT_SIZE];
        v[0] = self.protocol.0;
        // b[1:4] is RFFU = 0.
        // The RFFU field MUST be set to zero on transmission and MUST be
        // ignored on reception. It is reserved for future uses.
        m.add(ATTR_REQUESTED_TRANSPORT, &v);
        Ok(())
    }
}

impl Getter for RequestedTransport {
    /// Decodes `REQUESTED-TRANSPORT` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let v = m.get(ATTR_REQUESTED_TRANSPORT)?;

        check_size(ATTR_REQUESTED_TRANSPORT, v.len(), REQUESTED_TRANSPORT_SIZE)?;
        self.protocol = Protocol(v[0]);
        Ok(())
    }
}

#[cfg(test)]
mod reqtrans_test {
    use super::*;

    #[test]
    fn test_requested_transport_string() -> Result<(), stun::Error> {
        let mut r = RequestedTransport {
            protocol: PROTO_UDP,
        };
        assert_eq!(
            r.to_string(),
            "protocol: UDP",
            "bad string {}, expected {}",
            r,
            "protocol: UDP",
        );
        r.protocol = Protocol(254);
        if r.to_string() != "protocol: 254" {
            assert_eq!(
                r.to_string(),
                "protocol: UDP",
                "bad string {}, expected {}",
                r,
                "protocol: 254",
            );
        }

        Ok(())
    }

    #[test]
    fn test_requested_transport_add_to() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let r = RequestedTransport {
            protocol: PROTO_UDP,
        };
        r.add_to(&mut m)?;
        m.write_header();

        //"GetFrom"
        {
            let mut decoded = Message::new();
            decoded.write(&m.raw)?;
            let mut req = RequestedTransport {
                protocol: PROTO_UDP,
            };
            req.get_from(&decoded)?;
            assert_eq!(req, r, "Decoded {req}, expected {r}");

            //"HandleErr"
            {
                let mut m = Message::new();
                let mut handle = RequestedTransport::default();
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        stun::Error::ErrAttributeNotFound,
                        err,
                        "{err} should be not found"
                    );
                } else {
                    panic!("expected error, got ok");
                }

                m.add(ATTR_REQUESTED_TRANSPORT, &[1, 2, 3]);
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        err,
                        stun::Error::ErrAttributeSizeInvalid,
                        "IsAttrSizeInvalid should be true"
                    );
                } else {
                    panic!("expected error, got ok");
                }
            }
        }

        Ok(())
    }
}
