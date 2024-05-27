use std::fmt;

use crate::stun::{self, attrs::*, checks::*, msg::*};

// Values for RequestedAddressFamily as defined in RFC 6156 Section 4.1.1.
pub const REQUESTED_FAMILY_IPV4: RequestedAddressFamily = RequestedAddressFamily(0x01);
pub const REQUESTED_FAMILY_IPV6: RequestedAddressFamily = RequestedAddressFamily(0x02);

/// `RequestedAddressFamily` represents the `REQUESTED-ADDRESS-FAMILY` Attribute
/// as defined in [RFC 6156 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc6156#section-4.1.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RequestedAddressFamily(pub u8);

impl fmt::Display for RequestedAddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            REQUESTED_FAMILY_IPV4 => "IPv4",
            REQUESTED_FAMILY_IPV6 => "IPv6",
            _ => "unknown",
        };
        write!(f, "{s}")
    }
}

const REQUESTED_FAMILY_SIZE: usize = 4;

impl Setter for RequestedAddressFamily {
    /// Adds `REQUESTED-ADDRESS-FAMILY` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let mut v = vec![0; REQUESTED_FAMILY_SIZE];
        v[0] = self.0;
        // b[1:4] is RFFU = 0.
        // The RFFU field MUST be set to zero on transmission and MUST be
        // ignored on reception. It is reserved for future uses.
        m.add(ATTR_REQUESTED_ADDRESS_FAMILY, &v);
        Ok(())
    }
}

impl Getter for RequestedAddressFamily {
    /// Decodes `REQUESTED-ADDRESS-FAMILY` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let v = m.get(ATTR_REQUESTED_ADDRESS_FAMILY)?;
        check_size(
            ATTR_REQUESTED_ADDRESS_FAMILY,
            v.len(),
            REQUESTED_FAMILY_SIZE,
        )?;

        if v[0] != REQUESTED_FAMILY_IPV4.0 && v[0] != REQUESTED_FAMILY_IPV6.0 {
            return Err(stun::Error::Other("ErrInvalidRequestedFamilyValue".into()));
        }
        self.0 = v[0];
        Ok(())
    }
}

#[cfg(test)]
mod reqfamily_test {
    use super::*;

    #[test]
    fn test_requested_address_family_string() -> Result<(), stun::Error> {
        assert_eq!(
            REQUESTED_FAMILY_IPV4.to_string(),
            "IPv4",
            "bad string {}, expected {}",
            REQUESTED_FAMILY_IPV4,
            "IPv4"
        );

        assert_eq!(
            REQUESTED_FAMILY_IPV6.to_string(),
            "IPv6",
            "bad string {}, expected {}",
            REQUESTED_FAMILY_IPV6,
            "IPv6"
        );

        assert_eq!(
            RequestedAddressFamily(0x04).to_string(),
            "unknown",
            "should be unknown"
        );

        Ok(())
    }

    #[test]
    fn test_requested_address_family_add_to() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let r = REQUESTED_FAMILY_IPV4;
        r.add_to(&mut m)?;
        m.write_header();

        //"GetFrom"
        {
            let mut decoded = Message::new();
            decoded.write(&m.raw)?;
            let mut req = RequestedAddressFamily::default();
            req.get_from(&decoded)?;
            assert_eq!(req, r, "Decoded {req}, expected {r}");

            //"HandleErr"
            {
                let mut m = Message::new();
                let mut handle = RequestedAddressFamily::default();
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        stun::Error::ErrAttributeNotFound,
                        err,
                        "{err} should be not found"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
                m.add(ATTR_REQUESTED_ADDRESS_FAMILY, &[1, 2, 3]);
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        err,
                        stun::Error::ErrAttributeSizeInvalid,
                        "IsAttrSizeInvalid should be true"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
                m.reset();
                m.add(ATTR_REQUESTED_ADDRESS_FAMILY, &[5, 0, 0, 0]);
                assert!(
                    handle.get_from(&m).is_err(),
                    "should error on invalid value"
                );
            }
        }

        Ok(())
    }
}
