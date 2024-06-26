use std::{fmt, time::Duration};

use crate::stun::{self, attrs::*, checks::*, msg::*};

/// `DEFAULT_LIFETIME` in RFC 5766 is 10 minutes.
///
/// [RFC 5766 Section 2.2](https://www.rfc-editor.org/rfc/rfc5766#section-2.2).
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// `Lifetime` represents `LIFETIME` attribute.
///
/// The `LIFETIME` attribute represents the duration for which the server
/// will maintain an allocation in the absence of a refresh. The value
/// portion of this attribute is 4-bytes long and consists of a 32-bit
/// unsigned integral value representing the number of seconds remaining
/// until expiration.
///
/// [RFC 5766 Section 14.2](https://www.rfc-editor.org/rfc/rfc5766#section-14.2).
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Lifetime(pub Duration);

impl fmt::Display for Lifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

// uint32 seconds
const LIFETIME_SIZE: usize = 4; // 4 bytes, 32 bits

impl Setter for Lifetime {
    /// Adds `LIFETIME` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let mut v = vec![0; LIFETIME_SIZE];
        v.copy_from_slice(&(self.0.as_secs() as u32).to_be_bytes());
        m.add(ATTR_LIFETIME, &v);
        Ok(())
    }
}

impl Getter for Lifetime {
    /// Decodes `LIFETIME` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let v = m.get(ATTR_LIFETIME)?;

        check_size(ATTR_LIFETIME, v.len(), LIFETIME_SIZE)?;

        let seconds = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        self.0 = Duration::from_secs(seconds as u64);

        Ok(())
    }
}

#[cfg(test)]
mod lifetime_test {
    use super::*;

    #[test]
    fn test_lifetime_string() -> Result<(), stun::Error> {
        let l = Lifetime(Duration::from_secs(10));
        assert_eq!(l.to_string(), "10s", "bad string {l}, expected 10s");

        Ok(())
    }

    #[test]
    fn test_lifetime_add_to() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let l = Lifetime(Duration::from_secs(10));
        l.add_to(&mut m)?;
        m.write_header();

        //"GetFrom"
        {
            let mut decoded = Message::new();
            decoded.write(&m.raw)?;

            let mut life = Lifetime::default();
            life.get_from(&decoded)?;
            assert_eq!(life, l, "Decoded {life}, expected {l}");

            //"HandleErr"
            {
                let mut m = Message::new();
                let mut n_handle = Lifetime::default();
                if let Err(err) = n_handle.get_from(&m) {
                    assert_eq!(
                        stun::Error::ErrAttributeNotFound,
                        err,
                        "{err} should be not found"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
                m.add(ATTR_LIFETIME, &[1, 2, 3]);

                if let Err(err) = n_handle.get_from(&m) {
                    assert_eq!(
                        err,
                        stun::Error::ErrAttributeSizeInvalid,
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
