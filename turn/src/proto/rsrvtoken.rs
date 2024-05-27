use crate::stun::{self, attrs::*, checks::*, msg::*};

/// `ReservationToken` represents `RESERVATION-TOKEN` attribute.
///
/// The `RESERVATION-TOKEN` attribute contains a token that uniquely
/// identifies a relayed transport address being held in reserve by the
/// server. The server includes this attribute in a success response to
/// tell the client about the token, and the client includes this
/// attribute in a subsequent Allocate request to request the server use
/// that relayed transport address for the allocation.
///
/// [RFC 5766 Section 14.9](https://www.rfc-editor.org/rfc/rfc5766#section-14.9).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReservationToken(pub Vec<u8>);

const RESERVATION_TOKEN_SIZE: usize = 8; // 8 bytes

impl Setter for ReservationToken {
    /// Adds `RESERVATION-TOKEN` to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        check_size(ATTR_RESERVATION_TOKEN, self.0.len(), RESERVATION_TOKEN_SIZE)?;
        m.add(ATTR_RESERVATION_TOKEN, &self.0);
        Ok(())
    }
}

impl Getter for ReservationToken {
    /// Decodes `RESERVATION-TOKEN` from message.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let v = m.get(ATTR_RESERVATION_TOKEN)?;
        check_size(ATTR_RESERVATION_TOKEN, v.len(), RESERVATION_TOKEN_SIZE)?;
        self.0 = v;
        Ok(())
    }
}

#[cfg(test)]
mod rsrvtoken_test {
    use super::*;

    #[test]
    fn test_reservation_token() -> Result<(), stun::Error> {
        let mut m = Message::new();
        let mut v = vec![0; 8];
        v[2] = 33;
        v[7] = 1;
        let tk = ReservationToken(v);
        tk.add_to(&mut m)?;
        m.write_header();

        //"HandleErr"
        {
            let bad_tk = ReservationToken(vec![34, 45]);
            if let Err(err) = bad_tk.add_to(&mut m) {
                assert_eq!(
                    err,
                    stun::Error::ErrAttributeSizeInvalid,
                    "IsAttrSizeInvalid should be true"
                );
            } else {
                panic!("expected error, but got ok");
            }
        }

        //"GetFrom"
        {
            let mut decoded = Message::new();
            decoded.write(&m.raw)?;
            let mut tok = ReservationToken::default();
            tok.get_from(&decoded)?;
            assert_eq!(tok, tk, "Decoded {tok:?}, expected {tk:?}");

            //"HandleErr"
            {
                let mut m = Message::new();
                let mut handle = ReservationToken::default();
                if let Err(err) = handle.get_from(&m) {
                    assert_eq!(
                        stun::Error::ErrAttributeNotFound,
                        err,
                        "{err} should be not found"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
                m.add(ATTR_RESERVATION_TOKEN, &[1, 2, 3]);
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
