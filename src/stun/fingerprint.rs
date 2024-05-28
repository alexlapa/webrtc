use crate::stun;
use crc::{Crc, CRC_32_ISO_HDLC};

use crate::stun::{attrs::ATTR_FINGERPRINT, msg::*};

// FingerprintAttr represents FINGERPRINT attribute.
//
// RFC 5389 Section 15.5
pub struct FingerprintAttr;

// FINGERPRINT is shorthand for FingerprintAttr.
//
// Example:
//
//  m := New()
//  FINGERPRINT.add_to(m)
pub const FINGERPRINT: FingerprintAttr = FingerprintAttr {};

pub const FINGERPRINT_XOR_VALUE: u32 = 0x5354554e;
pub const FINGERPRINT_SIZE: usize = 4; // 32 bit

// FingerprintValue returns CRC-32 of b XOR-ed by 0x5354554e.
//
// The value of the attribute is computed as the CRC-32 of the STUN message
// up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
// the 32-bit value 0x5354554e (the XOR helps in cases where an
// application packet is also using CRC-32 in it).
pub fn fingerprint_value(b: &[u8]) -> u32 {
    let checksum = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(b);
    checksum ^ FINGERPRINT_XOR_VALUE // XOR
}

impl Setter for FingerprintAttr {
    // add_to adds fingerprint to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        let l = m.length;
        // length in header should include size of fingerprint attribute
        m.length += (FINGERPRINT_SIZE + ATTRIBUTE_HEADER_SIZE) as u32; // increasing length
        m.write_length(); // writing Length to Raw
        let val = fingerprint_value(&m.raw);
        let b = val.to_be_bytes();
        m.length = l;
        m.add(ATTR_FINGERPRINT, &b);
        Ok(())
    }
}

#[cfg(test)]
mod fingerprint_test {
    use super::*;
    use crate::stun::{attrs::ATTR_SOFTWARE, textattrs::TextAttribute, Error};

    impl FingerprintAttr {
        // Check reads fingerprint value from m and checks it, returning error if any.
        // Can return *AttrLengthErr, ErrAttributeNotFound, and *CRCMismatch.
        pub fn check(&self, m: &Message) -> Result<(), stun::Error> {
            let b = m.get(ATTR_FINGERPRINT)?;
            stun::checks::check_size(ATTR_FINGERPRINT, b.len(), FINGERPRINT_SIZE)?;
            let val = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let attr_start = m.raw.len() - (FINGERPRINT_SIZE + ATTRIBUTE_HEADER_SIZE);
            let expected = fingerprint_value(&m.raw[..attr_start]);
            if val == expected {
                Ok(())
            } else {
                Err(Error::ErrFingerprintMismatch)
            }
        }
    }

    #[test]
    fn fingerprint_uses_crc_32_iso_hdlc() {
        let mut m = Message::new();

        let a = TextAttribute {
            attr: ATTR_SOFTWARE,
            text: "software".to_owned(),
        };
        a.add_to(&mut m).unwrap();
        m.write_header();

        FINGERPRINT.add_to(&mut m).unwrap();
        m.write_header();

        #[rustfmt::skip]
        assert_eq!(&m.raw[0..m.raw.len()-8], b"\x00\x00\x00\x14\x21\x12\xA4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x22\x00\x08\x73\x6F\x66\x74\x77\x61\x72\x65");

        assert_eq!(m.raw[m.raw.len() - 4..], [0xe4, 0x4c, 0x33, 0xd9]);
    }

    #[test]
    fn test_fingerprint_check() {
        let mut m = Message::new();
        let a = TextAttribute {
            attr: ATTR_SOFTWARE,
            text: "software".to_owned(),
        };
        a.add_to(&mut m).unwrap();
        m.write_header();

        FINGERPRINT.add_to(&mut m).unwrap();
        m.write_header();
        FINGERPRINT.check(&m).unwrap();
        m.raw[3] += 1;

        let result = FINGERPRINT.check(&m);
        assert!(result.is_err(), "should error");
    }

    #[test]
    fn test_fingerprint_check_bad() {
        let mut m = Message::new();
        let a = TextAttribute {
            attr: ATTR_SOFTWARE,
            text: "software".to_owned(),
        };
        a.add_to(&mut m).unwrap();
        m.write_header();

        let result = FINGERPRINT.check(&m);
        assert!(result.is_err(), "should error");

        m.add(ATTR_FINGERPRINT, &[1, 2, 3]);

        let result = FINGERPRINT.check(&m);
        if let Err(err) = result {
            assert_eq!(
                err,
                stun::Error::ErrAttributeSizeInvalid,
                "IsAttrSizeInvalid should be true"
            );
        } else {
            panic!("Expected error, but got ok");
        }
    }
}
