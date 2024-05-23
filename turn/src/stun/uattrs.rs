use std::fmt;

use crate::stun::{attributes::*, error::*, message::*};

// UnknownAttributes represents UNKNOWN-ATTRIBUTES attribute.
//
// RFC 5389 Section 15.9
pub struct UnknownAttributes(pub Vec<AttrType>);

impl fmt::Display for UnknownAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "<nil>")
        } else {
            let mut s = vec![];
            for t in &self.0 {
                s.push(t.to_string());
            }
            write!(f, "{}", s.join(", "))
        }
    }
}

// type size is 16 bit.
const ATTR_TYPE_SIZE: usize = 2;

impl Setter for UnknownAttributes {
    // add_to adds UNKNOWN-ATTRIBUTES attribute to message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let mut v = Vec::with_capacity(ATTR_TYPE_SIZE * 20); // 20 should be enough

        // If len(a.Types) > 20, there will be allocations.
        for t in &self.0 {
            v.extend_from_slice(&t.value().to_be_bytes());
        }
        m.add(ATTR_UNKNOWN_ATTRIBUTES, &v);
        Ok(())
    }
}

impl Getter for UnknownAttributes {
    // GetFrom parses UNKNOWN-ATTRIBUTES from message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_UNKNOWN_ATTRIBUTES)?;
        if v.len() % ATTR_TYPE_SIZE != 0 {
            return Err(Error::ErrBadUnknownAttrsSize);
        }
        self.0.clear();
        let mut first = 0usize;
        while first < v.len() {
            let last = first + ATTR_TYPE_SIZE;
            self.0
                .push(AttrType(u16::from_be_bytes([v[first], v[first + 1]])));
            first = last;
        }
        Ok(())
    }
}

#[cfg(test)]
mod uattrs_test {
    use super::*;

    #[test]
    fn test_unknown_attributes() -> Result<()> {
        let mut m = Message::new();
        let a = UnknownAttributes(vec![ATTR_DONT_FRAGMENT, ATTR_CHANNEL_NUMBER]);
        assert_eq!(
            a.to_string(),
            "DONT-FRAGMENT, CHANNEL-NUMBER",
            "bad String:{a}"
        );
        assert_eq!(
            UnknownAttributes(vec![]).to_string(),
            "<nil>",
            "bad blank string"
        );

        a.add_to(&mut m)?;

        //"GetFrom"
        {
            let mut attrs = UnknownAttributes(Vec::with_capacity(10));
            attrs.get_from(&m)?;
            for i in 0..a.0.len() {
                assert_eq!(a.0[i], attrs.0[i], "expected {} != {}", a.0[i], attrs.0[i]);
            }
            let mut m_blank = Message::new();
            let result = attrs.get_from(&m_blank);
            assert!(result.is_err(), "should error");

            m_blank.add(ATTR_UNKNOWN_ATTRIBUTES, &[1, 2, 3]);
            let result = attrs.get_from(&m_blank);
            assert!(result.is_err(), "should error");
        }

        Ok(())
    }
}
