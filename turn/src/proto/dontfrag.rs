use crate::stun::{self, attributes::*, message::*};

/// `DontFragmentAttr` represents `DONT-FRAGMENT` attribute.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DontFragmentAttr;

impl Setter for DontFragmentAttr {
    /// Adds `DONT-FRAGMENT` attribute to message.
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        m.add(ATTR_DONT_FRAGMENT, &[]);
        Ok(())
    }
}

impl Getter for DontFragmentAttr {
    /// Returns true if `DONT-FRAGMENT` attribute is set.
    fn get_from(&mut self, m: &Message) -> Result<(), stun::Error> {
        let _ = m.get(ATTR_DONT_FRAGMENT)?;
        Ok(())
    }
}

#[cfg(test)]
mod dontfrag_test {
    use super::*;

    #[test]
    fn test_dont_fragment_false() -> Result<(), stun::Error> {
        let mut dont_fragment = DontFragmentAttr;

        let mut m = Message::new();
        m.write_header();
        assert!(dont_fragment.get_from(&m).is_err(), "should not be set");

        Ok(())
    }

    #[test]
    fn test_dont_fragment_add_to() -> Result<(), stun::Error> {
        let mut dont_fragment = DontFragmentAttr;

        let mut m = Message::new();
        dont_fragment.add_to(&mut m)?;
        m.write_header();

        let mut decoded = Message::new();
        decoded.write(&m.raw)?;
        assert!(dont_fragment.get_from(&m).is_ok(), "should be set");

        Ok(())
    }
}
