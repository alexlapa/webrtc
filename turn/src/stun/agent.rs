use rand::Rng;

use crate::stun::{self, msg::*};

#[derive(Debug, Clone)]
pub enum EventType {
    Callback(TransactionId),
}

impl Default for EventType {
    fn default() -> Self {
        EventType::Callback(TransactionId::default())
    }
}

/// Event is passed to Handler describing the transaction event.
/// Do not reuse outside Handler.
#[derive(Debug)] // Clone
pub struct Event {
    pub event_type: EventType,
    pub event_body: Result<Message, stun::Error>,
}

impl Default for Event {
    fn default() -> Self {
        Event {
            event_type: EventType::default(),
            event_body: Ok(Message::default()),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Default, Debug)]
pub struct TransactionId(pub [u8; TRANSACTION_ID_SIZE]);

impl TransactionId {
    /// new returns new random transaction ID using crypto/rand
    /// as source.
    pub fn new() -> Self {
        let mut b = TransactionId([0u8; TRANSACTION_ID_SIZE]);
        rand::thread_rng().fill(&mut b.0);
        b
    }
}

impl Setter for TransactionId {
    fn add_to(&self, m: &mut Message) -> Result<(), stun::Error> {
        m.transaction_id = *self;
        m.write_transaction_id();
        Ok(())
    }
}
