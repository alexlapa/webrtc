use std::{collections::HashMap, sync::Arc};

use rand::Rng;
use tokio::{sync::mpsc, time::Instant};

use crate::stun::{client::ClientTransaction, error::*, message::*};

/// Handler handles state changes of transaction.
/// Handler is called on transaction state change.
/// Usage of e is valid only during call, user must
/// copy needed fields explicitly.
pub type Handler = Option<Arc<mpsc::UnboundedSender<Event>>>;

/// noop_handler just discards any event.
pub fn noop_handler() -> Handler {
    None
}

/// Agent is low-level abstraction over transaction list that
/// handles concurrency (all calls are goroutine-safe) and
/// time outs (via Collect call).
pub struct Agent {
    /// transactions is map of transactions that are currently
    /// in progress. Event handling is done in such way when
    /// transaction is unregistered before AgentTransaction access,
    /// minimizing mux lock and protecting AgentTransaction from
    /// data races via unexpected concurrent access.
    transactions: HashMap<TransactionId, AgentTransaction>,
    /// all calls are invalid if true
    closed: bool,
    /// handles transactions
    handler: Handler,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Callback(TransactionId),
    Insert(ClientTransaction),
    Remove(TransactionId),
    Close,
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
    pub event_body: Result<Message>,
}

impl Default for Event {
    fn default() -> Self {
        Event {
            event_type: EventType::default(),
            event_body: Ok(Message::default()),
        }
    }
}

/// AgentTransaction represents transaction in progress.
/// Concurrent access is invalid.
pub(crate) struct AgentTransaction {
    id: TransactionId,
    deadline: Instant,
}

/// AGENT_COLLECT_CAP is initial capacity for Agent.Collect slices,
/// sufficient to make function zero-alloc in most cases.
const AGENT_COLLECT_CAP: usize = 100;

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
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.transaction_id = *self;
        m.write_transaction_id();
        Ok(())
    }
}

/// ClientAgent is Agent implementation that is used by Client to
/// process transactions.
#[derive(Debug)]
pub enum ClientAgent {
    Process(Message),
    Collect(Instant),
    Start(TransactionId, Instant),
    Stop(TransactionId),
    Close,
}

impl Agent {
    /// new initializes and returns new Agent with provided handler.
    pub fn new(handler: Handler) -> Self {
        Agent {
            transactions: HashMap::new(),
            closed: false,
            handler,
        }
    }

    /// stop_with_error removes transaction from list and calls handler with
    /// provided error. Can return ErrTransactionNotExists and ErrAgentClosed.
    pub fn stop_with_error(&mut self, id: TransactionId, error: Error) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        let v = self.transactions.remove(&id);
        if let Some(t) = v {
            if let Some(handler) = &self.handler {
                handler.send(Event {
                    event_type: EventType::Callback(t.id),
                    event_body: Err(error),
                })?;
            }
            Ok(())
        } else {
            Err(Error::ErrTransactionNotExists)
        }
    }

    /// process incoming message, synchronously passing it to handler.
    pub fn process(&mut self, message: Message) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        self.transactions.remove(&message.transaction_id);

        let e = Event {
            event_type: EventType::Callback(message.transaction_id),
            event_body: Ok(message),
        };

        if let Some(handler) = &self.handler {
            handler.send(e)?;
        }

        Ok(())
    }

    /// close terminates all transactions with ErrAgentClosed and renders Agent
    /// to closed state.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        for id in self.transactions.keys() {
            let e = Event {
                event_type: EventType::Callback(*id),
                event_body: Err(Error::ErrAgentClosed),
            };
            if let Some(handler) = &self.handler {
                handler.send(e)?;
            }
        }
        self.transactions = HashMap::new();
        self.closed = true;
        self.handler = noop_handler();

        Ok(())
    }

    /// start registers transaction with provided id and deadline.
    /// Could return ErrAgentClosed, ErrTransactionExists.
    ///
    /// Agent handler is guaranteed to be eventually called.
    pub fn start(&mut self, id: TransactionId, deadline: Instant) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }
        if self.transactions.contains_key(&id) {
            return Err(Error::ErrTransactionExists);
        }

        self.transactions
            .insert(id, AgentTransaction { id, deadline });

        Ok(())
    }

    /// stop stops transaction by id with ErrTransactionStopped, blocking
    /// until handler returns.
    pub fn stop(&mut self, id: TransactionId) -> Result<()> {
        self.stop_with_error(id, Error::ErrTransactionStopped)
    }

    /// collect terminates all transactions that have deadline before provided
    /// time, blocking until all handlers will process ErrTransactionTimeOut.
    /// Will return ErrAgentClosed if agent is already closed.
    ///
    /// It is safe to call Collect concurrently but makes no sense.
    pub fn collect(&mut self, deadline: Instant) -> Result<()> {
        if self.closed {
            // Doing nothing if agent is closed.
            // All transactions should be already closed
            // during Close() call.
            return Err(Error::ErrAgentClosed);
        }

        let mut to_remove: Vec<TransactionId> = Vec::with_capacity(AGENT_COLLECT_CAP);

        // Adding all transactions with deadline before gc_time
        // to toCall and to_remove slices.
        // No allocs if there are less than AGENT_COLLECT_CAP
        // timed out transactions.
        for (id, t) in &self.transactions {
            if t.deadline < deadline {
                to_remove.push(*id);
            }
        }
        // Un-registering timed out transactions.
        for id in &to_remove {
            self.transactions.remove(id);
        }

        for id in to_remove {
            let event = Event {
                event_type: EventType::Callback(id),
                event_body: Err(Error::ErrTransactionTimeOut),
            };
            if let Some(handler) = &self.handler {
                handler.send(event)?;
            }
        }

        Ok(())
    }

    /// set_handler sets agent handler to h.
    pub fn set_handler(&mut self, h: Handler) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }
        self.handler = h;

        Ok(())
    }

    pub(crate) async fn run(mut agent: Agent, mut rx: mpsc::Receiver<ClientAgent>) {
        while let Some(client_agent) = rx.recv().await {
            let result = match client_agent {
                ClientAgent::Process(message) => agent.process(message),
                ClientAgent::Collect(deadline) => agent.collect(deadline),
                ClientAgent::Start(tid, deadline) => agent.start(tid, deadline),
                ClientAgent::Stop(tid) => agent.stop(tid),
                ClientAgent::Close => agent.close(),
            };

            if let Err(err) = result {
                if Error::ErrAgentClosed == err {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod agent_test {
    use std::ops::Add;

    use tokio::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_agent_process_in_transaction() -> Result<()> {
        let mut m = Message::new();
        let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = Agent::new(Some(Arc::new(handler_tx)));
        m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        a.start(m.transaction_id, Instant::now())?;
        a.process(m)?;
        a.close()?;

        while let Some(e) = handler_rx.recv().await {
            assert!(e.event_body.is_ok(), "got error: {:?}", e.event_body);

            let tid = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            assert_eq!(
                e.event_body.as_ref().unwrap().transaction_id,
                tid,
                "{:?} (got) != {:?} (expected)",
                e.event_body.as_ref().unwrap().transaction_id,
                tid
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_agent_process() -> Result<()> {
        let mut m = Message::new();
        let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = Agent::new(Some(Arc::new(handler_tx)));
        m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        a.process(m.clone())?;
        a.close()?;

        while let Some(e) = handler_rx.recv().await {
            assert!(e.event_body.is_ok(), "got error: {:?}", e.event_body);

            let tid = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            assert_eq!(
                e.event_body.as_ref().unwrap().transaction_id,
                tid,
                "{:?} (got) != {:?} (expected)",
                e.event_body.as_ref().unwrap().transaction_id,
                tid
            );
        }

        let result = a.process(m);
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrAgentClosed,
                "closed agent should return <{}>, but got <{}>",
                Error::ErrAgentClosed,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        Ok(())
    }

    #[test]
    fn test_agent_start() -> Result<()> {
        let mut a = Agent::new(noop_handler());
        let id = TransactionId::new();
        let deadline = Instant::now().add(Duration::from_secs(3600));
        a.start(id, deadline)?;

        let result = a.start(id, deadline);
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrTransactionExists,
                "duplicate start should return <{}>, got <{}>",
                Error::ErrTransactionExists,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }
        a.close()?;

        let id = TransactionId::new();
        let result = a.start(id, deadline);
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrAgentClosed,
                "start on closed agent should return <{}>, got <{}>",
                Error::ErrAgentClosed,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        let result = a.set_handler(noop_handler());
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrAgentClosed,
                "SetHandler on closed agent should return <{}>, got <{}>",
                Error::ErrAgentClosed,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_agent_stop() -> Result<()> {
        let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = Agent::new(Some(Arc::new(handler_tx)));

        let result = a.stop(TransactionId::default());
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrTransactionNotExists,
                "unexpected error: {}, should be {}",
                Error::ErrTransactionNotExists,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        let id = TransactionId::new();
        let deadline = Instant::now().add(Duration::from_millis(200));
        a.start(id, deadline)?;
        a.stop(id)?;

        let timeout = tokio::time::sleep(Duration::from_millis(400));
        tokio::pin!(timeout);

        tokio::select! {
            evt = handler_rx.recv() => {
                if let Err(err) = evt.unwrap().event_body{
                    assert_eq!(
                        err,
                        Error::ErrTransactionStopped,
                        "unexpected error: {}, should be {}",
                        err,
                        Error::ErrTransactionStopped
                    );
                }else{
                    panic!("expected error, got ok");
                }
            }
         _ = timeout.as_mut() => panic!("timed out"),
        }

        a.close()?;

        let result = a.close();
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrAgentClosed,
                "a.Close returned {} instead of {}",
                Error::ErrAgentClosed,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        let result = a.stop(TransactionId::default());
        if let Err(err) = result {
            assert_eq!(
                err,
                Error::ErrAgentClosed,
                "unexpected error: {}, should be {}",
                Error::ErrAgentClosed,
                err,
            );
        } else {
            panic!("expected error, but got ok");
        }

        Ok(())
    }
}
