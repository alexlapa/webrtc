use std::sync::{atomic::Ordering, Arc};

use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};

use super::*;
use crate::proto::channum::*;

/// `ChannelBind` represents a TURN Channel.
///
/// https://tools.ietf.org/html/rfc5766#section-2.5.
#[derive(Clone)]
pub struct ChannelBind {
    pub(crate) peer: SocketAddr,
    pub(crate) number: ChannelNumber,
    pub(crate) channel_bindings: Option<Arc<Mutex<HashMap<ChannelNumber, ChannelBind>>>>,
    reset_tx: Option<mpsc::Sender<Duration>>,
    timer_expired: Arc<AtomicBool>,
}

impl ChannelBind {
    /// Creates a new [`ChannelBind`]
    pub fn new(number: ChannelNumber, peer: SocketAddr) -> Self {
        ChannelBind {
            number,
            peer,
            channel_bindings: None,
            reset_tx: None,
            timer_expired: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) async fn start(&mut self, lifetime: Duration) {
        let (reset_tx, mut reset_rx) = mpsc::channel(1);
        self.reset_tx = Some(reset_tx);

        let channel_bindings = self.channel_bindings.clone();
        let number = self.number;
        let timer_expired = Arc::clone(&self.timer_expired);

        tokio::spawn(async move {
            let timer = tokio::time::sleep(lifetime);
            tokio::pin!(timer);
            let mut done = false;

            while !done {
                tokio::select! {
                    _ = &mut timer => {
                        if let Some(cbs) = &channel_bindings{
                            let mut cb = cbs.lock().await;
                            if cb.remove(&number).is_none() {
                                log::error!("Failed to remove ChannelBind for {}", number);
                            }
                        }
                        done = true;
                    },
                    result = reset_rx.recv() => {
                        if let Some(d) = result {
                            timer.as_mut().reset(Instant::now() + d);
                        } else {
                            done = true;
                        }
                    },
                }
            }

            timer_expired.store(true, Ordering::SeqCst);
        });
    }

    pub(crate) fn stop(&mut self) -> bool {
        let expired = self.reset_tx.is_none() || self.timer_expired.load(Ordering::SeqCst);
        self.reset_tx.take();
        expired
    }

    pub(crate) async fn refresh(&self, lifetime: Duration) {
        if let Some(tx) = &self.reset_tx {
            let _ = tx.send(lifetime).await;
        }
    }
}

#[cfg(test)]
mod channel_bind_test {
    use std::net::Ipv4Addr;

    use crate::stun::{attrs::ATTR_USERNAME, textattrs::TextAttribute};
    use tokio::net::UdpSocket;

    use super::*;

    async fn create_channel_bind(lifetime: Duration) -> Result<Allocation, Error> {
        let turn_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let relay_socket = Arc::clone(&turn_socket);
        let relay_addr = relay_socket.local_addr()?;
        let a = Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            FiveTuple::default(),
            TextAttribute::new(ATTR_USERNAME, "user".into()),
            None,
        );

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);
        let c = ChannelBind::new(ChannelNumber(MIN_CHANNEL_NUMBER), addr);

        a.add_channel_bind(c, lifetime).await?;

        Ok(a)
    }

    #[tokio::test]
    async fn test_channel_bind() {
        let a = create_channel_bind(Duration::from_millis(20))
            .await
            .unwrap();

        let result = a.get_channel_addr(&ChannelNumber(MIN_CHANNEL_NUMBER)).await;
        if let Some(addr) = result {
            assert_eq!(addr.ip().to_string(), "0.0.0.0");
        } else {
            panic!("expected some, but got none");
        }
    }
}
