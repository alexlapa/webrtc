use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::StreamExt;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, mpsc::error::TrySendError, oneshot, Mutex},
};
use tokio_util::codec::{Decoder, FramedRead};

use crate::{
    con::{Conn, Error},
    proto::{Protocol, PROTO_TCP},
    stun::attrs::nearest_padded_value_length,
};

pub struct TcpServer {
    ingress_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local_addr: SocketAddr,
    #[allow(clippy::type_complexity)]
    writers: Arc<
        Mutex<HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, oneshot::Sender<Result<usize, Error>>)>>>,
    >,
}

#[async_trait]
impl Conn for TcpServer {
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), Error> {
        if let Some((data, addr)) = self.ingress_rx.lock().await.recv().await {
            Ok((data, addr))
        } else {
            Err(Error::ErrTransportIsDead)
        }
    }

    async fn send_to(&self, data: Vec<u8>, target: SocketAddr) -> Result<usize, Error> {
        let mut writers = self.writers.lock().await;
        match writers.entry(target) {
            Entry::Occupied(mut e) => {
                let (res_tx, res_rx) = oneshot::channel();
                if e.get_mut().send((data, res_tx)).await.is_err() {
                    // Underlying TCP stream is dead.
                    _ = e.remove_entry();
                    Err(Error::ErrTransportIsDead)
                } else {
                    res_rx.await.map_err(|_| Error::ErrTransportIsDead)?
                }
            }
            Entry::Vacant(_) => Err(Error::ErrTransportIsDead),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn proto(&self) -> Protocol {
        PROTO_TCP
    }

    async fn close(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl TcpServer {
    pub fn new(listener: TcpListener) -> Self {
        let local_addr = listener.local_addr().unwrap();
        let (ingress_tx, ingress_rx) = mpsc::channel(256);
        let writers = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn({
            let writers = Arc::clone(&writers);
            async move {
                loop {
                    let Ok((mut stream, remote)) = listener.accept().await else {
                        log::debug!("Closing TCP listener at {local_addr}");
                        break;
                    };

                    let ingress_tx = ingress_tx.clone();
                    let writers = Arc::clone(&writers);
                    tokio::spawn(async move {
                        let (egress_tx, mut egress_rx) =
                            mpsc::channel::<(Vec<u8>, oneshot::Sender<Result<usize, Error>>)>(256);
                        writers.lock().await.insert(remote, egress_tx);

                        let (reader, mut writer) = stream.split();
                        let mut reader = FramedRead::new(reader, StunTcpCodec::default());
                        loop {
                            tokio::select! {
                                msg = egress_rx.recv() => {
                                    if let Some((msg, tx)) = msg {
                                        let len = msg.len();
                                        let res =
                                            writer.write_all(msg.as_slice()).await
                                                .map(|_| len)
                                                .map_err(Error::from);

                                        _ = tx.send(res);
                                    } else {
                                        log::debug!("Closing TCP {local_addr} <=> {remote}");

                                        break;
                                    }
                                },
                                msg = reader.next() => {
                                    match msg {
                                        Some(Ok(msg)) => {
                                            match ingress_tx.try_send((msg, remote)) {
                                                Ok(_) => {},
                                                Err(TrySendError::Full(_)) => {
                                                    log::debug!("Dropped ingress message from TCP \
                                                        {local_addr} <=> {remote}")
                                                }
                                                Err(TrySendError::Closed(_)) => {
                                                    log::debug!("Closing TCP \
                                                        {local_addr} <=> {remote}");

                                                    break;
                                                }
                                            }
                                        }
                                        Some(Err(_)) => {},
                                        None => {
                                            log::debug!("Closing TCP {local_addr} <=> {remote}");

                                            break;
                                        }
                                    }
                                },
                            }
                        }
                    });
                }
            }
        });

        Self {
            ingress_rx: Mutex::new(ingress_rx),
            local_addr,
            writers,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum StunMessageKind {
    // Header:
    //
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0 0|     STUN Message Type     |         Message Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Magic Cookie                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                     Transaction ID (96 bits)                  |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Method(usize),

    // Header:
    //
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         Channel Number        |            Length             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // /                       Application Data                        /
    // /                                                               /
    // |                                                               |
    // |                               +-------------------------------+
    // |                               |
    // +-------------------------------+
    ChannelData(usize),
}

impl StunMessageKind {
    fn detect_kind(first_4_bytes: &[u8; 4]) -> Self {
        let size = u16::from_be_bytes([first_4_bytes[2], first_4_bytes[3]]) as usize;

        // If the first two bits are zeroes, then this is a STUN method.
        if first_4_bytes[0] & 0b1100_0000 == 0 {
            Self::Method(nearest_padded_value_length(size + 20))
        } else {
            Self::ChannelData(nearest_padded_value_length(size + 4))
        }
    }

    fn length(&self) -> usize {
        *match self {
            StunMessageKind::Method(l) => l,
            StunMessageKind::ChannelData(l) => l,
        }
    }
}

#[derive(Default)]
struct StunTcpCodec {
    pending: Option<StunMessageKind>,
}

impl Decoder for StunTcpCodec {
    type Error = Error;
    type Item = Vec<u8>;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.pending.is_none() && buf.len() >= 4 {
            self.pending = Some(StunMessageKind::detect_kind(&[
                buf[0], buf[1], buf[2], buf[3],
            ]));
        }
        if let Some(pending) = self.pending {
            if buf.len() >= pending.length() {
                let pending = self.pending.take().unwrap();
                let msg = buf.split_to(pending.length()).to_vec();

                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
