use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, ToSocketAddrs, UdpSocket},
    sync::{mpsc, Mutex},
};

use crate::{
    con::{Conn, Error},
    proto::{Protocol, PROTO_TCP},
    stun::attrs::nearest_padded_value_length,
};

pub struct TcpServer {
    ingress_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local_addr: SocketAddr,
    writers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}

#[async_trait]
impl Conn for TcpServer {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let (data, addr) = self.ingress_rx.lock().await.recv().await.unwrap();
        let len = data.len();
        buf[0..len].copy_from_slice(data.as_slice());

        Ok((len, addr))
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, Error> {
        let mut writers = self.writers.lock().await;
        let vals: Vec<_> = writers.keys().cloned().collect();
        match writers.entry(target) {
            Entry::Occupied(mut e) => {
                if e.get_mut().send(buf.to_vec()).await.is_err() {
                    // Underlying TCP stream is dead.
                    _ = e.remove_entry();
                    // TODO: return error
                }
            }
            Entry::Vacant(_) => {
                // TODO: return error
            }
        }

        Ok(buf.len())
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
                    match listener.accept().await {
                        Ok((mut stream, remote)) => {
                            let ingress_tx = ingress_tx.clone();
                            let writers = Arc::clone(&writers);
                            tokio::spawn(async move {
                                let (mut reader, mut writer) = stream.split();
                                let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(256);
                                writers.lock().await.insert(remote, egress_tx);

                                let mut buf = Vec::new();
                                let mut full_size = None;

                                loop {
                                    tokio::select! {
                                        msg = egress_rx.recv() => {
                                            if let Some(msg) = msg {
                                                writer.write_all(msg.as_slice())
                                                .await.unwrap();
                                            } else {
                                                println!("Exit TCP loop 000 \
                                                {remote}");
                                                return;
                                            }
                                        },
                                        b = reader.read_u8() => {
                                            let b = match b {
                                                Ok(b) => b,
                                                Err(e) => {
                                                  println!("Exit TCP loop 111 \
                                                 {remote} {e:?}");
                                                  return;
                                                }
                                            };
                                            buf.push(b);

                                            if buf.len() == 4 {
                                                let size = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                                // First two bits are 0 for STUN
                                                // methods.
                                                if buf[0] & 0b1100_0000 == 0 {
                                                    full_size = Some
                                                    (nearest_padded_value_length(size + 20));
                                                } else {
                                                    full_size = Some
                                                    (nearest_padded_value_length(size + 4));
                                                }
                                                // println!("full_size {full_size:?}");
                                            }
                                            if Some(buf.len()) == full_size {
                                                let pkt =
                                                    std::mem::replace(&mut
                                                    buf, Vec::new());
                                                ingress_tx.try_send((pkt, remote)).unwrap()
                                            }
                                        },
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            println!("couldn't get client: {:?}", e)
                        }
                    }
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
