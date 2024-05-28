use std::io;

use thiserror::Error;

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
    proto::{Protocol, PROTO_TCP, PROTO_UDP},
    stun::attrs::nearest_padded_value_length,
};

// Net represents a local network stack equivalent to a set of layers from NIC
// up to the transport (UDP / TCP) layer.
pub struct Net;

impl Default for Net {
    fn default() -> Self {
        Self
    }
}

impl Net {
    pub async fn bind(
        &self,
        addr: SocketAddr,
        protocol: Protocol,
    ) -> Result<Arc<dyn Conn + Send + Sync>, Error> {
        match protocol {
            PROTO_UDP => {
                println!("BIND UDP {addr}");
                Ok(Arc::new(UdpSocket::bind(addr).await?))
            }
            PROTO_TCP => {
                println!("BIND TCP {addr}");
                let tcp_conn = TcpListener::bind(addr).await?;
                Ok(Arc::new(TcpServer::new(tcp_conn)))
            }
            _ => Err(Error::ErrUnsupportedRelayProto),
        }
    }
}

#[async_trait]
pub trait Conn {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, Error>;
    fn local_addr(&self) -> SocketAddr;
    fn proto(&self) -> Protocol;
    async fn close(&self) -> Result<(), Error>;
}

pub async fn lookup_host<T>(use_ipv4: bool, host: T) -> Result<SocketAddr, Error>
where
    T: ToSocketAddrs,
{
    for remote_addr in tokio::net::lookup_host(host).await? {
        if (use_ipv4 && remote_addr.is_ipv4()) || (!use_ipv4 && remote_addr.is_ipv6()) {
            return Ok(remote_addr);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "No available {} IP address found!",
            if use_ipv4 { "ipv4" } else { "ipv6" },
        ),
    )
    .into())
}

pub struct TcpServer {
    ingress_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local_addr: SocketAddr,
    writers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}

#[async_trait]
impl Conn for UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let r = self.recv_from(buf).await?;

        // println!("recv_from UDP {:?}", buf[0..r.0].to_vec());

        Ok(r)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, Error> {
        // println!("send_to UDP {:?}", buf.to_vec());

        Ok(self.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr().unwrap()
    }

    fn proto(&self) -> Protocol {
        PROTO_UDP
    }

    async fn close(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[async_trait]
impl Conn for TcpServer {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let (data, addr) = self.ingress_rx.lock().await.recv().await.unwrap();
        let len = data.len();
        if len > 1500 {
            println!("{data:?}")
        }
        buf[0..len].copy_from_slice(data.as_slice());

        // println!("recv_from TCP {addr}: {data:?}");
        // println!("recv_from TCP {}", len);

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
                    println!("TCP send_to err 000 {}=>{target} {vals:?}", self.local_addr);
                    // TODO: return error
                }
            }
            Entry::Vacant(_) => {
                println!("TCP send_to err 111 {}=>{target} {vals:?}", self.local_addr);
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
                                println!(
                                    "new connection {} <=> {}",
                                    stream.local_addr().unwrap(),
                                    remote
                                );
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

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("Unsupported relay proto")]
    ErrUnsupportedRelayProto,

    #[error("Invalid mask")]
    ErrInvalidMask,

    #[error("{0}")]
    Io(#[source] IoError),

    #[error("{0}")]
    Std(#[source] StdError),
}

impl Error {
    pub fn from_std<T>(error: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error::Std(StdError(Box::new(error)))
    }

    pub fn downcast_ref<T: std::error::Error + 'static>(&self) -> Option<&T> {
        if let Error::Std(s) = self {
            return s.0.downcast_ref();
        }

        None
    }
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

/// An escape hatch to preserve stack traces when we don't know the error.
///
/// This crate exports some traits such as `Conn` and `Listener`. The trait
/// functions produce the local error `util::Error`. However when used in crates
/// higher up the stack, we are forced to handle errors that are local to that
/// crate. For example we use `Listener` the `dtls` crate and it needs to handle
/// `dtls::Error`.
///
/// By using `util::Error::from_std` we can preserve the underlying error (and
/// stack trace!).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StdError(pub Box<dyn std::error::Error + Send + Sync>);

impl PartialEq for StdError {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

#[cfg(test)]
mod conn_test {
    use super::*;

    #[tokio::test]
    async fn test_conn_lookup_host() {
        let stun_serv_addr = "stun1.l.google.com:19302";

        if let Ok(ipv4_addr) = lookup_host(true, stun_serv_addr).await {
            assert!(
                ipv4_addr.is_ipv4(),
                "expected ipv4 but got ipv6: {ipv4_addr}"
            );
        }

        if let Ok(ipv6_addr) = lookup_host(false, stun_serv_addr).await {
            assert!(
                ipv6_addr.is_ipv6(),
                "expected ipv6 but got ipv4: {ipv6_addr}"
            );
        }
    }
}

#[cfg(test)]
mod net_test {
    use crate::con;
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_net_native_resolve_addr() {
        let udp_addr = con::lookup_host(true, "localhost:1234").await.unwrap();
        assert_eq!(udp_addr.ip().to_string(), "127.0.0.1", "should match");
        assert_eq!(udp_addr.port(), 1234, "should match");

        let result = con::lookup_host(false, "127.0.0.1:1234").await;
        assert!(result.is_err(), "should not match");
    }

    #[tokio::test]
    async fn test_net_native_bind() {
        let nw = Net::default();
        let conn = nw
            .bind(SocketAddr::from_str("127.0.0.1:0").unwrap(), PROTO_UDP)
            .await
            .unwrap();
        let laddr = conn.local_addr();
        assert_eq!(
            laddr.ip().to_string(),
            "127.0.0.1",
            "local_addr ip should match 127.0.0.1"
        );
        log::debug!("laddr: {}", laddr);
    }
}
