pub(crate) mod conn;
pub(crate) mod ifaces;

mod error;

pub use self::{conn::Conn, error::Error};

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicU64, Arc},
};

use crate::net;
use tokio::net::UdpSocket;

lazy_static::lazy_static! {
    pub static ref MAC_ADDR_COUNTER: AtomicU64 = AtomicU64::new(0xBEEFED910200);
}

// Net represents a local network stack equivalent to a set of layers from NIC
// up to the transport (UDP / TCP) layer.
pub struct Net;

impl Default for Net {
    fn default() -> Self {
        Self
    }
}

impl Net {
    pub async fn resolve_addr(
        &self,
        use_ipv4: bool,
        address: &str,
    ) -> Result<SocketAddr, net::Error> {
        conn::lookup_host(use_ipv4, address).await
    }

    pub async fn bind(&self, addr: SocketAddr) -> Result<Arc<dyn Conn + Send + Sync>, net::Error> {
        Ok(Arc::new(UdpSocket::bind(addr).await.unwrap()))
    }

    pub async fn dail(
        &self,
        use_ipv4: bool,
        remote_addr: &str,
    ) -> Result<Arc<dyn Conn + Send + Sync>, net::Error> {
        let any_ip = if use_ipv4 {
            Ipv4Addr::new(0, 0, 0, 0).into()
        } else {
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into()
        };
        let local_addr = SocketAddr::new(any_ip, 0);

        let conn = UdpSocket::bind(local_addr).await.unwrap();
        conn.connect(remote_addr).await.unwrap();

        Ok(Arc::new(conn))
    }
}

#[cfg(test)]
mod net_test {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_net_native_resolve_addr() {
        let nw = Net::default();
        let udp_addr = nw.resolve_addr(true, "localhost:1234").await.unwrap();
        assert_eq!(udp_addr.ip().to_string(), "127.0.0.1", "should match");
        assert_eq!(udp_addr.port(), 1234, "should match");

        let result = nw.resolve_addr(false, "127.0.0.1:1234").await;
        assert!(result.is_err(), "should not match");
    }

    #[tokio::test]
    async fn test_net_native_bind() {
        let nw = Net::default();
        let conn = nw
            .bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let laddr = conn.local_addr().unwrap();
        assert_eq!(
            laddr.ip().to_string(),
            "127.0.0.1",
            "local_addr ip should match 127.0.0.1"
        );
        log::debug!("laddr: {}", laddr);
    }

    #[tokio::test]
    async fn test_net_native_dail() {
        let nw = Net::default();
        let conn = nw.dail(true, "127.0.0.1:1234").await.unwrap();
        let laddr = conn.local_addr().unwrap();
        assert_eq!(
            laddr.ip().to_string(),
            "127.0.0.1",
            "local_addr should match 127.0.0.1"
        );
        assert_ne!(laddr.port(), 1234, "local_addr port should match 1234");
        log::debug!("laddr: {}", laddr);
    }

    #[tokio::test]
    async fn test_net_native_loopback() {
        let nw = Net::default();
        let conn = nw
            .bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let laddr = conn.local_addr().unwrap();

        let msg = "PING!";
        let n = conn.send_to(msg.as_bytes(), laddr).await.unwrap();
        assert_eq!(n, msg.len(), "should match msg size {}", msg.len());

        let mut buf = vec![0u8; 1000];
        let (n, raddr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, msg.len(), "should match msg size {}", msg.len());
        assert_eq!(&buf[..n], msg.as_bytes(), "should match msg content {msg}");
        assert_eq!(laddr, raddr, "should match addr {laddr}");
    }
}
