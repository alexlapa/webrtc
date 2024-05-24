pub mod conn_udp;

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::net::ToSocketAddrs;

use crate::util::error::Result;

#[async_trait]
pub trait Conn {
    async fn connect(&self, addr: SocketAddr) -> Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn send(&self, buf: &[u8]) -> Result<usize>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn remote_addr(&self) -> Option<SocketAddr>;
    async fn close(&self) -> Result<()>;
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync);
}

/// A Listener is a generic network listener for connection-oriented protocols.
/// Multiple connections may invoke methods on a Listener simultaneously.
#[async_trait]
pub trait Listener {
    /// accept waits for and returns the next connection to the listener.
    async fn accept(&self) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr)>;

    /// close closes the listener.
    /// Any blocked accept operations will be unblocked and return errors.
    async fn close(&self) -> Result<()>;

    /// addr returns the listener's network address.
    async fn addr(&self) -> Result<SocketAddr>;
}

pub async fn lookup_host<T>(use_ipv4: bool, host: T) -> Result<SocketAddr>
where
    T: ToSocketAddrs,
{
    for remote_addr in tokio::net::lookup_host(host).await? {
        if (use_ipv4 && remote_addr.is_ipv4()) || (!use_ipv4 && remote_addr.is_ipv6()) {
            return Ok(remote_addr);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!(
            "No available {} IP address found!",
            if use_ipv4 { "ipv4" } else { "ipv6" },
        ),
    )
    .into())
}

#[cfg(test)]
mod conn_test {
    use super::*;

    #[tokio::test]
    async fn test_conn_lookup_host() -> Result<()> {
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

        Ok(())
    }
}
