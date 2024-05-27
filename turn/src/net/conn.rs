use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::{TcpListener, ToSocketAddrs, UdpSocket};

use crate::net;

#[async_trait]
pub trait Conn {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, net::Error>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), net::Error>;
    async fn send(&self, buf: &[u8]) -> Result<usize, net::Error>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, net::Error>;
    fn local_addr(&self) -> Result<SocketAddr, net::Error>;
    fn remote_addr(&self) -> Option<SocketAddr>;
    async fn close(&self) -> Result<(), net::Error>;
}

pub async fn lookup_host<T>(use_ipv4: bool, host: T) -> Result<SocketAddr, net::Error>
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

#[async_trait]
impl Conn for UdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, net::Error> {
        Ok(self.recv(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), net::Error> {
        Ok(self.recv_from(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, net::Error> {
        Ok(self.send(buf).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, net::Error> {
        Ok(self.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr, net::Error> {
        Ok(self.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> Result<(), net::Error> {
        Ok(())
    }
}

#[async_trait]
impl Conn for TcpListener {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, net::Error> {
        // self.
        Ok(self.recv(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), net::Error> {
        Ok(self.recv_from(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, net::Error> {
        Ok(self.send(buf).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, net::Error> {
        Ok(self.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr, net::Error> {
        Ok(self.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> Result<(), net::Error> {
        Ok(())
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
