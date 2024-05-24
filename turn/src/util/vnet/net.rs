use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicU64, Arc},
};

use ipnet::IpNet;
use tokio::net::UdpSocket;

use super::interface::*;
use crate::util::{conn, error::*, ifaces, Conn};

lazy_static::lazy_static! {
    pub static ref MAC_ADDR_COUNTER: AtomicU64 = AtomicU64::new(0xBEEFED910200);
}

// Net represents a local network stack equivalent to a set of layers from NIC
// up to the transport (UDP / TCP) layer.
pub struct Net {
    ifs: Vec<Interface>,
}

impl Default for Net {
    fn default() -> Self {
        let interfaces = ifaces::ifaces().unwrap_or_else(|_| vec![]);

        let mut m: HashMap<String, Vec<IpNet>> = HashMap::new();
        for iface in interfaces {
            if let Some(addrs) = m.get_mut(&iface.name) {
                if let Some(addr) = iface.addr {
                    if let Ok(inet) = Interface::convert(addr, iface.mask) {
                        addrs.push(inet);
                    }
                }
            } else if let Some(addr) = iface.addr {
                if let Ok(inet) = Interface::convert(addr, iface.mask) {
                    m.insert(iface.name, vec![inet]);
                }
            }
        }

        let mut ifs = vec![];
        for (name, addrs) in m.into_iter() {
            ifs.push(Interface::new(name, addrs));
        }

        Self { ifs }
    }
}

impl Net {
    // Interfaces returns a list of the system's network interfaces.
    pub async fn get_interfaces(&self) -> Vec<Interface> {
        self.ifs.clone()
    }

    // InterfaceByName returns the interface specified by name.
    pub async fn get_interface(&self, ifc_name: &str) -> Option<Interface> {
        for ifc in &self.ifs {
            if ifc.name == ifc_name {
                return Some(ifc.clone());
            }
        }

        None
    }

    pub async fn resolve_addr(&self, use_ipv4: bool, address: &str) -> Result<SocketAddr> {
        conn::lookup_host(use_ipv4, address).await
    }

    pub async fn bind(&self, addr: SocketAddr) -> Result<Arc<dyn Conn + Send + Sync>> {
        Ok(Arc::new(UdpSocket::bind(addr).await?))
    }

    pub async fn dail(
        &self,
        use_ipv4: bool,
        remote_addr: &str,
    ) -> Result<Arc<dyn Conn + Send + Sync>> {
        let any_ip = if use_ipv4 {
            Ipv4Addr::new(0, 0, 0, 0).into()
        } else {
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into()
        };
        let local_addr = SocketAddr::new(any_ip, 0);

        let conn = UdpSocket::bind(local_addr).await?;
        conn.connect(remote_addr).await?;

        Ok(Arc::new(conn))
    }
}

#[cfg(test)]
mod net_test {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_net_native_interfaces() -> Result<()> {
        let nw = Net::new();

        let interfaces = nw.get_interfaces().await;
        log::debug!("interfaces: {:?}", interfaces);
        for ifc in interfaces {
            let addrs = ifc.addrs();
            for addr in addrs {
                log::debug!("{}", addr)
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_net_native_resolve_addr() -> Result<()> {
        let nw = Net::new();
        let udp_addr = nw.resolve_addr(true, "localhost:1234").await?;
        assert_eq!(udp_addr.ip().to_string(), "127.0.0.1", "should match");
        assert_eq!(udp_addr.port(), 1234, "should match");

        let result = nw.resolve_addr(false, "127.0.0.1:1234").await;
        assert!(result.is_err(), "should not match");

        Ok(())
    }

    #[tokio::test]
    async fn test_net_native_bind() -> Result<()> {
        let nw = Net::new();
        let conn = nw.bind(SocketAddr::from_str("127.0.0.1:0")?).await?;
        let laddr = conn.local_addr()?;
        assert_eq!(
            laddr.ip().to_string(),
            "127.0.0.1",
            "local_addr ip should match 127.0.0.1"
        );
        log::debug!("laddr: {}", laddr);

        Ok(())
    }

    #[tokio::test]
    async fn test_net_native_dail() -> Result<()> {
        let nw = Net::new();
        let conn = nw.dail(true, "127.0.0.1:1234").await?;
        let laddr = conn.local_addr()?;
        assert_eq!(
            laddr.ip().to_string(),
            "127.0.0.1",
            "local_addr should match 127.0.0.1"
        );
        assert_ne!(laddr.port(), 1234, "local_addr port should match 1234");
        log::debug!("laddr: {}", laddr);

        Ok(())
    }

    #[tokio::test]
    async fn test_net_native_loopback() -> Result<()> {
        let nw = Net::new();
        let conn = nw.bind(SocketAddr::from_str("127.0.0.1:0")?).await?;
        let laddr = conn.local_addr()?;

        let msg = "PING!";
        let n = conn.send_to(msg.as_bytes(), laddr).await?;
        assert_eq!(n, msg.len(), "should match msg size {}", msg.len());

        let mut buf = vec![0u8; 1000];
        let (n, raddr) = conn.recv_from(&mut buf).await?;
        assert_eq!(n, msg.len(), "should match msg size {}", msg.len());
        assert_eq!(&buf[..n], msg.as_bytes(), "should match msg content {msg}");
        assert_eq!(laddr, raddr, "should match addr {laddr}");

        Ok(())
    }

    #[tokio::test]
    async fn test_net_native_unexpected_operations() -> Result<()> {
        let mut lo_name = String::new();
        let ifcs = ifaces::ifaces()?;
        for ifc in &ifcs {
            if let Some(addr) = ifc.addr {
                if addr.ip().is_loopback() {
                    lo_name.clone_from(&ifc.name);
                    break;
                }
            }
        }

        let nw = Net::new();

        if !lo_name.is_empty() {
            if let Some(ifc) = nw.get_interface(&lo_name).await {
                assert_eq!(ifc.name, lo_name, "should match ifc name");
            } else {
                panic!("should succeed");
            }
        }

        let result = nw.get_interface("foo0").await;
        assert!(result.is_none(), "should be none");

        Ok(())
    }
}
