use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
};

use crate::proto::*;

/// `FiveTuple` is the combination (client IP address and port, server IP
/// address and port, and transport protocol (currently one of UDP,
/// TCP, or TLS)) used to communicate between the client and the
/// server.  The 5-tuple uniquely identifies this communication
/// stream.  The 5-tuple also uniquely identifies the Allocation on
/// the server.
#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct FiveTuple {
    pub protocol: Protocol,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

impl Default for FiveTuple {
    fn default() -> Self {
        FiveTuple {
            protocol: PROTO_UDP,
            src_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
            dst_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
        }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}_{}", self.protocol, self.src_addr, self.dst_addr)
    }
}

impl fmt::Debug for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FiveTuple")
            .field("protocol", &self.protocol)
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

#[cfg(test)]
mod five_tuple_test {
    use super::*;
    use crate::error::Result;

    #[test]
    fn test_five_tuple_protocol() -> Result<()> {
        let udp_expect = PROTO_UDP;
        let tcp_expect = PROTO_TCP;

        assert_eq!(
            udp_expect, PROTO_UDP,
            "Invalid UDP Protocol value, expect {udp_expect} but {PROTO_UDP}"
        );
        assert_eq!(
            tcp_expect, PROTO_TCP,
            "Invalid TCP Protocol value, expect {tcp_expect} but {PROTO_TCP}"
        );

        assert_eq!(udp_expect.to_string(), "UDP");
        assert_eq!(tcp_expect.to_string(), "TCP");

        Ok(())
    }

    #[test]
    fn test_five_tuple_equal() -> Result<()> {
        let src_addr1: SocketAddr = "0.0.0.0:3478".parse::<SocketAddr>()?;
        let src_addr2: SocketAddr = "0.0.0.0:3479".parse::<SocketAddr>()?;

        let dst_addr1: SocketAddr = "0.0.0.0:3480".parse::<SocketAddr>()?;
        let dst_addr2: SocketAddr = "0.0.0.0:3481".parse::<SocketAddr>()?;

        let tests = vec![
            (
                "Equal",
                true,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentProtocol",
                false,
                FiveTuple {
                    protocol: PROTO_TCP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentSrcAddr",
                false,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr2,
                    dst_addr: dst_addr1,
                },
            ),
            (
                "DifferentDstAddr",
                false,
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr1,
                },
                FiveTuple {
                    protocol: PROTO_UDP,
                    src_addr: src_addr1,
                    dst_addr: dst_addr2,
                },
            ),
        ];

        for (name, expect, a, b) in tests {
            let fact = a == b;
            assert_eq!(
                expect, fact,
                "{name}: {a}, {b} equal check should be {expect}, but {fact}"
            );
        }

        Ok(())
    }
}
