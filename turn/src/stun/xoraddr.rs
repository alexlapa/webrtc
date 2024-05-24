use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::stun::{addr::*, attributes::*, checks::*, error::*, message::*};

fn safe_xor_bytes(dst: &mut [u8], a: &[u8], b: &[u8]) -> usize {
    let mut n = a.len();
    if b.len() < n {
        n = b.len();
    }
    if dst.len() < n {
        n = dst.len();
    }
    for i in 0..n {
        dst[i] = a[i] ^ b[i];
    }
    n
}

/// xor_bytes xors the bytes in a and b. The destination is assumed to have
/// enough space. Returns the number of bytes xor'd.
pub fn xor_bytes(dst: &mut [u8], a: &[u8], b: &[u8]) -> usize {
    // TODO: if supportsUnaligned {
    // 	return fastXORBytes(dst, a, b)
    //}
    safe_xor_bytes(dst, a, b)
}

/// XORMappedAddress implements XOR-MAPPED-ADDRESS attribute.
///
/// RFC 5389 Section 15.2
pub struct XorMappedAddress {
    pub ip: IpAddr,
    pub port: u16,
}

impl Default for XorMappedAddress {
    fn default() -> Self {
        XorMappedAddress {
            ip: IpAddr::V4(Ipv4Addr::from(0)),
            port: 0,
        }
    }
}

impl fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };
        if family == FAMILY_IPV4 {
            write!(f, "{}:{}", self.ip, self.port)
        } else {
            write!(f, "[{}]:{}", self.ip, self.port)
        }
    }
}

impl Setter for XorMappedAddress {
    /// add_to adds XOR-MAPPED-ADDRESS to m. Can return ErrBadIPLength
    /// if len(a.IP) is invalid.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        self.add_to_as(m, ATTR_XORMAPPED_ADDRESS)
    }
}

impl Getter for XorMappedAddress {
    /// get_from decodes XOR-MAPPED-ADDRESS attribute in message and returns
    /// error if any. While decoding, a.IP is reused if possible and can be
    /// rendered to invalid state (e.g. if a.IP was set to IPv6 and then
    /// IPv4 value were decoded into it), be careful.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        self.get_from_as(m, ATTR_XORMAPPED_ADDRESS)
    }
}

impl XorMappedAddress {
    /// add_to_as adds XOR-MAPPED-ADDRESS value to m as t attribute.
    pub fn add_to_as(&self, m: &mut Message, t: AttrType) -> Result<()> {
        let (family, ip_len, ip) = match self.ip {
            IpAddr::V4(ipv4) => (FAMILY_IPV4, IPV4LEN, ipv4.octets().to_vec()),
            IpAddr::V6(ipv6) => (FAMILY_IPV6, IPV6LEN, ipv6.octets().to_vec()),
        };

        let mut value = [0; 32 + 128];
        // value[0] = 0 // first 8 bits are zeroes
        let mut xor_value = vec![0; IPV6LEN];
        xor_value[4..].copy_from_slice(&m.transaction_id.0);
        xor_value[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        value[0..2].copy_from_slice(&family.to_be_bytes());
        value[2..4].copy_from_slice(&(self.port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        xor_bytes(&mut value[4..4 + ip_len], &ip, &xor_value);
        m.add(t, &value[..4 + ip_len]);
        Ok(())
    }

    /// get_from_as decodes XOR-MAPPED-ADDRESS attribute value in message
    /// getting it as for t type.
    pub fn get_from_as(&mut self, m: &Message, t: AttrType) -> Result<()> {
        let v = m.get(t)?;
        if v.len() <= 4 {
            return Err(Error::ErrUnexpectedEof);
        }

        let family = u16::from_be_bytes([v[0], v[1]]);
        if family != FAMILY_IPV6 && family != FAMILY_IPV4 {
            return Err(Error::Other(format!("bad value {family}")));
        }

        check_overflow(
            t,
            v[4..].len(),
            if family == FAMILY_IPV4 {
                IPV4LEN
            } else {
                IPV6LEN
            },
        )?;
        self.port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
        let mut xor_value = vec![0; 4 + TRANSACTION_ID_SIZE];
        xor_value[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        xor_value[4..].copy_from_slice(&m.transaction_id.0);

        if family == FAMILY_IPV6 {
            let mut ip = [0; IPV6LEN];
            xor_bytes(&mut ip, &v[4..], &xor_value);
            self.ip = IpAddr::V6(Ipv6Addr::from(ip));
        } else {
            let mut ip = [0; IPV4LEN];
            xor_bytes(&mut ip, &v[4..], &xor_value);
            self.ip = IpAddr::V4(Ipv4Addr::from(ip));
        };

        Ok(())
    }
}

#[cfg(test)]
mod xoraddr_test {
    use std::io::BufReader;

    use base64::{prelude::BASE64_STANDARD, Engine};

    use super::*;

    #[test]
    fn test_xor_safe() -> Result<()> {
        let mut dst = vec![0; 8];
        let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let b = vec![8, 7, 7, 6, 6, 3, 4, 1];
        safe_xor_bytes(&mut dst, &a, &b);
        let c = dst.clone();
        safe_xor_bytes(&mut dst, &c, &a);
        for i in 0..dst.len() {
            assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
        }

        Ok(())
    }

    #[test]
    fn test_xor_safe_bsmaller() -> Result<()> {
        let mut dst = vec![0; 5];
        let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let b = vec![8, 7, 7, 6, 6];
        safe_xor_bytes(&mut dst, &a, &b);
        let c = dst.clone();
        safe_xor_bytes(&mut dst, &c, &a);
        for i in 0..dst.len() {
            assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
        }

        Ok(())
    }

    #[test]
    fn test_xormapped_address_get_from() -> Result<()> {
        let mut m = Message::new();
        let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
        m.transaction_id.0.copy_from_slice(&transaction_id);
        let addr_value = vec![0x00, 0x01, 0x9c, 0xd5, 0xf4, 0x9f, 0x38, 0xae];
        m.add(ATTR_XORMAPPED_ADDRESS, &addr_value);
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        addr.get_from(&m)?;
        assert_eq!(
            addr.ip.to_string(),
            "213.141.156.236",
            "bad IP {} != 213.141.156.236",
            addr.ip
        );
        assert_eq!(addr.port, 48583, "bad Port {} != 48583", addr.port);

        //"UnexpectedEOF"
        {
            let mut m = Message::new();
            // {0, 1} is correct addr family.
            m.add(ATTR_XORMAPPED_ADDRESS, &[0, 1, 3, 4]);
            let mut addr = XorMappedAddress {
                ip: "0.0.0.0".parse().unwrap(),
                port: 0,
            };
            let result = addr.get_from(&m);
            if let Err(err) = result {
                assert_eq!(
                    Error::ErrUnexpectedEof,
                    err,
                    "len(v) = 4 should render <{}> error, got <{}>",
                    Error::ErrUnexpectedEof,
                    err
                );
            } else {
                panic!("expected error, got ok");
            }
        }
        //"AttrOverflowErr"
        {
            let mut m = Message::new();
            // {0, 1} is correct addr family.
            m.add(
                ATTR_XORMAPPED_ADDRESS,
                &[0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4],
            );
            let mut addr = XorMappedAddress {
                ip: "0.0.0.0".parse().unwrap(),
                port: 0,
            };
            let result = addr.get_from(&m);
            if let Err(err) = result {
                assert!(
                    is_attr_size_overflow(&err),
                    "AddTo should return AttrOverflowErr, got: {err}"
                );
            } else {
                panic!("expected error, got ok");
            }
        }

        Ok(())
    }

    #[test]
    fn test_xormapped_address_get_from_invalid() -> Result<()> {
        let mut m = Message::new();
        let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
        m.transaction_id.0.copy_from_slice(&transaction_id);
        let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
        let expected_port = 21254u16;
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        let result = addr.get_from(&m);
        assert!(result.is_err(), "should be error");

        addr.ip = expected_ip;
        addr.port = expected_port;
        addr.add_to(&mut m)?;
        m.write_header();

        let mut m_res = Message::new();
        m.raw[20 + 4 + 1] = 0x21;
        m.decode()?;
        let mut reader = BufReader::new(m.raw.as_slice());
        m_res.read_from(&mut reader)?;
        let result = addr.get_from(&m);
        assert!(result.is_err(), "should be error");

        Ok(())
    }

    #[test]
    fn test_xormapped_address_add_to() -> Result<()> {
        let mut m = Message::new();
        let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
        m.transaction_id.0.copy_from_slice(&transaction_id);
        let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
        let expected_port = 21254u16;
        let mut addr = XorMappedAddress {
            ip: "213.141.156.236".parse().unwrap(),
            port: expected_port,
        };
        addr.add_to(&mut m)?;
        m.write_header();

        let mut m_res = Message::new();
        m_res.write(&m.raw)?;
        addr.get_from(&m_res)?;
        assert_eq!(
            addr.ip, expected_ip,
            "{} (got) != {} (expected)",
            addr.ip, expected_ip
        );

        assert_eq!(
            addr.port, expected_port,
            "bad Port {} != {}",
            addr.port, expected_port
        );

        Ok(())
    }

    #[test]
    fn test_xormapped_address_add_to_ipv6() -> Result<()> {
        let mut m = Message::new();
        let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
        m.transaction_id.0.copy_from_slice(&transaction_id);
        let expected_ip: IpAddr = "fe80::dc2b:44ff:fe20:6009".parse().unwrap();
        let expected_port = 21254u16;
        let addr = XorMappedAddress {
            ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
            port: 21254,
        };
        addr.add_to(&mut m)?;
        m.write_header();

        let mut m_res = Message::new();
        let mut reader = BufReader::new(m.raw.as_slice());
        m_res.read_from(&mut reader)?;

        let mut got_addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        got_addr.get_from(&m)?;

        assert_eq!(
            got_addr.ip, expected_ip,
            "bad IP {} != {}",
            got_addr.ip, expected_ip
        );
        assert_eq!(
            got_addr.port, expected_port,
            "bad Port {} != {}",
            got_addr.port, expected_port
        );

        Ok(())
    }

    #[test]
    fn test_xormapped_address_string() -> Result<()> {
        let tests = vec![
            (
                // 0
                XorMappedAddress {
                    ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
                    port: 124,
                },
                "[fe80::dc2b:44ff:fe20:6009]:124",
            ),
            (
                // 1
                XorMappedAddress {
                    ip: "213.141.156.236".parse().unwrap(),
                    port: 8147,
                },
                "213.141.156.236:8147",
            ),
        ];

        for (addr, ip) in tests {
            assert_eq!(
                addr.to_string(),
                ip,
                " XORMappesAddress.String() {addr} (got) != {ip} (expected)",
            );
        }

        Ok(())
    }
}
