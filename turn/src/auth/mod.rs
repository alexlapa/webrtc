use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use md5::{Digest, Md5};
use ring::hmac;

use crate::error::*;

pub trait AuthHandler {
    fn auth_handle(&self, username: &str, realm: &str, src_addr: SocketAddr) -> Result<Vec<u8>>;
}

/// `generate_long_term_credentials()` can be used to create credentials valid
/// for `duration` time/
pub fn generate_long_term_credentials(
    shared_secret: &str,
    duration: Duration,
) -> Result<(String, String)> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)? + duration;
    let username = format!("{}", t.as_secs());
    let password = long_term_credentials(&username, shared_secret);
    Ok((username, password))
}

fn long_term_credentials(username: &str, shared_secret: &str) -> String {
    let mac = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        shared_secret.as_bytes(),
    );
    let password = hmac::sign(&mac, username.as_bytes()).as_ref().to_vec();
    BASE64_STANDARD.encode(password)
}

/// A convenience function to easily generate keys in the format used by
/// [`AuthHandler`].
pub fn generate_auth_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let s = format!("{username}:{realm}:{password}");

    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().as_slice().to_vec()
}

pub struct LongTermAuthHandler {
    shared_secret: String,
}

impl AuthHandler for LongTermAuthHandler {
    fn auth_handle(&self, username: &str, realm: &str, src_addr: SocketAddr) -> Result<Vec<u8>> {
        log::trace!(
            "Authentication username={} realm={} src_addr={}",
            username,
            realm,
            src_addr
        );

        let t = Duration::from_secs(username.parse::<u64>()?);
        if t < SystemTime::now().duration_since(UNIX_EPOCH)? {
            return Err(Error::Other(format!(
                "Expired time-windowed username {username}"
            )));
        }

        let password = long_term_credentials(username, &self.shared_secret);
        Ok(generate_auth_key(username, realm, &password))
    }
}

impl LongTermAuthHandler {
    /// https://tools.ietf.org/search/rfc5389#section-10.2
    pub fn new(shared_secret: String) -> Self {
        LongTermAuthHandler { shared_secret }
    }
}

#[cfg(test)]
mod auth_test {
    use super::*;

    #[test]
    fn test_lt_cred() -> Result<()> {
        let username = "1599491771";
        let shared_secret = "foobar";

        let expected_password = "Tpz/nKkyvX/vMSLKvL4sbtBt8Vs=";
        let actual_password = long_term_credentials(username, shared_secret);
        assert_eq!(
            expected_password, actual_password,
            "Expected {expected_password}, got {actual_password}"
        );

        Ok(())
    }

    #[test]
    fn test_generate_auth_key() -> Result<()> {
        let username = "60";
        let password = "HWbnm25GwSj6jiHTEDMTO5D7aBw=";
        let realm = "webrtc.rs";

        let expected_key = vec![
            56, 22, 47, 139, 198, 127, 13, 188, 171, 80, 23, 29, 195, 148, 216, 224,
        ];
        let actual_key = generate_auth_key(username, realm, password);
        assert_eq!(
            expected_key, actual_key,
            "Expected {expected_key:?}, got {actual_key:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_new_long_term_auth_handler() -> Result<()> {
        use std::{net::IpAddr, str::FromStr, sync::Arc};

        use crate::util::vnet::net::*;
        use tokio::net::UdpSocket;

        use crate::{
            client::*,
            relay::*,
            server::{config::*, *},
        };

        // env_logger::init();

        const SHARED_SECRET: &str = "HELLO_WORLD";

        // here, it should use static port, like "0.0.0.0:3478",
        // but, due to different test environment, let's fake it by using
        // "0.0.0.0:0" to auto assign a "static" port
        let conn = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let server_port = conn.local_addr()?.port();

        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::from_str("127.0.0.1")?,
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new()),
                }),
            }],
            realm: "webrtc.rs".to_owned(),
            auth_handler: Arc::new(LongTermAuthHandler::new(SHARED_SECRET.to_string())),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await?;

        let (username, password) =
            generate_long_term_credentials(SHARED_SECRET, Duration::from_secs(60))?;

        let conn = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let client = Client::new(ClientConfig {
            stun_serv_addr: format!("0.0.0.0:{server_port}"),
            turn_serv_addr: format!("0.0.0.0:{server_port}"),
            username,
            password,
            realm: "webrtc.rs".to_owned(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            vnet: None,
        })
        .await?;

        client.listen().await?;

        let _allocation = client.allocate().await?;

        client.close().await?;
        server.close().await?;

        Ok(())
    }
}
