use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use md5::{Digest, Md5};
use ring::hmac;

use crate::error::*;

pub trait AuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error>;
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
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
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
    fn test_lt_cred() {
        let username = "1599491771";
        let shared_secret = "foobar";

        let expected_password = "Tpz/nKkyvX/vMSLKvL4sbtBt8Vs=";
        let actual_password = long_term_credentials(username, shared_secret);
        assert_eq!(
            expected_password, actual_password,
            "Expected {expected_password}, got {actual_password}"
        );
    }

    #[test]
    fn test_generate_auth_key() {
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
    }
}
