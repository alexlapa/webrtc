use std::net::SocketAddr;

use md5::{Digest, Md5};

use crate::error::*;

pub trait AuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error>;
}

/// A convenience function to easily generate keys in the format used by
/// [`AuthHandler`].
pub fn generate_auth_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let s = format!("{username}:{realm}:{password}");

    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().as_slice().to_vec()
}

#[cfg(test)]
mod auth_test {
    use super::*;

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
