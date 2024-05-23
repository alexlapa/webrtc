use std::fmt;

use crate::stun::error::*;

// SCHEME definitions from RFC 7064 Section 3.2.

pub const SCHEME: &str = "stun";
pub const SCHEME_SECURE: &str = "stuns";

// URI as defined in RFC 7064.
#[derive(PartialEq, Eq, Debug)]
pub struct Uri {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains("::") {
            "[".to_owned() + self.host.as_str() + "]"
        } else {
            self.host.clone()
        };

        if let Some(port) = self.port {
            write!(f, "{}:{}:{}", self.scheme, host, port)
        } else {
            write!(f, "{}:{}", self.scheme, host)
        }
    }
}

impl Uri {
    // parse_uri parses URI from string.
    pub fn parse_uri(raw: &str) -> Result<Self> {
        // work around for url crate
        if raw.contains("//") {
            return Err(Error::ErrInvalidUrl);
        }

        let mut s = raw.to_string();
        let pos = raw.find(':');
        if let Some(p) = pos {
            s.replace_range(p..p + 1, "://");
        } else {
            return Err(Error::ErrSchemeType);
        }

        let raw_parts = url::Url::parse(&s)?;

        let scheme = raw_parts.scheme().into();
        if scheme != SCHEME && scheme != SCHEME_SECURE {
            return Err(Error::ErrSchemeType);
        }

        let host = if let Some(host) = raw_parts.host_str() {
            host.trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned()
        } else {
            return Err(Error::ErrHost);
        };

        let port = raw_parts.port();

        Ok(Uri { scheme, host, port })
    }
}

#[cfg(test)]
mod uri_test {
    use super::*;

    #[test]
    fn test_parse_uri() -> Result<()> {
        let tests = vec![
            (
                "default",
                "stun:example.org",
                Uri {
                    host: "example.org".to_owned(),
                    scheme: SCHEME.to_owned(),
                    port: None,
                },
                "stun:example.org",
            ),
            (
                "secure",
                "stuns:example.org",
                Uri {
                    host: "example.org".to_owned(),
                    scheme: SCHEME_SECURE.to_owned(),
                    port: None,
                },
                "stuns:example.org",
            ),
            (
                "with port",
                "stun:example.org:8000",
                Uri {
                    host: "example.org".to_owned(),
                    scheme: SCHEME.to_owned(),
                    port: Some(8000),
                },
                "stun:example.org:8000",
            ),
            (
                "ipv6 address",
                "stun:[::1]:123",
                Uri {
                    host: "::1".to_owned(),
                    scheme: SCHEME.to_owned(),
                    port: Some(123),
                },
                "stun:[::1]:123",
            ),
        ];

        for (name, input, output, expected_str) in tests {
            let out = Uri::parse_uri(input)?;
            assert_eq!(out, output, "{name}: {out} != {output}");
            assert_eq!(out.to_string(), expected_str, "{name}");
        }

        //"MustFail"
        {
            let tests = vec![
                ("hierarchical", "stun://example.org"),
                ("bad scheme", "tcp:example.org"),
                ("invalid uri scheme", "stun_s:test"),
            ];
            for (name, input) in tests {
                let result = Uri::parse_uri(input);
                assert!(result.is_err(), "{name} should fail, but did not");
            }
        }

        Ok(())
    }
}
