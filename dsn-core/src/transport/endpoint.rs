use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportScheme {
    Tcp,
    Udp,
    Tls,
    Quic,
    Ws,
    Wss,
    H2,
    G2,
}

impl TransportScheme {
    pub fn supports_path(self) -> bool {
        matches!(self, Self::Ws | Self::Wss | Self::H2 | Self::G2)
    }

    pub fn from_scheme(value: &str) -> Option<Self> {
        match value {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "tls" => Some(Self::Tls),
            "quic" => Some(Self::Quic),
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            "h2" => Some(Self::H2),
            "g2" => Some(Self::G2),
            _ => None,
        }
    }
}

impl Display for TransportScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Tls => "tls",
            Self::Quic => "quic",
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::H2 => "h2",
            Self::G2 => "g2",
        };

        write!(f, "{value}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpoint {
    pub scheme: TransportScheme,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportParam {
    ServerName,
    Alpn,
    Ca,
    Cert,
    Key,
    Insecure,
}

impl TransportParam {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerName => "servername",
            Self::Alpn => "alpn",
            Self::Ca => "ca",
            Self::Cert => "cert",
            Self::Key => "key",
            Self::Insecure => "insecure",
        }
    }
}

pub fn reserved_transport_params() -> BTreeSet<&'static str> {
    [
        TransportParam::ServerName.as_str(),
        TransportParam::Alpn.as_str(),
        TransportParam::Ca.as_str(),
        TransportParam::Cert.as_str(),
        TransportParam::Key.as_str(),
        TransportParam::Insecure.as_str(),
    ]
    .into_iter()
    .collect()
}

pub fn parse_bool_param(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("expected boolean value (1/0/true/false/yes/no/on/off), got '{value}'"),
    }
}

impl TransportEndpoint {
    pub fn ensure_security_policy(&self, allow_insecure: bool) -> Result<()> {
        let Some(raw_insecure) = self.params.get(TransportParam::Insecure.as_str()) else {
            return Ok(());
        };

        let insecure_enabled = parse_bool_param(raw_insecure)
            .with_context(|| "query param insecure has invalid boolean value")?;

        if insecure_enabled && !allow_insecure {
            bail!(
                "endpoint has insecure=1, but global allow_insecure is disabled; refusing unsafe transport"
            );
        }

        Ok(())
    }
}

impl FromStr for TransportEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parsed =
            Url::parse(s).with_context(|| format!("invalid transport endpoint URL: {s}"))?;

        let scheme = TransportScheme::from_scheme(parsed.scheme())
            .ok_or_else(|| anyhow!("unsupported transport scheme '{}'", parsed.scheme()))?;

        if parsed.host_str().is_none() {
            bail!("transport endpoint must include host");
        }

        let host = parsed
            .host_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("transport endpoint host is missing"))?;

        if !has_explicit_port(s) {
            bail!("transport endpoint must include explicit port");
        }

        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| anyhow!("transport endpoint must include explicit port"))?;

        let raw_path = parsed.path();
        let path = if scheme.supports_path() {
            Some(if raw_path.is_empty() || raw_path == "/" {
                "/".to_owned()
            } else {
                raw_path.to_owned()
            })
        } else if raw_path.is_empty() || raw_path == "/" {
            None
        } else {
            bail!("scheme '{}' does not allow path component", scheme);
        };

        let mut params = BTreeMap::new();
        for (key, value) in parsed.query_pairs() {
            if key.is_empty() {
                bail!("query parameter key must not be empty");
            }
            params.insert(key.into_owned(), value.into_owned());
        }

        Ok(Self {
            scheme,
            host,
            port,
            path,
            params,
        })
    }
}

fn has_explicit_port(input: &str) -> bool {
    let Some((_, remainder)) = input.split_once("://") else {
        return false;
    };

    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();

    if authority.starts_with('[') {
        let Some((_, port)) = authority.rsplit_once("]:") else {
            return false;
        };
        return !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit());
    }

    let Some((_, port)) = authority.rsplit_once(':') else {
        return false;
    };

    !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        TransportEndpoint, TransportParam, TransportScheme, parse_bool_param,
        reserved_transport_params,
    };
    use std::str::FromStr;

    #[test]
    fn parses_wss_with_path() {
        let endpoint = TransportEndpoint::from_str("wss://127.0.0.1:443/path")
            .expect("wss endpoint should parse");

        assert_eq!(endpoint.scheme, TransportScheme::Wss);
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path.as_deref(), Some("/path"));
    }

    #[test]
    fn parses_tls_with_query_param() {
        let endpoint = TransportEndpoint::from_str("tls://10.0.0.1:443?servername=example.com")
            .expect("tls endpoint should parse");

        assert_eq!(endpoint.scheme, TransportScheme::Tls);
        assert_eq!(endpoint.path, None);
        assert_eq!(
            endpoint
                .params
                .get(TransportParam::ServerName.as_str())
                .map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn defaults_http_style_scheme_path_to_root() {
        let endpoint = TransportEndpoint::from_str("h2://example.org:8443")
            .expect("h2 endpoint should parse with default path");

        assert_eq!(endpoint.path.as_deref(), Some("/"));
    }

    #[test]
    fn rejects_endpoint_without_port() {
        let err = TransportEndpoint::from_str("tls://10.0.0.1")
            .expect_err("missing explicit port must fail");
        assert!(err.to_string().contains("explicit port"));
    }

    #[test]
    fn rejects_wss_endpoint_with_implicit_default_port() {
        let err = TransportEndpoint::from_str("wss://example.com/path")
            .expect_err("missing explicit wss port must fail");
        assert!(err.to_string().contains("explicit port"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        let err = TransportEndpoint::from_str("unix://tmp.sock")
            .expect_err("unsupported scheme must fail");
        assert!(err.to_string().contains("unsupported transport scheme"));
    }

    #[test]
    fn rejects_path_for_tcp() {
        let err = TransportEndpoint::from_str("tcp://127.0.0.1:9000/path")
            .expect_err("tcp path must be rejected");
        assert!(err.to_string().contains("does not allow path"));
    }

    #[test]
    fn rejects_out_of_range_port() {
        let err = TransportEndpoint::from_str("udp://127.0.0.1:70000")
            .expect_err("invalid port must fail");
        assert!(err.to_string().contains("invalid transport endpoint URL"));
    }

    #[test]
    fn enforces_double_flag_for_insecure_mode() {
        let endpoint = TransportEndpoint::from_str("wss://localhost:443/?insecure=1")
            .expect("endpoint should parse");

        let err = endpoint
            .ensure_security_policy(false)
            .expect_err("unsafe transport must require global allow flag");
        assert!(err.to_string().contains("allow_insecure"));

        endpoint
            .ensure_security_policy(true)
            .expect("global allow_insecure enables insecure endpoint");
    }

    #[test]
    fn parses_reserved_params_set() {
        let params = reserved_transport_params();
        assert!(params.contains(TransportParam::ServerName.as_str()));
        assert!(params.contains(TransportParam::Alpn.as_str()));
        assert!(params.contains(TransportParam::Ca.as_str()));
        assert!(params.contains(TransportParam::Cert.as_str()));
        assert!(params.contains(TransportParam::Key.as_str()));
        assert!(params.contains(TransportParam::Insecure.as_str()));
    }

    #[test]
    fn parses_boolean_values_for_query_flags() {
        assert!(parse_bool_param("1").expect("1 should parse as bool"));
        assert!(parse_bool_param("true").expect("true should parse as bool"));
        assert!(!parse_bool_param("0").expect("0 should parse as bool"));
        assert!(!parse_bool_param("false").expect("false should parse as bool"));
    }
}
