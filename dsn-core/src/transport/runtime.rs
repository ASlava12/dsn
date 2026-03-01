use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Once;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{WebSocketStream, accept_async, client_async};
use tracing::{info, warn};

use super::{TransportEndpoint, TransportParam, TransportScheme, parse_bool_param};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + ?Sized {}

pub type BoxedStreamConn = Box<dyn AsyncReadWrite + Send + Unpin>;

pub enum Connection {
    Stream(BoxedStreamConn),
    Datagram(Box<dyn DatagramConn>),
}

#[async_trait]
pub trait DatagramConn: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn send(&self, payload: &[u8], target: Option<SocketAddr>) -> Result<usize>;
    async fn connect(&self, peer: SocketAddr) -> Result<()>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection>;
    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection>;
}

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub struct TcpRawTransport;

#[async_trait]
impl Transport for TcpRawTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Tcp {
            bail!(
                "tcp transport requires tcp:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind tcp listener on {bind_addr}"))?;
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first tcp client on {bind_addr}"))?;

        Ok(Connection::Stream(Box::new(stream)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Tcp {
            bail!(
                "tcp transport requires tcp:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect tcp stream to {remote_addr}"))?;

        Ok(Connection::Stream(Box::new(stream)))
    }
}

pub struct TlsTransport;

#[async_trait]
impl Transport for TlsTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Tls {
            bail!(
                "tls transport requires tls:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let tls_acceptor = build_server_tls_acceptor(endpoint)?;
        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind tls listener on {bind_addr}"))?;
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first tls client on {bind_addr}"))?;

        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .context("failed tls server handshake")?;

        Ok(Connection::Stream(Box::new(tls_stream)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Tls {
            bail!(
                "tls transport requires tls:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect tls stream to {remote_addr}"))?;

        let tls_stream = connect_tls_stream(endpoint, stream).await?;
        Ok(Connection::Stream(Box::new(tls_stream)))
    }
}

pub struct WsTransport;

#[async_trait]
impl Transport for WsTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Ws {
            bail!(
                "ws transport requires ws:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind ws listener on {bind_addr}"))?;
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first ws client on {bind_addr}"))?;

        let ws_stream = accept_async(stream)
            .await
            .context("failed websocket server handshake")?;

        Ok(Connection::Stream(websocket_as_read_write(ws_stream)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Ws {
            bail!(
                "ws transport requires ws:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect ws tcp stream to {remote_addr}"))?;
        let request = websocket_client_request(endpoint)?;

        let (ws_stream, _) = client_async(request, stream)
            .await
            .context("failed websocket client handshake")?;

        Ok(Connection::Stream(websocket_as_read_write(ws_stream)))
    }
}

pub struct WssTransport;

#[async_trait]
impl Transport for WssTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Wss {
            bail!(
                "wss transport requires wss:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let tls_acceptor = build_server_tls_acceptor(endpoint)?;
        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind wss listener on {bind_addr}"))?;
        let (tcp_stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first wss client on {bind_addr}"))?;

        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .context("failed tls handshake for wss listener")?;

        let ws_stream = accept_async(tls_stream)
            .await
            .context("failed websocket upgrade on tls stream")?;

        Ok(Connection::Stream(websocket_as_read_write(ws_stream)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Wss {
            bail!(
                "wss transport requires wss:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let tcp_stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect wss tcp stream to {remote_addr}"))?;
        let tls_stream = connect_tls_stream(endpoint, tcp_stream).await?;
        let request = websocket_client_request(endpoint)?;

        let (ws_stream, _) = client_async(request, tls_stream)
            .await
            .context("failed websocket upgrade over tls stream")?;

        Ok(Connection::Stream(websocket_as_read_write(ws_stream)))
    }
}

pub struct QuicTransport;

#[async_trait]
impl Transport for QuicTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Quic {
            bail!(
                "quic transport requires quic:// endpoint, got {}",
                endpoint.scheme
            );
        }

        info!(
            "QUIC transport uses TLS1.3; certificate validation is required unless explicitly insecure"
        );

        let cert_path = endpoint
            .params
            .get(TransportParam::Cert.as_str())
            .ok_or_else(|| anyhow!("quic listen requires query param 'cert' with PEM path"))?;
        let key_path = endpoint
            .params
            .get(TransportParam::Key.as_str())
            .ok_or_else(|| anyhow!("quic listen requires query param 'key' with PEM path"))?;

        let cert_chain = load_cert_chain(cert_path)?;
        let private_key = load_private_key(key_path)?;

        let server_cfg = QuinnServerConfig::with_single_cert(cert_chain, private_key)
            .context("failed to build quic server config")?;

        let bind_addr = endpoint_socket_addr(endpoint)?;
        let server_endpoint = QuinnEndpoint::server(server_cfg, bind_addr)
            .with_context(|| format!("failed to bind quic endpoint on {bind_addr}"))?;

        let incoming = server_endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("quic endpoint closed before first connection"))?;
        let connection = incoming.await.context("failed quic server handshake")?;
        let (send, recv) = connection
            .accept_bi()
            .await
            .context("failed to accept first quic bidi stream")?;

        Ok(Connection::Stream(quic_bidi_as_read_write(recv, send)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Quic {
            bail!(
                "quic transport requires quic:// endpoint, got {}",
                endpoint.scheme
            );
        }

        info!(
            "QUIC transport uses TLS1.3; certificate validation is required unless explicitly insecure"
        );

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let mut client_endpoint = QuinnEndpoint::client("0.0.0.0:0".parse().expect("valid addr"))
            .context("failed to create quic client endpoint")?;

        let client_crypto = build_client_crypto_config(endpoint)?;
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("failed to convert rustls config for quic")?;
        client_endpoint.set_default_client_config(QuinnClientConfig::new(Arc::new(quic_crypto)));

        let server_name = endpoint_server_name(endpoint)?;
        let server_name = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            _ => bail!("quic server_name must be DNS name"),
        };

        let connection = client_endpoint
            .connect(remote_addr, &server_name)
            .with_context(|| format!("failed to start quic connect to {remote_addr}"))?
            .await
            .context("failed quic client handshake")?;

        let (send, recv) = connection
            .open_bi()
            .await
            .context("failed to open first quic bidi stream")?;

        Ok(Connection::Stream(quic_bidi_as_read_write(recv, send)))
    }
}

pub struct H2Transport;

#[async_trait]
impl Transport for H2Transport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::H2 {
            bail!(
                "h2 transport requires h2:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let tls_acceptor = build_server_tls_acceptor(endpoint)?;
        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind h2 listener on {bind_addr}"))?;
        let (tcp_stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first h2 client on {bind_addr}"))?;
        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .context("failed tls handshake for h2 listener")?;

        accept_h2_tunnel(endpoint.path.as_deref().unwrap_or("/"), tls_stream, false).await
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::H2 {
            bail!(
                "h2 transport requires h2:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let tcp_stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect h2 tcp stream to {remote_addr}"))?;
        let tls_stream = connect_tls_stream(endpoint, tcp_stream).await?;

        connect_h2_tunnel(
            endpoint.path.as_deref().unwrap_or("/"),
            endpoint,
            tls_stream,
            false,
        )
        .await
    }
}

pub struct G2Transport;

#[async_trait]
impl Transport for G2Transport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::G2 {
            bail!(
                "g2 transport requires g2:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let tls_acceptor = build_server_tls_acceptor(endpoint)?;
        let bind_addr = endpoint_socket_addr(endpoint)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind g2 listener on {bind_addr}"))?;
        let (tcp_stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first g2 client on {bind_addr}"))?;
        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .context("failed tls handshake for g2 listener")?;

        accept_h2_tunnel(endpoint.path.as_deref().unwrap_or("/"), tls_stream, true).await
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::G2 {
            bail!(
                "g2 transport requires g2:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let tcp_stream = TcpStream::connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect g2 tcp stream to {remote_addr}"))?;
        let tls_stream = connect_tls_stream(endpoint, tcp_stream).await?;

        connect_h2_tunnel(
            endpoint.path.as_deref().unwrap_or("/"),
            endpoint,
            tls_stream,
            true,
        )
        .await
    }
}

pub struct UnixTransport;

#[async_trait]
impl Transport for UnixTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Unix {
            bail!(
                "unix transport requires unix:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let path = endpoint_unix_path(endpoint)?;
        if std::path::Path::new(path).exists() {
            let _ = std::fs::remove_file(path);
        }

        let listener = UnixListener::bind(path)
            .with_context(|| format!("failed to bind unix listener on {path}"))?;
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept first unix client on {path}"))?;

        Ok(Connection::Stream(Box::new(stream)))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Unix {
            bail!(
                "unix transport requires unix:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let path = endpoint_unix_path(endpoint)?;
        let stream = UnixStream::connect(path)
            .await
            .with_context(|| format!("failed to connect unix stream to {path}"))?;

        Ok(Connection::Stream(Box::new(stream)))
    }
}

pub struct UdpRawTransport;

#[async_trait]
impl Transport for UdpRawTransport {
    async fn listen(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Udp {
            bail!(
                "udp transport requires udp:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let bind_addr = endpoint_socket_addr(endpoint)?;
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind udp socket on {bind_addr}"))?;

        Ok(Connection::Datagram(Box::new(UdpRawConn::new(socket))))
    }

    async fn connect(&self, endpoint: &TransportEndpoint) -> Result<Connection> {
        if endpoint.scheme != TransportScheme::Udp {
            bail!(
                "udp transport requires udp:// endpoint, got {}",
                endpoint.scheme
            );
        }

        let remote_addr = endpoint_socket_addr(endpoint)?;
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind udp client socket")?;
        socket
            .connect(remote_addr)
            .await
            .with_context(|| format!("failed to connect udp socket to {remote_addr}"))?;

        let conn = UdpRawConn::new(socket);
        conn.connect(remote_addr).await?;

        Ok(Connection::Datagram(Box::new(conn)))
    }
}

pub struct UdpRawConn {
    socket: Arc<UdpSocket>,
    connected_peer: Mutex<Option<SocketAddr>>,
}

impl UdpRawConn {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            connected_peer: Mutex::new(None),
        }
    }
}

#[async_trait]
impl DatagramConn for UdpRawConn {
    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let connected_peer = *self.connected_peer.lock().await;
        if let Some(peer) = connected_peer {
            let size = self
                .socket
                .recv(buf)
                .await
                .context("failed to receive connected udp datagram")?;
            return Ok((size, peer));
        }

        self.socket
            .recv_from(buf)
            .await
            .context("failed to receive udp datagram")
    }

    async fn send(&self, payload: &[u8], target: Option<SocketAddr>) -> Result<usize> {
        if let Some(target) = target {
            return self
                .socket
                .send_to(payload, target)
                .await
                .context("failed to send udp datagram");
        }

        let connected_peer = *self.connected_peer.lock().await;
        if connected_peer.is_some() {
            return self
                .socket
                .send(payload)
                .await
                .context("failed to send connected udp datagram");
        }

        bail!("udp target address is required for unconnected socket")
    }

    async fn connect(&self, peer: SocketAddr) -> Result<()> {
        self.socket
            .connect(peer)
            .await
            .with_context(|| format!("failed to connect udp socket to {peer}"))?;
        *self.connected_peer.lock().await = Some(peer);
        Ok(())
    }
}

pub fn endpoint_socket_addr(endpoint: &TransportEndpoint) -> Result<SocketAddr> {
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    addr.parse().with_context(|| {
        format!(
            "host must be an IP address for now in raw transport mode: {}",
            endpoint.host
        )
    })
}

fn endpoint_unix_path(endpoint: &TransportEndpoint) -> Result<&str> {
    if endpoint.scheme != TransportScheme::Unix {
        bail!("endpoint_unix_path is valid only for unix scheme");
    }

    endpoint
        .path
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "/")
        .ok_or_else(|| anyhow!("unix endpoint must include non-empty socket path"))
}

pub fn transport_for_scheme(scheme: TransportScheme) -> Result<Box<dyn Transport>> {
    let transport: Box<dyn Transport> = match scheme {
        TransportScheme::Tcp => Box::new(TcpRawTransport),
        TransportScheme::Tls => Box::new(TlsTransport),
        TransportScheme::Quic => Box::new(QuicTransport),
        TransportScheme::Ws => Box::new(WsTransport),
        TransportScheme::Wss => Box::new(WssTransport),
        TransportScheme::H2 => Box::new(H2Transport),
        TransportScheme::G2 => Box::new(G2Transport),
        TransportScheme::Udp => Box::new(UdpRawTransport),
        TransportScheme::Unix => Box::new(UnixTransport),
    };

    Ok(transport)
}

fn build_server_tls_acceptor(endpoint: &TransportEndpoint) -> Result<TlsAcceptor> {
    ensure_rustls_crypto_provider();
    let cert_path = endpoint
        .params
        .get(TransportParam::Cert.as_str())
        .ok_or_else(|| anyhow!("tls/wss listen requires query param 'cert' with PEM path"))?;
    let key_path = endpoint
        .params
        .get(TransportParam::Key.as_str())
        .ok_or_else(|| anyhow!("tls/wss listen requires query param 'key' with PEM path"))?;

    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key(key_path)?;

    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build rustls server config")?;

    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

async fn connect_tls_stream(
    endpoint: &TransportEndpoint,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = build_client_crypto_config(endpoint)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = endpoint_server_name(endpoint)?;
    connector
        .connect(server_name, stream)
        .await
        .context("failed tls client handshake")
}

fn build_client_crypto_config(endpoint: &TransportEndpoint) -> Result<ClientConfig> {
    ensure_rustls_crypto_provider();
    let insecure = endpoint
        .params
        .get(TransportParam::Insecure.as_str())
        .map(|value| parse_bool_param(value))
        .transpose()?
        .unwrap_or(false);

    if insecure {
        warn!("TLS trust mode: insecure (certificate verification disabled)");
        return Ok(ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth());
    }

    let root_store = build_client_root_store(endpoint)?;
    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

async fn accept_h2_tunnel<S>(path: &str, io_stream: S, grpc_mode: bool) -> Result<Connection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut h2 = h2::server::handshake(io_stream)
        .await
        .context("failed h2 server handshake")?;

    let (request, mut respond) = h2
        .accept()
        .await
        .ok_or_else(|| anyhow!("h2 server closed before first request"))
        .and_then(|r| r.context("failed to accept h2 request"))?;

    if request.uri().path() != path {
        bail!(
            "unexpected h2 path '{}', expected '{}'",
            request.uri().path(),
            path
        );
    }

    let (local_end, bridge_end) = io::duplex(64 * 1024);
    let (mut bridge_reader, mut bridge_writer) = io::split(bridge_end);

    let mut req_body = request.into_body();
    let mut send_stream = respond
        .send_response(
            http::Response::builder()
                .status(200)
                .body(())
                .expect("h2 response"),
            false,
        )
        .context("failed to send h2 response headers")?;

    tokio::spawn(async move {
        let mut grpc_decoder = GrpcFrameDecoder::default();
        while let Some(chunk_result) = req_body.data().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(_) => break,
            };

            if grpc_mode {
                for frame in grpc_decoder.feed(&chunk) {
                    if bridge_writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                if bridge_writer.flush().await.is_err() {
                    return;
                }
            } else {
                if bridge_writer.write_all(&chunk).await.is_err() {
                    return;
                }
                if bridge_writer.flush().await.is_err() {
                    return;
                }
            }
        }

        let _ = bridge_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let size = match bridge_reader.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if size == 0 {
                let _ = send_stream.send_data(Bytes::new(), true);
                break;
            }

            if grpc_mode {
                let frame = grpc_frame_encode(&buf[..size]);
                if send_stream.send_data(frame, false).is_err() {
                    break;
                }
            } else if send_stream
                .send_data(Bytes::copy_from_slice(&buf[..size]), false)
                .is_err()
            {
                break;
            }
        }
    });

    tokio::spawn(async move { while let Some(_event) = h2.accept().await {} });

    Ok(Connection::Stream(Box::new(local_end)))
}

async fn connect_h2_tunnel<S>(
    path: &str,
    endpoint: &TransportEndpoint,
    io_stream: S,
    grpc_mode: bool,
) -> Result<Connection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = h2::client::handshake(io_stream)
        .await
        .context("failed h2 client handshake")?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    let authority = format!("{}:{}", endpoint.host, endpoint.port);
    let mut request = http::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", authority)
        .body(())
        .expect("h2 request");

    if grpc_mode {
        request
            .headers_mut()
            .insert("content-type", "application/grpc".parse().expect("ct"));
        request
            .headers_mut()
            .insert("te", "trailers".parse().expect("te"));
    }

    let (response_fut, mut req_send) = sender
        .send_request(request, false)
        .context("failed to send h2 request headers")?;
    let response = response_fut
        .await
        .context("failed to receive h2 response")?;
    let mut res_body = response.into_body();

    let (local_end, bridge_end) = io::duplex(64 * 1024);
    let (mut bridge_reader, mut bridge_writer) = io::split(bridge_end);

    tokio::spawn(async move {
        let mut grpc_decoder = GrpcFrameDecoder::default();
        while let Some(chunk_result) = res_body.data().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(_) => break,
            };

            if grpc_mode {
                for frame in grpc_decoder.feed(&chunk) {
                    if bridge_writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                if bridge_writer.flush().await.is_err() {
                    return;
                }
            } else {
                if bridge_writer.write_all(&chunk).await.is_err() {
                    return;
                }
                if bridge_writer.flush().await.is_err() {
                    return;
                }
            }
        }

        let _ = bridge_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let size = match bridge_reader.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if size == 0 {
                let _ = req_send.send_data(Bytes::new(), true);
                break;
            }

            if grpc_mode {
                let frame = grpc_frame_encode(&buf[..size]);
                if req_send.send_data(frame, false).is_err() {
                    break;
                }
            } else if req_send
                .send_data(Bytes::copy_from_slice(&buf[..size]), false)
                .is_err()
            {
                break;
            }
        }
    });

    Ok(Connection::Stream(Box::new(local_end)))
}

fn grpc_frame_encode(payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

#[derive(Default)]
struct GrpcFrameDecoder {
    buffer: Vec<u8>,
}

impl GrpcFrameDecoder {
    fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::new();

        loop {
            if self.buffer.len() < 5 {
                break;
            }

            let len = u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;

            if self.buffer.len() < 5 + len {
                break;
            }

            let payload = self.buffer[5..5 + len].to_vec();
            self.buffer.drain(0..5 + len);
            out.push(payload);
        }

        out
    }
}

fn websocket_client_request(
    endpoint: &TransportEndpoint,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request> {
    let target = websocket_target_url(endpoint)?;
    let mut request = target
        .into_client_request()
        .map_err(|err| anyhow!("failed to initialize websocket client request: {err}"))?;

    let host_header = format!("{}:{}", endpoint.host, endpoint.port);
    request.headers_mut().insert(
        http::header::HOST,
        host_header
            .parse()
            .map_err(|err| anyhow!("invalid Host header value: {err}"))?,
    );

    if let Some(origin) = endpoint.params.get("origin") {
        request.headers_mut().insert(
            http::header::ORIGIN,
            origin
                .parse()
                .map_err(|err| anyhow!("invalid Origin header value: {err}"))?,
        );
    }

    for (key, value) in &endpoint.params {
        if let Some(name) = key.strip_prefix("header.") {
            request.headers_mut().insert(
                http::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|err| anyhow!("invalid header name '{name}': {err}"))?,
                value
                    .parse()
                    .map_err(|err| anyhow!("invalid header value for '{name}': {err}"))?,
            );
        }
    }

    Ok(request)
}

fn websocket_target_url(endpoint: &TransportEndpoint) -> Result<String> {
    let scheme = match endpoint.scheme {
        TransportScheme::Ws => "ws",
        TransportScheme::Wss => "wss",
        _ => bail!("websocket target URL is available only for ws/wss schemes"),
    };

    let path = endpoint.path.as_deref().unwrap_or("/");
    let mut query_pairs = Vec::new();
    for (key, value) in &endpoint.params {
        if key.starts_with("header.") {
            continue;
        }
        if matches!(
            key.as_str(),
            "servername" | "ca" | "cert" | "key" | "insecure" | "alpn" | "origin"
        ) {
            continue;
        }
        query_pairs.push(format!(
            "{}={}",
            urlencoding::encode(key),
            urlencoding::encode(value)
        ));
    }

    let mut url = format!("{scheme}://{}:{}{path}", endpoint.host, endpoint.port);
    if !query_pairs.is_empty() {
        url.push('?');
        url.push_str(&query_pairs.join("&"));
    }

    Ok(url)
}

fn quic_bidi_as_read_write(
    recv: quinn::RecvStream,
    mut send: quinn::SendStream,
) -> BoxedStreamConn {
    let (local_end, bridge_end) = io::duplex(64 * 1024);
    let (mut bridge_reader, mut bridge_writer) = io::split(bridge_end);
    let mut recv_stream = recv;

    tokio::spawn(async move {
        loop {
            match recv_stream.read_chunk(64 * 1024, true).await {
                Ok(Some(chunk)) => {
                    if bridge_writer.write_all(chunk.bytes.as_ref()).await.is_err() {
                        break;
                    }
                    if bridge_writer.flush().await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        let _ = bridge_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match bridge_reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = send.finish();
                    break;
                }
                Ok(size) => {
                    if send.write_all(&buf[..size]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Box::new(local_end)
}

fn websocket_as_read_write<S>(ws_stream: WebSocketStream<S>) -> BoxedStreamConn
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (local_end, bridge_end) = io::duplex(64 * 1024);
    let (mut bridge_reader, mut bridge_writer) = io::split(bridge_end);
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    tokio::spawn(async move {
        while let Some(message) = ws_source.next().await {
            match message {
                Ok(Message::Binary(payload)) => {
                    if bridge_writer.write_all(&payload).await.is_err() {
                        break;
                    }
                    if bridge_writer.flush().await.is_err() {
                        break;
                    }
                }
                Ok(Message::Text(payload)) => {
                    if bridge_writer.write_all(payload.as_bytes()).await.is_err() {
                        break;
                    }
                    if bridge_writer.flush().await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    break;
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Frame(_)) => {}
                Err(_) => break,
            }
        }

        let _ = bridge_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match bridge_reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = ws_sink.send(Message::Close(None)).await;
                    break;
                }
                Ok(size) => {
                    if ws_sink
                        .send(Message::Binary(buf[..size].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Box::new(local_end)
}

fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem =
        fs::read(path).with_context(|| format!("failed to read certificate PEM from {path}"))?;
    let mut reader = BufReader::new(pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM chain")?;
    if certs.is_empty() {
        bail!("certificate PEM does not contain any certificates");
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem =
        fs::read(path).with_context(|| format!("failed to read private key PEM from {path}"))?;
    let mut reader = BufReader::new(pem.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .context("failed to parse private key PEM")?
        .ok_or_else(|| anyhow!("private key PEM does not contain a supported key"))
}

fn endpoint_server_name(endpoint: &TransportEndpoint) -> Result<ServerName<'static>> {
    let value = endpoint
        .params
        .get(TransportParam::ServerName.as_str())
        .cloned()
        .unwrap_or_else(|| endpoint.host.clone());

    ServerName::try_from(value.clone())
        .map(|name| name.to_owned())
        .map_err(|_| {
            anyhow!("invalid servername value for tls handshake: expected DNS name, got '{value}'")
        })
}

fn build_client_root_store(endpoint: &TransportEndpoint) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

    if let Some(ca_path) = endpoint.params.get(TransportParam::Ca.as_str()) {
        info!(path = %ca_path, "TLS trust mode: custom CA bundle");
        let cert_chain = load_cert_chain(ca_path)?;
        let (_, rejected) = roots.add_parsable_certificates(cert_chain);
        if rejected > 0 {
            bail!("failed to add one or more certificates from custom CA bundle");
        }
        return Ok(roots);
    }

    info!("TLS trust mode: system roots");
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        warn!(
            count = native.errors.len(),
            "some system root certificates failed to load"
        );
    }

    let (_, rejected) = roots.add_parsable_certificates(native.certs);
    if rejected > 0 {
        warn!(
            count = rejected,
            "some system root certificates were rejected by rustls parser"
        );
    }

    if roots.is_empty() {
        bail!("no usable system root certificates loaded");
    }

    Ok(roots)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Connection, G2Transport, H2Transport, QuicTransport, TcpRawTransport, TlsTransport,
        Transport, TransportEndpoint, TransportScheme, UdpRawTransport, UnixTransport, WsTransport,
        WssTransport, transport_for_scheme,
    };
    use anyhow::Result;
    use std::fs;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_raw_transport_connects_and_exchanges_data() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write");
        });

        let endpoint = TransportEndpoint::from_str(&format!("tcp://{}", addr))?;
        let transport = TcpRawTransport;
        let conn = transport.connect(&endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("tcp must return stream connection"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        Ok(())
    }

    #[tokio::test]
    async fn unix_transport_e2e_loopback() -> Result<()> {
        let sock = std::env::temp_dir().join(format!(
            "dsn-unix-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));

        let listen_endpoint = TransportEndpoint::from_str(&format!("unix://{}", sock.display()))?;
        let connect_endpoint = TransportEndpoint::from_str(&format!("unix://{}", sock.display()))?;

        let server_task = tokio::spawn(async move {
            let transport = UnixTransport;
            let conn = transport
                .listen(&listen_endpoint)
                .await
                .expect("listen unix");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("unix must return stream"),
            };

            let mut buf = [0u8; 5];
            stream
                .read_exact(&mut buf)
                .await
                .expect("read unix payload");
            assert_eq!(&buf, b"hello");
            stream
                .write_all(b"world")
                .await
                .expect("write unix payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let transport = UnixTransport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("unix must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = std::fs::remove_file(&sock);
        Ok(())
    }

    #[tokio::test]
    async fn udp_raw_transport_connect_works() -> Result<()> {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;

        let endpoint = TransportEndpoint::from_str(&format!("udp://{}", addr))?;
        let transport = UdpRawTransport;
        let conn = transport.connect(&endpoint).await?;

        let datagram = match conn {
            Connection::Datagram(datagram) => datagram,
            Connection::Stream(_) => panic!("udp must return datagram connection"),
        };

        datagram.send(b"ping", None).await?;

        let mut buf = [0u8; 16];
        let (n, peer) = server.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"ping");
        server.send_to(b"pong", peer).await?;

        let mut inbuf = [0u8; 16];
        let (m, _) = datagram.recv(&mut inbuf).await?;
        assert_eq!(&inbuf[..m], b"pong");

        Ok(())
    }

    #[tokio::test]
    async fn udp_raw_transport_listen_can_lock_first_peer() -> Result<()> {
        let transport = UdpRawTransport;
        let bind_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let bind_addr = bind_socket.local_addr()?;
        drop(bind_socket);

        let endpoint = TransportEndpoint::from_str(&format!("udp://{}", bind_addr))?;
        let conn = transport.listen(&endpoint).await?;
        let datagram = match conn {
            Connection::Datagram(datagram) => datagram,
            Connection::Stream(_) => panic!("udp must return datagram connection"),
        };

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        peer.send_to(b"first", bind_addr).await?;

        let mut buf = [0u8; 32];
        let (n, peer_addr) = datagram.recv(&mut buf).await?;
        assert_eq!(&buf[..n], b"first");

        datagram.connect(peer_addr).await?;
        datagram.send(b"reply", None).await?;

        let mut response = [0u8; 32];
        let (r, _) = peer.recv_from(&mut response).await?;
        assert_eq!(&response[..r], b"reply");

        Ok(())
    }

    #[tokio::test]
    async fn tls_transport_e2e_with_custom_ca_and_servername() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "dsn-tls-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&tmp)?;

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_pem = ca.cert.pem();
        let key_pem = ca.key_pair.serialize_pem();

        let cert_path = tmp.join("server-cert.pem");
        let key_path = tmp.join("server-key.pem");
        let ca_path = tmp.join("ca.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        fs::write(&ca_path, &cert_pem)?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint = TransportEndpoint::from_str(&format!(
            "tls://127.0.0.1:{}?cert={}&key={}",
            addr.port(),
            cert_path.display(),
            key_path.display()
        ))?;

        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "tls://127.0.0.1:{}?ca={}&servername=localhost",
            addr.port(),
            ca_path.display()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = TlsTransport;
            let conn = transport
                .listen(&listen_endpoint)
                .await
                .expect("listen tls");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("tls must return stream"),
            };

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read tls payload");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write tls payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = TlsTransport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("tls must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }

    #[tokio::test]
    async fn quic_transport_e2e_with_custom_ca_and_servername() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "dsn-quic-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&tmp)?;

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_pem = ca.cert.pem();
        let key_pem = ca.key_pair.serialize_pem();

        let cert_path = tmp.join("server-cert.pem");
        let key_path = tmp.join("server-key.pem");
        let ca_path = tmp.join("ca.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        fs::write(&ca_path, &cert_pem)?;

        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint = TransportEndpoint::from_str(&format!(
            "quic://127.0.0.1:{}?cert={}&key={}",
            addr.port(),
            cert_path.display(),
            key_path.display()
        ))?;

        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "quic://127.0.0.1:{}?ca={}&servername=localhost",
            addr.port(),
            ca_path.display()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = QuicTransport;
            let conn = transport
                .listen(&listen_endpoint)
                .await
                .expect("listen quic");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("quic must return stream"),
            };

            let mut buf = [0u8; 5];
            stream
                .read_exact(&mut buf)
                .await
                .expect("read quic payload");
            assert_eq!(&buf, b"hello");
            stream
                .write_all(b"world")
                .await
                .expect("write quic payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = QuicTransport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("quic must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }

    #[tokio::test]
    async fn h2_transport_e2e_tunnel() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "dsn-h2-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&tmp)?;

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_pem = ca.cert.pem();
        let key_pem = ca.key_pair.serialize_pem();

        let cert_path = tmp.join("server-cert.pem");
        let key_path = tmp.join("server-key.pem");
        let ca_path = tmp.join("ca.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        fs::write(&ca_path, &cert_pem)?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint = TransportEndpoint::from_str(&format!(
            "h2://127.0.0.1:{}/tunnel?cert={}&key={}",
            addr.port(),
            cert_path.display(),
            key_path.display()
        ))?;

        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "h2://127.0.0.1:{}/tunnel?ca={}&servername=localhost",
            addr.port(),
            ca_path.display()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = H2Transport;
            let conn = transport.listen(&listen_endpoint).await.expect("listen h2");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("h2 must return stream"),
            };

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read h2 payload");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write h2 payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = H2Transport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("h2 must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }

    #[tokio::test]
    async fn g2_transport_e2e_tunnel() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "dsn-g2-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&tmp)?;

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_pem = ca.cert.pem();
        let key_pem = ca.key_pair.serialize_pem();

        let cert_path = tmp.join("server-cert.pem");
        let key_path = tmp.join("server-key.pem");
        let ca_path = tmp.join("ca.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        fs::write(&ca_path, &cert_pem)?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint = TransportEndpoint::from_str(&format!(
            "g2://127.0.0.1:{}/tunnel.Tunnel/Stream?cert={}&key={}",
            addr.port(),
            cert_path.display(),
            key_path.display()
        ))?;

        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "g2://127.0.0.1:{}/tunnel.Tunnel/Stream?ca={}&servername=localhost",
            addr.port(),
            ca_path.display()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = G2Transport;
            let conn = transport.listen(&listen_endpoint).await.expect("listen g2");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("g2 must return stream"),
            };

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read g2 payload");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write g2 payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = G2Transport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("g2 must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }

    #[test]
    fn transport_factory_supports_h2_and_g2() {
        assert!(transport_for_scheme(TransportScheme::H2).is_ok());
        assert!(transport_for_scheme(TransportScheme::G2).is_ok());
    }

    #[tokio::test]
    async fn ws_transport_e2e_loopback() -> Result<()> {
        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint =
            TransportEndpoint::from_str(&format!("ws://127.0.0.1:{}/chat", addr.port()))?;
        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "ws://127.0.0.1:{}/chat?header.Origin=https://example.test",
            addr.port()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = WsTransport;
            let conn = transport.listen(&listen_endpoint).await.expect("listen ws");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("ws must return stream"),
            };

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read ws payload");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write ws payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = WsTransport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("ws must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        Ok(())
    }

    #[tokio::test]
    async fn wss_transport_e2e_with_self_signed_ca() -> Result<()> {
        let tmp = std::env::temp_dir().join(format!(
            "dsn-wss-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&tmp)?;

        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_pem = ca.cert.pem();
        let key_pem = ca.key_pair.serialize_pem();

        let cert_path = tmp.join("server-cert.pem");
        let key_path = tmp.join("server-key.pem");
        let ca_path = tmp.join("ca.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        fs::write(&ca_path, &cert_pem)?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let addr = probe.local_addr()?;
        drop(probe);

        let listen_endpoint = TransportEndpoint::from_str(&format!(
            "wss://127.0.0.1:{}/chat?cert={}&key={}",
            addr.port(),
            cert_path.display(),
            key_path.display()
        ))?;

        let connect_endpoint = TransportEndpoint::from_str(&format!(
            "wss://127.0.0.1:{}/chat?ca={}&servername=localhost&header.Origin=https://example.test",
            addr.port(),
            ca_path.display()
        ))?;

        let server_task = tokio::spawn(async move {
            let transport = WssTransport;
            let conn = transport
                .listen(&listen_endpoint)
                .await
                .expect("listen wss");
            let mut stream = match conn {
                Connection::Stream(stream) => stream,
                Connection::Datagram(_) => panic!("wss must return stream"),
            };

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read wss payload");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("write wss payload");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let transport = WssTransport;
        let conn = transport.connect(&connect_endpoint).await?;
        let mut stream = match conn {
            Connection::Stream(stream) => stream,
            Connection::Datagram(_) => panic!("wss must return stream"),
        };

        stream.write_all(b"hello").await?;
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await?;
        assert_eq!(&out, b"world");

        server_task.await?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }
}
