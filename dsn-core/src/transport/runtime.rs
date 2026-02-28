use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use super::{TransportEndpoint, TransportScheme};

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

pub fn transport_for_scheme(scheme: TransportScheme) -> Result<Box<dyn Transport>> {
    match scheme {
        TransportScheme::Tcp => Ok(Box::new(TcpRawTransport)),
        TransportScheme::Udp => Ok(Box::new(UdpRawTransport)),
        _ => Err(anyhow!(
            "transport scheme '{scheme}' is not implemented in raw runtime yet"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{Connection, TcpRawTransport, Transport, TransportEndpoint, UdpRawTransport};
    use anyhow::Result;
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
}
