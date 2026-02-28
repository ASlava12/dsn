use anyhow::{Context, Result, bail};
use dsn_core::{DsnConfig, TransportEndpoint, TransportScheme, load_config, resolve_config_path};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{
    self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::cmd::cli::TransportCommands;

pub async fn handle(
    command: TransportCommands,
    explicit_config: Option<std::path::PathBuf>,
) -> Result<()> {
    let _cfg = load_runtime_config(explicit_config.as_deref())?;

    match command {
        TransportCommands::Listen { transport } => {
            let endpoint = parse_transport_endpoint(&transport)?;
            run_listen(endpoint).await
        }
        TransportCommands::Connect { transport } => {
            let endpoint = parse_transport_endpoint(&transport)?;
            run_connect(endpoint).await
        }
    }
}

fn load_runtime_config(explicit_config: Option<&std::path::Path>) -> Result<Option<DsnConfig>> {
    let path = resolve_config_path(explicit_config)?;
    if !path.exists() {
        return Ok(None);
    }

    Ok(Some(load_config(&path)?))
}

fn parse_transport_endpoint(raw: &str) -> Result<TransportEndpoint> {
    TransportEndpoint::from_str(raw).with_context(|| format!("invalid transport endpoint: {raw}"))
}

async fn run_listen(endpoint: TransportEndpoint) -> Result<()> {
    match endpoint.scheme {
        TransportScheme::Tcp => run_tcp_listen(endpoint).await,
        TransportScheme::Udp => run_udp_listen(endpoint).await,
        scheme => {
            bail!("transport listen is currently implemented only for tcp/udp, got '{scheme}'")
        }
    }
}

async fn run_connect(endpoint: TransportEndpoint) -> Result<()> {
    match endpoint.scheme {
        TransportScheme::Tcp => run_tcp_connect(endpoint).await,
        TransportScheme::Udp => run_udp_connect(endpoint).await,
        scheme => {
            bail!("transport connect is currently implemented only for tcp/udp, got '{scheme}'")
        }
    }
}

async fn run_tcp_listen(endpoint: TransportEndpoint) -> Result<()> {
    let bind_addr = endpoint_socket_addr(&endpoint)?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind tcp listener on {bind_addr}"))?;

    let (stream, _) = listener
        .accept()
        .await
        .with_context(|| format!("failed to accept first tcp client on {bind_addr}"))?;

    pipe_tcp_with_io(stream, io::stdin(), io::stdout()).await
}

async fn run_tcp_connect(endpoint: TransportEndpoint) -> Result<()> {
    let remote_addr = endpoint_socket_addr(&endpoint)?;
    let stream = TcpStream::connect(remote_addr)
        .await
        .with_context(|| format!("failed to connect tcp stream to {remote_addr}"))?;

    pipe_tcp_with_io(stream, io::stdin(), io::stdout()).await
}

async fn run_udp_listen(endpoint: TransportEndpoint) -> Result<()> {
    let bind_addr = endpoint_socket_addr(&endpoint)?;
    let socket = Arc::new(
        UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind udp listener on {bind_addr}"))?,
    );

    let mut first_buf = vec![0u8; 64 * 1024];
    let (size, peer_addr) = socket
        .recv_from(&mut first_buf)
        .await
        .with_context(|| format!("failed to receive first udp datagram on {bind_addr}"))?;
    let first_payload = first_buf[..size].to_vec();

    pipe_udp_listen_with_io(
        socket,
        peer_addr,
        Some(first_payload),
        io::stdin(),
        io::stdout(),
    )
    .await
}

async fn run_udp_connect(endpoint: TransportEndpoint) -> Result<()> {
    let remote_addr = endpoint_socket_addr(&endpoint)?;
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind udp client socket")?,
    );
    socket
        .connect(remote_addr)
        .await
        .with_context(|| format!("failed to connect udp socket to {remote_addr}"))?;

    pipe_udp_connected_with_io(socket, io::stdin(), io::stdout()).await
}

fn endpoint_socket_addr(endpoint: &TransportEndpoint) -> Result<SocketAddr> {
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    addr.parse()
        .with_context(|| format!("host must be an IP address for now: {}", endpoint.host))
}

async fn pipe_tcp_with_io<S, I, O>(stream: S, stdin: I, stdout: O) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let (mut stream_read, mut stream_write) = io::split(stream);
    let mut stdin = stdin;
    let mut stdout = stdout;

    let read_to_stdout = async {
        io::copy(&mut stream_read, &mut stdout).await?;
        stdout.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let stdin_to_stream = async {
        io::copy(&mut stdin, &mut stream_write).await?;
        stream_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    tokio::pin!(read_to_stdout);
    tokio::pin!(stdin_to_stream);

    tokio::select! {
        r = &mut read_to_stdout => {
            r.context("failed to forward transport stream into stdout")?;
        }
        r = &mut stdin_to_stream => {
            r.context("failed to forward stdin into transport stream")?;
            read_to_stdout
                .await
                .context("failed to forward transport stream into stdout")?;
        }
    }

    Ok(())
}

async fn pipe_udp_listen_with_io<I, O>(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    initial_payload: Option<Vec<u8>>,
    stdin: I,
    stdout: O,
) -> Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut recv_stdout = Box::pin(recv_udp_from_peer(
        socket.clone(),
        peer_addr,
        initial_payload,
        stdout,
    ));
    let mut send_stdin = Box::pin(send_lines_to_udp_peer(socket, peer_addr, stdin));

    tokio::select! {
        r = &mut recv_stdout => {
            r?;
        }
        r = &mut send_stdin => {
            r?;
        }
    }

    Ok(())
}

async fn pipe_udp_connected_with_io<I, O>(socket: Arc<UdpSocket>, stdin: I, stdout: O) -> Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut recv_stdout = Box::pin(recv_udp_connected(socket.clone(), stdout));
    let mut send_stdin = Box::pin(send_lines_to_udp_connected(socket, stdin));

    tokio::select! {
        r = &mut recv_stdout => {
            r?;
        }
        r = &mut send_stdin => {
            r?;
        }
    }

    Ok(())
}

async fn recv_udp_from_peer<O>(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    initial_payload: Option<Vec<u8>>,
    mut stdout: O,
) -> Result<()>
where
    O: AsyncWrite + Unpin,
{
    if let Some(payload) = initial_payload {
        stdout
            .write_all(&payload)
            .await
            .context("failed to write first udp payload to stdout")?;
        stdout.flush().await.context("failed to flush stdout")?;
    }

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (size, addr) = socket
            .recv_from(&mut buf)
            .await
            .context("failed to receive udp datagram")?;
        if addr != peer_addr {
            continue;
        }

        stdout
            .write_all(&buf[..size])
            .await
            .context("failed to write udp payload to stdout")?;
        stdout.flush().await.context("failed to flush stdout")?;
    }
}

async fn send_lines_to_udp_peer<I>(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    stdin: I,
) -> Result<()>
where
    I: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stdin).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .context("failed to read line from stdin")?
    {
        socket
            .send_to(line.as_bytes(), peer_addr)
            .await
            .context("failed to send udp datagram")?;
    }

    Ok(())
}

async fn recv_udp_connected<O>(socket: Arc<UdpSocket>, mut stdout: O) -> Result<()>
where
    O: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let size = socket
            .recv(&mut buf)
            .await
            .context("failed to receive connected udp datagram")?;
        stdout
            .write_all(&buf[..size])
            .await
            .context("failed to write udp payload to stdout")?;
        stdout.flush().await.context("failed to flush stdout")?;
    }
}

async fn send_lines_to_udp_connected<I>(socket: Arc<UdpSocket>, stdin: I) -> Result<()>
where
    I: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stdin).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .context("failed to read line from stdin")?
    {
        socket
            .send(line.as_bytes())
            .await
            .context("failed to send connected udp datagram")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{pipe_tcp_with_io, pipe_udp_connected_with_io};
    use anyhow::Result;
    use std::sync::Arc;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn tcp_loopback_pipe_forwards_both_directions() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");

            let mut inbuf = vec![0u8; 5];
            stream
                .read_exact(&mut inbuf)
                .await
                .expect("read from client");
            assert_eq!(&inbuf, b"hello");

            stream.write_all(b"world").await.expect("write to client");
            let _ = stream.shutdown().await;
        });

        let client_stream = TcpStream::connect(addr).await?;

        let (mut stdin_tx, stdin_rx) = io::duplex(64);
        stdin_tx.write_all(b"hello").await?;
        stdin_tx.shutdown().await?;

        let (stdout_tx, mut stdout_rx) = io::duplex(64);

        timeout(
            Duration::from_secs(3),
            pipe_tcp_with_io(client_stream, stdin_rx, stdout_tx),
        )
        .await??;

        let mut out = Vec::new();
        stdout_rx.read_to_end(&mut out).await?;
        assert_eq!(out, b"world");

        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn udp_loopback_pipe_is_line_based_stdin_to_datagrams() -> Result<()> {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = server.local_addr()?;

        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        client.connect(server_addr).await?;

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (n1, peer) = server.recv_from(&mut buf).await.expect("recv #1");
                assert_eq!(&buf[..n1], b"line-1");
                server.send_to(b"ack-1", peer).await.expect("send ack1");

                let (n2, _) = server.recv_from(&mut buf).await.expect("recv #2");
                assert_eq!(&buf[..n2], b"line-2");
                server.send_to(b"ack-2", peer).await.expect("send ack2");
            })
        };

        let (mut stdin_tx, stdin_rx) = io::duplex(128);
        let (stdout_tx, mut stdout_rx) = io::duplex(128);

        let pipe_task = tokio::spawn(pipe_udp_connected_with_io(client, stdin_rx, stdout_tx));

        stdin_tx.write_all(b"line-1\nline-2\n").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        stdin_tx.shutdown().await?;

        timeout(Duration::from_secs(3), async {
            pipe_task.await.expect("pipe join")
        })
        .await??;

        server_task.await?;

        let mut out = Vec::new();
        stdout_rx.read_to_end(&mut out).await?;
        assert_eq!(out, b"ack-1ack-2");

        Ok(())
    }
}
