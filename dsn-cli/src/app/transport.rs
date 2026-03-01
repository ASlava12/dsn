use anyhow::{Context, Result, bail};
use dsn_core::{
    Connection, DatagramConn, DsnConfig, TransportEndpoint, TransportScheme, load_config,
    resolve_config_path, transport_for_scheme,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::cmd::cli::TransportCommands;

pub async fn handle(command: TransportCommands, explicit_config: Option<PathBuf>) -> Result<()> {
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

fn load_runtime_config(explicit_config: Option<&Path>) -> Result<Option<DsnConfig>> {
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
    let transport = transport_for_scheme(endpoint.scheme)?;
    let connection = transport.listen(&endpoint).await?;

    match connection {
        Connection::Stream(stream) => pipe_stream_with_io(stream, io::stdin(), io::stdout()).await,
        Connection::Datagram(datagram) => {
            if endpoint.scheme != TransportScheme::Udp {
                bail!("listen datagram mode is currently supported only for udp");
            }
            run_udp_listen_pipe(datagram).await
        }
    }
}

async fn run_connect(endpoint: TransportEndpoint) -> Result<()> {
    let transport = transport_for_scheme(endpoint.scheme)?;
    let connection = transport.connect(&endpoint).await?;

    match connection {
        Connection::Stream(stream) => pipe_stream_with_io(stream, io::stdin(), io::stdout()).await,
        Connection::Datagram(datagram) => {
            if endpoint.scheme != TransportScheme::Udp {
                bail!("connect datagram mode is currently supported only for udp");
            }
            pipe_udp_connected_with_io(Arc::from(datagram), io::stdin(), io::stdout(), None).await
        }
    }
}

async fn run_udp_listen_pipe(datagram: Box<dyn DatagramConn>) -> Result<()> {
    let mut first_buf = vec![0u8; 64 * 1024];
    let (size, peer_addr) = datagram
        .recv(&mut first_buf)
        .await
        .context("failed to receive first udp datagram")?;
    let first_payload = first_buf[..size].to_vec();

    datagram
        .connect(peer_addr)
        .await
        .with_context(|| format!("failed to lock udp listener to first peer {peer_addr}"))?;

    pipe_udp_connected_with_io(
        Arc::from(datagram),
        io::stdin(),
        io::stdout(),
        Some(first_payload),
    )
    .await
    .with_context(|| "failed udp listen pipe after first peer lock")
}

async fn pipe_stream_with_io<S, I, O>(stream: S, stdin: I, stdout: O) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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

async fn pipe_udp_connected_with_io<I, O>(
    conn: Arc<dyn DatagramConn>,
    stdin: I,
    stdout: O,
    initial_payload: Option<Vec<u8>>,
) -> Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut recv_stdout = Box::pin(recv_udp_connected(conn.clone(), stdout, initial_payload));
    let mut send_stdin = Box::pin(send_lines_to_udp_connected(conn, stdin));

    tokio::select! {
        r = &mut recv_stdout => r?,
        r = &mut send_stdin => r?,
    }

    Ok(())
}

async fn recv_udp_connected<O>(
    conn: Arc<dyn DatagramConn>,
    mut stdout: O,
    initial_payload: Option<Vec<u8>>,
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
        let (size, _) = conn
            .recv(&mut buf)
            .await
            .context("failed to receive udp datagram")?;
        stdout
            .write_all(&buf[..size])
            .await
            .context("failed to write udp payload to stdout")?;
        stdout.flush().await.context("failed to flush stdout")?;
    }
}

async fn send_lines_to_udp_connected<I>(conn: Arc<dyn DatagramConn>, stdin: I) -> Result<()>
where
    I: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stdin).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .context("failed to read line from stdin")?
    {
        conn.send(line.as_bytes(), None)
            .await
            .context("failed to send connected udp datagram")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{pipe_stream_with_io, pipe_udp_connected_with_io};
    use anyhow::Result;
    use dsn_core::{Connection, DatagramConn, Transport, TransportEndpoint, UdpRawTransport};
    use std::str::FromStr;
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
            pipe_stream_with_io(client_stream, stdin_rx, stdout_tx),
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

        let endpoint = TransportEndpoint::from_str(&format!("udp://{}", server_addr))?;
        let transport = UdpRawTransport;
        let conn = transport.connect(&endpoint).await?;
        let datagram: Arc<dyn DatagramConn> = match conn {
            Connection::Datagram(datagram) => Arc::from(datagram),
            Connection::Stream(_) => panic!("udp transport must return datagram connection"),
        };

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

        let pipe_task = tokio::spawn(pipe_udp_connected_with_io(
            datagram, stdin_rx, stdout_tx, None,
        ));

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
