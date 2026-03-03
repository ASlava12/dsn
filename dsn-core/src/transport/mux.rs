use std::error::Error;
use std::fmt::{Display, Formatter};

use tokio::io;
use tokio::sync::{Mutex, mpsc};

use super::{
    BoxedStreamConn, FrameClass, FrameIoError, FrameLimits, FrameV1, read_frame, write_frame,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinksMode {
    SingleMux,
    MultiConn,
}

impl Default for PeerLinksMode {
    fn default() -> Self {
        Self::SingleMux
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MuxConfig {
    pub queue_capacity_control: usize,
    pub queue_capacity_net: usize,
    pub queue_capacity_data: usize,
    pub net_quota_per_cycle: usize,
    pub frame_limits: FrameLimits,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            queue_capacity_control: 256,
            queue_capacity_net: 1024,
            queue_capacity_data: 2048,
            net_quota_per_cycle: 8,
            frame_limits: FrameLimits::default(),
        }
    }
}

#[derive(Debug)]
pub enum MuxError {
    Frame(FrameIoError),
    QueueClosed(&'static str),
    RecvClosed,
}

impl Display for MuxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(err) => write!(f, "frame error: {err}"),
            Self::QueueClosed(name) => write!(f, "queue '{name}' is closed"),
            Self::RecvClosed => write!(f, "receive channel is closed"),
        }
    }
}

impl Error for MuxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Frame(err) => Some(err),
            _ => None,
        }
    }
}

impl From<FrameIoError> for MuxError {
    fn from(value: FrameIoError) -> Self {
        Self::Frame(value)
    }
}

pub struct MuxConn {
    control_tx: mpsc::Sender<FrameV1>,
    net_tx: mpsc::Sender<FrameV1>,
    data_tx: mpsc::Sender<FrameV1>,
    recv_rx: Mutex<mpsc::Receiver<FrameV1>>,
}

impl MuxConn {
    pub fn new(stream: BoxedStreamConn, config: MuxConfig) -> Self {
        let (read_half, write_half) = io::split(stream);

        let (control_tx, control_rx) = mpsc::channel(config.queue_capacity_control);
        let (net_tx, net_rx) = mpsc::channel(config.queue_capacity_net);
        let (data_tx, data_rx) = mpsc::channel(config.queue_capacity_data);
        let (recv_tx, recv_rx) = mpsc::channel(config.queue_capacity_net.max(64));

        tokio::spawn(writer_loop(write_half, control_rx, net_rx, data_rx, config));
        tokio::spawn(reader_loop(read_half, recv_tx, config.frame_limits));

        Self {
            control_tx,
            net_tx,
            data_tx,
            recv_rx: Mutex::new(recv_rx),
        }
    }

    pub async fn send_control(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        self.control_tx
            .send(FrameV1 {
                class: FrameClass::Control,
                msg_type,
                flags,
                payload,
            })
            .await
            .map_err(|_| MuxError::QueueClosed("control"))
    }

    pub async fn send_net(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        self.net_tx
            .send(FrameV1 {
                class: FrameClass::Net,
                msg_type,
                flags,
                payload,
            })
            .await
            .map_err(|_| MuxError::QueueClosed("net"))
    }

    pub fn send_data(&self, msg_type: u16, flags: u16, payload: Vec<u8>) -> Result<bool, MuxError> {
        let frame = FrameV1 {
            class: FrameClass::Data,
            msg_type,
            flags,
            payload,
        };
        match self.data_tx.try_send(frame) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(MuxError::QueueClosed("data")),
        }
    }

    pub async fn recv(&self) -> Result<FrameV1, MuxError> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(MuxError::RecvClosed)
    }
}

pub struct MultiConn {
    control: ClassConn,
    net: ClassConn,
    data: ClassConn,
    recv_rx: Mutex<mpsc::Receiver<FrameV1>>,
}

impl MultiConn {
    pub fn new(
        control_stream: BoxedStreamConn,
        net_stream: BoxedStreamConn,
        data_stream: BoxedStreamConn,
        limits: FrameLimits,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(1024);

        let control = ClassConn::new(control_stream, recv_tx.clone(), limits);
        let net = ClassConn::new(net_stream, recv_tx.clone(), limits);
        let data = ClassConn::new(data_stream, recv_tx, limits);

        Self {
            control,
            net,
            data,
            recv_rx: Mutex::new(recv_rx),
        }
    }

    pub async fn send_control(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        self.control
            .send(FrameV1 {
                class: FrameClass::Control,
                msg_type,
                flags,
                payload,
            })
            .await
    }

    pub async fn send_net(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        self.net
            .send(FrameV1 {
                class: FrameClass::Net,
                msg_type,
                flags,
                payload,
            })
            .await
    }

    pub async fn send_data(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        self.data
            .send(FrameV1 {
                class: FrameClass::Data,
                msg_type,
                flags,
                payload,
            })
            .await
    }

    pub async fn recv(&self) -> Result<FrameV1, MuxError> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(MuxError::RecvClosed)
    }
}

pub enum PeerLinks {
    SingleMux(MuxConn),
    MultiConn(MultiConn),
}

impl PeerLinks {
    pub fn single_mux(stream: BoxedStreamConn, config: MuxConfig) -> Self {
        Self::SingleMux(MuxConn::new(stream, config))
    }

    pub fn multi_conn(
        control_stream: BoxedStreamConn,
        net_stream: BoxedStreamConn,
        data_stream: BoxedStreamConn,
        limits: FrameLimits,
    ) -> Self {
        Self::MultiConn(MultiConn::new(
            control_stream,
            net_stream,
            data_stream,
            limits,
        ))
    }

    pub fn mode(&self) -> PeerLinksMode {
        match self {
            Self::SingleMux(_) => PeerLinksMode::SingleMux,
            Self::MultiConn(_) => PeerLinksMode::MultiConn,
        }
    }

    pub async fn send_control(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        match self {
            Self::SingleMux(conn) => conn.send_control(msg_type, flags, payload).await,
            Self::MultiConn(conn) => conn.send_control(msg_type, flags, payload).await,
        }
    }

    pub async fn send_net(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        match self {
            Self::SingleMux(conn) => conn.send_net(msg_type, flags, payload).await,
            Self::MultiConn(conn) => conn.send_net(msg_type, flags, payload).await,
        }
    }

    pub async fn send_data(
        &self,
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<bool, MuxError> {
        match self {
            Self::SingleMux(conn) => conn.send_data(msg_type, flags, payload),
            Self::MultiConn(conn) => conn.send_data(msg_type, flags, payload).await.map(|_| true),
        }
    }

    pub async fn recv(&self) -> Result<FrameV1, MuxError> {
        match self {
            Self::SingleMux(conn) => conn.recv().await,
            Self::MultiConn(conn) => conn.recv().await,
        }
    }
}

struct ClassConn {
    write_half: Mutex<io::WriteHalf<BoxedStreamConn>>,
    limits: FrameLimits,
}

impl ClassConn {
    fn new(stream: BoxedStreamConn, recv_tx: mpsc::Sender<FrameV1>, limits: FrameLimits) -> Self {
        let (read_half, write_half) = io::split(stream);
        tokio::spawn(reader_loop(read_half, recv_tx, limits));

        Self {
            write_half: Mutex::new(write_half),
            limits,
        }
    }

    async fn send(&self, frame: FrameV1) -> Result<(), MuxError> {
        let mut writer = self.write_half.lock().await;
        write_frame(&mut *writer, &frame, self.limits).await?;
        Ok(())
    }
}

async fn reader_loop(
    mut read_half: io::ReadHalf<BoxedStreamConn>,
    recv_tx: mpsc::Sender<FrameV1>,
    limits: FrameLimits,
) {
    loop {
        let frame = match read_frame(&mut read_half, limits).await {
            Ok(frame) => frame,
            Err(_) => break,
        };

        if recv_tx.send(frame).await.is_err() {
            break;
        }
    }
}

async fn writer_loop(
    mut write_half: io::WriteHalf<BoxedStreamConn>,
    mut control_rx: mpsc::Receiver<FrameV1>,
    mut net_rx: mpsc::Receiver<FrameV1>,
    mut data_rx: mpsc::Receiver<FrameV1>,
    config: MuxConfig,
) {
    let mut net_budget = config.net_quota_per_cycle;

    loop {
        let frame = if net_budget > 0 {
            tokio::select! {
                biased;
                msg = control_rx.recv() => match msg {
                    Some(frame) => frame,
                    None => break,
                },
                msg = net_rx.recv() => match msg {
                    Some(frame) => {
                        net_budget = net_budget.saturating_sub(1);
                        frame
                    }
                    None => break,
                },
                msg = data_rx.recv() => match msg {
                    Some(frame) => {
                        net_budget = config.net_quota_per_cycle;
                        frame
                    }
                    None => break,
                },
            }
        } else {
            tokio::select! {
                biased;
                msg = control_rx.recv() => match msg {
                    Some(frame) => frame,
                    None => break,
                },
                msg = data_rx.recv() => match msg {
                    Some(frame) => {
                        net_budget = config.net_quota_per_cycle;
                        frame
                    }
                    None => break,
                },
                msg = net_rx.recv() => match msg {
                    Some(frame) => {
                        net_budget = config.net_quota_per_cycle.saturating_sub(1);
                        frame
                    }
                    None => break,
                },
            }
        };

        if write_frame(&mut write_half, &frame, config.frame_limits)
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::io;
    use tokio::time::{Duration, timeout};

    use super::{FrameClass, FrameLimits, MultiConn, MuxConfig, MuxConn};
    use crate::{BoxedStreamConn, FrameV1, read_frame};

    #[tokio::test]
    async fn control_ping_is_not_starved_by_data_flood() {
        let (a, mut b) = io::duplex(8 * 1024);
        let config = MuxConfig {
            queue_capacity_control: 32,
            queue_capacity_net: 64,
            queue_capacity_data: 128,
            net_quota_per_cycle: 4,
            frame_limits: FrameLimits {
                control_max_len: 1024,
                net_max_len: 1024,
                data_max_len: 1024,
            },
        };

        let mux = Arc::new(MuxConn::new(Box::new(a) as BoxedStreamConn, config));

        let control_sent = Arc::new(AtomicBool::new(false));
        let control_sent_flag = control_sent.clone();
        let limits = config.frame_limits;
        let recv_task = tokio::spawn(async move {
            let mut data_after_control_send = 0usize;
            loop {
                let frame = read_frame(&mut b, limits).await.expect("frame decode");
                if frame.class == FrameClass::Control && frame.msg_type == 1 {
                    return data_after_control_send;
                }
                if control_sent_flag.load(Ordering::Relaxed) && frame.class == FrameClass::Data {
                    data_after_control_send += 1;
                }
            }
        });

        let flood_mux = mux.clone();
        let flood = tokio::spawn(async move {
            for _ in 0..20_000 {
                let _ = flood_mux.send_data(200, 0, vec![7; 32]);
                tokio::task::yield_now().await;
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        control_sent.store(true, Ordering::Relaxed);
        mux.send_control(1, 0, b"ping".to_vec())
            .await
            .expect("control enqueue must work");

        let seen_after_control_send = timeout(Duration::from_secs(1), recv_task)
            .await
            .expect("control frame must arrive in time")
            .expect("recv task must join");

        assert!(
            seen_after_control_send < 50,
            "control frame was starved by data flood: {seen_after_control_send} data frames after control send"
        );

        flood.await.expect("flood task must complete");
    }

    #[test]
    fn peer_links_mode_default_is_single_mux() {
        assert_eq!(
            super::PeerLinksMode::default(),
            super::PeerLinksMode::SingleMux
        );
    }

    #[tokio::test]
    async fn multiconn_data_failure_does_not_break_control() {
        let (control_local, mut control_remote) = io::duplex(4096);
        let (net_local, _net_remote) = io::duplex(4096);
        let (data_local, data_remote) = io::duplex(64);

        drop(data_remote);

        let links = MultiConn::new(
            Box::new(control_local) as BoxedStreamConn,
            Box::new(net_local) as BoxedStreamConn,
            Box::new(data_local) as BoxedStreamConn,
            FrameLimits::default(),
        );

        let data_err = links.send_data(99, 0, vec![0u8; 1024]).await;
        assert!(data_err.is_err(), "data path should fail independently");

        links
            .send_control(7, 0, b"still-alive".to_vec())
            .await
            .expect("control path must remain alive");

        let control = timeout(
            Duration::from_secs(1),
            read_frame(&mut control_remote, FrameLimits::default()),
        )
        .await
        .expect("control receive timeout")
        .expect("control frame decode");

        assert_eq!(
            control,
            FrameV1 {
                class: FrameClass::Control,
                msg_type: 7,
                flags: 0,
                payload: b"still-alive".to_vec(),
            }
        );
    }
}
