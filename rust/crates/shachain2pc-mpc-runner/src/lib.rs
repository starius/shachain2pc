use shachain2pc_emp_wire::ByteIo;
use shachain2pc_mpc_core::{
    receive_session_start_ack, receive_session_start_and_ack, send_session_start, ChannelFlow,
    CoreError, SessionParams, StepResult,
};
use shachain2pc_mpc_types::{LogicalChannel, MpcFrame};
use shachain2pc_types::Role;
use std::fmt;
use std::future::Future;
use tokio::sync::mpsc;

pub use shachain2pc_mpc_core::SessionParams as RunnerSessionParams;

const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub trait MpcTransport: Send {
    fn send<'a>(&'a mut self, frame: MpcFrame) -> impl Future<Output = Result<()>> + Send + 'a;

    fn recv(&mut self) -> impl Future<Output = Result<MpcFrame>> + Send + '_;

    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send + '_;
}

pub trait MpcTransportSet {
    type Main: MpcTransport;
    type Sibling: MpcTransport;

    fn main(&mut self) -> &mut Self::Main;

    fn sibling(&mut self) -> &mut Self::Sibling;
}

pub struct TransportPair<M, S = M> {
    pub main: M,
    pub sibling: S,
}

impl<M: MpcTransport, S: MpcTransport> MpcTransportSet for TransportPair<M, S> {
    type Main = M;
    type Sibling = S;

    fn main(&mut self) -> &mut Self::Main {
        &mut self.main
    }

    fn sibling(&mut self) -> &mut Self::Sibling {
        &mut self.sibling
    }
}

pub struct ByteFrameTransport<S> {
    stream: S,
    max_frame_bytes: usize,
}

impl<S> ByteFrameTransport<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    pub fn with_max_frame_bytes(stream: S, max_frame_bytes: usize) -> Self {
        Self {
            stream,
            max_frame_bytes,
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: ByteIo> MpcTransport for ByteFrameTransport<S> {
    async fn send(&mut self, frame: MpcFrame) -> Result<()> {
        let bytes = frame
            .encode_to_vec()
            .map_err(|err| RunnerError::Frame(err.to_string()))?;
        if bytes.len() > self.max_frame_bytes {
            return Err(RunnerError::FrameTooLarge {
                len: bytes.len(),
                max: self.max_frame_bytes,
            });
        }
        let len = u32::try_from(bytes.len())
            .map_err(|_| RunnerError::Frame(err_frame_too_large(bytes.len())))?;
        self.stream.send_data(&len.to_le_bytes()).await?;
        self.stream.send_data(&bytes).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<MpcFrame> {
        let len = self.stream.recv_data(4).await?;
        let len = u32::from_le_bytes(len.as_slice().try_into().expect("length prefix is 4 bytes"))
            as usize;
        if len > self.max_frame_bytes {
            return Err(RunnerError::FrameTooLarge {
                len,
                max: self.max_frame_bytes,
            });
        }
        let bytes = self.stream.recv_data(len).await?;
        MpcFrame::decode(&bytes).map_err(|err| RunnerError::Frame(err.to_string()))
    }

    async fn flush(&mut self) -> Result<()> {
        self.stream.flush().await?;
        Ok(())
    }
}

pub fn memory_transport_pair(
    job_id: Vec<u8>,
    capacity: usize,
) -> (
    TransportPair<MemoryTransport>,
    TransportPair<MemoryTransport>,
) {
    let (alice_main_tx, bob_main_rx) = mpsc::channel(capacity);
    let (bob_main_tx, alice_main_rx) = mpsc::channel(capacity);
    let (alice_sibling_tx, bob_sibling_rx) = mpsc::channel(capacity);
    let (bob_sibling_tx, alice_sibling_rx) = mpsc::channel(capacity);

    let alice = TransportPair {
        main: MemoryTransport::new(
            job_id.clone(),
            Role::Alice,
            LogicalChannel::Main,
            alice_main_tx,
            alice_main_rx,
        ),
        sibling: MemoryTransport::new(
            job_id.clone(),
            Role::Alice,
            LogicalChannel::Sibling,
            alice_sibling_tx,
            alice_sibling_rx,
        ),
    };
    let bob = TransportPair {
        main: MemoryTransport::new(
            job_id.clone(),
            Role::Bob,
            LogicalChannel::Main,
            bob_main_tx,
            bob_main_rx,
        ),
        sibling: MemoryTransport::new(
            job_id,
            Role::Bob,
            LogicalChannel::Sibling,
            bob_sibling_tx,
            bob_sibling_rx,
        ),
    };
    (alice, bob)
}

pub async fn run_session_handshake<T: MpcTransportSet>(
    transports: &mut T,
    job_id: Vec<u8>,
    role: Role,
    params: SessionParams,
) -> Result<()> {
    let mut flow = ChannelFlow::new(job_id, role, LogicalChannel::Main);
    match role {
        Role::Alice => {
            let (next, start) = map_core(send_session_start(flow, &params))?;
            flow = next;
            transports.main().send(start).await?;
            transports.main().flush().await?;

            let peer_ack = transports.main().recv().await?;
            flow = map_core(receive_session_start_ack(flow, &params, peer_ack))?;

            let peer_start = transports.main().recv().await?;
            let (_flow, ack) = map_core(receive_session_start_and_ack(flow, &params, peer_start))?;
            transports.main().send(ack).await?;
            transports.main().flush().await?;
        }
        Role::Bob => {
            let peer_start = transports.main().recv().await?;
            let (next, ack) = map_core(receive_session_start_and_ack(flow, &params, peer_start))?;
            flow = next;
            transports.main().send(ack).await?;
            transports.main().flush().await?;

            let (next, start) = map_core(send_session_start(flow, &params))?;
            flow = next;
            transports.main().send(start).await?;
            transports.main().flush().await?;

            let peer_ack = transports.main().recv().await?;
            map_core(receive_session_start_ack(flow, &params, peer_ack))?;
        }
    }
    Ok(())
}

pub struct MemoryTransport {
    flow: Option<ChannelFlow>,
    tx: mpsc::Sender<MpcFrame>,
    rx: mpsc::Receiver<MpcFrame>,
}

impl MemoryTransport {
    pub fn new(
        job_id: Vec<u8>,
        local_role: Role,
        channel: LogicalChannel,
        tx: mpsc::Sender<MpcFrame>,
        rx: mpsc::Receiver<MpcFrame>,
    ) -> Self {
        Self {
            flow: Some(ChannelFlow::new(job_id, local_role, channel)),
            tx,
            rx,
        }
    }

    fn take_flow(&mut self) -> Result<ChannelFlow> {
        self.flow.take().ok_or(RunnerError::InternalStateMissing)
    }
}

impl MpcTransport for MemoryTransport {
    async fn send(&mut self, frame: MpcFrame) -> Result<()> {
        let flow = self.take_flow()?;
        let (flow, frame) = match flow.accept_outbound(frame) {
            Ok(ok) => ok,
            Err(err) => {
                let (flow, error) = err.into_parts();
                self.flow = Some(flow);
                return Err(RunnerError::Core(error));
            }
        };
        self.flow = Some(flow);
        self.tx
            .send(frame)
            .await
            .map_err(|_| RunnerError::TransportClosed)?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<MpcFrame> {
        let frame = self.rx.recv().await.ok_or(RunnerError::TransportClosed)?;
        let flow = self.take_flow()?;
        let (flow, frame) = match flow.accept_inbound(frame) {
            Ok(ok) => ok,
            Err(err) => {
                let (flow, error) = err.into_parts();
                self.flow = Some(flow);
                return Err(RunnerError::Core(error));
            }
        };
        self.flow = Some(flow);
        Ok(frame)
    }

    async fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

pub type Result<T> = std::result::Result<T, RunnerError>;

fn map_core<T>(result: StepResult<T>) -> Result<T> {
    result.map_err(|err| {
        let (_state, error) = err.into_parts();
        RunnerError::Core(error)
    })
}

fn err_frame_too_large(len: usize) -> String {
    format!("MPC frame length {len} does not fit in u32")
}

#[derive(Debug, Eq, PartialEq)]
pub enum RunnerError {
    TransportClosed,
    InternalStateMissing,
    Frame(String),
    FrameTooLarge { len: usize, max: usize },
    Core(CoreError),
    Wire(String),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportClosed => write!(f, "MPC transport is closed"),
            Self::InternalStateMissing => write!(f, "MPC transport state is missing"),
            Self::Frame(err) => write!(f, "bad MPC frame: {err}"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "MPC frame is too large: {len} bytes > {max} bytes")
            }
            Self::Core(err) => write!(f, "{err}"),
            Self::Wire(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<shachain2pc_emp_wire::WireError> for RunnerError {
    fn from(value: shachain2pc_emp_wire::WireError) -> Self {
        Self::Wire(value.to_string())
    }
}

#[cfg(test)]
mod tests;
