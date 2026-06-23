use shachain2pc_mpc_core::{ChannelFlow, CoreError};
use shachain2pc_mpc_types::{LogicalChannel, MpcFrame};
use shachain2pc_types::Role;
use std::fmt;
use std::future::Future;
use tokio::sync::mpsc;

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

#[derive(Debug, Eq, PartialEq)]
pub enum RunnerError {
    TransportClosed,
    InternalStateMissing,
    Core(CoreError),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportClosed => write!(f, "MPC transport is closed"),
            Self::InternalStateMissing => write!(f, "MPC transport state is missing"),
            Self::Core(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for RunnerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use shachain2pc_mpc_core::CoreError;
    use shachain2pc_mpc_types::MessageKind;

    fn frame(
        job_id: &[u8],
        sender_role: Role,
        channel: LogicalChannel,
        sequence: u64,
        payload: &[u8],
    ) -> MpcFrame {
        MpcFrame::new(
            job_id.to_vec(),
            sender_role,
            channel,
            sequence,
            MessageKind::ProgramRunRequest,
            payload.to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn memory_transport_moves_main_and_sibling_independently() {
        let job_id = b"job-a".to_vec();
        let (mut alice, mut bob) = memory_transport_pair(job_id.clone(), 4);

        alice
            .main()
            .send(frame(
                &job_id,
                Role::Alice,
                LogicalChannel::Main,
                0,
                b"main",
            ))
            .await
            .unwrap();
        alice
            .sibling()
            .send(frame(
                &job_id,
                Role::Alice,
                LogicalChannel::Sibling,
                0,
                b"sibling",
            ))
            .await
            .unwrap();

        assert_eq!(bob.sibling().recv().await.unwrap().payload, b"sibling");
        assert_eq!(bob.main().recv().await.unwrap().payload, b"main");
    }

    #[tokio::test]
    async fn memory_transport_rejects_sequence_gap() {
        let job_id = b"job-b".to_vec();
        let (mut alice, _bob) = memory_transport_pair(job_id.clone(), 4);
        let err = alice
            .main()
            .send(frame(&job_id, Role::Alice, LogicalChannel::Main, 1, b"gap"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RunnerError::Core(CoreError::SequenceMismatch {
                expected: 0,
                got: 1,
            })
        );
    }

    #[tokio::test]
    async fn memory_transport_rejects_wrong_channel() {
        let job_id = b"job-c".to_vec();
        let (mut alice, _bob) = memory_transport_pair(job_id.clone(), 4);
        let err = alice
            .main()
            .send(frame(
                &job_id,
                Role::Alice,
                LogicalChannel::Sibling,
                0,
                b"wrong",
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RunnerError::Core(CoreError::ChannelMismatch {
                expected: LogicalChannel::Main,
                got: LogicalChannel::Sibling
            })
        );
    }

    #[tokio::test]
    async fn memory_transport_keeps_jobs_separate() {
        let (mut alice_a, mut bob_a) = memory_transport_pair(b"job-a".to_vec(), 4);
        let (mut alice_b, mut bob_b) = memory_transport_pair(b"job-b".to_vec(), 4);

        alice_a
            .main()
            .send(frame(b"job-a", Role::Alice, LogicalChannel::Main, 0, b"a"))
            .await
            .unwrap();
        alice_b
            .main()
            .send(frame(b"job-b", Role::Alice, LogicalChannel::Main, 0, b"b"))
            .await
            .unwrap();

        assert_eq!(bob_b.main().recv().await.unwrap().payload, b"b");
        assert_eq!(bob_a.main().recv().await.unwrap().payload, b"a");
    }
}
