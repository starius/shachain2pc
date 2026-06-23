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
    job_id: Vec<u8>,
    local_role: Role,
    channel: LogicalChannel,
    tx: mpsc::Sender<MpcFrame>,
    rx: mpsc::Receiver<MpcFrame>,
    next_send: u64,
    next_recv: u64,
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
            job_id,
            local_role,
            channel,
            tx,
            rx,
            next_send: 0,
            next_recv: 0,
        }
    }

    fn validate_send(&self, frame: &MpcFrame) -> Result<()> {
        if frame.job_id != self.job_id {
            return Err(RunnerError::JobMismatch);
        }
        if frame.sender_role != self.local_role {
            return Err(RunnerError::RoleMismatch {
                expected: self.local_role,
                got: frame.sender_role,
            });
        }
        if frame.channel != self.channel {
            return Err(RunnerError::ChannelMismatch {
                expected: self.channel,
                got: frame.channel,
            });
        }
        if frame.sequence != self.next_send {
            return Err(RunnerError::SequenceMismatch {
                expected: self.next_send,
                got: frame.sequence,
            });
        }
        Ok(())
    }

    fn validate_recv(&self, frame: &MpcFrame) -> Result<()> {
        if frame.job_id != self.job_id {
            return Err(RunnerError::JobMismatch);
        }
        if frame.sender_role == self.local_role {
            return Err(RunnerError::RoleMismatch {
                expected: opposite_role(self.local_role),
                got: frame.sender_role,
            });
        }
        if frame.channel != self.channel {
            return Err(RunnerError::ChannelMismatch {
                expected: self.channel,
                got: frame.channel,
            });
        }
        if frame.sequence != self.next_recv {
            return Err(RunnerError::SequenceMismatch {
                expected: self.next_recv,
                got: frame.sequence,
            });
        }
        Ok(())
    }
}

impl MpcTransport for MemoryTransport {
    async fn send(&mut self, frame: MpcFrame) -> Result<()> {
        self.validate_send(&frame)?;
        self.tx
            .send(frame)
            .await
            .map_err(|_| RunnerError::TransportClosed)?;
        self.next_send = self.next_send.saturating_add(1);
        Ok(())
    }

    async fn recv(&mut self) -> Result<MpcFrame> {
        let frame = self.rx.recv().await.ok_or(RunnerError::TransportClosed)?;
        self.validate_recv(&frame)?;
        self.next_recv = self.next_recv.saturating_add(1);
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
    JobMismatch,
    RoleMismatch {
        expected: Role,
        got: Role,
    },
    ChannelMismatch {
        expected: LogicalChannel,
        got: LogicalChannel,
    },
    SequenceMismatch {
        expected: u64,
        got: u64,
    },
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportClosed => write!(f, "MPC transport is closed"),
            Self::JobMismatch => write!(f, "MPC frame job id does not match this transport"),
            Self::RoleMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame role mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::ChannelMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame channel mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::SequenceMismatch { expected, got } => {
                write!(
                    f,
                    "MPC frame sequence mismatch: expected {expected}, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for RunnerError {}

fn opposite_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            RunnerError::SequenceMismatch {
                expected: 0,
                got: 1
            }
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
            RunnerError::ChannelMismatch {
                expected: LogicalChannel::Main,
                got: LogicalChannel::Sibling
            }
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
