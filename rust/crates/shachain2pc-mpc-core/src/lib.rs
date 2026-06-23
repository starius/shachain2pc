use sha2::{Digest, Sha256};
use shachain2pc_mpc_types::{LogicalChannel, MessageKind, MpcFrame, SessionStart, SessionStartAck};
use shachain2pc_types::Role;
use std::fmt;

const SESSION_ACK_DOMAIN: &[u8] = b"shachain2pc-mpc-core/session-start-ack/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelFlow {
    job_id: Vec<u8>,
    local_role: Role,
    channel: LogicalChannel,
    next_send: u64,
    next_recv: u64,
    aborted: bool,
}

impl ChannelFlow {
    pub fn new(job_id: Vec<u8>, local_role: Role, channel: LogicalChannel) -> Self {
        Self {
            job_id,
            local_role,
            channel,
            next_send: 0,
            next_recv: 0,
            aborted: false,
        }
    }

    pub fn job_id(&self) -> &[u8] {
        &self.job_id
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    pub fn channel(&self) -> LogicalChannel {
        self.channel
    }

    pub fn next_send(&self) -> u64 {
        self.next_send
    }

    pub fn next_recv(&self) -> u64 {
        self.next_recv
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    pub fn abort(mut self) -> Self {
        self.aborted = true;
        self
    }

    pub fn outbound_frame(
        self,
        kind: MessageKind,
        payload: Vec<u8>,
    ) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        let sequence = self.next_send;
        let frame = MpcFrame::new(
            self.job_id.clone(),
            self.local_role,
            self.channel,
            sequence,
            kind,
            payload,
        )
        .map_err(|err| StepError::new(self.clone(), CoreError::Frame(err.to_string())))?;
        self.accept_outbound(frame)
    }

    pub fn accept_outbound(mut self, frame: MpcFrame) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        if frame.job_id != self.job_id {
            return Err(aborting_error(self, CoreError::JobMismatch));
        }
        if frame.sender_role != self.local_role {
            let expected = self.local_role;
            let got = frame.sender_role;
            return Err(aborting_error(
                self,
                CoreError::RoleMismatch { expected, got },
            ));
        }
        if frame.channel != self.channel {
            let expected = self.channel;
            let got = frame.channel;
            return Err(aborting_error(
                self,
                CoreError::ChannelMismatch { expected, got },
            ));
        }
        if frame.sequence != self.next_send {
            let expected = self.next_send;
            let got = frame.sequence;
            return Err(aborting_error(
                self,
                CoreError::SequenceMismatch { expected, got },
            ));
        }
        self.next_send = self.next_send.saturating_add(1);
        Ok((self, frame))
    }

    pub fn accept_inbound(mut self, frame: MpcFrame) -> StepResult<(Self, MpcFrame)> {
        if self.aborted {
            return Err(StepError::new(self, CoreError::Aborted));
        }
        if frame.job_id != self.job_id {
            return Err(aborting_error(self, CoreError::JobMismatch));
        }
        if frame.sender_role == self.local_role {
            let expected = opposite_role(self.local_role);
            let got = frame.sender_role;
            return Err(aborting_error(
                self,
                CoreError::RoleMismatch { expected, got },
            ));
        }
        if frame.channel != self.channel {
            let expected = self.channel;
            let got = frame.channel;
            return Err(aborting_error(
                self,
                CoreError::ChannelMismatch { expected, got },
            ));
        }
        if frame.sequence != self.next_recv {
            let expected = self.next_recv;
            let got = frame.sequence;
            return Err(aborting_error(
                self,
                CoreError::SequenceMismatch { expected, got },
            ));
        }
        self.next_recv = self.next_recv.saturating_add(1);
        Ok((self, frame))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionParams {
    pub ssp: u32,
    pub circuit_digest: Vec<u8>,
    pub job_binding: Vec<u8>,
}

impl SessionParams {
    pub fn new(ssp: u32, circuit_digest: Vec<u8>, job_binding: Vec<u8>) -> Self {
        Self {
            ssp,
            circuit_digest,
            job_binding,
        }
    }

    pub fn to_start(&self) -> SessionStart {
        SessionStart {
            ssp: self.ssp,
            circuit_digest: self.circuit_digest.clone(),
            job_binding: self.job_binding.clone(),
        }
    }
}

impl From<SessionStart> for SessionParams {
    fn from(value: SessionStart) -> Self {
        Self {
            ssp: value.ssp,
            circuit_digest: value.circuit_digest,
            job_binding: value.job_binding,
        }
    }
}

pub fn send_session_start(
    flow: ChannelFlow,
    params: &SessionParams,
) -> StepResult<(ChannelFlow, MpcFrame)> {
    require_main(flow)?.outbound_frame(MessageKind::SessionStart, params.to_start().encode_to_vec())
}

pub fn receive_session_start_and_ack(
    flow: ChannelFlow,
    expected: &SessionParams,
    frame: MpcFrame,
) -> StepResult<(ChannelFlow, MpcFrame)> {
    let flow = require_main(flow)?;
    let (flow, frame) = flow.accept_inbound(frame)?;
    require_kind(flow, &frame, MessageKind::SessionStart).and_then(|flow| {
        let start = SessionStart::decode(&frame.payload)
            .map_err(|err| aborting_error(flow.clone(), CoreError::Frame(err.to_string())))?;
        compare_session_params(flow, expected, &SessionParams::from(start)).and_then(|flow| {
            let ack = session_start_ack(flow.job_id(), flow.local_role(), expected);
            flow.outbound_frame(MessageKind::SessionStartAck, ack.encode_to_vec())
        })
    })
}

pub fn receive_session_start_ack(
    flow: ChannelFlow,
    expected: &SessionParams,
    frame: MpcFrame,
) -> StepResult<ChannelFlow> {
    let flow = require_main(flow)?;
    let (flow, frame) = flow.accept_inbound(frame)?;
    require_kind(flow, &frame, MessageKind::SessionStartAck).and_then(|flow| {
        let ack = SessionStartAck::decode(&frame.payload)
            .map_err(|err| aborting_error(flow.clone(), CoreError::Frame(err.to_string())))?;
        let expected_ack = session_start_ack(flow.job_id(), frame.sender_role, expected);
        if ack != expected_ack {
            return Err(aborting_error(flow, CoreError::SessionAckMismatch));
        }
        Ok(flow)
    })
}

pub type StepResult<T> = Result<T, StepError>;

#[derive(Debug, Eq, PartialEq)]
pub struct StepError {
    state: ChannelFlow,
    error: CoreError,
}

impl StepError {
    pub fn new(state: ChannelFlow, error: CoreError) -> Self {
        Self { state, error }
    }

    pub fn state(&self) -> &ChannelFlow {
        &self.state
    }

    pub fn error(&self) -> &CoreError {
        &self.error
    }

    pub fn into_parts(self) -> (ChannelFlow, CoreError) {
        (self.state, self.error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    Aborted,
    JobMismatch,
    WrongChannelForPhase {
        expected: LogicalChannel,
        got: LogicalChannel,
    },
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
    UnexpectedMessageKind {
        expected: MessageKind,
        got: MessageKind,
    },
    SessionParameterMismatch {
        field: &'static str,
    },
    SessionAckMismatch,
    Frame(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aborted => write!(f, "MPC job is aborted"),
            Self::JobMismatch => write!(f, "MPC frame job id does not match this state"),
            Self::WrongChannelForPhase { expected, got } => {
                write!(
                    f,
                    "MPC phase channel mismatch: expected {expected:?}, got {got:?}"
                )
            }
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
            Self::UnexpectedMessageKind { expected, got } => {
                write!(
                    f,
                    "MPC frame kind mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::SessionParameterMismatch { field } => {
                write!(f, "MPC session parameter mismatch in {field}")
            }
            Self::SessionAckMismatch => write!(f, "MPC session-start ack mismatch"),
            Self::Frame(err) => write!(f, "invalid MPC frame: {err}"),
        }
    }
}

impl std::error::Error for CoreError {}

fn opposite_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

fn require_main(flow: ChannelFlow) -> StepResult<ChannelFlow> {
    if flow.channel() != LogicalChannel::Main {
        let got = flow.channel();
        return Err(aborting_error(
            flow,
            CoreError::WrongChannelForPhase {
                expected: LogicalChannel::Main,
                got,
            },
        ));
    }
    Ok(flow)
}

fn require_kind(
    flow: ChannelFlow,
    frame: &MpcFrame,
    expected: MessageKind,
) -> StepResult<ChannelFlow> {
    if frame.kind != expected {
        return Err(aborting_error(
            flow,
            CoreError::UnexpectedMessageKind {
                expected,
                got: frame.kind,
            },
        ));
    }
    Ok(flow)
}

fn compare_session_params(
    flow: ChannelFlow,
    expected: &SessionParams,
    got: &SessionParams,
) -> StepResult<ChannelFlow> {
    if expected.ssp != got.ssp {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch { field: "ssp" },
        ));
    }
    if expected.circuit_digest != got.circuit_digest {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch {
                field: "circuit_digest",
            },
        ));
    }
    if expected.job_binding != got.job_binding {
        return Err(aborting_error(
            flow,
            CoreError::SessionParameterMismatch {
                field: "job_binding",
            },
        ));
    }
    Ok(flow)
}

fn aborting_error(flow: ChannelFlow, error: CoreError) -> StepError {
    StepError::new(flow.abort(), error)
}

fn session_start_ack(job_id: &[u8], sender_role: Role, params: &SessionParams) -> SessionStartAck {
    let mut hash = Sha256::new();
    hash.update(SESSION_ACK_DOMAIN);
    update_len_prefixed(&mut hash, job_id);
    hash.update([role_code(sender_role)]);
    hash.update(params.ssp.to_le_bytes());
    update_len_prefixed(&mut hash, &params.circuit_digest);
    update_len_prefixed(&mut hash, &params.job_binding);
    SessionStartAck {
        transcript_binding: hash.finalize().to_vec(),
    }
}

fn update_len_prefixed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn role_code(role: Role) -> u8 {
    match role {
        Role::Alice => 1,
        Role::Bob => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SessionParams {
        SessionParams::new(73, vec![0x11; 32], b"job-binding".to_vec())
    }

    fn frame(job_id: &[u8], sender_role: Role, channel: LogicalChannel, sequence: u64) -> MpcFrame {
        MpcFrame::new(
            job_id.to_vec(),
            sender_role,
            channel,
            sequence,
            MessageKind::ProgramRunRequest,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn outbound_builder_assigns_sequence_and_advances() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main);
        let (state, frame) = state
            .outbound_frame(MessageKind::SessionStart, vec![1, 2, 3])
            .unwrap();
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.sender_role, Role::Alice);
        assert_eq!(frame.channel, LogicalChannel::Main);
        assert_eq!(frame.payload, vec![1, 2, 3]);
        assert_eq!(state.next_send(), 1);
        assert_eq!(state.next_recv(), 0);
    }

    #[test]
    fn inbound_accepts_peer_sequence_and_advances() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Bob, LogicalChannel::Sibling);
        let (state, frame) = state
            .accept_inbound(frame(b"job", Role::Alice, LogicalChannel::Sibling, 0))
            .unwrap();
        assert_eq!(frame.sender_role, Role::Alice);
        assert_eq!(state.next_recv(), 1);
        assert_eq!(state.next_send(), 0);
    }

    #[test]
    fn sequence_gap_preserves_state_in_error() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main);
        let err = state
            .accept_outbound(frame(b"job", Role::Alice, LogicalChannel::Main, 1))
            .unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::SequenceMismatch {
                expected: 0,
                got: 1,
            }
        );
        assert_eq!(err.state().next_send(), 0);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn abort_poisoning_rejects_future_frames() {
        let state = ChannelFlow::new(b"job".to_vec(), Role::Alice, LogicalChannel::Main).abort();
        let err = state
            .accept_outbound(frame(b"job", Role::Alice, LogicalChannel::Main, 0))
            .unwrap_err();
        assert_eq!(err.error(), &CoreError::Aborted);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn session_start_ack_round_trip_validates_params() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);

        let (alice, start) = send_session_start(alice, &params).unwrap();
        assert_eq!(start.kind, MessageKind::SessionStart);
        assert_eq!(alice.next_send(), 1);

        let (bob, ack) = receive_session_start_and_ack(bob, &params, start).unwrap();
        assert_eq!(ack.kind, MessageKind::SessionStartAck);
        assert_eq!(bob.next_recv(), 1);
        assert_eq!(bob.next_send(), 1);

        let alice = receive_session_start_ack(alice, &params, ack).unwrap();
        assert_eq!(alice.next_recv(), 1);
    }

    #[test]
    fn session_start_mismatch_aborts_after_receive() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let mut peer_params = params.clone();
        peer_params.circuit_digest[0] ^= 1;

        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);
        let (_alice, start) = send_session_start(alice, &params).unwrap();
        let err = receive_session_start_and_ack(bob, &peer_params, start).unwrap_err();

        assert_eq!(
            err.error(),
            &CoreError::SessionParameterMismatch {
                field: "circuit_digest"
            }
        );
        assert!(err.state().is_aborted());
        assert_eq!(err.state().next_recv(), 1);
    }

    #[test]
    fn session_ack_tamper_aborts() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let alice = ChannelFlow::new(job_id.clone(), Role::Alice, LogicalChannel::Main);
        let bob = ChannelFlow::new(job_id, Role::Bob, LogicalChannel::Main);
        let (alice, start) = send_session_start(alice, &params).unwrap();
        let (_bob, mut ack) = receive_session_start_and_ack(bob, &params, start).unwrap();
        let mut decoded = SessionStartAck::decode(&ack.payload).unwrap();
        decoded.transcript_binding[0] ^= 1;
        ack.payload = decoded.encode_to_vec();

        let err = receive_session_start_ack(alice, &params, ack).unwrap_err();
        assert_eq!(err.error(), &CoreError::SessionAckMismatch);
        assert!(err.state().is_aborted());
    }

    #[test]
    fn session_start_rejects_wrong_kind_and_sibling_channel() {
        let job_id = b"session-job".to_vec();
        let params = params();
        let bob = ChannelFlow::new(job_id.clone(), Role::Bob, LogicalChannel::Main);
        let wrong = MpcFrame::new(
            job_id.clone(),
            Role::Alice,
            LogicalChannel::Main,
            0,
            MessageKind::ProgramRunRequest,
            Vec::new(),
        )
        .unwrap();
        let err = receive_session_start_and_ack(bob, &params, wrong).unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::UnexpectedMessageKind {
                expected: MessageKind::SessionStart,
                got: MessageKind::ProgramRunRequest,
            }
        );
        assert!(err.state().is_aborted());

        let sibling = ChannelFlow::new(job_id, Role::Alice, LogicalChannel::Sibling);
        let err = send_session_start(sibling, &params).unwrap_err();
        assert_eq!(
            err.error(),
            &CoreError::WrongChannelForPhase {
                expected: LogicalChannel::Main,
                got: LogicalChannel::Sibling,
            }
        );
        assert!(err.state().is_aborted());
    }
}
