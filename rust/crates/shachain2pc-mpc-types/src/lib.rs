use prost::Message;
use shachain2pc_types::Role;
use std::fmt;
use zeroize::Zeroize;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/shachain2pc.mpc.v1.rs"));
}

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_JOB_ID_BYTES: usize = 64;
pub const FRAME_FLAG_OPTIONAL_KIND: u32 = 1 << 0;
const SUPPORTED_FRAME_FLAGS: u32 = FRAME_FLAG_OPTIONAL_KIND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalChannel {
    Main,
    Sibling,
}

impl LogicalChannel {
    pub fn from_code(code: u32) -> Result<Self, MpcTypeError> {
        match code {
            1 => Ok(Self::Main),
            2 => Ok(Self::Sibling),
            _ => Err(MpcTypeError::BadChannel(code)),
        }
    }

    pub fn code(self) -> u32 {
        match self {
            Self::Main => 1,
            Self::Sibling => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    SessionStart,
    SessionStartAck,
    InputAuthRequest,
    InputAuthResponse,
    ProgramRunRequest,
    ProgramRunResponse,
    CotCheckRequest,
    CotCheckResponse,
    RevealRequest,
    RevealResponse,
    Abort,
    UnknownOptional(u32),
}

impl MessageKind {
    pub fn from_code(code: u32, flags: u32) -> Result<Self, MpcTypeError> {
        match code {
            1 => Ok(Self::SessionStart),
            2 => Ok(Self::SessionStartAck),
            3 => Ok(Self::InputAuthRequest),
            4 => Ok(Self::InputAuthResponse),
            5 => Ok(Self::ProgramRunRequest),
            6 => Ok(Self::ProgramRunResponse),
            7 => Ok(Self::CotCheckRequest),
            8 => Ok(Self::CotCheckResponse),
            9 => Ok(Self::RevealRequest),
            10 => Ok(Self::RevealResponse),
            11 => Ok(Self::Abort),
            _ if flags & FRAME_FLAG_OPTIONAL_KIND != 0 => Ok(Self::UnknownOptional(code)),
            _ => Err(MpcTypeError::UnknownMandatoryKind(code)),
        }
    }

    pub fn code(self) -> u32 {
        match self {
            Self::SessionStart => 1,
            Self::SessionStartAck => 2,
            Self::InputAuthRequest => 3,
            Self::InputAuthResponse => 4,
            Self::ProgramRunRequest => 5,
            Self::ProgramRunResponse => 6,
            Self::CotCheckRequest => 7,
            Self::CotCheckResponse => 8,
            Self::RevealRequest => 9,
            Self::RevealResponse => 10,
            Self::Abort => 11,
            Self::UnknownOptional(code) => code,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MpcFrame {
    pub job_id: Vec<u8>,
    pub sender_role: Role,
    pub channel: LogicalChannel,
    pub sequence: u64,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
    pub flags: u32,
}

impl MpcFrame {
    pub fn new(
        job_id: Vec<u8>,
        sender_role: Role,
        channel: LogicalChannel,
        sequence: u64,
        kind: MessageKind,
        payload: Vec<u8>,
    ) -> Result<Self, MpcTypeError> {
        let flags = match kind {
            MessageKind::UnknownOptional(_) => FRAME_FLAG_OPTIONAL_KIND,
            _ => 0,
        };
        let frame = Self {
            job_id,
            sender_role,
            channel,
            sequence,
            kind,
            payload,
            flags,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), MpcTypeError> {
        validate_job_id(&self.job_id)?;
        validate_flags(self.flags)?;
        if matches!(self.kind, MessageKind::UnknownOptional(_))
            && self.flags & FRAME_FLAG_OPTIONAL_KIND == 0
        {
            return Err(MpcTypeError::UnknownOptionalWithoutFlag);
        }
        Ok(())
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>, MpcTypeError> {
        self.validate()?;
        Ok(self.to_proto().encode_to_vec())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpcTypeError> {
        let proto = proto::MpcFrame::decode(bytes).map_err(MpcTypeError::Decode)?;
        let frame = Self::from_proto(proto)?;
        let canonical = frame.encode_to_vec()?;
        if canonical.as_slice() != bytes {
            return Err(MpcTypeError::NonCanonicalFrame);
        }
        Ok(frame)
    }

    pub fn to_proto(&self) -> proto::MpcFrame {
        proto::MpcFrame {
            protocol_version: PROTOCOL_VERSION,
            job_id: self.job_id.clone(),
            sender_role: role_code(self.sender_role),
            channel: self.channel.code(),
            sequence: self.sequence,
            message_kind: self.kind.code(),
            payload: self.payload.clone(),
            flags: self.flags,
        }
    }

    pub fn from_proto(proto: proto::MpcFrame) -> Result<Self, MpcTypeError> {
        if proto.protocol_version != PROTOCOL_VERSION {
            return Err(MpcTypeError::UnsupportedVersion(proto.protocol_version));
        }
        validate_job_id(&proto.job_id)?;
        validate_flags(proto.flags)?;
        let sender_role = role_from_code(proto.sender_role)?;
        let channel = LogicalChannel::from_code(proto.channel)?;
        let kind = MessageKind::from_code(proto.message_kind, proto.flags)?;
        let frame = Self {
            job_id: proto.job_id,
            sender_role,
            channel,
            sequence: proto.sequence,
            kind,
            payload: proto.payload,
            flags: proto.flags,
        };
        frame.validate()?;
        Ok(frame)
    }
}

impl Clone for MpcFrame {
    fn clone(&self) -> Self {
        Self {
            job_id: self.job_id.clone(),
            sender_role: self.sender_role,
            channel: self.channel,
            sequence: self.sequence,
            kind: self.kind,
            payload: self.payload.clone(),
            flags: self.flags,
        }
    }
}

impl Drop for MpcFrame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStart {
    pub ssp: u32,
    pub circuit_digest: Vec<u8>,
    pub job_binding: Vec<u8>,
}

impl SessionStart {
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpcTypeError> {
        let proto = proto::SessionStart::decode(bytes).map_err(MpcTypeError::Decode)?;
        let out = Self::from_proto(proto);
        if out.encode_to_vec().as_slice() != bytes {
            return Err(MpcTypeError::NonCanonicalFrame);
        }
        Ok(out)
    }

    pub fn to_proto(&self) -> proto::SessionStart {
        proto::SessionStart {
            ssp: self.ssp,
            circuit_digest: self.circuit_digest.clone(),
            job_binding: self.job_binding.clone(),
        }
    }

    pub fn from_proto(proto: proto::SessionStart) -> Self {
        Self {
            ssp: proto.ssp,
            circuit_digest: proto.circuit_digest,
            job_binding: proto.job_binding,
        }
    }
}

#[derive(Debug)]
pub enum MpcTypeError {
    Decode(prost::DecodeError),
    UnsupportedVersion(u32),
    EmptyJobId,
    JobIdTooLong(usize),
    BadRole(u32),
    BadChannel(u32),
    UnsupportedFlags(u32),
    UnknownMandatoryKind(u32),
    UnknownOptionalWithoutFlag,
    NonCanonicalFrame,
}

impl fmt::Display for MpcTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "failed to decode MPC frame: {err}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported MPC protocol version {version}")
            }
            Self::EmptyJobId => write!(f, "MPC frame job_id must not be empty"),
            Self::JobIdTooLong(len) => write!(f, "MPC frame job_id is too long: {len}"),
            Self::BadRole(role) => write!(f, "bad MPC sender role code {role}"),
            Self::BadChannel(channel) => write!(f, "bad MPC logical channel code {channel}"),
            Self::UnsupportedFlags(flags) => write!(f, "unsupported MPC frame flags {flags:#x}"),
            Self::UnknownMandatoryKind(kind) => {
                write!(f, "unknown mandatory MPC message kind {kind}")
            }
            Self::UnknownOptionalWithoutFlag => {
                write!(
                    f,
                    "unknown optional MPC message kind is missing its optional flag"
                )
            }
            Self::NonCanonicalFrame => write!(f, "MPC frame is not canonically encoded"),
        }
    }
}

impl std::error::Error for MpcTypeError {}

fn validate_job_id(job_id: &[u8]) -> Result<(), MpcTypeError> {
    if job_id.is_empty() {
        return Err(MpcTypeError::EmptyJobId);
    }
    if job_id.len() > MAX_JOB_ID_BYTES {
        return Err(MpcTypeError::JobIdTooLong(job_id.len()));
    }
    Ok(())
}

fn validate_flags(flags: u32) -> Result<(), MpcTypeError> {
    if flags & !SUPPORTED_FRAME_FLAGS != 0 {
        return Err(MpcTypeError::UnsupportedFlags(flags));
    }
    Ok(())
}

fn role_code(role: Role) -> u32 {
    match role {
        Role::Alice => 1,
        Role::Bob => 2,
    }
}

fn role_from_code(code: u32) -> Result<Role, MpcTypeError> {
    match code {
        1 => Ok(Role::Alice),
        2 => Ok(Role::Bob),
        _ => Err(MpcTypeError::BadRole(code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn frame_canonical_encoding_is_pinned() {
        let frame = MpcFrame::new(
            vec![1, 2, 3, 4],
            Role::Alice,
            LogicalChannel::Main,
            7,
            MessageKind::SessionStart,
            vec![0xaa, 0x55],
        )
        .unwrap();
        let encoded = frame.encode_to_vec().unwrap();
        assert_eq!(hex(&encoded), "080112040102030418012001280730013a02aa55");
        assert_eq!(MpcFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn session_start_encoding_is_pinned() {
        let msg = SessionStart {
            ssp: 64,
            circuit_digest: vec![0xab, 0xcd],
            job_binding: vec![0x7f],
        };
        let encoded = msg.encode_to_vec();
        assert_eq!(hex(&encoded), "08401202abcd1a017f");
        assert_eq!(SessionStart::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn frame_rejects_bad_context_and_mandatory_unknowns() {
        let mut proto = proto::MpcFrame {
            protocol_version: PROTOCOL_VERSION,
            job_id: vec![1],
            sender_role: 3,
            channel: LogicalChannel::Main.code(),
            sequence: 0,
            message_kind: MessageKind::SessionStart.code(),
            payload: Vec::new(),
            flags: 0,
        };
        assert!(matches!(
            MpcFrame::from_proto(proto.clone()),
            Err(MpcTypeError::BadRole(3))
        ));

        proto.sender_role = role_code(Role::Alice);
        proto.message_kind = 99;
        assert!(matches!(
            MpcFrame::from_proto(proto.clone()),
            Err(MpcTypeError::UnknownMandatoryKind(99))
        ));

        proto.flags = FRAME_FLAG_OPTIONAL_KIND;
        assert_eq!(
            MpcFrame::from_proto(proto).unwrap().kind,
            MessageKind::UnknownOptional(99)
        );
    }

    #[test]
    fn frame_rejects_noncanonical_bytes() {
        let frame = MpcFrame::new(
            vec![1],
            Role::Bob,
            LogicalChannel::Sibling,
            1,
            MessageKind::Abort,
            Vec::new(),
        )
        .unwrap();
        let mut encoded = frame.encode_to_vec().unwrap();
        encoded.extend_from_slice(&[0x40, 0x00]);
        assert!(matches!(
            MpcFrame::decode(&encoded),
            Err(MpcTypeError::NonCanonicalFrame)
        ));
    }
}
