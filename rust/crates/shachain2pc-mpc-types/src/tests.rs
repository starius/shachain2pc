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
fn session_start_ack_encoding_is_pinned() {
    let msg = SessionStartAck {
        transcript_binding: vec![0xab, 0xcd],
    };
    let encoded = msg.encode_to_vec();
    assert_eq!(hex(&encoded), "0a02abcd");
    assert_eq!(SessionStartAck::decode(&encoded).unwrap(), msg);
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
