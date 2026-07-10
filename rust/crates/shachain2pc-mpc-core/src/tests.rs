use super::*;

fn auth_pair(
    local_bit: u8,
    peer_bit: u8,
    local_key_low: u64,
    peer_key_low: u64,
    local_delta: Block,
    peer_delta: Block,
) -> (AShareBundle, AShareBundle) {
    let local_key = Block::make(0, local_key_low & !1);
    let peer_key = Block::make(0, peer_key_low & !1);
    let local_mac = peer_key.xor(select_block(local_bit).and(peer_delta));
    let peer_mac = local_key.xor(select_block(peer_bit).and(local_delta));
    (
        AShareBundle {
            mac: local_mac,
            key: local_key,
        },
        AShareBundle {
            mac: peer_mac,
            key: peer_key,
        },
    )
}

fn auth_vectors() -> (Block, Block, Vec<AShareBundle>, Vec<AShareBundle>) {
    let local_delta = Block::make(0, 0x101);
    let peer_delta = Block::make(0, 0x201);
    let pairs = [
        auth_pair(1, 0, 0x10, 0x20, local_delta, peer_delta),
        auth_pair(0, 1, 0x30, 0x40, local_delta, peer_delta),
        auth_pair(1, 1, 0x50, 0x60, local_delta, peer_delta),
    ];
    let local = pairs.iter().map(|(local, _peer)| *local).collect();
    let peer = pairs.iter().map(|(_local, peer)| *peer).collect();
    (local_delta, peer_delta, local, peer)
}

#[test]
fn transpose_128_rows_matches_bit_reference() {
    const ROWS: usize = 128;
    for row_bytes in [1usize, 16, 32, 256] {
        let output_len = row_bytes * 8;
        let mut rows = vec![0u8; ROWS * row_bytes];
        for (i, byte) in rows.iter_mut().enumerate() {
            *byte = ((i * 37 + i / 7 + 0x5a) & 0xff) as u8;
        }
        let reference = transpose_128_rows_bit_reference(&rows, row_bytes, output_len);
        assert_eq!(transpose_128_rows(&rows, row_bytes, output_len), reference);
        assert_eq!(
            transpose_128_rows_soft(&rows, row_bytes, output_len),
            reference
        );
    }
}

fn transpose_128_rows_bit_reference(
    rows: &[u8],
    row_bytes: usize,
    output_len: usize,
) -> Vec<Block> {
    let mut out = vec![Block::zero(); output_len];
    for (col, out_block) in out.iter_mut().enumerate() {
        let mut bytes = [0u8; BLOCK_BYTES];
        let source_byte = col / 8;
        let source_mask = 1 << (col % 8);
        for row in 0..128 {
            if (rows[row * row_bytes + source_byte] & source_mask) != 0 {
                bytes[row / 8] |= 1 << (row % 8);
            }
        }
        *out_block = Block::from_bytes(bytes);
    }
    out
}

fn next_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn next_block(state: &mut u64) -> Block {
    Block::make(next_u64(state), next_u64(state))
}

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
fn gf_mul_clmul_matches_soft() {
    let mut state = 0x7f4a_7c15_9e37_79b9;
    for _ in 0..5000 {
        let lhs = next_block(&mut state);
        let rhs = next_block(&mut state);
        assert_eq!(gf_mul(lhs, rhs), gf_mul_soft(lhs, rhs));
    }

    let one = Block::make(0, 1);
    let ones = Block::make(u64::MAX, u64::MAX);
    let hi = Block::make(1 << 63, 0);
    for &lhs in &[Block::zero(), one, ones, hi] {
        for &rhs in &[Block::zero(), one, ones, hi] {
            assert_eq!(gf_mul(lhs, rhs), gf_mul_soft(lhs, rhs));
        }
    }
}

#[test]
fn gf_pack_128_clmul_matches_soft() {
    let mut state = 0x1234_5678_9abc_def0;
    for _ in 0..200 {
        let data: Vec<Block> = (0..128).map(|_| next_block(&mut state)).collect();
        assert_eq!(gf_pack_128(&data), gf_pack_128_soft(&data));
    }

    let zero = vec![Block::zero(); 128];
    assert_eq!(gf_pack_128(&zero), gf_pack_128_soft(&zero));
    let ones = vec![Block::make(u64::MAX, u64::MAX); 128];
    assert_eq!(gf_pack_128(&ones), gf_pack_128_soft(&ones));
    for i in 0..128 {
        let mut data = vec![Block::zero(); 128];
        data[i] = Block::make(u64::MAX, u64::MAX);
        assert_eq!(gf_pack_128(&data), gf_pack_128_soft(&data));
    }
}

#[test]
fn reveal_recovers_authenticated_public_bits() {
    let (local_delta, peer_delta, local, peer) = auth_vectors();
    assert!(verify_share_relation(
        &local,
        local_delta,
        &peer,
        peer_delta
    ));
    let peer_open = reveal_local_share(&peer);
    let lambda = vec![1, 0, 1];
    let bits = reveal_recipient_bits(
        &lambda,
        &local,
        &peer_open.share_bits,
        peer_open.mac_digest,
        local_delta,
    )
    .unwrap();
    assert_eq!(bits, vec![0, 1, 1]);
}

#[test]
fn reveal_rejects_digest_tamper_and_bad_shape() {
    let (local_delta, _peer_delta, local, peer) = auth_vectors();
    let mut peer_open = reveal_local_share(&peer);
    peer_open.mac_digest[0] ^= 1;
    let err = reveal_recipient_bits(
        &[1, 0, 1],
        &local,
        &peer_open.share_bits,
        peer_open.mac_digest,
        local_delta,
    )
    .unwrap_err();
    assert_eq!(err, RevealError::MacDigestMismatch);

    let err = reveal_recipient_bits(&[1, 0], &local, &[0, 1, 1], [0; 32], local_delta).unwrap_err();
    assert_eq!(
        err,
        RevealError::BadWireShape {
            lambda_len: 2,
            bundle_len: 3,
        }
    );

    let peer_open = reveal_local_share(&peer);
    let err = reveal_recipient_bits(
        &[1, 0, 1],
        &local,
        &[0, 1],
        peer_open.mac_digest,
        local_delta,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RevealError::PeerShareLength {
            expected: 3,
            actual: 2,
        }
    );
}

#[test]
fn input_open_finalizes_authenticated_lambdas() {
    let (local_delta, _peer_delta, local, peer) = auth_vectors();
    let peer_open = reveal_local_share(&peer);
    let lambda = finalize_input_open(
        &local,
        &[1, 0, 0],
        &[1],
        &peer_open.share_bits,
        peer_open.mac_digest,
        &[1],
        local_delta,
    )
    .unwrap();
    assert_eq!(lambda, vec![0, 0, 0]);
}

#[test]
fn input_open_rejects_tamper_and_bad_peer_index() {
    let (local_delta, _peer_delta, local, peer) = auth_vectors();
    let mut peer_open = reveal_local_share(&peer);
    peer_open.mac_digest[0] ^= 1;
    let err = finalize_input_open(
        &local,
        &[1, 0, 0],
        &[1],
        &peer_open.share_bits,
        peer_open.mac_digest,
        &[1],
        local_delta,
    )
    .unwrap_err();
    assert_eq!(err, InputOpenError::MacDigestMismatch);

    let peer_open = reveal_local_share(&peer);
    let err = finalize_input_open(
        &local,
        &[1, 0, 0],
        &[3],
        &peer_open.share_bits,
        peer_open.mac_digest,
        &[1],
        local_delta,
    )
    .unwrap_err();
    assert_eq!(err, InputOpenError::PeerInputIndex { index: 3, len: 3 });
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
