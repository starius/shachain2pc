use super::*;
use shachain2pc_emp_wire::ChannelByteStream;
use shachain2pc_mpc_core::CoreError;
use shachain2pc_mpc_types::MessageKind;

fn params() -> SessionParams {
    SessionParams::new(73, vec![0x22; 32], b"runner-binding".to_vec())
}

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

#[tokio::test]
async fn runner_session_handshake_completes_in_process() {
    let job_id = b"handshake-job".to_vec();
    let (mut alice, mut bob) = memory_transport_pair(job_id.clone(), 8);
    let alice_params = params();
    let bob_params = alice_params.clone();
    let alice_job_id = job_id.clone();
    let bob_job_id = job_id;

    let (alice_result, bob_result) = tokio::join!(
        async move { run_session_handshake(&mut alice, alice_job_id, Role::Alice, alice_params).await },
        async move { run_session_handshake(&mut bob, bob_job_id, Role::Bob, bob_params).await },
    );

    alice_result.unwrap();
    bob_result.unwrap();
}

#[tokio::test]
async fn byte_frame_transport_runs_session_handshake() {
    let (alice_main_tx, bob_main_rx) = mpsc::channel(8);
    let (bob_main_tx, alice_main_rx) = mpsc::channel(8);
    let (alice_sibling_tx, bob_sibling_rx) = mpsc::channel(8);
    let (bob_sibling_tx, alice_sibling_rx) = mpsc::channel(8);

    let mut alice = TransportPair {
        main: ByteFrameTransport::new(ChannelByteStream::new(alice_main_tx, alice_main_rx)),
        sibling: ByteFrameTransport::new(ChannelByteStream::new(
            alice_sibling_tx,
            alice_sibling_rx,
        )),
    };
    let mut bob = TransportPair {
        main: ByteFrameTransport::new(ChannelByteStream::new(bob_main_tx, bob_main_rx)),
        sibling: ByteFrameTransport::new(ChannelByteStream::new(bob_sibling_tx, bob_sibling_rx)),
    };
    let job_id = b"byte-handshake".to_vec();
    let alice_params = params();
    let bob_params = alice_params.clone();
    let alice_job_id = job_id.clone();

    let (alice_result, bob_result) = tokio::join!(
        async move { run_session_handshake(&mut alice, alice_job_id, Role::Alice, alice_params).await },
        async move { run_session_handshake(&mut bob, job_id, Role::Bob, bob_params).await },
    );

    alice_result.unwrap();
    bob_result.unwrap();
}

#[tokio::test]
async fn byte_frame_transport_rejects_oversized_frame() {
    let (tx, rx) = mpsc::channel(1);
    let mut transport = ByteFrameTransport::with_max_frame_bytes(ChannelByteStream::new(tx, rx), 8);
    let err = transport
        .send(frame(
            b"job-d",
            Role::Alice,
            LogicalChannel::Main,
            0,
            b"this payload is too large",
        ))
        .await
        .unwrap_err();
    match err {
        RunnerError::FrameTooLarge { len, max } => {
            assert!(len > max);
            assert_eq!(max, 8);
        }
        err => panic!("unexpected error: {err}"),
    }
}

#[tokio::test]
async fn runner_session_handshake_rejects_param_mismatch() {
    let job_id = b"handshake-job".to_vec();
    let (mut alice, mut bob) = memory_transport_pair(job_id.clone(), 8);
    let alice_params = params();
    let mut bob_params = alice_params.clone();
    bob_params.job_binding.push(0xff);
    let alice_job_id = job_id.clone();
    let bob_job_id = job_id;

    let (alice_result, bob_result) = tokio::join!(
        async move { run_session_handshake(&mut alice, alice_job_id, Role::Alice, alice_params).await },
        async move { run_session_handshake(&mut bob, bob_job_id, Role::Bob, bob_params).await },
    );

    let bob_err = bob_result.unwrap_err();
    assert_eq!(
        bob_err,
        RunnerError::Core(CoreError::SessionParameterMismatch {
            field: "job_binding"
        })
    );
    assert!(matches!(
        alice_result,
        Err(RunnerError::TransportClosed) | Err(RunnerError::Core(_))
    ));
}
