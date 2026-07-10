use super::*;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tokio::sync::Mutex;
use tokio::time::timeout;

const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
static LIVE_CPP_INTEROP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn cpp_root() -> PathBuf {
    repo_root().join("cpp")
}

fn fixture_records() -> Vec<Value> {
    let path = repo_root().join("compat/v1/probes/cpp-compat-probe.jsonl");
    let data = std::fs::read_to_string(path).unwrap();
    data.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn parse_hex_u64(input: &str) -> u64 {
    u64::from_str_radix(input, 16).unwrap()
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

#[test]
fn emp_block_fixture_matches_cpp() {
    let xor_probe = Block::make(0xfeedfacecafebeef, 0x0123456789abcdef);
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_block")
    {
        let high = parse_hex_u64(record["inputs"]["high"].as_str().unwrap());
        let low = parse_hex_u64(record["inputs"]["low"].as_str().unwrap());
        let block = Block::make(high, low);
        assert_eq!(block.to_hex(), record["outputs"]["block"].as_str().unwrap());
        assert_eq!(
            block.get_lsb(),
            record["outputs"]["get_lsb"].as_bool().unwrap()
        );
        assert_eq!(
            block.sigma().to_hex(),
            record["outputs"]["sigma"].as_str().unwrap()
        );
        assert_eq!(
            block.xor(xor_probe).to_hex(),
            record["outputs"]["xor_probe"].as_str().unwrap()
        );
    }
}

#[test]
fn emp_bool_fixture_matches_cpp() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_bool")
    {
        let ptr_mod8 = record["inputs"]["ptr_mod8"].as_u64().unwrap() as usize;
        let bool_bytes: Vec<u8> = record["inputs"]["bits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| u8::from(b.as_bool().unwrap()))
            .collect();
        let got = pack_emp_bools(&bool_bytes, ptr_mod8).unwrap();
        assert_eq!(
            hex_encode(&got),
            record["outputs"]["sent"].as_str().unwrap()
        );
        assert_eq!(
            unpack_emp_bools(&got, bool_bytes.len(), ptr_mod8).unwrap(),
            bool_bytes
        );
    }
}

#[test]
fn emp_partial_block_fixture_matches_cpp() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_partial_block")
    {
        let partial_bytes = record["inputs"]["partial_bytes"].as_u64().unwrap() as usize;
        let blocks: Vec<Block> = record["inputs"]["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let bytes: [u8; BLOCK_BYTES] = hex_decode(v.as_str().unwrap()).try_into().unwrap();
                Block::from_bytes(bytes)
            })
            .collect();
        let got = encode_partial_blocks(&blocks, partial_bytes).unwrap();
        assert_eq!(
            hex_encode(&got),
            record["outputs"]["sent"].as_str().unwrap()
        );
        let decoded = decode_partial_blocks(&got, partial_bytes).unwrap();
        for (actual, expected) in decoded.iter().zip(blocks.iter()) {
            assert_eq!(
                &actual.as_bytes()[..partial_bytes],
                &expected.as_bytes()[..partial_bytes]
            );
            assert!(actual.as_bytes()[partial_bytes..].iter().all(|b| *b == 0));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "old C++ probe target is not built by the new emp-ag2pc Makefile"]
async fn live_cpp_peer_three_stream_interop() {
    let _guard = live_cpp_interop_lock().lock().await;
    let bin = cpp_wire_probe();
    run_live_case(&bin, Role::Alice).await;
    run_live_case(&bin, Role::Bob).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ag2pc_rust_rust_transport_interop() {
    let _guard = live_cpp_interop_lock().lock().await;
    let port = free_port();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let alice = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Alice, port, peer).await?;
        exercise_ag2pc_transport(&mut streams, Role::Alice).await
    });
    let bob = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Bob, port, peer).await?;
        exercise_ag2pc_transport(&mut streams, Role::Bob).await
    });
    let (alice, bob) = timeout(LIVE_INTEROP_TIMEOUT, async { tokio::try_join!(alice, bob) })
        .await
        .unwrap()
        .unwrap();
    alice.unwrap();
    bob.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fs_digest_matches_emp_direction_order() {
    let _guard = live_cpp_interop_lock().lock().await;
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut stream = EmpStream::listen(port).await?;
        stream.enable_fs(true)?;
        stream.send_data(b"alpha").await?;
        stream.flush().await?;
        assert_eq!(stream.recv_data(4).await?, b"beta");
        stream.send_data(b"gamma").await?;
        stream.flush().await?;
        Ok::<_, WireError>((
            stream.get_send_digest()?,
            stream.get_recv_digest()?,
            stream.get_digest()?,
            stream.rounds(),
        ))
    });
    let bob = tokio::spawn(async move {
        let mut stream = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await?;
        stream.enable_fs(false)?;
        assert_eq!(stream.recv_data(5).await?, b"alpha");
        stream.send_data(b"beta").await?;
        stream.flush().await?;
        assert_eq!(stream.recv_data(5).await?, b"gamma");
        Ok::<_, WireError>((
            stream.get_send_digest()?,
            stream.get_recv_digest()?,
            stream.get_digest()?,
            stream.rounds(),
        ))
    });
    let (alice, bob) = timeout(LIVE_INTEROP_TIMEOUT, async { tokio::try_join!(alice, bob) })
        .await
        .unwrap()
        .unwrap();
    let (alice_send, alice_recv, alice_digest, alice_rounds) = alice.unwrap();
    let (bob_send, bob_recv, bob_digest, bob_rounds) = bob.unwrap();
    assert_eq!(alice_send, bob_recv);
    assert_eq!(alice_recv, bob_send);
    assert_eq!(alice_digest, bob_digest);
    assert_eq!(alice_rounds, 3);
    assert_eq!(bob_rounds, 3);
}

#[tokio::test]
async fn channel_byte_stream_buffers_and_hashes_transcript() {
    let (alice_tx, bob_rx) = mpsc::channel(4);
    let (bob_tx, alice_rx) = mpsc::channel(4);
    let mut alice = ChannelByteStream::new(alice_tx, alice_rx);
    let mut bob = ChannelByteStream::new(bob_tx, bob_rx);

    alice.enable_fs(true).unwrap();
    bob.enable_fs(false).unwrap();

    alice.send_data(b"alpha").await.unwrap();
    assert_eq!(bob.recv_data(2).await.unwrap(), b"al");
    assert_eq!(bob.recv_data(3).await.unwrap(), b"pha");

    bob.send_data(b"beta").await.unwrap();
    assert_eq!(alice.recv_data(4).await.unwrap(), b"beta");

    alice.send_data(b"gamma").await.unwrap();
    assert_eq!(bob.recv_data(5).await.unwrap(), b"gamma");
    alice.trim_idle_allocations();
    bob.trim_idle_allocations();

    assert_eq!(
        alice.get_send_digest().unwrap(),
        bob.get_recv_digest().unwrap()
    );
    assert_eq!(
        alice.get_recv_digest().unwrap(),
        bob.get_send_digest().unwrap()
    );
    assert_eq!(alice.get_digest().unwrap(), bob.get_digest().unwrap());
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_cpp_ag2pc_transport_interop() {
    let _guard = live_cpp_interop_lock().lock().await;
    let bin = cpp_ag2pc_transport_probe();
    run_live_ag2pc_transport_case(&bin, Role::Alice).await;
    run_live_ag2pc_transport_case(&bin, Role::Bob).await;
}

fn live_cpp_interop_lock() -> &'static Mutex<()> {
    LIVE_CPP_INTEROP_LOCK.get_or_init(|| Mutex::new(()))
}

async fn run_live_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = match rust_role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    };
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let open_result = timeout(
        LIVE_INTEROP_TIMEOUT,
        EmpStreams::open(rust_role, port, peer),
    )
    .await;
    let mut streams = match open_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust stream open timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };

    match timeout(
        LIVE_INTEROP_TIMEOUT,
        exercise_wire_probe_script(&mut streams, rust_role),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("Rust wire script failed: {e}"),
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust wire script timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ wire probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn run_live_ag2pc_transport_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = match rust_role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    };
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let open_result = timeout(
        LIVE_INTEROP_TIMEOUT,
        Ag2pcStreams::open(rust_role, port, peer),
    )
    .await;
    let mut streams = match open_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC stream open timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };

    match timeout(
        LIVE_INTEROP_TIMEOUT,
        exercise_ag2pc_transport(&mut streams, rust_role),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("Rust AG2PC wire script failed: {e}"),
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC wire script timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ AG2PC transport probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn exercise_wire_probe_script(streams: &mut EmpStreams, role: Role) -> Result<()> {
    for (stream_id, stream) in streams.streams_mut().into_iter().enumerate() {
        exercise_stream(stream, role, stream_id).await?;
    }
    Ok(())
}

async fn exercise_ag2pc_transport(streams: &mut Ag2pcStreams, role: Role) -> Result<()> {
    for (stream_id, stream) in streams.streams_mut().into_iter().enumerate() {
        match role {
            Role::Alice => {
                stream
                    .send_data(&ag2pc_payload(Role::Alice, stream_id))
                    .await?;
                stream.flush().await?;
                assert_eq!(
                    stream.recv_data(8).await?,
                    ag2pc_payload(Role::Bob, stream_id)
                );
            }
            Role::Bob => {
                assert_eq!(
                    stream.recv_data(8).await?,
                    ag2pc_payload(Role::Alice, stream_id)
                );
                stream
                    .send_data(&ag2pc_payload(Role::Bob, stream_id))
                    .await?;
                stream.flush().await?;
            }
        }
    }
    Ok(())
}

async fn exercise_stream(stream: &mut EmpStream, role: Role, stream_id: usize) -> Result<()> {
    match role {
        Role::Alice => {
            stream
                .send_data(&raw_payload(Role::Alice, stream_id))
                .await?;
            stream.flush().await?;
            assert_eq!(
                stream.recv_data(8).await?,
                raw_payload(Role::Bob, stream_id)
            );

            let alice_blocks = full_blocks(Role::Alice, stream_id);
            stream.send_block(&alice_blocks).await?;
            stream.flush().await?;
            assert_eq!(
                stream.recv_block(2).await?,
                full_blocks(Role::Bob, stream_id)
            );

            exchange_bools_as_alice(stream, stream_id, 0).await?;
            exchange_bools_as_alice(stream, stream_id, 1).await?;

            let alice_partial = partial_blocks(Role::Alice, stream_id);
            stream
                .send_partial_blocks(&alice_partial, EMP_PARTIAL_BLOCK_BYTES)
                .await?;
            stream.flush().await?;
            assert_partial_prefixes(
                &stream
                    .recv_partial_blocks(3, EMP_PARTIAL_BLOCK_BYTES)
                    .await?,
                &partial_blocks(Role::Bob, stream_id),
            );
        }
        Role::Bob => {
            assert_eq!(
                stream.recv_data(8).await?,
                raw_payload(Role::Alice, stream_id)
            );
            stream.send_data(&raw_payload(Role::Bob, stream_id)).await?;
            stream.flush().await?;

            assert_eq!(
                stream.recv_block(2).await?,
                full_blocks(Role::Alice, stream_id)
            );
            stream
                .send_block(&full_blocks(Role::Bob, stream_id))
                .await?;
            stream.flush().await?;

            exchange_bools_as_bob(stream, stream_id, 0).await?;
            exchange_bools_as_bob(stream, stream_id, 1).await?;

            assert_partial_prefixes(
                &stream
                    .recv_partial_blocks(3, EMP_PARTIAL_BLOCK_BYTES)
                    .await?,
                &partial_blocks(Role::Alice, stream_id),
            );
            stream
                .send_partial_blocks(
                    &partial_blocks(Role::Bob, stream_id),
                    EMP_PARTIAL_BLOCK_BYTES,
                )
                .await?;
            stream.flush().await?;
        }
    }
    Ok(())
}

async fn exchange_bools_as_alice(
    stream: &mut EmpStream,
    stream_id: usize,
    ptr_mod8: usize,
) -> Result<()> {
    let alice_bools = bool_pattern(Role::Alice, stream_id, ptr_mod8);
    stream.send_bool_bytes(&alice_bools, ptr_mod8).await?;
    stream.flush().await?;
    assert_eq!(
        stream
            .recv_bool_bytes(bool_pattern(Role::Bob, stream_id, ptr_mod8).len(), ptr_mod8)
            .await?,
        bool_pattern(Role::Bob, stream_id, ptr_mod8)
    );
    Ok(())
}

async fn exchange_bools_as_bob(
    stream: &mut EmpStream,
    stream_id: usize,
    ptr_mod8: usize,
) -> Result<()> {
    assert_eq!(
        stream
            .recv_bool_bytes(
                bool_pattern(Role::Alice, stream_id, ptr_mod8).len(),
                ptr_mod8,
            )
            .await?,
        bool_pattern(Role::Alice, stream_id, ptr_mod8)
    );
    stream
        .send_bool_bytes(&bool_pattern(Role::Bob, stream_id, ptr_mod8), ptr_mod8)
        .await?;
    stream.flush().await?;
    Ok(())
}

fn assert_partial_prefixes(actual: &[Block], expected: &[Block]) {
    assert_eq!(actual.len(), expected.len());
    for (a, e) in actual.iter().zip(expected.iter()) {
        assert_eq!(
            &a.as_bytes()[..EMP_PARTIAL_BLOCK_BYTES],
            &e.as_bytes()[..EMP_PARTIAL_BLOCK_BYTES]
        );
        assert!(a.as_bytes()[EMP_PARTIAL_BLOCK_BYTES..]
            .iter()
            .all(|b| *b == 0));
    }
}

fn raw_payload(role: Role, stream_id: usize) -> Vec<u8> {
    let tag = match role {
        Role::Alice => 0xa1,
        Role::Bob => 0xb2,
    };
    vec![
        tag,
        stream_id as u8,
        0x10 + stream_id as u8,
        0x20 + stream_id as u8,
        0x30 + stream_id as u8,
        0x40 + stream_id as u8,
        0x50 + stream_id as u8,
        0x60 + stream_id as u8,
    ]
}

fn full_blocks(role: Role, stream_id: usize) -> Vec<Block> {
    let role_tag = u64::from(role.party_id());
    (0..2)
        .map(|i| {
            Block::make(
                0xf000_0000_0000_0000 | (role_tag << 16) | ((stream_id as u64) << 8) | i,
                0x0f00_0000_0000_0000 | (role_tag << 16) | ((stream_id as u64) << 8) | i,
            )
        })
        .collect()
}

fn partial_blocks(role: Role, stream_id: usize) -> Vec<Block> {
    let role_tag = u64::from(role.party_id());
    (0..3)
        .map(|i| {
            Block::make(
                0xc000_0000_0000_0000 | (role_tag << 16) | ((stream_id as u64) << 8) | i,
                0x0c00_0000_0000_0000 | (role_tag << 16) | ((stream_id as u64) << 8) | i,
            )
        })
        .collect()
}

fn bool_pattern(role: Role, stream_id: usize, ptr_mod8: usize) -> Vec<u8> {
    let role_bias = usize::from(role.party_id());
    (0..(17 + stream_id))
        .map(|i| u8::from(((i * 5 + stream_id + role_bias + ptr_mod8) % 7) < 3))
        .collect()
}

fn ag2pc_payload(role: Role, stream_id: usize) -> Vec<u8> {
    let tag = match role {
        Role::Alice => 0xa7,
        Role::Bob => 0xb8,
    };
    vec![
        tag,
        stream_id as u8,
        0x11 + stream_id as u8,
        0x22 + stream_id as u8,
        0x33 + stream_id as u8,
        0x44 + stream_id as u8,
        0x55 + stream_id as u8,
        0x66 + stream_id as u8,
    ]
}

fn cpp_wire_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/emp_wire_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/emp_wire_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success(), "failed to build .build/emp_wire_probe");
    }
    assert!(
        bin.exists(),
        ".build/emp_wire_probe was not built by the Cargo build script or test setup"
    );
    bin
}

#[cfg(feature = "cpp-probes")]
fn cpp_ag2pc_transport_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/ag2pc_transport_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/ag2pc_transport_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to build .build/ag2pc_transport_probe"
        );
    }
    assert!(
        bin.exists(),
        ".build/ag2pc_transport_probe was not built by the Cargo build script"
    );
    bin
}

fn free_port() -> u16 {
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
