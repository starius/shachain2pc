use shachain2pc_types::Role;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

pub const BLOCK_BYTES: usize = 16;
pub const EMP_PARTIAL_BLOCK_BYTES: usize = 5;
pub const EMP_STREAM_COUNT: usize = 3;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Block([u8; BLOCK_BYTES]);

impl Block {
    pub const fn from_bytes(bytes: [u8; BLOCK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn make(high: u64, low: u64) -> Self {
        let mut bytes = [0u8; BLOCK_BYTES];
        bytes[..8].copy_from_slice(&low.to_le_bytes());
        bytes[8..].copy_from_slice(&high.to_le_bytes());
        Self(bytes)
    }

    pub fn zero() -> Self {
        Self([0; BLOCK_BYTES])
    }

    pub fn as_bytes(&self) -> &[u8; BLOCK_BYTES] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; BLOCK_BYTES] {
        self.0
    }

    pub fn get_lsb(self) -> bool {
        (self.0[0] & 1) == 1
    }

    pub fn xor(self, rhs: Self) -> Self {
        let mut out = [0u8; BLOCK_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0[i] ^ rhs.0[i];
        }
        Self(out)
    }

    pub fn and(self, rhs: Self) -> Self {
        let mut out = [0u8; BLOCK_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0[i] & rhs.0[i];
        }
        Self(out)
    }

    pub fn sigma(self) -> Self {
        let low = self.low64();
        let high = self.high64();
        Self::make(low ^ high, high)
    }

    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }

    fn low64(self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().expect("slice length"))
    }

    fn high64(self) -> u64 {
        u64::from_le_bytes(self.0[8..].try_into().expect("slice length"))
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Block").field(&self.to_hex()).finish()
    }
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    InvalidPtrMod8(usize),
    InvalidPartialBlockBytes(usize),
    MalformedBoolEncoding {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    MalformedPartialBlocks {
        partial_bytes: usize,
        actual_bytes: usize,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::InvalidPtrMod8(v) => write!(f, "EMP bool ptr_mod8 must be in 0..8, got {v}"),
            Self::InvalidPartialBlockBytes(v) => {
                write!(f, "partial block byte count must be in 1..16, got {v}")
            }
            Self::MalformedBoolEncoding {
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "malformed EMP bool encoding: expected {expected_bytes} bytes, got {actual_bytes}"
            ),
            Self::MalformedPartialBlocks {
                partial_bytes,
                actual_bytes,
            } => write!(
                f,
                "malformed partial blocks: byte length {actual_bytes} is not a multiple of {partial_bytes}"
            ),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, WireError>;

pub fn emp_bool_wire_len(length: usize, ptr_mod8: usize) -> Result<usize> {
    let Some(prefix) = aligned_prefix_len(length, ptr_mod8)? else {
        return Ok(length);
    };
    Ok(prefix + (length - prefix) / 8 + (length - prefix) % 8)
}

pub fn pack_emp_bools(bool_bytes: &[u8], ptr_mod8: usize) -> Result<Vec<u8>> {
    let Some(prefix) = aligned_prefix_len(bool_bytes.len(), ptr_mod8)? else {
        return Ok(bool_bytes.to_vec());
    };

    let mut out = Vec::with_capacity(emp_bool_wire_len(bool_bytes.len(), ptr_mod8)?);
    out.extend_from_slice(&bool_bytes[..prefix]);

    let aligned = &bool_bytes[prefix..];
    for chunk in aligned.chunks_exact(8) {
        let mut packed = 0u8;
        for (i, b) in chunk.iter().enumerate() {
            packed |= (b & 1) << i;
        }
        out.push(packed);
    }
    let suffix = aligned.len() - aligned.len() % 8;
    out.extend_from_slice(&aligned[suffix..]);
    Ok(out)
}

pub fn unpack_emp_bools(encoded: &[u8], length: usize, ptr_mod8: usize) -> Result<Vec<u8>> {
    let expected = emp_bool_wire_len(length, ptr_mod8)?;
    if encoded.len() != expected {
        return Err(WireError::MalformedBoolEncoding {
            expected_bytes: expected,
            actual_bytes: encoded.len(),
        });
    }

    let Some(prefix) = aligned_prefix_len(length, ptr_mod8)? else {
        return Ok(encoded.to_vec());
    };

    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&encoded[..prefix]);
    let mut pos = prefix;
    let aligned_len = length - prefix;
    for _ in 0..aligned_len / 8 {
        let packed = encoded[pos];
        pos += 1;
        for bit in 0..8 {
            out.push((packed >> bit) & 1);
        }
    }
    out.extend_from_slice(&encoded[pos..]);
    Ok(out)
}

pub fn encode_partial_blocks(blocks: &[Block], partial_bytes: usize) -> Result<Vec<u8>> {
    validate_partial_bytes(partial_bytes)?;
    let mut out = Vec::with_capacity(blocks.len() * partial_bytes);
    for block in blocks {
        out.extend_from_slice(&block.as_bytes()[..partial_bytes]);
    }
    Ok(out)
}

pub fn decode_partial_blocks(bytes: &[u8], partial_bytes: usize) -> Result<Vec<Block>> {
    validate_partial_bytes(partial_bytes)?;
    if !bytes.len().is_multiple_of(partial_bytes) {
        return Err(WireError::MalformedPartialBlocks {
            partial_bytes,
            actual_bytes: bytes.len(),
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / partial_bytes);
    for chunk in bytes.chunks_exact(partial_bytes) {
        let mut block = [0u8; BLOCK_BYTES];
        block[..partial_bytes].copy_from_slice(chunk);
        out.push(Block::from_bytes(block));
    }
    Ok(out)
}

pub struct EmpStream {
    stream: TcpStream,
    counter: u64,
}

impl EmpStream {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self { stream, counter: 0 })
    }

    pub async fn listen(port: u16) -> Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)).await?;
        accept_emp(&listener).await
    }

    pub async fn connect(peer_ip: IpAddr, port: u16) -> Result<Self> {
        connect_emp(SocketAddr::new(peer_ip, port)).await
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.counter += data.len() as u64;
        Ok(())
    }

    pub async fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.stream.read_exact(&mut out).await?;
        Ok(out)
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn send_block(&mut self, blocks: &[Block]) -> Result<()> {
        for block in blocks {
            self.send_data(block.as_bytes()).await?;
        }
        Ok(())
    }

    pub async fn recv_block(&mut self, count: usize) -> Result<Vec<Block>> {
        let bytes = self.recv_data(count * BLOCK_BYTES).await?;
        Ok(bytes
            .chunks_exact(BLOCK_BYTES)
            .map(|chunk| Block::from_bytes(chunk.try_into().expect("chunk length")))
            .collect())
    }

    pub async fn send_bool_bytes(&mut self, bool_bytes: &[u8], ptr_mod8: usize) -> Result<()> {
        let packed = pack_emp_bools(bool_bytes, ptr_mod8)?;
        self.send_data(&packed).await
    }

    pub async fn recv_bool_bytes(&mut self, length: usize, ptr_mod8: usize) -> Result<Vec<u8>> {
        let wire_len = emp_bool_wire_len(length, ptr_mod8)?;
        let encoded = self.recv_data(wire_len).await?;
        unpack_emp_bools(&encoded, length, ptr_mod8)
    }

    pub async fn send_partial_blocks(
        &mut self,
        blocks: &[Block],
        partial_bytes: usize,
    ) -> Result<()> {
        let bytes = encode_partial_blocks(blocks, partial_bytes)?;
        self.send_data(&bytes).await
    }

    pub async fn recv_partial_blocks(
        &mut self,
        count: usize,
        partial_bytes: usize,
    ) -> Result<Vec<Block>> {
        validate_partial_bytes(partial_bytes)?;
        let bytes = self.recv_data(count * partial_bytes).await?;
        decode_partial_blocks(&bytes, partial_bytes)
    }
}

pub struct EmpStreams {
    pub main: EmpStream,
    pub fpre_io0: EmpStream,
    pub fpre_io2_0: EmpStream,
}

impl EmpStreams {
    pub async fn open(role: Role, port: u16, peer_ip: IpAddr) -> Result<Self> {
        match role {
            Role::Alice => Self::listen(port).await,
            Role::Bob => Self::connect(peer_ip, port).await,
        }
    }

    pub async fn listen(port: u16) -> Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)).await?;
        let main = accept_emp(&listener).await?;
        let fpre_io0 = accept_emp(&listener).await?;
        let fpre_io2_0 = accept_emp(&listener).await?;
        Ok(Self {
            main,
            fpre_io0,
            fpre_io2_0,
        })
    }

    pub async fn connect(peer_ip: IpAddr, port: u16) -> Result<Self> {
        let addr = SocketAddr::new(peer_ip, port);
        let main = connect_emp(addr).await?;
        sleep(Duration::from_millis(1)).await;
        let fpre_io0 = connect_emp(addr).await?;
        sleep(Duration::from_millis(1)).await;
        let fpre_io2_0 = connect_emp(addr).await?;
        Ok(Self {
            main,
            fpre_io0,
            fpre_io2_0,
        })
    }

    pub fn streams_mut(&mut self) -> [&mut EmpStream; EMP_STREAM_COUNT] {
        [&mut self.main, &mut self.fpre_io0, &mut self.fpre_io2_0]
    }
}

async fn accept_emp(listener: &TcpListener) -> Result<EmpStream> {
    loop {
        let (stream, _) = listener.accept().await?;
        match EmpStream::new(stream) {
            Ok(stream) => return Ok(stream),
            Err(_) => sleep(Duration::from_millis(1)).await,
        }
    }
}

async fn connect_emp(addr: SocketAddr) -> Result<EmpStream> {
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => match EmpStream::new(stream) {
                Ok(stream) => return Ok(stream),
                Err(_) => sleep(Duration::from_millis(1)).await,
            },
            Err(_) => sleep(Duration::from_millis(1)).await,
        }
    }
}

fn aligned_prefix_len(length: usize, ptr_mod8: usize) -> Result<Option<usize>> {
    if ptr_mod8 >= 8 {
        return Err(WireError::InvalidPtrMod8(ptr_mod8));
    }
    let diff = if ptr_mod8 == 0 { 0 } else { 8 - ptr_mod8 };
    if diff > length || length - diff < 8 {
        Ok(None)
    } else {
        Ok(Some(diff))
    }
}

fn validate_partial_bytes(partial_bytes: usize) -> Result<()> {
    if (1..=BLOCK_BYTES).contains(&partial_bytes) {
        Ok(())
    } else {
        Err(WireError::InvalidPartialBlockBytes(partial_bytes))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use tokio::time::timeout;

    const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
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
                    let bytes: [u8; BLOCK_BYTES] =
                        hex_decode(v.as_str().unwrap()).try_into().unwrap();
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
    async fn live_cpp_peer_three_stream_interop() {
        let bin = cpp_wire_probe();
        run_live_case(&bin, Role::Alice).await;
        run_live_case(&bin, Role::Bob).await;
    }

    async fn run_live_case(bin: &Path, rust_role: Role) {
        let port = free_port();
        let cpp_role = match rust_role {
            Role::Alice => Role::Bob,
            Role::Bob => Role::Alice,
        };
        let mut child = Command::new(bin)
            .current_dir(repo_root())
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

    async fn exercise_wire_probe_script(streams: &mut EmpStreams, role: Role) -> Result<()> {
        for (stream_id, stream) in streams.streams_mut().into_iter().enumerate() {
            exercise_stream(stream, role, stream_id).await?;
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

    fn cpp_wire_probe() -> PathBuf {
        let root = repo_root();
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

    fn free_port() -> u16 {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
