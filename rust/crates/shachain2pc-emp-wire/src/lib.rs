use sha2::{Digest, Sha256};
use shachain2pc_types::Role;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::sleep;
use zeroize::Zeroize;

pub const BLOCK_BYTES: usize = 16;
pub const EMP_PARTIAL_BLOCK_BYTES: usize = 5;
pub const EMP_STREAM_COUNT: usize = 3;
pub const AG2PC_STREAM_COUNT: usize = 2;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
#[repr(transparent)] // same layout as [u8; 16] / aes::Block, so &mut [Block] can be
                     // reinterpreted for batched AES-NI (see emp-compat Prp).
pub struct Block([u8; BLOCK_BYTES]);

impl Block {
    #[inline]
    pub const fn from_bytes(bytes: [u8; BLOCK_BYTES]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn make(high: u64, low: u64) -> Self {
        Self((((high as u128) << 64) | (low as u128)).to_le_bytes())
    }

    #[inline]
    pub fn zero() -> Self {
        Self([0; BLOCK_BYTES])
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; BLOCK_BYTES] {
        &self.0
    }

    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; BLOCK_BYTES] {
        &mut self.0
    }

    /// View a slice of `Block`s as the underlying contiguous bytes, with no copy.
    #[inline]
    pub fn slice_as_bytes(blocks: &[Block]) -> &[u8] {
        // SAFETY: Block is repr(transparent) over [u8; BLOCK_BYTES] (align 1), so a
        // run of `blocks` is exactly blocks.len() * BLOCK_BYTES contiguous bytes.
        unsafe {
            core::slice::from_raw_parts(blocks.as_ptr().cast::<u8>(), blocks.len() * BLOCK_BYTES)
        }
    }

    /// Mutable byte view of a contiguous block slice, with no copy.
    #[inline]
    pub fn slice_as_mut_bytes(blocks: &mut [Block]) -> &mut [u8] {
        // SAFETY: same layout argument as slice_as_bytes.
        unsafe {
            core::slice::from_raw_parts_mut(
                blocks.as_mut_ptr().cast::<u8>(),
                blocks.len() * BLOCK_BYTES,
            )
        }
    }

    #[inline]
    pub fn into_bytes(self) -> [u8; BLOCK_BYTES] {
        self.0
    }

    #[inline]
    pub fn get_lsb(self) -> bool {
        (self.0[0] & 1) == 1
    }

    // 128-bit xor/and: from_ne_bytes/to_ne_bytes are bit reinterprets, so these
    // compile to a single SIMD op instead of a 16-byte scalar loop.
    #[inline]
    pub fn xor(self, rhs: Self) -> Self {
        Self((u128::from_ne_bytes(self.0) ^ u128::from_ne_bytes(rhs.0)).to_ne_bytes())
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        Self((u128::from_ne_bytes(self.0) & u128::from_ne_bytes(rhs.0)).to_ne_bytes())
    }

    #[inline]
    pub fn sigma(self) -> Self {
        let low = self.low64();
        let high = self.high64();
        Self::make(low ^ high, high)
    }

    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }

    #[inline]
    fn low64(self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().expect("slice length"))
    }

    #[inline]
    fn high64(self) -> u64 {
        u64::from_le_bytes(self.0[8..].try_into().expect("slice length"))
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Block").field(&self.to_hex()).finish()
    }
}

impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    FsAlreadyEnabled,
    FsNotEnabled,
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
            Self::FsAlreadyEnabled => write!(f, "Fiat-Shamir transcript already enabled"),
            Self::FsNotEnabled => write!(f, "Fiat-Shamir transcript is not enabled"),
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

pub trait ByteIo: Send {
    fn send_data<'a>(&'a mut self, data: &'a [u8]) -> impl Future<Output = Result<()>> + Send + 'a;

    fn recv_data(&mut self, len: usize) -> impl Future<Output = Result<Vec<u8>>> + Send + '_;

    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send + '_;

    fn send_block<'a>(
        &'a mut self,
        blocks: &'a [Block],
    ) -> impl Future<Output = Result<()>> + Send + 'a {
        async move { self.send_data(Block::slice_as_bytes(blocks)).await }
    }

    fn recv_block(&mut self, count: usize) -> impl Future<Output = Result<Vec<Block>>> + Send + '_ {
        async move {
            let bytes = self.recv_data(count * BLOCK_BYTES).await?;
            let mut out = Vec::with_capacity(count);
            for chunk in bytes.chunks_exact(BLOCK_BYTES) {
                let mut block = [0u8; BLOCK_BYTES];
                block.copy_from_slice(chunk);
                out.push(Block::from_bytes(block));
            }
            Ok(out)
        }
    }

    fn send_bool_bytes<'a>(
        &'a mut self,
        bool_bytes: &'a [u8],
        ptr_mod8: usize,
    ) -> impl Future<Output = Result<()>> + Send + 'a {
        async move {
            let packed = pack_emp_bools(bool_bytes, ptr_mod8)?;
            self.send_data(&packed).await
        }
    }

    fn recv_bool_bytes(
        &mut self,
        length: usize,
        ptr_mod8: usize,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send + '_ {
        async move {
            let wire_len = emp_bool_wire_len(length, ptr_mod8)?;
            let encoded = self.recv_data(wire_len).await?;
            unpack_emp_bools(&encoded, length, ptr_mod8)
        }
    }

    fn send_partial_blocks<'a>(
        &'a mut self,
        blocks: &'a [Block],
        partial_bytes: usize,
    ) -> impl Future<Output = Result<()>> + Send + 'a {
        async move {
            let bytes = encode_partial_blocks(blocks, partial_bytes)?;
            self.send_data(&bytes).await
        }
    }

    fn recv_partial_blocks(
        &mut self,
        count: usize,
        partial_bytes: usize,
    ) -> impl Future<Output = Result<Vec<Block>>> + Send + '_ {
        async move {
            let bytes = self.recv_data(count * partial_bytes).await?;
            decode_partial_blocks(&bytes, partial_bytes)
        }
    }
}

pub trait TranscriptIo: ByteIo {
    fn enable_fs(&mut self, send_first: bool) -> Result<()>;

    fn fs_enabled(&self) -> bool;

    fn get_send_digest(&self) -> Result<Block>;

    fn get_recv_digest(&self) -> Result<Block>;

    fn get_digest(&self) -> Result<Block>;
}

pub trait IdleTrim {
    fn trim_idle_allocations(&mut self) {}
}

/// In-memory byte stream backed by paired Tokio channels.
///
/// This is used by non-EMP transports, such as daemon JobStream, after their
/// frame layer has already validated job and channel metadata.
pub struct ChannelByteStream {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    recv_buf: VecDeque<u8>,
    fs_send_first: bool,
    fs_send: Option<Sha256>,
    fs_recv: Option<Sha256>,
}

impl ChannelByteStream {
    pub fn new(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            tx,
            rx,
            recv_buf: VecDeque::new(),
            fs_send_first: false,
            fs_send: None,
            fs_recv: None,
        }
    }
}

impl IdleTrim for ChannelByteStream {
    fn trim_idle_allocations(&mut self) {
        self.recv_buf.shrink_to_fit();
    }
}

impl ByteIo for ChannelByteStream {
    async fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Result<()> {
        if let Some(fs_send) = &mut self.fs_send {
            fs_send.update(data);
        }
        self.tx.send(data.to_vec()).await.map_err(|_| {
            WireError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "byte channel closed",
            ))
        })
    }

    async fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        while self.recv_buf.len() < len {
            let chunk = self.rx.recv().await.ok_or_else(|| {
                WireError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "byte channel closed",
                ))
            })?;
            self.recv_buf.extend(chunk);
        }
        let out: Vec<u8> = self.recv_buf.drain(..len).collect();
        if let Some(fs_recv) = &mut self.fs_recv {
            fs_recv.update(&out);
        }
        Ok(out)
    }

    async fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl TranscriptIo for ChannelByteStream {
    fn enable_fs(&mut self, send_first: bool) -> Result<()> {
        if self.fs_send.is_some() {
            return Err(WireError::FsAlreadyEnabled);
        }
        self.fs_send_first = send_first;
        self.fs_send = Some(Sha256::new());
        self.fs_recv = Some(Sha256::new());
        Ok(())
    }

    fn fs_enabled(&self) -> bool {
        self.fs_send.is_some()
    }

    fn get_send_digest(&self) -> Result<Block> {
        let digest = digest_snapshot(self.fs_send.as_ref().ok_or(WireError::FsNotEnabled)?);
        Ok(first_digest_block(&digest))
    }

    fn get_recv_digest(&self) -> Result<Block> {
        let digest = digest_snapshot(self.fs_recv.as_ref().ok_or(WireError::FsNotEnabled)?);
        Ok(first_digest_block(&digest))
    }

    fn get_digest(&self) -> Result<Block> {
        let send = digest_snapshot(self.fs_send.as_ref().ok_or(WireError::FsNotEnabled)?);
        let recv = digest_snapshot(self.fs_recv.as_ref().ok_or(WireError::FsNotEnabled)?);
        let mut h = Sha256::new();
        if self.fs_send_first {
            h.update(send);
            h.update(recv);
        } else {
            h.update(recv);
            h.update(send);
        }
        let digest: [u8; 32] = h.finalize().into();
        Ok(first_digest_block(&digest))
    }
}

impl IdleTrim for EmpStream {}

pub struct EmpStream {
    stream: TcpStream,
    send_counter: u64,
    recv_counter: u64,
    rounds: u64,
    flushes_count: u64,
    last_dir: LastDir,
    send_dirty: bool,
    fs_send_first: bool,
    fs_send: Option<Sha256>,
    fs_recv: Option<Sha256>,
}

impl EmpStream {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            send_counter: 0,
            recv_counter: 0,
            rounds: 0,
            flushes_count: 0,
            last_dir: LastDir::None,
            send_dirty: false,
            fs_send_first: false,
            fs_send: None,
            fs_recv: None,
        })
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
        self.send_counter
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }

    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    pub fn flushes_count(&self) -> u64 {
        self.flushes_count
    }

    pub fn enable_fs(&mut self, send_first: bool) -> Result<()> {
        if self.fs_send.is_some() {
            return Err(WireError::FsAlreadyEnabled);
        }
        self.fs_send_first = send_first;
        self.fs_send = Some(Sha256::new());
        self.fs_recv = Some(Sha256::new());
        Ok(())
    }

    pub fn fs_enabled(&self) -> bool {
        self.fs_send.is_some()
    }

    pub fn get_send_digest(&self) -> Result<Block> {
        let digest = digest_snapshot(self.fs_send.as_ref().ok_or(WireError::FsNotEnabled)?);
        Ok(first_digest_block(&digest))
    }

    pub fn get_recv_digest(&self) -> Result<Block> {
        let digest = digest_snapshot(self.fs_recv.as_ref().ok_or(WireError::FsNotEnabled)?);
        Ok(first_digest_block(&digest))
    }

    pub fn get_digest(&self) -> Result<Block> {
        let send = digest_snapshot(self.fs_send.as_ref().ok_or(WireError::FsNotEnabled)?);
        let recv = digest_snapshot(self.fs_recv.as_ref().ok_or(WireError::FsNotEnabled)?);
        let mut h = Sha256::new();
        if self.fs_send_first {
            h.update(send);
            h.update(recv);
        } else {
            h.update(recv);
            h.update(send);
        }
        let digest: [u8; 32] = h.finalize().into();
        Ok(first_digest_block(&digest))
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        self.send_counter += data.len() as u64;
        if self.last_dir != LastDir::Send {
            self.rounds += 1;
            self.last_dir = LastDir::Send;
        }
        if let Some(fs_send) = &mut self.fs_send {
            fs_send.update(data);
        }
        self.stream.write_all(data).await?;
        self.send_dirty = true;
        Ok(())
    }

    pub async fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        self.recv_counter += len as u64;
        if self.last_dir != LastDir::Recv {
            self.rounds += 1;
            self.last_dir = LastDir::Recv;
        }
        let mut out = vec![0u8; len];
        self.stream.read_exact(&mut out).await?;
        if let Some(fs_recv) = &mut self.fs_recv {
            fs_recv.update(&out);
        }
        Ok(out)
    }

    pub async fn flush(&mut self) -> Result<()> {
        if self.send_dirty {
            self.flushes_count += 1;
            self.send_dirty = false;
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn send_block(&mut self, blocks: &[Block]) -> Result<()> {
        self.send_data(Block::slice_as_bytes(blocks)).await
    }

    pub async fn recv_block(&mut self, count: usize) -> Result<Vec<Block>> {
        let len = count * BLOCK_BYTES;
        self.recv_counter += len as u64;
        if self.last_dir != LastDir::Recv {
            self.rounds += 1;
            self.last_dir = LastDir::Recv;
        }
        let mut out = vec![Block::zero(); count];
        let bytes = Block::slice_as_mut_bytes(&mut out);
        self.stream.read_exact(bytes).await?;
        if let Some(fs_recv) = &mut self.fs_recv {
            fs_recv.update(bytes);
        }
        Ok(out)
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

impl ByteIo for EmpStream {
    async fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Result<()> {
        EmpStream::send_data(self, data).await
    }

    async fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        EmpStream::recv_data(self, len).await
    }

    async fn flush(&mut self) -> Result<()> {
        EmpStream::flush(self).await
    }

    async fn send_block<'a>(&'a mut self, blocks: &'a [Block]) -> Result<()> {
        EmpStream::send_block(self, blocks).await
    }

    async fn recv_block(&mut self, count: usize) -> Result<Vec<Block>> {
        EmpStream::recv_block(self, count).await
    }

    async fn send_bool_bytes<'a>(
        &'a mut self,
        bool_bytes: &'a [u8],
        ptr_mod8: usize,
    ) -> Result<()> {
        EmpStream::send_bool_bytes(self, bool_bytes, ptr_mod8).await
    }

    async fn recv_bool_bytes(&mut self, length: usize, ptr_mod8: usize) -> Result<Vec<u8>> {
        EmpStream::recv_bool_bytes(self, length, ptr_mod8).await
    }

    async fn send_partial_blocks<'a>(
        &'a mut self,
        blocks: &'a [Block],
        partial_bytes: usize,
    ) -> Result<()> {
        EmpStream::send_partial_blocks(self, blocks, partial_bytes).await
    }

    async fn recv_partial_blocks(
        &mut self,
        count: usize,
        partial_bytes: usize,
    ) -> Result<Vec<Block>> {
        EmpStream::recv_partial_blocks(self, count, partial_bytes).await
    }
}

impl TranscriptIo for EmpStream {
    fn enable_fs(&mut self, send_first: bool) -> Result<()> {
        EmpStream::enable_fs(self, send_first)
    }

    fn fs_enabled(&self) -> bool {
        EmpStream::fs_enabled(self)
    }

    fn get_send_digest(&self) -> Result<Block> {
        EmpStream::get_send_digest(self)
    }

    fn get_recv_digest(&self) -> Result<Block> {
        EmpStream::get_recv_digest(self)
    }

    fn get_digest(&self) -> Result<Block> {
        EmpStream::get_digest(self)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LastDir {
    None,
    Send,
    Recv,
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

pub struct Ag2pcStreams<S = EmpStream> {
    pub main: S,
    pub sibling: S,
}

impl<S: IdleTrim> Ag2pcStreams<S> {
    pub fn trim_idle_allocations(&mut self) {
        self.main.trim_idle_allocations();
        self.sibling.trim_idle_allocations();
    }
}

impl Ag2pcStreams<EmpStream> {
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
        sleep(Duration::from_millis(100)).await;
        let sibling = accept_emp(&listener).await?;
        Ok(Self { main, sibling })
    }

    pub async fn connect(peer_ip: IpAddr, port: u16) -> Result<Self> {
        let addr = SocketAddr::new(peer_ip, port);
        let main = connect_emp(addr).await?;
        sleep(Duration::from_millis(100)).await;
        let sibling = connect_emp(addr).await?;
        Ok(Self { main, sibling })
    }
}

impl<S> Ag2pcStreams<S> {
    pub fn streams_mut(&mut self) -> [&mut S; AG2PC_STREAM_COUNT] {
        [&mut self.main, &mut self.sibling]
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

fn digest_snapshot(hasher: &Sha256) -> [u8; 32] {
    let digest = hasher.clone().finalize();
    digest.into()
}

fn first_digest_block(digest: &[u8; 32]) -> Block {
    let mut out = [0u8; BLOCK_BYTES];
    out.copy_from_slice(&digest[..BLOCK_BYTES]);
    Block::from_bytes(out)
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
mod tests;
