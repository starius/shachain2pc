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
mod tests {
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

    #[cfg(feature = "cpp-probes")]
    async fn run_live_ag2pc_transport_case(bin: &Path, rust_role: Role) {
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

    #[cfg(feature = "cpp-probes")]
    fn cpp_ag2pc_transport_probe() -> PathBuf {
        let root = repo_root();
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
}
