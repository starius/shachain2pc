pub struct SoftSpoken4 {
    state: SoftSpoken4State,
}

impl ops::Deref for SoftSpoken4 {
    type Target = SoftSpoken4State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl ops::DerefMut for SoftSpoken4 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl SoftSpoken4 {
    pub fn new(role: Role, malicious: bool) -> Result<Self> {
        let mut delta = Block::zero();
        if role == Role::Alice {
            delta = random_block()?;
            let mut bytes = delta.into_bytes();
            bytes[0] |= 1;
            delta = Block::from_bytes(bytes);
        }
        Ok(Self {
            state: SoftSpoken4State::new(role, malicious, delta, random_block()?),
        })
    }

    pub fn new_with_delta(role: Role, malicious: bool, delta: Block) -> Result<Self> {
        let mut out = Self::new(role, malicious)?;
        out.set_delta(delta)?;
        Ok(out)
    }

    pub fn set_delta(&mut self, delta: Block) -> Result<()> {
        if self.state.set_delta(delta).is_err() {
            return Err(CompatError::BadOtRole("SoftSpoken4::set_delta"));
        }
        Ok(())
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub async fn run<S: TranscriptIo>(
        &mut self,
        stream: &mut S,
        length: usize,
    ) -> Result<Vec<Block>> {
        let mut out = vec![Block::zero(); length];
        let got = self.drain_leftover(&mut out);
        if got == length {
            return Ok(out);
        }
        self.begin(stream).await?;
        let rest = self.next_n(stream, length - got).await?;
        self.end(stream).await?;
        out[got..].copy_from_slice(&rest);
        Ok(out)
    }

    pub async fn begin<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        if self.role == Role::Alice {
            self.send_begin(stream).await
        } else {
            self.recv_begin(stream).await
        }
    }

    pub async fn end<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        if self.role == Role::Alice {
            self.send_end(stream).await
        } else {
            self.recv_end(stream).await
        }
    }

    pub async fn next_n<S: TranscriptIo>(
        &mut self,
        stream: &mut S,
        length: usize,
    ) -> Result<Vec<Block>> {
        let mut out = vec![Block::zero(); length];
        let mut got = self.drain_leftover(&mut out);
        while got + SOFTSPOKEN_CHUNK_OTS <= length {
            let chunk = self.next_chunk(stream, SOFTSPOKEN_CHUNK_BLOCKS).await?;
            out[got..got + SOFTSPOKEN_CHUNK_OTS].copy_from_slice(&chunk);
            got += SOFTSPOKEN_CHUNK_OTS;
        }
        if got < length {
            let chunk = self.next_chunk(stream, SOFTSPOKEN_CHUNK_BLOCKS).await?;
            let take = length - got;
            out[got..].copy_from_slice(&chunk[..take]);
            self.leftover = chunk;
            self.leftover_pos = take;
            self.leftover_count = SOFTSPOKEN_CHUNK_OTS - take;
        }
        Ok(out)
    }

    async fn next_chunk<S: TranscriptIo>(
        &mut self,
        stream: &mut S,
        bs: usize,
    ) -> Result<Vec<Block>> {
        if self.role == Role::Alice {
            self.send_chunk_pipeline(stream, bs).await
        } else {
            self.recv_chunk_pipeline(stream, bs).await
        }
    }

    async fn send_begin<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        self.reset_leftover();
        if !self.setup_done {
            self.bootstrap_send(stream).await?;
        }
        self.begin_send_session();
        Ok(())
    }

    async fn recv_begin<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        self.reset_leftover();
        if !self.setup_done {
            self.bootstrap_recv(stream).await?;
        }
        self.begin_recv_session();
        Ok(())
    }

    async fn send_end<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        if self.malicious {
            let _scratch = self.send_chunk_pipeline(stream, 1).await?;
            let x = stream.recv_block(1).await?[0];
            let t = stream.recv_block(1).await?[0];
            self.verify_send_check(x, t)
                .map_err(|_| CompatError::FeqMismatch)?;
        }
        Ok(())
    }

    async fn recv_end<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        if self.malicious {
            let _scratch = self.recv_chunk_pipeline(stream, 1).await?;
            let (check_x, check_t) = self.recv_check_blocks();
            stream.send_block(&[check_x]).await?;
            stream.send_block(&[check_t]).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    async fn bootstrap_send<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        let choices = self.bootstrap_send_choices();
        let received = csw_recv(stream, &choices).await?;
        self.bootstrap_send_apply_received(&received)
            .map_err(|_| CompatError::BadCswLength(received.len()))?;
        if self.malicious {
            self.pprf_check_recv(stream).await?;
            if !stream.fs_enabled() {
                stream.enable_fs(true)?;
            }
        }
        self.mark_setup_done();
        Ok(())
    }

    async fn bootstrap_recv<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        let (k0, k1) = self.bootstrap_recv_keys();
        csw_send(stream, &k0, &k1).await?;
        if self.malicious {
            self.pprf_check_send(stream).await?;
            if !stream.fs_enabled() {
                stream.enable_fs(false)?;
            }
        }
        self.mark_setup_done();
        Ok(())
    }

    async fn pprf_check_send<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        let (t_buf, digest) = self.pprf_check_send_prepare();
        stream.send_block(&t_buf).await?;
        stream.send_data(&digest).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn pprf_check_recv<S: TranscriptIo>(&mut self, stream: &mut S) -> Result<()> {
        let t_buf = stream.recv_block(SOFTSPOKEN_N * 2).await?;
        let their_digest = stream.recv_data(HASH_DIGEST_BYTES).await?;
        self.pprf_check_recv_verify(&t_buf, &their_digest)
            .map_err(|_| CompatError::FeqMismatch)
    }

    async fn send_chunk_pipeline<S: TranscriptIo>(
        &mut self,
        stream: &mut S,
        bs: usize,
    ) -> Result<Vec<Block>> {
        let planes = self.send_chunk_prepare(bs);
        let d_bufs = stream.recv_block((SOFTSPOKEN_N - 1) * bs).await?;
        let transcript_seed = self.malicious.then(|| stream.get_digest()).transpose()?;
        self.send_chunk_finish(planes, &d_bufs, transcript_seed, bs)
            .map_err(|_| CompatError::FeqMismatch)
    }

    async fn recv_chunk_pipeline<S: TranscriptIo>(
        &mut self,
        stream: &mut S,
        bs: usize,
    ) -> Result<Vec<Block>> {
        let (d_bufs, out, u_canonical) = self.recv_chunk_prepare(bs);
        stream.send_block(&d_bufs).await?;
        let transcript_seed = self.malicious.then(|| stream.get_digest()).transpose()?;
        self.recv_chunk_finish(transcript_seed, &out, &u_canonical, bs);
        Ok(out)
    }

    pub fn trim_idle_allocations(&mut self) {
        self.leftover.zeroize();
        self.leftover.clear();
        self.leftover.shrink_to_fit();
        self.leftover_pos = 0;
        self.leftover_count = 0;
    }
}
