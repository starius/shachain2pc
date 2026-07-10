pub struct EmpRo {
    domain: Vec<u8>,
    buf: Vec<u8>,
}

impl EmpRo {
    pub fn new(domain: &str, sid: Block) -> Self {
        let mut out = Self {
            domain: domain.as_bytes().to_vec(),
            buf: Vec::new(),
        };
        out.frame(1, domain.as_bytes());
        out.frame(3, sid.as_bytes());
        out
    }

    pub fn absorb_bytes(mut self, data: &[u8]) -> Self {
        self.frame(2, data);
        self
    }

    pub fn absorb_block(mut self, block: Block) -> Self {
        self.frame(3, block.as_bytes());
        self
    }

    pub fn absorb_u64(mut self, value: u64) -> Self {
        self.frame(4, &value.to_le_bytes());
        self
    }

    pub fn absorb_point(mut self, point: &[u8]) -> Self {
        self.frame(5, point);
        self
    }

    pub fn squeeze_block(&self) -> Block {
        let digest = hash_once(&self.buf);
        let mut bytes = [0u8; BLOCK_BYTES];
        bytes.copy_from_slice(&digest[..BLOCK_BYTES]);
        Block::from_bytes(bytes)
    }

    pub fn squeeze_p256_point(&self) -> Result<Vec<u8>> {
        let point =
            p256::NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&self.buf], &[&self.domain])
                .map_err(|_| CompatError::HashToCurve)?;
        Ok(point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn frame(&mut self, typ: u32, data: &[u8]) {
        let len: u32 = data
            .len()
            .try_into()
            .expect("EMP RO frame length exceeds u32");
        self.buf.extend_from_slice(&typ.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(data);
    }
}

fn zero_key_prp() -> &'static Prp {
    static ZERO_KEY_PRP: OnceLock<Prp> = OnceLock::new();
    ZERO_KEY_PRP.get_or_init(Prp::zero_key)
}

pub fn garble_hash_preprocess(
    a: Block,
    b: Block,
    delta: Block,
    gate_index: u64,
) -> [[Block; 2]; 4] {
    let a0 = a.sigma();
    let a1 = a.xor(delta).sigma();
    let b0 = b.sigma().sigma();
    let b1 = b.xor(delta).sigma().sigma();

    let mut rows = [
        [a0.xor(b0), a0.xor(b0)],
        [a0.xor(b1), a0.xor(b1)],
        [a1.xor(b0), a1.xor(b0)],
        [a1.xor(b1), a1.xor(b1)],
    ];
    for (row, pair) in rows.iter_mut().enumerate() {
        pair[0] = pair[0].xor(Block::make(4 * gate_index + row as u64, 0));
        pair[1] = pair[1].xor(Block::make(4 * gate_index + row as u64, 1));
    }

    let mut flat = [
        rows[0][0], rows[0][1], rows[1][0], rows[1][1], rows[2][0], rows[2][1], rows[3][0],
        rows[3][1],
    ];
    zero_key_prp().permute_block(&mut flat);
    [
        [flat[0], flat[1]],
        [flat[2], flat[3]],
        [flat[4], flat[5]],
        [flat[6], flat[7]],
    ]
}

pub fn garble_hash_online(a: Block, b: Block, gate_index: u64, row: u64) -> [Block; 2] {
    let base = a.sigma().xor(b.sigma().sigma());
    let mut blocks = [
        base.xor(Block::make(4 * gate_index + row, 0)),
        base.xor(Block::make(4 * gate_index + row, 1)),
    ];
    zero_key_prp().permute_block(&mut blocks);
    blocks
}

pub struct P256 {
    group: EcGroup,
}

impl P256 {
    pub fn new() -> Result<Self> {
        Ok(Self {
            group: EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
        })
    }

    pub fn mul_gen(&self, scalar: u64) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let scalar = BigNum::from_dec_str(&scalar.to_string())?;
        self.mul_gen_bn(&scalar, &mut ctx)
    }

    fn random_scalar(&self) -> Result<BigNum> {
        let mut ctx = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        self.group.order(&mut order, &mut ctx)?;
        let mut out = BigNum::new()?;
        order.rand_range(&mut out)?;
        Ok(out)
    }

    fn mul_gen_bn(&self, scalar: &BigNumRef, ctx: &mut BigNumContext) -> Result<Vec<u8>> {
        let mut point = EcPoint::new(&self.group)?;
        point.mul_generator2(&self.group, scalar, ctx)?;
        point_bytes(&self.group, &point, ctx)
    }

    pub fn point_add(&self, lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let lhs = point_from_bytes(&self.group, lhs, &mut ctx)?;
        let rhs = point_from_bytes(&self.group, rhs, &mut ctx)?;
        let mut out = EcPoint::new(&self.group)?;
        out.add(&self.group, &lhs, &rhs, &mut ctx)?;
        point_bytes(&self.group, &out, &mut ctx)
    }

    pub fn point_mul(&self, point: &[u8], scalar: u64) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let point = point_from_bytes(&self.group, point, &mut ctx)?;
        let scalar = BigNum::from_dec_str(&scalar.to_string())?;
        self.point_mul_bn_ref(&point, &scalar, &mut ctx)
    }

    fn point_mul_bn(&self, point: &[u8], scalar: &BigNumRef) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let point = point_from_bytes(&self.group, point, &mut ctx)?;
        self.point_mul_bn_ref(&point, scalar, &mut ctx)
    }

    fn point_mul_bn_ref(
        &self,
        point: &EcPointRef,
        scalar: &BigNumRef,
        ctx: &mut BigNumContext,
    ) -> Result<Vec<u8>> {
        let mut out = EcPoint::new(&self.group)?;
        out.mul2(&self.group, point, scalar, ctx)?;
        point_bytes(&self.group, &out, ctx)
    }

    pub fn point_inv(&self, point: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let mut point = point_from_bytes(&self.group, point, &mut ctx)?;
        point.invert2(&self.group, &mut ctx)?;
        point_bytes(&self.group, &point, &mut ctx)
    }

    pub fn send_pt_bytes(&self, point: &[u8]) -> Result<Vec<u8>> {
        if point.len() != POINT_BYTES {
            return Err(CompatError::BadPointLength(point.len()));
        }
        let mut out = Vec::with_capacity(4 + point.len());
        out.extend_from_slice(&(point.len() as u32).to_le_bytes());
        out.extend_from_slice(point);
        Ok(out)
    }

    pub fn kdf(&self, point: &[u8], id: u64) -> Result<Block> {
        if point.len() != POINT_BYTES {
            return Err(CompatError::BadPointLength(point.len()));
        }
        let mut data = Vec::with_capacity(point.len() + 8);
        data.extend_from_slice(point);
        data.extend_from_slice(&id.to_le_bytes());
        let digest = hash_once(&data);
        let mut block = [0u8; 16];
        block.copy_from_slice(&digest[..16]);
        Ok(Block::from_bytes(block))
    }

    pub fn hash_to_point(&self, msg: &[u8], dst: &str) -> Result<Vec<u8>> {
        let _ = &self.group;
        let point =
            p256::NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst.as_bytes()])
                .map_err(|_| CompatError::HashToCurve)?;
        Ok(point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }
}

async fn send_point<S: ByteIo>(stream: &mut S, point: &[u8]) -> Result<()> {
    if point.len() != POINT_BYTES {
        return Err(CompatError::BadPointLength(point.len()));
    }
    stream
        .send_data(&(point.len() as u32).to_le_bytes())
        .await?;
    stream.send_data(point).await?;
    Ok(())
}

async fn recv_point<S: ByteIo>(stream: &mut S) -> Result<Vec<u8>> {
    let len_bytes = stream.recv_data(4).await?;
    let len = u32::from_le_bytes(len_bytes.try_into().expect("length prefix"));
    if len != POINT_BYTES as u32 {
        return Err(CompatError::BadPointWireLength(len));
    }
    Ok(stream.recv_data(POINT_BYTES).await?)
}

pub async fn csw_send<S: ByteIo>(stream: &mut S, data0: &[Block], data1: &[Block]) -> Result<()> {
    if data0.len() != data1.len() {
        return Err(CompatError::BadOtLength {
            data0: data0.len(),
            data1: data1.len(),
        });
    }
    if data0.len() < 80 {
        return Err(CompatError::BadCswLength(data0.len()));
    }

    let group = P256::new()?;
    let sid = Block::zero();

    let seed = stream.recv_block(1).await?[0];
    let mut b_points = Vec::with_capacity(data0.len());
    for _ in 0..data0.len() {
        b_points.push(recv_point(stream).await?);
    }

    let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
        .absorb_block(seed)
        .squeeze_p256_point()?;
    let r = group.random_scalar()?;
    let z = {
        let mut ctx = BigNumContext::new()?;
        group.mul_gen_bn(&r, &mut ctx)?
    };
    let t_r = group.point_mul_bn(&t, &r)?;
    let t_r_neg = group.point_inv(&t_r)?;

    let mut p0 = Vec::with_capacity(data0.len());
    let mut p1 = Vec::with_capacity(data0.len());
    let mut h0 = Vec::with_capacity(data0.len());
    for (i, b_point) in b_points.iter().enumerate() {
        let rho0 = group.point_mul_bn(b_point, &r)?;
        let rho1 = group.point_add(&rho0, &t_r_neg)?;
        let pad0 = csw_pad_block(sid, i, &rho0);
        let pad1 = csw_pad_block(sid, i, &rho1);
        h0.push(csw_short_block(sid, pad0));
        p0.push(pad0);
        p1.push(pad1);
    }

    let otans = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
        .absorb_bytes(&blocks_to_bytes(&h0))
        .squeeze_block();
    let proof = csw_short_block(sid, otans);
    let mut chi = Vec::with_capacity(data0.len());
    let mut c0 = Vec::with_capacity(data0.len());
    let mut c1 = Vec::with_capacity(data0.len());
    for i in 0..data0.len() {
        chi.push(h0[i].xor(csw_short_block(sid, p1[i])));
        c0.push(p0[i].xor(data0[i]));
        c1.push(p1[i].xor(data1[i]));
    }

    send_point(stream, &z).await?;
    stream.send_block(&chi).await?;
    stream.send_block(&[proof]).await?;
    stream.send_block(&c0).await?;
    stream.send_block(&c1).await?;
    stream.flush().await?;

    let otans_prime = stream.recv_block(1).await?[0];
    if otans_prime != otans {
        return Err(CompatError::CswReceiverMismatch);
    }
    Ok(())
}

pub async fn csw_recv<S: ByteIo>(stream: &mut S, choices: &[bool]) -> Result<Vec<Block>> {
    if choices.len() < 80 {
        return Err(CompatError::BadCswLength(choices.len()));
    }

    let group = P256::new()?;
    let sid = Block::zero();
    let seed = random_block()?;
    let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
        .absorb_block(seed)
        .squeeze_p256_point()?;

    stream.send_block(&[seed]).await?;
    let mut alphas = Vec::with_capacity(choices.len());
    for choice in choices {
        let alpha = group.random_scalar()?;
        let b_point = {
            let mut ctx = BigNumContext::new()?;
            group.mul_gen_bn(&alpha, &mut ctx)?
        };
        let b_point = if *choice {
            group.point_add(&b_point, &t)?
        } else {
            b_point
        };
        send_point(stream, &b_point).await?;
        alphas.push(alpha);
    }
    stream.flush().await?;

    let z = recv_point(stream).await?;
    let mut p_bi = Vec::with_capacity(choices.len());
    let mut h_bi = Vec::with_capacity(choices.len());
    for (i, alpha) in alphas.iter().enumerate() {
        let z_alpha = group.point_mul_bn(&z, alpha)?;
        let pad = csw_pad_block(sid, i, &z_alpha);
        h_bi.push(csw_short_block(sid, pad));
        p_bi.push(pad);
    }

    let chi = stream.recv_block(choices.len()).await?;
    let proof = stream.recv_block(1).await?[0];
    let c0 = stream.recv_block(choices.len()).await?;
    let c1 = stream.recv_block(choices.len()).await?;

    let mut otresp = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        otresp.push(if choices[i] {
            h_bi[i].xor(chi[i])
        } else {
            h_bi[i]
        });
    }
    let otans_prime = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
        .absorb_bytes(&blocks_to_bytes(&otresp))
        .squeeze_block();
    if csw_short_block(sid, otans_prime) != proof {
        return Err(CompatError::CswProofMismatch);
    }

    let mut out = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        out.push(p_bi[i].xor(if choices[i] { c1[i] } else { c0[i] }));
    }
    stream.send_block(&[otans_prime]).await?;
    stream.flush().await?;
    Ok(out)
}

fn csw_pad_block(sid: Block, i: usize, point: &[u8]) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:pad", sid)
        .absorb_u64(i as u64)
        .absorb_point(point)
        .squeeze_block()
}

fn csw_short_block(sid: Block, block: Block) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:short", sid)
        .absorb_block(block)
        .squeeze_block()
}

fn blocks_to_bytes(blocks: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * BLOCK_BYTES);
    for block in blocks {
        out.extend_from_slice(block.as_bytes());
    }
    out
}
