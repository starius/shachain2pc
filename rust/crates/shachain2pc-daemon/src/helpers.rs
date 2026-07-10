fn channel_response(index: u64, channel: &ChannelRecord) -> pb::ChannelResponse {
    pb::ChannelResponse {
        channel_index: index,
        enabled: channel.enabled,
        precompute: channel.precompute_target,
        ssp_target: channel.ssp_target,
        delta_lifetime_checked_units_cap: channel.delta_lifetime_checked_units_cap,
        frontier_nodes: channel.frontier_nodes.len() as u64,
        known_secrets: channel.known_secrets.len() as u64,
        estimated_checked_units: channel.estimated_checked_units,
        attempted_checked_units: channel.attempted_checked_units,
        failed_precompute_jobs: channel.failed_precompute_jobs,
    }
}

fn reveal_response(
    channel_index: u64,
    index: Index48,
    secret: Value32,
    from_cache: bool,
    source: &str,
) -> pb::RevealResponse {
    pb::RevealResponse {
        channel_index,
        index: index.get(),
        secret_hex: secret.to_hex(),
        from_cache,
        source: source.to_owned(),
    }
}

fn to_status(err: DaemonError) -> Status {
    match err {
        DaemonError::NotFound(msg) => Status::not_found(msg),
        DaemonError::Refused(msg) | DaemonError::Usage(msg) | DaemonError::Parse(msg) => {
            Status::invalid_argument(msg)
        }
        other => Status::internal(other.to_string()),
    }
}

fn is_cached_reveal_cache_miss(err: &DaemonError) -> bool {
    match err {
        DaemonError::NotFound(msg) => msg.contains("cached reveal node is not stored"),
        DaemonError::Refused(msg) => {
            msg.contains("cached reveal node is not stored")
                || msg.contains("timed out waiting for peer cached reveal")
        }
        DaemonError::TonicStatus(status) => {
            (status.code() == tonic::Code::NotFound
                || status.code() == tonic::Code::InvalidArgument)
                && status
                    .message()
                    .contains("cached reveal node is not stored")
        }
        _ => false,
    }
}

fn parse_mac_digest(bytes: Vec<u8>, context: &str) -> Result<[u8; HASH_DIGEST_BYTES]> {
    if bytes.len() != HASH_DIGEST_BYTES {
        return Err(DaemonError::Parse(format!(
            "{context} MAC digest must be {HASH_DIGEST_BYTES} bytes"
        )));
    }
    let mut out = [0u8; HASH_DIGEST_BYTES];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn peer_reveal_wait() -> Duration {
    std::env::var("SHACHAIN2PC_PEER_REVEAL_WAIT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_PEER_REVEAL_WAIT)
}

fn binding_pair(inner: &Inner, channel_index: u64, mask: u64) -> ([u8; 32], [u8; 32]) {
    let channel = inner
        .db
        .channels
        .get(&channel_key(channel_index))
        .expect("channel exists for binding");
    let public = public_binding(
        channel_index,
        mask,
        channel.ssp_target,
        channel.delta_lifetime_checked_units_cap,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc frontier local binding v1");
    hasher.update(public);
    hasher.update([inner.cfg.role.party_id()]);
    (public, hasher.finalize().into())
}

fn public_binding(channel_index: u64, mask: u64, ssp_target: u32, cap: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc frontier public binding v1");
    hasher.update(channel_index.to_le_bytes());
    hasher.update(mask.to_le_bytes());
    hasher.update(ssp_target.to_le_bytes());
    hasher.update(cap.to_le_bytes());
    hasher.update(PROTOCOL_VERSION.to_le_bytes());
    hasher.finalize().into()
}

fn job_digest(
    channel_index: u64,
    kind: &str,
    parent_mask: u64,
    child_mask: u64,
    ssp: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc daemon one-H job v1");
    hasher.update(channel_index.to_le_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(parent_mask.to_le_bytes());
    hasher.update(child_mask.to_le_bytes());
    hasher.update(ssp.to_le_bytes());
    hasher.update(PROTOCOL_VERSION.to_le_bytes());
    hasher.finalize().into()
}

fn descriptor_from_job_frame(
    frame: &pb::JobFrame,
) -> std::result::Result<GrpcJobDescriptor, &'static str> {
    if frame.job_id.is_empty() {
        return Err("JobStream job_id is empty");
    }
    if frame.digest.len() != 32 {
        return Err("JobStream digest must be 32 bytes");
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&frame.digest);
    Ok(GrpcJobDescriptor {
        job_id: frame.job_id.clone(),
        channel_index: frame.channel_index,
        target_index: frame.target_index,
        ssp: frame.ssp,
        ssp_target: frame.ssp_target,
        delta_lifetime_checked_units_cap: frame.delta_lifetime_checked_units_cap,
        digest,
    })
}

fn validate_job_channel(channel: u32) -> std::result::Result<u32, &'static str> {
    match channel {
        1 | 2 => Ok(channel),
        _ => Err("JobStream channel must be 1 or 2"),
    }
}

fn validate_job_payload_context(frame: &pb::JobFrame, descriptor: &GrpcJobDescriptor) -> bool {
    frame.channel_index == descriptor.channel_index
        && frame.target_index == descriptor.target_index
        && frame.ssp == descriptor.ssp
        && frame.ssp_target == descriptor.ssp_target
        && frame.delta_lifetime_checked_units_cap == descriptor.delta_lifetime_checked_units_cap
        && frame.digest.as_slice() == descriptor.digest
}

async fn run_jobstream_session_handshake(
    role: Role,
    descriptor: &GrpcJobDescriptor,
    streams: Ag2pcStreams<ChannelByteStream>,
) -> Result<Ag2pcStreams<ChannelByteStream>> {
    let params = RunnerSessionParams::new(
        descriptor.ssp,
        descriptor.digest.to_vec(),
        jobstream_session_binding(descriptor),
    );
    let mut framed = TransportPair {
        main: ByteFrameTransport::new(streams.main),
        sibling: ByteFrameTransport::new(streams.sibling),
    };
    run_session_handshake(
        &mut framed,
        descriptor.job_id.as_bytes().to_vec(),
        role,
        params,
    )
    .await
    .map_err(|e| DaemonError::Refused(format!("JobStream session handshake failed: {e}")))?;
    Ok(Ag2pcStreams {
        main: framed.main.into_inner(),
        sibling: framed.sibling.into_inner(),
    })
}

fn jobstream_session_binding(descriptor: &GrpcJobDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOBSTREAM_SESSION_BINDING_DOMAIN.len() + 8 + 8 + 4 + 8 + 4);
    out.extend_from_slice(JOBSTREAM_SESSION_BINDING_DOMAIN);
    out.extend_from_slice(&descriptor.channel_index.to_le_bytes());
    out.extend_from_slice(&descriptor.target_index.to_le_bytes());
    out.extend_from_slice(&descriptor.ssp_target.to_le_bytes());
    out.extend_from_slice(&descriptor.delta_lifetime_checked_units_cap.to_le_bytes());
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out
}

fn job_frame(
    descriptor: &GrpcJobDescriptor,
    channel: u32,
    start: bool,
    payload: Vec<u8>,
) -> pb::JobFrame {
    pb::JobFrame {
        job_id: descriptor.job_id.clone(),
        channel,
        channel_index: descriptor.channel_index,
        target_index: descriptor.target_index,
        ssp: descriptor.ssp,
        digest: descriptor.digest.to_vec(),
        start,
        payload,
        ssp_target: descriptor.ssp_target,
        delta_lifetime_checked_units_cap: descriptor.delta_lifetime_checked_units_cap,
    }
}

#[cfg(test)]
fn job_payload_frames(
    descriptor: &GrpcJobDescriptor,
    channel: u32,
    payload: Vec<u8>,
) -> Vec<pb::JobFrame> {
    if payload.is_empty() {
        return Vec::new();
    }
    payload
        .chunks(JOBSTREAM_PAYLOAD_CHUNK_BYTES)
        .map(|chunk| job_frame(descriptor, channel, false, chunk.to_vec()))
        .collect()
}

pub fn channel_seed_share(master_secret: &[u8], channel_index: u64) -> Value32 {
    let mut out = [0u8; 32];
    hkdf_expand(
        master_secret,
        b"",
        &info_with_u64(b"shachain2pc channel seed share v1", channel_index),
        &mut out,
    );
    Value32::new(out)
}

pub fn channel_delta(master_secret: &[u8], channel_index: u64, role: Role) -> Block {
    let mut out = [0u8; 16];
    let mut info = info_with_u64(b"shachain2pc channel delta v1", channel_index);
    info.push(role.party_id());
    hkdf_expand(master_secret, b"", &info, &mut out);
    normalize_ag2pc_delta(role, Block::from_bytes(out))
}

fn derive_db_key(master_secret: &[u8], salt: &[u8; DB_SALT_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_expand(
        master_secret,
        salt,
        b"shachain2pc daemon db key v1",
        &mut out,
    );
    out
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac_sha256(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm);
    let mut t = Vec::new();
    let mut offset = 0usize;
    for counter in 1u8.. {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(&prk, &msg).to_vec();
        let take = (out.len() - offset).min(t.len());
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        if offset == out.len() {
            break;
        }
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn peer_channels_from_url(
    peer_url: &Option<String>,
    tls: Option<&PeerTlsConfig>,
) -> Result<Option<Arc<[Channel]>>> {
    let Some(peer_url) = peer_url else {
        return Ok(None);
    };
    let mut channels = Vec::with_capacity(PEER_GRPC_CHANNEL_SHARDS);
    for _ in 0..PEER_GRPC_CHANNEL_SHARDS {
        let mut endpoint = Endpoint::from_shared(peer_url.clone())
            .map_err(|e| DaemonError::Parse(format!("bad peer URL: {e}")))?
            .initial_stream_window_size(Some(PEER_HTTP2_STREAM_WINDOW_BYTES))
            .initial_connection_window_size(Some(PEER_HTTP2_CONNECTION_WINDOW_BYTES));
        if let Some(tls) = tls {
            endpoint = endpoint.tls_config(peer_client_tls_config(tls)?)?;
        }
        channels.push(endpoint.connect_lazy());
    }
    Ok(Some(Arc::from(channels)))
}

fn peer_server_tls_config(tls: &PeerTlsConfig) -> Result<ServerTlsConfig> {
    Ok(ServerTlsConfig::new()
        .identity(load_tls_identity(tls)?)
        .client_ca_root(load_tls_ca(tls)?))
}

fn peer_client_tls_config(tls: &PeerTlsConfig) -> Result<ClientTlsConfig> {
    Ok(ClientTlsConfig::new()
        .ca_certificate(load_tls_ca(tls)?)
        .identity(load_tls_identity(tls)?)
        .domain_name(tls.domain_name.clone()))
}

fn load_tls_identity(tls: &PeerTlsConfig) -> Result<Identity> {
    let cert = fs::read(&tls.cert_path)?;
    let key = fs::read(&tls.key_path)?;
    Ok(Identity::from_pem(cert, key))
}

fn load_tls_ca(tls: &PeerTlsConfig) -> Result<Certificate> {
    Ok(Certificate::from_pem(fs::read(&tls.ca_path)?))
}

fn info_with_u64(prefix: &[u8], value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

fn ssp_effective(ssp_target: u32, cap: u64) -> usize {
    let cap_log = if cap <= 1 {
        0
    } else {
        u64::BITS - (cap - 1).leading_zeros()
    };
    (ssp_target + cap_log) as usize
}

fn resource_model(inner: &Inner, live_session_count: u64) -> ResourceModel {
    let configured_workers = inner.cfg.workers.max(1);
    ResourceModel {
        configured_workers,
        effective_workers: configured_workers,
        ram_limited_workers_raw: configured_workers,
        ram_overcommit_warning: false,
        baseline_daemon_rss_bytes: 0,
        current_rss_bytes: 0,
        idle_session_rss_estimate_bytes: 0,
        one_h_worker_peak_rss_estimate_bytes: 0,
        live_session_count,
        reserved_ram_bytes: 0,
    }
}

fn set_bits_desc(value: u64) -> Vec<usize> {
    let mut bits = Vec::new();
    for bit in (0..INDEX_BITS).rev() {
        if ((value >> bit) & 1) != 0 {
            bits.push(bit as usize);
        }
    }
    bits
}

fn derive_from_known(from_index: u64, secret: Value32, to_index: u64) -> Option<Value32> {
    if from_index & !to_index != 0 {
        return None;
    }
    let missing = to_index & !from_index;
    if from_index != 0 {
        let lowest_applied = from_index.trailing_zeros();
        if missing >> lowest_applied != 0 {
            return None;
        }
    }
    let mut p = secret.into_bytes();
    for bit in set_bits_desc(missing) {
        p[bit / 8] ^= 1u8 << (bit % 8);
        let digest = Sha256::digest(p);
        p.copy_from_slice(&digest);
    }
    Some(Value32::new(p))
}

pub fn reference_for_channel(
    master_a: &[u8],
    master_b: &[u8],
    channel_index: u64,
    index: Index48,
) -> Value32 {
    let seed = channel_seed_share(master_a, channel_index)
        .xor(channel_seed_share(master_b, channel_index));
    generate_from_seed(seed, index)
}

fn channel_key(index: u64) -> String {
    index.to_string()
}

fn node_key(mask: u64) -> String {
    mask.to_string()
}

fn daemon_id(master_secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shachain2pc daemon id v1");
    hasher.update(master_secret);
    to_hex(&hasher.finalize())
}

fn load_or_create_cookie(cfg: &DaemonConfig) -> Result<String> {
    let Some(path) = &cfg.cookie_file else {
        return random_cookie();
    };
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_owned());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cookie = random_cookie()?;
    fs::write(path, format!("{cookie}\n"))?;
    Ok(cookie)
}

fn random_cookie() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand_bytes(&mut bytes).map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(to_hex(&bytes))
}

fn write_control_file(
    path: &Path,
    addr: &SocketAddr,
    cookie: &str,
    cfg: &DaemonConfig,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cookie_path = if let Some(path) = &cfg.cookie_file {
        path.to_string_lossy().into_owned()
    } else {
        format!("inline:{cookie}")
    };
    let file = ControlFile {
        addr: format!("http://{addr}"),
        cookie_path,
    };
    fs::write(path, serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

pub fn read_control_file(path: &Path) -> Result<(String, String)> {
    let file: ControlFile = serde_json::from_slice(&fs::read(path)?)?;
    let cookie = if let Some(inline) = file.cookie_path.strip_prefix("inline:") {
        inline.to_owned()
    } else {
        fs::read_to_string(file.cookie_path)?.trim().to_owned()
    };
    Ok((file.addr, cookie))
}

fn peer_ip_from_url(url: &str) -> Option<IpAddr> {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host);
    host.parse().ok()
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    if *cursor + N > bytes.len() {
        return Err(DaemonError::Crypto("encrypted DB is truncated".to_owned()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble_hex(b >> 4));
        out.push(nibble_hex(b & 0x0f));
    }
    out
}

fn from_hex(input: &str) -> Result<Vec<u8>> {
    if input.len().checked_rem(2) != Some(0) {
        return Err(DaemonError::Parse("hex string has odd length".to_owned()));
    }
    let byte_len = input.len() / 2;
    let mut out = Vec::with_capacity(byte_len);
    let bytes = input.as_bytes();
    for i in 0..byte_len {
        out.push((hex_nibble(bytes[2 * i])? << 4) | hex_nibble(bytes[2 * i + 1])?);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DaemonError::Parse(format!("bad hex char '{}'", c as char))),
    }
}

fn nibble_hex(n: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    char::from(DIGITS[usize::from(n & 0x0f)])
}

pub fn parse_master_secret_hex(input: &str) -> Result<Vec<u8>> {
    from_hex(input)
}

pub fn parse_role(input: &str) -> Result<Role> {
    let id = input
        .parse::<u8>()
        .map_err(|_| DaemonError::Parse(format!("role must be 1 or 2, got {input}")))?;
    Role::from_party_id(id).map_err(|e| DaemonError::Parse(e.to_string()))
}

pub fn parse_addr(input: &str) -> Result<SocketAddr> {
    input
        .parse()
        .map_err(|_| DaemonError::Parse(format!("bad socket address: {input}")))
}

pub fn max_index() -> u64 {
    MAX_INDEX
}
