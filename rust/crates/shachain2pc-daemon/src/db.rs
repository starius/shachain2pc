#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PlainDb {
    channels: BTreeMap<String, ChannelRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelScalars {
    enabled: bool,
    last_observed_next_reveal_index: Option<u64>,
    precompute_target: u64,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    estimated_checked_units: u64,
    attempted_checked_units: u64,
    failed_precompute_jobs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRecord {
    record_type: u8,
    channel_index: u64,
    sub_id: u64,
    payload: StoredPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoredPayload {
    Meta { verifier_hex: String },
    Channel(ChannelScalars),
    Secret { secret_hex: String },
    Frontier(WireRecord),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelRecord {
    enabled: bool,
    last_observed_next_reveal_index: Option<u64>,
    precompute_target: u64,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    frontier_nodes: BTreeMap<String, WireRecord>,
    known_secrets: BTreeMap<String, String>,
    estimated_checked_units: u64,
    #[serde(default)]
    attempted_checked_units: u64,
    #[serde(default)]
    failed_precompute_jobs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireRecord {
    public_binding_hex: String,
    local_binding_hex: String,
    wires: SerializableWires,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableWires {
    lambda: Vec<u8>,
    mac: Vec<[u8; BLOCK_BYTES]>,
    key: Vec<[u8; BLOCK_BYTES]>,
}

#[derive(Clone, Debug)]
struct JobRecord {
    channel_index: u64,
    kind: String,
    state: String,
    planned_checked_units: u64,
}

#[derive(Clone, Copy, Debug)]
struct PeerFrontierConfig {
    channel_enabled: bool,
    precompute: u64,
    workers: u32,
    effective_workers: u32,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
}

#[derive(Clone, Copy, Debug)]
struct ResourceModel {
    configured_workers: u32,
    effective_workers: u32,
    ram_limited_workers_raw: u32,
    ram_overcommit_warning: bool,
    baseline_daemon_rss_bytes: u64,
    current_rss_bytes: u64,
    idle_session_rss_estimate_bytes: u64,
    one_h_worker_peak_rss_estimate_bytes: u64,
    live_session_count: u64,
    reserved_ram_bytes: u64,
}

struct PrecomputeJob {
    job_id: String,
    planned_checked_units: u64,
}

struct IncomingPrecomputeJob {
    job_id: String,
}

struct IncomingPrecomputeSession {
    delta: Block,
    ssp: usize,
    share: Value32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RevealRequestKey {
    channel_index: u64,
    requested_index: u64,
    expected_next_index: u64,
    allow_seed_reveal: bool,
}

struct PendingReveal {
    response: oneshot::Sender<Result<Value32>>,
}

enum PrecomputeStart {
    AlreadyStored,
    Run(PrecomputeJob),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrpcJobDescriptor {
    job_id: String,
    channel_index: u64,
    target_index: u64,
    ssp: u32,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
    digest: [u8; 32],
}

struct PendingGrpcJob {
    descriptor: GrpcJobDescriptor,
    main: Option<ChannelByteStream>,
    sibling: Option<ChannelByteStream>,
}

#[derive(Clone)]
struct PrecomputeSessionHandle {
    tx: mpsc::Sender<PrecomputeSessionCommand>,
}

enum PrecomputeSessionCommand {
    Plan {
        index: Index48,
        response: oneshot::Sender<Result<u64>>,
    },
    Precompute {
        index: Index48,
        response: oneshot::Sender<Result<Ag2pcSecureWires>>,
    },
}

#[derive(Clone)]
struct DbWriter {
    tx: mpsc::Sender<WriteOp>,
}

enum WriteOp {
    Batch {
        mutations: Vec<Mutation>,
        durability: DbDurability,
    },
    Flush {
        ack: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DbDurability {
    Eventual,
    Immediate,
}

#[derive(Clone, Debug)]
enum Mutation {
    Upsert {
        key: LogicalKey,
        record: StoredRecord,
    },
    Delete {
        key: LogicalKey,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogicalKey {
    record_type: u8,
    channel_index: u64,
    sub_id: u64,
}

struct DbStore;

impl DbStore {
    fn open(path: PathBuf, master_secret: &[u8]) -> Result<(PlainDb, DbWriter)> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        recover_incomplete_migration(&path)?;
        if is_legacy_db_file(&path)? {
            let legacy = read_legacy_db(&path, master_secret)?;
            let migrated = migrated_legacy_path(&path);
            let temp = migration_temp_path(&path);
            let _ = fs::remove_file(&temp);
            migrate_legacy_db(&temp, master_secret, &legacy)?;
            let _ = fs::remove_file(&migrated);
            fs::rename(&path, &migrated)?;
            sync_parent_dir(&path)?;
            fs::rename(&temp, &path)?;
            sync_parent_dir(&path)?;
            return Self::open(path, master_secret);
        }

        let subkeys = DbSubkeys::derive(master_secret);
        let database = if path.exists() {
            Database::open(&path).map_err(redb_error)?
        } else {
            Database::create(&path).map_err(redb_error)?
        };
        ensure_meta_record(&database, &subkeys)?;
        let db = load_redb_state(&database, &subkeys)?;
        let writer = spawn_db_writer(database, subkeys);
        Ok((db, writer))
    }
}

fn migrated_legacy_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}.migrated",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("db")
    ))
}

fn migration_temp_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}.migrating",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("db")
    ))
}

fn recover_incomplete_migration(path: &Path) -> Result<()> {
    let temp = migration_temp_path(path);
    if path.exists() {
        if temp.exists() {
            let _ = fs::remove_file(temp);
        }
        return Ok(());
    }
    if temp.exists() {
        fs::rename(&temp, path)?;
        sync_parent_dir(path)?;
    }
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if let Ok(file) = fs::File::open(parent) {
            file.sync_all()?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct DbSubkeys {
    key_prf: [u8; 32],
    value_aead: [u8; 32],
}

impl DbSubkeys {
    fn derive(master_secret: &[u8]) -> Self {
        let mut key_prf = [0u8; 32];
        let mut value_aead = [0u8; 32];
        hkdf_expand(master_secret, b"", b"shachain-db-key-prf-v1", &mut key_prf);
        hkdf_expand(
            master_secret,
            b"",
            b"shachain-db-value-aead-v1",
            &mut value_aead,
        );
        Self {
            key_prf,
            value_aead,
        }
    }
}

impl DbWriter {
    async fn write_batch(&self, mutations: Vec<Mutation>, durability: DbDurability) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }
        let op = WriteOp::Batch {
            mutations,
            durability,
        };
        match self.tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(op)) => {
                eprintln!("WARNING: DB writer queue is full; waiting for enqueue");
                self.tx
                    .send(op)
                    .await
                    .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(DaemonError::Crypto("DB writer stopped".to_owned()))
            }
        }
    }

    async fn flush(&self) -> Result<()> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::Flush { ack })
            .await
            .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Crypto("DB writer stopped".to_owned()))?
    }
}

fn spawn_db_writer(database: Database, subkeys: DbSubkeys) -> DbWriter {
    spawn_db_writer_with_checkpoint_interval(database, subkeys, DEFAULT_DB_CHECKPOINT_INTERVAL)
}

fn spawn_db_writer_with_checkpoint_interval(
    database: Database,
    subkeys: DbSubkeys,
    checkpoint_interval: Duration,
) -> DbWriter {
    let (tx, mut rx) = mpsc::channel(16_384);
    let database = Arc::new(database);
    tokio::spawn(async move {
        let mut dirty = false;
        let mut checkpoint = tokio::time::interval(checkpoint_interval);
        checkpoint.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                maybe_first = rx.recv() => {
                    let Some(first) = maybe_first else {
                        if dirty {
                            if let Err(err) = run_db_checkpoint(&database, &subkeys).await {
                                eprintln!("WARNING: final DB checkpoint failed: {err}");
                            }
                        }
                        break;
                    };
                    let durable = process_db_writer_batch(
                        &database,
                        &subkeys,
                        first,
                        &mut rx,
                    )
                    .await;
                    match durable {
                        Ok(true) => dirty = false,
                        Ok(false) => dirty = true,
                        Err(()) => {}
                    }
                }
                _ = checkpoint.tick(), if dirty => {
                    match run_db_checkpoint(&database, &subkeys).await {
                        Ok(()) => dirty = false,
                        Err(err) => eprintln!("WARNING: periodic DB checkpoint failed: {err}"),
                    }
                }
            }
        }
    });
    DbWriter { tx }
}

async fn process_db_writer_batch(
    database: &Arc<Database>,
    subkeys: &DbSubkeys,
    first: WriteOp,
    rx: &mut mpsc::Receiver<WriteOp>,
) -> std::result::Result<bool, ()> {
    let mut mutations = Vec::new();
    let mut acks = Vec::new();
    let mut durability = DbDurability::Eventual;
    collect_write_op(first, &mut mutations, &mut acks, &mut durability);
    while let Ok(op) = rx.try_recv() {
        collect_write_op(op, &mut mutations, &mut acks, &mut durability);
    }
    let result = if mutations.is_empty() && acks.is_empty() {
        Ok(())
    } else {
        let database = Arc::clone(database);
        let subkeys = subkeys.clone();
        tokio::task::spawn_blocking(move || {
            apply_mutations(&database, &subkeys, mutations, durability)
        })
        .await
        .map_err(|e| DaemonError::Crypto(format!("DB writer task failed: {e}")))
        .and_then(|inner| inner)
    };
    if let Err(err) = result {
        let msg = err.to_string();
        for ack in acks {
            let _ = ack.send(Err(DaemonError::Crypto(msg.clone())));
        }
        eprintln!("WARNING: DB writer failed: {err}");
        Err(())
    } else {
        for ack in acks {
            let _ = ack.send(Ok(()));
        }
        Ok(durability == DbDurability::Immediate)
    }
}

async fn run_db_checkpoint(database: &Arc<Database>, subkeys: &DbSubkeys) -> Result<()> {
    let database = Arc::clone(database);
    let subkeys = subkeys.clone();
    tokio::task::spawn_blocking(move || checkpoint_database(&database, &subkeys))
        .await
        .map_err(|e| DaemonError::Crypto(format!("DB checkpoint task failed: {e}")))?
}

fn collect_write_op(
    op: WriteOp,
    mutations: &mut Vec<Mutation>,
    acks: &mut Vec<oneshot::Sender<Result<()>>>,
    durability: &mut DbDurability,
) {
    match op {
        WriteOp::Batch {
            mutations: batch,
            durability: batch_durability,
        } => {
            mutations.extend(batch);
            if batch_durability == DbDurability::Immediate {
                *durability = DbDurability::Immediate;
            }
        }
        WriteOp::Flush { ack } => {
            *durability = DbDurability::Immediate;
            acks.push(ack);
        }
    }
}

fn apply_mutations(
    database: &Database,
    subkeys: &DbSubkeys,
    mutations: Vec<Mutation>,
    durability: DbDurability,
) -> Result<()> {
    let mut write = database.begin_write().map_err(redb_error)?;
    write.set_durability(match durability {
        DbDurability::Eventual => Durability::Eventual,
        DbDurability::Immediate => Durability::Immediate,
    });
    {
        let mut table = write.open_table(REDB_TABLE).map_err(redb_error)?;
        for mutation in mutations {
            match mutation {
                Mutation::Upsert { key, record } => {
                    let stored_key = stored_key(subkeys, key);
                    let value = encrypt_stored_record(subkeys, &stored_key, &record)?;
                    table
                        .insert(stored_key.as_slice(), value.as_slice())
                        .map_err(redb_error)?;
                }
                Mutation::Delete { key } => {
                    let stored_key = stored_key(subkeys, key);
                    table.remove(stored_key.as_slice()).map_err(redb_error)?;
                }
            }
        }
    }
    write.commit().map_err(redb_error)
}

fn checkpoint_database(database: &Database, subkeys: &DbSubkeys) -> Result<()> {
    apply_mutations(
        database,
        subkeys,
        vec![Mutation::Upsert {
            key: LogicalKey::meta(),
            record: StoredRecord {
                record_type: RECORD_META,
                channel_index: 0,
                sub_id: 0,
                payload: StoredPayload::Meta {
                    verifier_hex: to_hex(REDB_META_VERIFIER),
                },
            },
        }],
        DbDurability::Immediate,
    )
}

fn ensure_meta_record(database: &Database, subkeys: &DbSubkeys) -> Result<()> {
    let mut write = database.begin_write().map_err(redb_error)?;
    write.set_durability(Durability::Immediate);
    let key = LogicalKey::meta();
    let stored_key = stored_key(subkeys, key);
    {
        let mut table = write.open_table(REDB_TABLE).map_err(redb_error)?;
        let existing = table
            .get(stored_key.as_slice())
            .map_err(redb_error)?
            .map(|value| value.value().to_vec());
        if let Some(value) = existing {
            let record = decrypt_stored_record(subkeys, &stored_key, &value)?;
            validate_meta_record(&record)?;
        } else {
            let record = StoredRecord {
                record_type: RECORD_META,
                channel_index: 0,
                sub_id: 0,
                payload: StoredPayload::Meta {
                    verifier_hex: to_hex(REDB_META_VERIFIER),
                },
            };
            let value = encrypt_stored_record(subkeys, &stored_key, &record)?;
            table
                .insert(stored_key.as_slice(), value.as_slice())
                .map_err(redb_error)?;
        }
    }
    write.commit().map_err(redb_error)
}

fn load_redb_state(database: &Database, subkeys: &DbSubkeys) -> Result<PlainDb> {
    let read = database.begin_read().map_err(redb_error)?;
    let table = read.open_table(REDB_TABLE).map_err(redb_error)?;
    let mut db = PlainDb::default();
    for item in table.iter().map_err(redb_error)? {
        let (key, value) = item.map_err(redb_error)?;
        let key = key.value().to_vec();
        let record = decrypt_stored_record(subkeys, &key, value.value())?;
        apply_stored_record(&mut db, record)?;
    }
    Ok(db)
}

fn apply_stored_record(db: &mut PlainDb, record: StoredRecord) -> Result<()> {
    match &record.payload {
        StoredPayload::Meta { .. } => validate_meta_record(&record),
        StoredPayload::Channel(scalars) => {
            if record.record_type != RECORD_CHANNEL || record.sub_id != 0 {
                return Err(DaemonError::Crypto(
                    "stored channel record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel.apply_scalars(scalars.clone());
            Ok(())
        }
        StoredPayload::Secret { secret_hex } => {
            if record.record_type != RECORD_SECRET {
                return Err(DaemonError::Crypto(
                    "stored secret record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel
                .known_secrets
                .insert(record.sub_id.to_string(), secret_hex.clone());
            Ok(())
        }
        StoredPayload::Frontier(wire) => {
            if record.record_type != RECORD_FRONTIER {
                return Err(DaemonError::Crypto(
                    "stored frontier record has a bad logical key".to_owned(),
                ));
            }
            let channel = db
                .channels
                .entry(channel_key(record.channel_index))
                .or_insert_with(empty_channel_record);
            channel
                .frontier_nodes
                .insert(record.sub_id.to_string(), wire.clone());
            Ok(())
        }
    }
}

fn validate_meta_record(record: &StoredRecord) -> Result<()> {
    match &record.payload {
        StoredPayload::Meta { verifier_hex }
            if record.record_type == RECORD_META
                && record.channel_index == 0
                && record.sub_id == 0
                && verifier_hex == &to_hex(REDB_META_VERIFIER) =>
        {
            Ok(())
        }
        _ => Err(DaemonError::Crypto(
            "encrypted DB verifier record is invalid".to_owned(),
        )),
    }
}

fn encrypt_stored_record(
    subkeys: &DbSubkeys,
    stored_key: &[u8; 32],
    record: &StoredRecord,
) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(record)?;
    let mut nonce = [0u8; DB_NONCE_LEN];
    let mut tag = [0u8; DB_TAG_LEN];
    rand_bytes(&mut nonce).map_err(|e| DaemonError::Crypto(e.to_string()))?;
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &subkeys.value_aead,
        Some(&nonce),
        stored_key,
        &plaintext,
        &mut tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(DB_NONCE_LEN + DB_TAG_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_stored_record(
    subkeys: &DbSubkeys,
    stored_key: &[u8],
    value: &[u8],
) -> Result<StoredRecord> {
    if stored_key.len() != 32 {
        return Err(DaemonError::Crypto(
            "encrypted DB stored key has a bad length".to_owned(),
        ));
    }
    if value.len() < DB_NONCE_LEN + DB_TAG_LEN {
        return Err(DaemonError::Crypto(
            "encrypted DB value is truncated".to_owned(),
        ));
    }
    let nonce: [u8; DB_NONCE_LEN] = value[..DB_NONCE_LEN]
        .try_into()
        .expect("nonce length checked");
    let tag: [u8; DB_TAG_LEN] = value[DB_NONCE_LEN..DB_NONCE_LEN + DB_TAG_LEN]
        .try_into()
        .expect("tag length checked");
    let ciphertext = &value[DB_NONCE_LEN + DB_TAG_LEN..];
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &subkeys.value_aead,
        Some(&nonce),
        stored_key,
        ciphertext,
        &tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn stored_key(subkeys: &DbSubkeys, key: LogicalKey) -> [u8; 32] {
    // Deterministic HMAC keys keep records addressable while hiding channel
    // ids and indices. The store still leaks record count and update pattern.
    hmac_sha256(&subkeys.key_prf, &key.canonical_bytes())
}

fn is_legacy_db_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let bytes = fs::read(path)?;
    Ok(bytes.starts_with(DB_MAGIC))
}

fn read_legacy_db(path: &Path, master_secret: &[u8]) -> Result<PlainDb> {
    let bytes = fs::read(path)?;
    if bytes.len() < DB_MAGIC.len() + DB_SALT_LEN + DB_NONCE_LEN + DB_TAG_LEN
        || &bytes[..DB_MAGIC.len()] != DB_MAGIC
    {
        return Err(DaemonError::Crypto(
            "legacy encrypted DB has an invalid header".to_owned(),
        ));
    }
    let mut cursor = DB_MAGIC.len();
    let salt = read_array::<DB_SALT_LEN>(&bytes, &mut cursor)?;
    let nonce = read_array::<DB_NONCE_LEN>(&bytes, &mut cursor)?;
    let tag = read_array::<DB_TAG_LEN>(&bytes, &mut cursor)?;
    let ciphertext = &bytes[cursor..];
    let key = derive_db_key(master_secret, &salt);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        DB_AAD,
        ciphertext,
        &tag,
    )
    .map_err(|e| DaemonError::Crypto(e.to_string()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn migrate_legacy_db(path: &Path, master_secret: &[u8], db: &PlainDb) -> Result<()> {
    let subkeys = DbSubkeys::derive(master_secret);
    let database = Database::create(path).map_err(redb_error)?;
    ensure_meta_record(&database, &subkeys)?;
    apply_mutations(
        &database,
        &subkeys,
        plain_db_mutations(db),
        DbDurability::Immediate,
    )
}

fn redb_error<E: fmt::Display>(error: E) -> DaemonError {
    DaemonError::Crypto(format!("redb error: {error}"))
}

impl LogicalKey {
    fn meta() -> Self {
        Self {
            record_type: RECORD_META,
            channel_index: 0,
            sub_id: 0,
        }
    }

    fn channel(channel_index: u64) -> Self {
        Self {
            record_type: RECORD_CHANNEL,
            channel_index,
            sub_id: 0,
        }
    }

    fn secret(channel_index: u64, index: u64) -> Self {
        Self {
            record_type: RECORD_SECRET,
            channel_index,
            sub_id: index,
        }
    }

    fn frontier(channel_index: u64, mask: u64) -> Self {
        Self {
            record_type: RECORD_FRONTIER,
            channel_index,
            sub_id: mask,
        }
    }

    fn canonical_bytes(self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0] = self.record_type;
        out[1..9].copy_from_slice(&self.channel_index.to_be_bytes());
        out[9..17].copy_from_slice(&self.sub_id.to_be_bytes());
        out
    }
}

impl ChannelRecord {
    fn scalars(&self) -> ChannelScalars {
        ChannelScalars {
            enabled: self.enabled,
            last_observed_next_reveal_index: self.last_observed_next_reveal_index,
            precompute_target: self.precompute_target,
            ssp_target: self.ssp_target,
            delta_lifetime_checked_units_cap: self.delta_lifetime_checked_units_cap,
            estimated_checked_units: self.estimated_checked_units,
            attempted_checked_units: self.attempted_checked_units,
            failed_precompute_jobs: self.failed_precompute_jobs,
        }
    }

    fn apply_scalars(&mut self, scalars: ChannelScalars) {
        self.enabled = scalars.enabled;
        self.last_observed_next_reveal_index = scalars.last_observed_next_reveal_index;
        self.precompute_target = scalars.precompute_target;
        self.ssp_target = scalars.ssp_target;
        self.delta_lifetime_checked_units_cap = scalars.delta_lifetime_checked_units_cap;
        self.estimated_checked_units = scalars.estimated_checked_units;
        self.attempted_checked_units = scalars.attempted_checked_units;
        self.failed_precompute_jobs = scalars.failed_precompute_jobs;
    }
}

fn empty_channel_record() -> ChannelRecord {
    ChannelRecord {
        enabled: false,
        last_observed_next_reveal_index: None,
        precompute_target: 0,
        ssp_target: DEFAULT_SSP_TARGET,
        delta_lifetime_checked_units_cap: DEFAULT_DELTA_CAP,
        frontier_nodes: BTreeMap::new(),
        known_secrets: BTreeMap::new(),
        estimated_checked_units: 0,
        attempted_checked_units: 0,
        failed_precompute_jobs: 0,
    }
}

fn upsert_channel_mutation(channel_index: u64, channel: &ChannelRecord) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::channel(channel_index),
        record: StoredRecord {
            record_type: RECORD_CHANNEL,
            channel_index,
            sub_id: 0,
            payload: StoredPayload::Channel(channel.scalars()),
        },
    }
}

fn upsert_secret_mutation(channel_index: u64, index: u64, secret_hex: String) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::secret(channel_index, index),
        record: StoredRecord {
            record_type: RECORD_SECRET,
            channel_index,
            sub_id: index,
            payload: StoredPayload::Secret { secret_hex },
        },
    }
}

fn upsert_frontier_mutation(channel_index: u64, mask: u64, record: WireRecord) -> Mutation {
    Mutation::Upsert {
        key: LogicalKey::frontier(channel_index, mask),
        record: StoredRecord {
            record_type: RECORD_FRONTIER,
            channel_index,
            sub_id: mask,
            payload: StoredPayload::Frontier(record),
        },
    }
}

fn delete_secret_mutation(channel_index: u64, index: u64) -> Mutation {
    Mutation::Delete {
        key: LogicalKey::secret(channel_index, index),
    }
}

fn delete_frontier_mutation(channel_index: u64, mask: u64) -> Mutation {
    Mutation::Delete {
        key: LogicalKey::frontier(channel_index, mask),
    }
}

fn plain_db_mutations(db: &PlainDb) -> Vec<Mutation> {
    let mut out = Vec::new();
    for (channel_s, channel) in &db.channels {
        let Ok(channel_index) = channel_s.parse::<u64>() else {
            continue;
        };
        out.push(upsert_channel_mutation(channel_index, channel));
        for (index_s, secret_hex) in &channel.known_secrets {
            if let Ok(index) = index_s.parse::<u64>() {
                out.push(upsert_secret_mutation(
                    channel_index,
                    index,
                    secret_hex.clone(),
                ));
            }
        }
        for (mask_s, record) in &channel.frontier_nodes {
            if let Ok(mask) = mask_s.parse::<u64>() {
                out.push(upsert_frontier_mutation(
                    channel_index,
                    mask,
                    record.clone(),
                ));
            }
        }
    }
    out
}
