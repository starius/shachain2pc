use super::*;
use tempfile::tempdir;

fn sample_job_descriptor() -> GrpcJobDescriptor {
    GrpcJobDescriptor {
        job_id: "job".to_owned(),
        channel_index: 42,
        target_index: 7,
        ssp: 64,
        ssp_target: 40,
        delta_lifetime_checked_units_cap: 1_000_000,
        digest: [9u8; 32],
    }
}

#[test]
fn fixed_delta_derivation_is_role_structured_and_stable() {
    let master = [7u8; 32];
    let a = channel_delta(&master, 42, Role::Alice);
    let b = channel_delta(&master, 42, Role::Bob);
    assert_eq!(a, channel_delta(&master, 42, Role::Alice));
    assert_ne!(a, b);
    assert_eq!(a.as_bytes()[0] & 1, 1);
    assert_eq!(a.as_bytes()[0] & 2, 2);
    assert_eq!(b.as_bytes()[0] & 1, 1);
    assert_eq!(b.as_bytes()[0] & 2, 0);
}

#[test]
fn job_payload_frames_chunk_without_changing_stream_bytes() {
    let descriptor = sample_job_descriptor();
    let payload_len = JOBSTREAM_PAYLOAD_CHUNK_BYTES * 2 + 17;
    let payload = (0..payload_len)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();

    let frames = job_payload_frames(&descriptor, 2, payload.clone());
    assert_eq!(frames.len(), 3);
    assert!(frames
        .iter()
        .all(|frame| frame.payload.len() <= JOBSTREAM_PAYLOAD_CHUNK_BYTES));
    assert!(frames
        .iter()
        .all(|frame| validate_job_payload_context(frame, &descriptor)));
    assert!(frames.iter().all(|frame| !frame.start));
    assert!(frames.iter().all(|frame| frame.channel == 2));

    let reconstructed = frames
        .iter()
        .flat_map(|frame| frame.payload.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(reconstructed, payload);
}

#[test]
fn job_payload_frames_drop_empty_byte_writes() {
    let descriptor = sample_job_descriptor();
    assert!(job_payload_frames(&descriptor, 1, Vec::new()).is_empty());
}

#[tokio::test]
async fn redb_store_round_trips_and_rejects_wrong_secret() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.enc");
    let master = vec![1u8; 32];
    let (_, writer) = DbStore::open(path.clone(), &master).unwrap();
    let mut channel = empty_channel_record();
    channel.enabled = true;
    channel.precompute_target = 7;
    channel.delta_lifetime_checked_units_cap = 100;
    writer
        .write_batch(
            vec![
                upsert_channel_mutation(1, &channel),
                upsert_secret_mutation(1, 3, "11".repeat(32)),
                upsert_frontier_mutation(1, 5, sample_wire_record()),
            ],
            DbDurability::Immediate,
        )
        .await
        .unwrap();
    close_writer_for_test(writer).await;

    let (loaded, writer) = DbStore::open(path.clone(), &master).unwrap();
    close_writer_for_test(writer).await;
    let loaded_channel = loaded.channels.get("1").unwrap();
    assert!(loaded_channel.enabled);
    assert_eq!(loaded_channel.precompute_target, 7);
    assert!(loaded_channel.known_secrets.contains_key("3"));
    assert!(loaded_channel.frontier_nodes.contains_key("5"));
    assert!(DbStore::open(path, &[2u8; 32]).is_err());
}

#[test]
fn redb_stored_keys_are_opaque_and_addressable() {
    let master = [1u8; 32];
    let subkeys = DbSubkeys::derive(&master);
    let other = DbSubkeys::derive(&[2u8; 32]);
    let logical = LogicalKey::secret(42, 0x0102_0304_0506);
    let key = stored_key(&subkeys, logical);
    assert_eq!(key, stored_key(&subkeys, logical));
    assert_ne!(key, stored_key(&other, logical));
    assert_ne!(&key[..17], &logical.canonical_bytes());
    assert!(!key.windows(8).any(|window| window == 42u64.to_be_bytes()));
    assert!(!key
        .windows(8)
        .any(|window| window == 0x0102_0304_0506u64.to_be_bytes()));
}

#[tokio::test]
async fn redb_store_rejects_tampered_value() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.redb");
    let master = vec![3u8; 32];
    let (_, writer) = DbStore::open(path.clone(), &master).unwrap();
    let mut channel = empty_channel_record();
    channel.enabled = true;
    writer
        .write_batch(
            vec![upsert_channel_mutation(9, &channel)],
            DbDurability::Immediate,
        )
        .await
        .unwrap();
    close_writer_for_test(writer).await;
    tamper_first_redb_value(&path);
    assert!(DbStore::open(path, &master).is_err());
}

#[tokio::test]
async fn legacy_blob_migrates_to_redb() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.enc");
    let master = vec![4u8; 32];
    let mut db = PlainDb::default();
    let mut channel = empty_channel_record();
    channel.enabled = true;
    channel
        .known_secrets
        .insert("7".to_owned(), "22".repeat(32));
    db.channels.insert("2".to_owned(), channel);
    write_legacy_db_for_test(&path, &master, &db);

    let (loaded, writer) = DbStore::open(path.clone(), &master).unwrap();
    close_writer_for_test(writer).await;
    assert!(loaded
        .channels
        .get("2")
        .unwrap()
        .known_secrets
        .contains_key("7"));
    assert!(path.exists());
    assert!(migrated_legacy_path(&path).exists());
}

#[tokio::test]
async fn legacy_migration_recovers_after_legacy_was_moved() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.enc");
    let master = vec![5u8; 32];
    let mut db = PlainDb::default();
    let mut channel = empty_channel_record();
    channel.enabled = true;
    channel
        .known_secrets
        .insert("9".to_owned(), "33".repeat(32));
    db.channels.insert("4".to_owned(), channel);
    write_legacy_db_for_test(&path, &master, &db);

    let legacy = read_legacy_db(&path, &master).unwrap();
    let temp = migration_temp_path(&path);
    migrate_legacy_db(&temp, &master, &legacy).unwrap();
    fs::rename(&path, migrated_legacy_path(&path)).unwrap();

    let (loaded, writer) = DbStore::open(path.clone(), &master).unwrap();
    close_writer_for_test(writer).await;
    assert!(path.exists());
    assert!(loaded
        .channels
        .get("4")
        .unwrap()
        .known_secrets
        .contains_key("9"));
}

#[test]
fn durable_wires_do_not_serialize_session_labels() {
    let wires = Ag2pcSecureWires {
        lambda: vec![1],
        wire_bundle: vec![AShareBundle {
            mac: Block::make(1, 2),
            key: Block::make(3, 4),
        }],
        label0: vec![Block::make(5, 6)],
        eval_label: vec![Block::make(7, 8)],
    };
    let durable = SerializableWires::from_secure_wires(&wires);
    let loaded = durable.to_secure_wires();
    assert_eq!(loaded.lambda, wires.lambda);
    assert_eq!(loaded.wire_bundle, wires.wire_bundle);
    assert!(loaded.label0.is_empty());
    assert!(loaded.eval_label.is_empty());
}

#[test]
fn daemon_has_single_sha_circuit_parse_site() {
    const NEEDLE: &str = concat!("sha256_compress_", "gadget(");
    let source = include_str!("lib.rs");
    assert_eq!(source.matches(NEEDLE).count(), 1);
}

#[test]
fn circuit_is_shareable_between_tasks() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Circuit>();
}

#[test]
fn known_secret_derivation_matches_reference_when_possible() {
    let seed =
        Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let from = Index48::from_hex("2").unwrap();
    let to = Index48::from_hex("3").unwrap();
    let from_secret = generate_from_seed(seed, from);
    let derived = derive_from_known(from.get(), from_secret, to.get()).unwrap();
    assert_eq!(derived, generate_from_seed(seed, to));
    assert!(derive_from_known(to.get(), generate_from_seed(seed, to), from.get()).is_none());
    assert!(derive_from_known(
        1,
        generate_from_seed(seed, Index48::from_hex("1").unwrap()),
        to.get()
    )
    .is_none());
}

#[test]
fn known_secret_derivation_rejects_unreachable_prefixes() {
    let seed =
        Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let from = Index48::from_hex("2").unwrap();
    let from_secret = generate_from_seed(seed, from);
    assert_eq!(
        derive_from_known(
            from.get(),
            from_secret,
            Index48::from_hex("3").unwrap().get()
        ),
        Some(generate_from_seed(seed, Index48::from_hex("3").unwrap()))
    );
    assert!(derive_from_known(
        from.get(),
        from_secret,
        Index48::from_hex("6").unwrap().get()
    )
    .is_none());
}

#[test]
fn resource_model_uses_configured_workers_directly() {
    let mut inner = test_inner(1, 8);
    inner.active_jobs.insert(
        "job".to_owned(),
        JobRecord {
            channel_index: 1,
            kind: "precompute".to_owned(),
            state: "test".to_owned(),
            planned_checked_units: 1,
        },
    );
    let model = resource_model(&inner, 3);
    assert_eq!(model.configured_workers, 8);
    assert_eq!(model.ram_limited_workers_raw, 8);
    assert_eq!(model.effective_workers, 8);
    assert!(!model.ram_overcommit_warning);
    assert_eq!(model.baseline_daemon_rss_bytes, 0);
    assert_eq!(model.current_rss_bytes, 0);
    assert_eq!(model.reserved_ram_bytes, 0);
    assert_eq!(model.live_session_count, 3);
}

fn test_inner(max_ram_bytes: u64, workers: u32) -> Inner {
    let dir = tempdir().unwrap();
    let master = vec![1u8; 32];
    Inner {
        cfg: DaemonConfig {
            role: Role::Alice,
            db_path: dir.path().join("test.db"),
            control_addr: "127.0.0.1:1".parse().unwrap(),
            peer_addr: "127.0.0.1:2".parse().unwrap(),
            peer_url: None,
            peer_tls: None,
            mpc_port: 30000,
            max_ram_bytes,
            workers,
            precompute: 0,
            control_file: None,
            cookie_file: None,
        },
        master_secret: SecretBytes(master),
        cookie: "cookie".to_owned(),
        db: PlainDb::default(),
        active_jobs: BTreeMap::new(),
        next_job_id: 0,
    }
}

fn sample_wire_record() -> WireRecord {
    let wires = Ag2pcSecureWires {
        lambda: vec![0, 1],
        wire_bundle: vec![
            AShareBundle {
                mac: Block::make(1, 2),
                key: Block::make(3, 4),
            },
            AShareBundle {
                mac: Block::make(5, 6),
                key: Block::make(7, 8),
            },
        ],
        label0: Vec::new(),
        eval_label: Vec::new(),
    };
    WireRecord {
        public_binding_hex: "aa".repeat(32),
        local_binding_hex: "bb".repeat(32),
        wires: SerializableWires::from_secure_wires(&wires),
    }
}

async fn close_writer_for_test(writer: DbWriter) {
    writer.flush().await.unwrap();
    drop(writer);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

fn tamper_first_redb_value(path: &Path) {
    let database = Database::open(path).unwrap();
    let write = database.begin_write().unwrap();
    let (key, mut value) = {
        let table = write.open_table(REDB_TABLE).unwrap();
        let (key, value) = table.iter().unwrap().next().unwrap().unwrap();
        (key.value().to_vec(), value.value().to_vec())
    };
    {
        let mut table = write.open_table(REDB_TABLE).unwrap();
        let last = value.last_mut().unwrap();
        *last ^= 1;
        table.insert(key.as_slice(), value.as_slice()).unwrap();
    }
    write.commit().unwrap();
}

fn write_legacy_db_for_test(path: &Path, master_secret: &[u8], db: &PlainDb) {
    let salt = [9u8; DB_SALT_LEN];
    let nonce = [8u8; DB_NONCE_LEN];
    let key = derive_db_key(master_secret, &salt);
    let plaintext = serde_json::to_vec(db).unwrap();
    let mut tag = [0u8; DB_TAG_LEN];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        DB_AAD,
        &plaintext,
        &mut tag,
    )
    .unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DB_MAGIC);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&ciphertext);
    fs::write(path, bytes).unwrap();
}
