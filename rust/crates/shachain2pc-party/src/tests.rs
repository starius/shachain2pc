use super::*;
use shachain2pc_circuit::generate_from_seed;
use std::net::TcpListener as StdTcpListener;
use std::sync::OnceLock;
use tokio::sync::Mutex;
use tokio::time::timeout;

const SHARE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHARE_B: &str = "abababababababababababababababababababababababababababababababab";
const INDEX_ZERO_RESULT: &str = "0101010101010101010101010101010101010101010101010101010101010101";
static PARTY_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn party_uses_shared_sha_circuit() {
    let first = shared_sha_circuit();
    let second = shared_sha_circuit();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first.n3, VALUE_BITS as i32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_party_i0_honest_matches_reference() {
    let (alice, bob) = run_pair(
        Index48::from_hex("0").unwrap(),
        Index48::from_hex("0").unwrap(),
        true,
        true,
        Duration::from_secs(60),
    )
    .await;
    let expected = Value32::from_hex(INDEX_ZERO_RESULT).unwrap();
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_party_i0_without_allow_seed_reveal_refuses_before_socket() {
    let port = free_port();
    let err = run_derivation(test_args(
        Role::Alice,
        port,
        Index48::from_hex("0").unwrap(),
        SHARE_A,
        false,
    ))
    .await
    .unwrap_err();
    assert!(matches!(err, PartyError::SeedRevealRefused));
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_party_rejects_index_mismatch_before_output() {
    let (alice, bob) = run_pair(
        Index48::from_hex("1").unwrap(),
        Index48::from_hex("3").unwrap(),
        false,
        false,
        Duration::from_secs(120),
    )
    .await;
    assert!(matches!(alice, Err(PartyError::CircuitMismatch)));
    assert!(matches!(bob, Err(PartyError::CircuitMismatch)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_party_real_circuits_match_reference() {
    assert_party_pair_matches_reference("1", Duration::from_secs(300)).await;
    assert_party_pair_matches_reference("3", Duration::from_secs(600)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_party_chunked_i0_matches_reference() {
    let index = Index48::from_hex("0").unwrap();
    let (alice, bob) = run_pair_chunked(index, 1, Duration::from_secs(300)).await;
    let expected = generate_from_seed(combined_seed(), index);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "48 SHA blocks are too slow for the default debug test run"]
async fn rust_party_full_start_index_matches_reference() {
    assert_party_pair_matches_reference("ffffffffffff", Duration::from_secs(7200)).await;
}

#[test]
fn parse_allow_seed_reveal_position_independently() {
    for args in [
        vec!["party", "--allow-seed-reveal", "1", "1234", "0", SHARE_A],
        vec!["party", "1", "--allow-seed-reveal", "1234", "0", SHARE_A],
        vec!["party", "1", "1234", "0", SHARE_A, "--allow-seed-reveal"],
    ] {
        let parsed = parse_args(args.into_iter().map(str::to_owned).collect()).unwrap();
        assert!(parsed.allow_seed_reveal);
        assert_eq!(
            parsed.index_spec,
            IndexSpec::Single(Index48::new(0).unwrap())
        );
    }
}

#[test]
fn parse_i0_without_allow_seed_reveal_refuses() {
    let err = parse_args(
        ["party", "1", "1234", "0", SHARE_A]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
    .unwrap_err();
    assert!(matches!(err, PartyError::SeedRevealRefused));
}

#[test]
fn parses_range_index_spec() {
    let parsed = parse_args(
        ["party", "1", "1234", "64-c8", SHARE_A]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
    .unwrap();
    assert_eq!(
        parsed.index_spec,
        IndexSpec::Range {
            lo: Index48::from_hex("64").unwrap(),
            hi: Index48::from_hex("c8").unwrap(),
        }
    );

    let err = parse_index_spec("c8-64").unwrap_err();
    assert!(matches!(err, PartyError::Parse(msg) if msg == "range LO must be <= HI"));

    let err = parse_index_spec("1-").unwrap_err();
    assert!(matches!(err, PartyError::Parse(msg) if msg == "range must be LO-HI (both hex)"));

    let err = parse_index_spec("0-186a0").unwrap_err();
    assert!(matches!(err, PartyError::Parse(msg) if msg == "range too large (max 100000 indices)"));
}

#[test]
fn precompute_cache_parent_rule_matches_shachain_derivability() {
    assert!(can_derive_mask(0b10, 0b11));
    assert!(can_derive_mask(0b100, 0b111));
    assert!(!can_derive_mask(0b11, 0b10));
    assert!(!can_derive_mask(0b10, 0b110));
}

#[test]
fn precompute_cache_retention_keeps_future_storage_closure() {
    assert_eq!(max_derivable_mask(0b1_0000), 0b1_1111);
    assert_eq!(max_derivable_mask(0b1_0010), 0b1_0011);

    assert!(retain_cache_mask_for_future(0b1_0000, 0b1_0010));
    assert!(retain_cache_mask_for_future(0b1_0010, 0b1_0010));
    assert!(!retain_cache_mask_for_future(0b1_0010, 0b1_0011));
    assert!(retain_cache_mask_for_future(0b1_0011, 0b1_0011));
}

#[test]
fn precompute_cache_pruning_preserves_adjacent_warm_parent() {
    let mut cache: BTreeMap<u32, (u64, Ag2pcSecureWires)> = BTreeMap::new();
    cache.insert(4, (0b1_0000, Ag2pcSecureWires::default()));
    cache.insert(1, (0b1_0010, Ag2pcSecureWires::default()));

    let parent_19 = cache
        .values()
        .filter(|(mask, _)| can_derive_mask(*mask, 0b1_0011))
        .max_by_key(|(mask, _)| mask.count_ones())
        .map(|(mask, _)| *mask);
    assert_eq!(parent_19, Some(0b1_0010));

    cache.insert(0, (0b1_0011, Ag2pcSecureWires::default()));
    prune_cache_for_target(&mut cache, 0b1_0011);
    assert!(cache.values().any(|(mask, _)| *mask == 0b1_0000));
    assert!(cache.values().any(|(mask, _)| *mask == 0b1_0011));
    assert!(!cache.values().any(|(mask, _)| *mask == 0b1_0010));

    let parent_20 = cache
        .values()
        .filter(|(mask, _)| can_derive_mask(*mask, 0b1_0100))
        .max_by_key(|(mask, _)| mask.count_ones())
        .map(|(mask, _)| *mask);
    assert_eq!(parent_20, Some(0b1_0000));
}

#[test]
fn parse_range_containing_seed_requires_flag() {
    let err = parse_args(
        ["party", "1", "1234", "0-5", SHARE_A]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
    .unwrap_err();
    assert!(matches!(err, PartyError::SeedRevealRefused));

    let parsed = parse_args(
        ["party", "--allow-seed-reveal", "1", "1234", "0-5", SHARE_A]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
    .unwrap();
    assert_eq!(
        parsed.index_spec,
        IndexSpec::Range {
            lo: Index48::new(0).unwrap(),
            hi: Index48::new(5).unwrap(),
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_range_i0_honest_matches_reference() {
    let index = Index48::from_hex("0").unwrap();
    let (alice, bob) = run_pair_range(index, index, true, Duration::from_secs(60)).await;
    let expected = vec![(index, generate_from_seed(combined_seed(), index))];
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_tree_range_matches_reference() {
    let lo = Index48::from_hex("800000000000").unwrap();
    let hi = Index48::from_hex("800000000001").unwrap();
    let (alice, bob) = run_pair_tree(lo, hi, 0, Duration::from_secs(900)).await;
    let expected = expected_range(lo, hi);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_cache_fallback_range_matches_reference() {
    let lo = Index48::from_hex("800000000000").unwrap();
    let hi = Index48::from_hex("800000000001").unwrap();
    let (alice, bob) = run_pair_cache(lo, hi, 16, 1, Duration::from_secs(900)).await;
    let expected = expected_range(lo, hi);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "16-leaf cache tile is too slow for the default debug test run"]
async fn rust_cache_tile_range_matches_reference() {
    let lo = Index48::from_hex("800000000000").unwrap();
    let hi = Index48::from_hex("80000000000f").unwrap();
    let (alice, bob) = run_pair_cache(lo, hi, 16, 16, Duration::from_secs(7200)).await;
    let expected = expected_range(lo, hi);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "recursive cache tile tree is too slow for the default debug test run"]
async fn rust_cache_recursive_tile_range_matches_reference() {
    let lo = Index48::from_hex("800000000000").unwrap();
    let hi = Index48::from_hex("800000000003").unwrap();
    let (alice, bob) = run_pair_cache(lo, hi, 16, 2, Duration::from_secs(7200)).await;
    let expected = expected_range(lo, hi);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

#[test]
fn mode_support_boundary_is_explicit() {
    let single = IndexSpec::Single(Index48::from_hex("1").unwrap());
    let range = IndexSpec::Range {
        lo: Index48::from_hex("64").unwrap(),
        hi: Index48::from_hex("65").unwrap(),
    };

    assert!(ensure_mode_supported_for_now(&single, RequestedMode::Full).is_ok());
    assert!(ensure_mode_supported_for_now(&range, RequestedMode::Full).is_ok());
    assert!(ensure_mode_supported_for_now(&single, RequestedMode::Chunked).is_ok());
    assert!(matches!(
        ensure_mode_supported_for_now(&range, RequestedMode::Chunked),
        Err(PartyError::UnsupportedMode(msg)) if msg.contains("single-index")
    ));
    assert!(ensure_mode_supported_for_now(&range, RequestedMode::Tree).is_ok());
    assert!(ensure_mode_supported_for_now(&range, RequestedMode::Cache).is_ok());
}

#[test]
fn range_split_masks_match_high_trunk_low_branch() {
    let indices = [
        Index48::from_hex("800000000010").unwrap(),
        Index48::from_hex("80000000001f").unwrap(),
    ];
    let (split, low_mask, high_mask) = range_split_masks(&indices).unwrap();
    assert_eq!(split, 3);
    assert_eq!(low_mask, 0x0f);
    assert_eq!(high_mask, 0xffff_ffff_fff0);
    assert_eq!(set_bits_desc(indices[0].get() & high_mask), vec![47, 4]);
    assert_eq!(set_bits_desc(indices[1].get() & low_mask), vec![3, 2, 1, 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_tree_without_shared_hash_refuses_before_socket() {
    let port = free_port();
    let lo = Index48::from_hex("1").unwrap();
    let hi = Index48::from_hex("2").unwrap();
    let err = run_derivation_tree(
        Role::Alice,
        port,
        &[lo, hi],
        Value32::from_hex(SHARE_A).unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, PartyError::UnsupportedMode(msg) if msg.contains("shared-trunk")));
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_cache_without_shared_hash_refuses_before_socket() {
    let port = free_port();
    let lo = Index48::from_hex("1").unwrap();
    let hi = Index48::from_hex("2").unwrap();
    let err = run_derivation_cache(
        Role::Alice,
        port,
        &[lo, hi],
        Value32::from_hex(SHARE_A).unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        16,
        16,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, PartyError::UnsupportedMode(msg) if msg.contains("cache needs")));
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

async fn assert_party_pair_matches_reference(index_hex: &str, timeout_duration: Duration) {
    let index = Index48::from_hex(index_hex).unwrap();
    let (alice, bob) = run_pair(index, index, false, false, timeout_duration).await;
    let expected = generate_from_seed(combined_seed(), index);
    assert_eq!(alice.unwrap(), expected);
    assert_eq!(bob.unwrap(), expected);
}

async fn run_pair(
    alice_index: Index48,
    bob_index: Index48,
    alice_allow_seed_reveal: bool,
    bob_allow_seed_reveal: bool,
    timeout_duration: Duration,
) -> (Result<Value32, PartyError>, Result<Value32, PartyError>) {
    let _guard = party_test_lock().lock().await;
    let port = free_port();
    let alice = tokio::spawn(run_derivation(test_args(
        Role::Alice,
        port,
        alice_index,
        SHARE_A,
        alice_allow_seed_reveal,
    )));
    sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(run_derivation(test_args(
        Role::Bob,
        port,
        bob_index,
        SHARE_B,
        bob_allow_seed_reveal,
    )));
    timeout(timeout_duration, async {
        let alice = alice.await.unwrap();
        let bob = bob.await.unwrap();
        (alice, bob)
    })
    .await
    .unwrap()
}

async fn run_pair_chunked(
    index: Index48,
    blocks_per_chunk: usize,
    timeout_duration: Duration,
) -> (Result<Value32, PartyError>, Result<Value32, PartyError>) {
    let _guard = party_test_lock().lock().await;
    let port = free_port();
    let alice = tokio::spawn(run_derivation_chunked(
        Role::Alice,
        port,
        index,
        Value32::from_hex(SHARE_A).unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        blocks_per_chunk,
    ));
    sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(run_derivation_chunked(
        Role::Bob,
        port,
        index,
        Value32::from_hex(SHARE_B).unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        blocks_per_chunk,
    ));
    timeout(timeout_duration, async {
        let alice = alice.await.unwrap();
        let bob = bob.await.unwrap();
        (alice, bob)
    })
    .await
    .unwrap()
}

async fn run_pair_tree(
    lo: Index48,
    hi: Index48,
    trunk_chunk_blocks: i32,
    timeout_duration: Duration,
) -> (
    Result<Vec<(Index48, Value32)>, PartyError>,
    Result<Vec<(Index48, Value32)>, PartyError>,
) {
    let _guard = party_test_lock().lock().await;
    let port = free_port();
    let alice_indices = indices_between(lo, hi);
    let bob_indices = alice_indices.clone();
    let alice = tokio::spawn(async move {
        run_derivation_tree(
            Role::Alice,
            port,
            &alice_indices,
            Value32::from_hex(SHARE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            trunk_chunk_blocks,
        )
        .await
    });
    sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        run_derivation_tree(
            Role::Bob,
            port,
            &bob_indices,
            Value32::from_hex(SHARE_B).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            trunk_chunk_blocks,
        )
        .await
    });
    timeout(timeout_duration, async {
        let alice = alice.await.unwrap();
        let bob = bob.await.unwrap();
        (alice, bob)
    })
    .await
    .unwrap()
}

async fn run_pair_cache(
    lo: Index48,
    hi: Index48,
    trunk_chunk_blocks: i32,
    tile_fanout: usize,
    timeout_duration: Duration,
) -> (
    Result<Vec<(Index48, Value32)>, PartyError>,
    Result<Vec<(Index48, Value32)>, PartyError>,
) {
    let _guard = party_test_lock().lock().await;
    let port = free_port();
    let alice_indices = indices_between(lo, hi);
    let bob_indices = alice_indices.clone();
    let alice = tokio::spawn(async move {
        run_derivation_cache(
            Role::Alice,
            port,
            &alice_indices,
            Value32::from_hex(SHARE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            trunk_chunk_blocks,
            tile_fanout,
        )
        .await
    });
    sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        run_derivation_cache(
            Role::Bob,
            port,
            &bob_indices,
            Value32::from_hex(SHARE_B).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            trunk_chunk_blocks,
            tile_fanout,
        )
        .await
    });
    timeout(timeout_duration, async {
        let alice = alice.await.unwrap();
        let bob = bob.await.unwrap();
        (alice, bob)
    })
    .await
    .unwrap()
}

async fn run_pair_range(
    lo: Index48,
    hi: Index48,
    allow_seed_reveal: bool,
    timeout_duration: Duration,
) -> (
    Result<Vec<(Index48, Value32)>, PartyError>,
    Result<Vec<(Index48, Value32)>, PartyError>,
) {
    let _guard = party_test_lock().lock().await;
    let port = free_port();
    let alice = tokio::spawn(run_party(test_range_args(
        Role::Alice,
        port,
        lo,
        hi,
        SHARE_A,
        allow_seed_reveal,
    )));
    sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(run_party(test_range_args(
        Role::Bob,
        port,
        lo,
        hi,
        SHARE_B,
        allow_seed_reveal,
    )));
    timeout(timeout_duration, async {
        let alice = match alice.await.unwrap() {
            Ok(PartyOutput::Range(outputs)) => Ok(outputs),
            Ok(PartyOutput::Single(_)) => Err(PartyError::UnsupportedMode(
                "test expected range output, got single output",
            )),
            Err(e) => Err(e),
        };
        let bob = match bob.await.unwrap() {
            Ok(PartyOutput::Range(outputs)) => Ok(outputs),
            Ok(PartyOutput::Single(_)) => Err(PartyError::UnsupportedMode(
                "test expected range output, got single output",
            )),
            Err(e) => Err(e),
        };
        (alice, bob)
    })
    .await
    .unwrap()
}

fn test_args(role: Role, port: u16, index: Index48, share: &str, allow_seed_reveal: bool) -> Args {
    Args {
        role,
        port,
        index_spec: IndexSpec::Single(index),
        share: Value32::from_hex(share).unwrap(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_seed_reveal,
    }
}

fn test_range_args(
    role: Role,
    port: u16,
    lo: Index48,
    hi: Index48,
    share: &str,
    allow_seed_reveal: bool,
) -> Args {
    Args {
        role,
        port,
        index_spec: IndexSpec::Range { lo, hi },
        share: Value32::from_hex(share).unwrap(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_seed_reveal,
    }
}

fn party_test_lock() -> &'static Mutex<()> {
    PARTY_TEST_LOCK.get_or_init(|| Mutex::new(()))
}

fn combined_seed() -> Value32 {
    Value32::from_hex(SHARE_A)
        .unwrap()
        .xor(Value32::from_hex(SHARE_B).unwrap())
}

fn indices_between(lo: Index48, hi: Index48) -> Vec<Index48> {
    (lo.get()..=hi.get())
        .map(|value| Index48::new(value).unwrap())
        .collect()
}

fn expected_range(lo: Index48, hi: Index48) -> Vec<(Index48, Value32)> {
    indices_between(lo, hi)
        .into_iter()
        .map(|index| (index, generate_from_seed(combined_seed(), index)))
        .collect()
}

fn free_port() -> u16 {
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
