use shachain2pc_daemon::pb::control_service_client::ControlServiceClient;
use shachain2pc_daemon::pb::{RevealRequest, RevealResponse};
use shachain2pc_daemon::{channel_seed_share, read_control_file, reference_for_channel};
use shachain2pc_types::Index48;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

const MASTER_A: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MASTER_B: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
static NEXT_PORT: AtomicUsize = AtomicUsize::new(23_000);
static DAEMON_PAIR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark harness; run explicitly"]
async fn daemon_bench_100_channels_good_case() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start_mtls().await;
    pair.cli(&pair.alice_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.bob_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.alice_control, &["config", "precompute", "1"])
        .await;
    pair.cli(&pair.bob_control, &["config", "precompute", "1"])
        .await;

    let channels: Vec<u64> = (1000..1100).collect();
    let setup_start = Instant::now();
    for channel in &channels {
        let channel_s = channel.to_string();
        pair.cli(&pair.alice_control, &["channel", "enable", &channel_s])
            .await;
        pair.cli(&pair.bob_control, &["channel", "enable", &channel_s])
            .await;
    }
    let setup_ms = setup_start.elapsed().as_millis() as u64;

    let precompute_start = Instant::now();
    pair.wait_frontier_total(&pair.alice_control, channels.len(), 1)
        .await;
    pair.wait_frontier_total(&pair.bob_control, channels.len(), 1)
        .await;
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let precompute_ms = precompute_start.elapsed().as_millis() as u64;
    let alice_idle_after_precompute = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_precompute = pair.bob.vm_rss_bytes().unwrap_or(0);

    let mut alice_control = ControlHarnessClient::connect(&pair.alice_control).await;
    let mut bob_control = ControlHarnessClient::connect(&pair.bob_control).await;
    let mut reveal_latencies = Vec::with_capacity(channels.len());
    for channel in &channels {
        let reveal_start = Instant::now();
        let (alice, bob) = tokio::join!(
            alice_control.reveal(*channel, 1, 1, false),
            bob_control.reveal(*channel, 1, 1, false)
        );
        assert_eq!(alice.secret_hex, bob.secret_hex);
        assert!(alice.from_cache);
        assert!(bob.from_cache);
        reveal_latencies.push(reveal_start.elapsed().as_millis() as u64);
    }
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let alice_idle_after_reveals = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_reveals = pair.bob.vm_rss_bytes().unwrap_or(0);

    let alice_hwm = pair.alice.vm_hwm_bytes().unwrap_or(0);
    let bob_hwm = pair.bob.vm_hwm_bytes().unwrap_or(0);
    let summary = serde_json::json!({
        "channels": channels.len(),
        "workers": 4,
        "setup_ms": setup_ms,
        "precompute": {
            "committed": channels.len(),
            "wall_ms": precompute_ms,
            "ms_per_secret": precompute_ms as f64 / channels.len() as f64
        },
        "cached_reveal": {
            "count": reveal_latencies.len(),
            "p50_ms": percentile(&mut reveal_latencies.clone(), 50),
            "p95_ms": percentile(&mut reveal_latencies.clone(), 95),
            "p99_ms": percentile(&mut reveal_latencies.clone(), 99),
            "max_ms": reveal_latencies.iter().copied().max().unwrap_or(0),
            "avg_ms": reveal_latencies.iter().sum::<u64>() as f64
                / reveal_latencies.len().max(1) as f64
        },
        "rss": {
            "alice_idle_after_precompute_mb": alice_idle_after_precompute / (1024 * 1024),
            "bob_idle_after_precompute_mb": bob_idle_after_precompute / (1024 * 1024),
            "pair_idle_after_precompute_sum_mb": (alice_idle_after_precompute
                + bob_idle_after_precompute) / (1024 * 1024),
            "alice_idle_after_reveals_mb": alice_idle_after_reveals / (1024 * 1024),
            "bob_idle_after_reveals_mb": bob_idle_after_reveals / (1024 * 1024),
            "pair_idle_after_reveals_sum_mb": (alice_idle_after_reveals
                + bob_idle_after_reveals) / (1024 * 1024),
            "alice_peak_mb": alice_hwm / (1024 * 1024),
            "bob_peak_mb": bob_hwm / (1024 * 1024),
            "pair_peak_sum_mb": (alice_hwm + bob_hwm) / (1024 * 1024)
        },
        "alice_status": pair.cli(&pair.alice_control, &["status"]).await.trim(),
        "bob_status": pair.cli(&pair.bob_control, &["status"]).await.trim()
    });
    println!("{summary}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark harness; run explicitly"]
async fn daemon_bench_100_channels_warm_refill() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start_mtls().await;
    pair.cli(&pair.alice_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.bob_control, &["config", "workers", "4"])
        .await;

    let channels: Vec<u64> = (2000..2100).collect();
    for channel in &channels {
        let channel_s = channel.to_string();
        pair.cli(&pair.alice_control, &["channel", "enable", &channel_s])
            .await;
        pair.cli(&pair.bob_control, &["channel", "enable", &channel_s])
            .await;
    }

    pair.cli(&pair.alice_control, &["config", "precompute", "2"])
        .await;
    pair.cli(&pair.bob_control, &["config", "precompute", "2"])
        .await;
    let cold_start = Instant::now();
    pair.wait_frontier_total(&pair.alice_control, channels.len(), 2)
        .await;
    pair.wait_frontier_total(&pair.bob_control, channels.len(), 2)
        .await;
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let cold_ms = cold_start.elapsed().as_millis() as u64;
    let alice_idle_after_cold = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_cold = pair.bob.vm_rss_bytes().unwrap_or(0);

    pair.cli(&pair.alice_control, &["config", "precompute", "3"])
        .await;
    pair.cli(&pair.bob_control, &["config", "precompute", "3"])
        .await;
    let warm_start = Instant::now();
    pair.wait_frontier_total(&pair.alice_control, channels.len(), 3)
        .await;
    pair.wait_frontier_total(&pair.bob_control, channels.len(), 3)
        .await;
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let warm_ms = warm_start.elapsed().as_millis() as u64;
    let alice_idle_after_warm = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_warm = pair.bob.vm_rss_bytes().unwrap_or(0);

    let alice_hwm = pair.alice.vm_hwm_bytes().unwrap_or(0);
    let bob_hwm = pair.bob.vm_hwm_bytes().unwrap_or(0);
    let summary = serde_json::json!({
        "channels": channels.len(),
        "workers": 4,
        "cold_fill": {
            "target": 2,
            "wall_ms": cold_ms,
            "ms_per_secret": cold_ms as f64 / channels.len() as f64
        },
        "warm_refill": {
            "target": 3,
            "wall_ms": warm_ms,
            "ms_per_secret": warm_ms as f64 / channels.len() as f64
        },
        "rss": {
            "alice_idle_after_cold_mb": alice_idle_after_cold / (1024 * 1024),
            "bob_idle_after_cold_mb": bob_idle_after_cold / (1024 * 1024),
            "pair_idle_after_cold_sum_mb": (alice_idle_after_cold
                + bob_idle_after_cold) / (1024 * 1024),
            "alice_idle_after_warm_mb": alice_idle_after_warm / (1024 * 1024),
            "bob_idle_after_warm_mb": bob_idle_after_warm / (1024 * 1024),
            "pair_idle_after_warm_sum_mb": (alice_idle_after_warm
                + bob_idle_after_warm) / (1024 * 1024),
            "alice_peak_mb": alice_hwm / (1024 * 1024),
            "bob_peak_mb": bob_hwm / (1024 * 1024),
            "pair_peak_sum_mb": (alice_hwm + bob_hwm) / (1024 * 1024)
        },
        "alice_status": pair.cli(&pair.alice_control, &["status"]).await.trim(),
        "bob_status": pair.cli(&pair.bob_control, &["status"]).await.trim()
    });
    println!("{summary}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark harness; run explicitly"]
async fn daemon_bench_1000_channels_idle_floor() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start_mtls().await;
    pair.cli(&pair.alice_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.bob_control, &["config", "workers", "4"])
        .await;

    let channels: Vec<u64> = (10_000..11_000).collect();
    let enable_start = Instant::now();
    for channel in &channels {
        let channel_s = channel.to_string();
        pair.cli(&pair.alice_control, &["channel", "enable", &channel_s])
            .await;
        pair.cli(&pair.bob_control, &["channel", "enable", &channel_s])
            .await;
    }
    let enable_ms = enable_start.elapsed().as_millis() as u64;

    pair.cli(&pair.alice_control, &["config", "precompute", "1"])
        .await;
    pair.cli(&pair.bob_control, &["config", "precompute", "1"])
        .await;
    let fill_start = Instant::now();
    pair.wait_frontier_total(&pair.alice_control, channels.len(), 1)
        .await;
    pair.wait_frontier_total(&pair.bob_control, channels.len(), 1)
        .await;
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let fill_ms = fill_start.elapsed().as_millis() as u64;
    let alice_idle_after_fill = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_fill = pair.bob.vm_rss_bytes().unwrap_or(0);

    let disable_start = Instant::now();
    for channel in &channels {
        let channel_s = channel.to_string();
        pair.cli(&pair.alice_control, &["channel", "disable", &channel_s])
            .await;
        pair.cli(&pair.bob_control, &["channel", "disable", &channel_s])
            .await;
    }
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    let disable_ms = disable_start.elapsed().as_millis() as u64;
    let alice_idle_after_disable = pair.alice.vm_rss_bytes().unwrap_or(0);
    let bob_idle_after_disable = pair.bob.vm_rss_bytes().unwrap_or(0);

    let alice_hwm = pair.alice.vm_hwm_bytes().unwrap_or(0);
    let bob_hwm = pair.bob.vm_hwm_bytes().unwrap_or(0);
    let summary = serde_json::json!({
        "channels": channels.len(),
        "workers": 4,
        "enable_ms": enable_ms,
        "fill": {
            "wall_ms": fill_ms,
            "ms_per_secret": fill_ms as f64 / channels.len() as f64
        },
        "disable_ms": disable_ms,
        "rss": {
            "alice_idle_after_fill_mb": alice_idle_after_fill / (1024 * 1024),
            "bob_idle_after_fill_mb": bob_idle_after_fill / (1024 * 1024),
            "pair_idle_after_fill_sum_mb": (alice_idle_after_fill
                + bob_idle_after_fill) / (1024 * 1024),
            "alice_idle_after_disable_mb": alice_idle_after_disable / (1024 * 1024),
            "bob_idle_after_disable_mb": bob_idle_after_disable / (1024 * 1024),
            "pair_idle_after_disable_sum_mb": (alice_idle_after_disable
                + bob_idle_after_disable) / (1024 * 1024),
            "alice_peak_mb": alice_hwm / (1024 * 1024),
            "bob_peak_mb": bob_hwm / (1024 * 1024),
            "pair_peak_sum_mb": (alice_hwm + bob_hwm) / (1024 * 1024)
        },
        "alice_status": pair.cli(&pair.alice_control, &["status"]).await.trim(),
        "bob_status": pair.cli(&pair.bob_control, &["status"]).await.trim()
    });
    println!("{summary}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_seed_reveal_restart_and_local_cache() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "7"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "7"])
        .await;

    let (alice, bob) = tokio::join!(
        pair.cli(
            &pair.alice_control,
            &["reveal", "7", "0", "0", "--allow-seed-reveal"]
        ),
        pair.cli(
            &pair.bob_control,
            &["reveal", "7", "0", "0", "--allow-seed-reveal"]
        )
    );
    let alice = parse_result(&alice);
    let bob = parse_result(&bob);
    assert_eq!(alice, bob);

    let expected = channel_seed_share(&hex(MASTER_A), 7).xor(channel_seed_share(&hex(MASTER_B), 7));
    assert_eq!(alice, expected.to_hex());
    assert!(!std::fs::read(pair.dir.path().join("alice.db"))
        .unwrap()
        .windows(expected.to_hex().len())
        .any(|window| window == expected.to_hex().as_bytes()));

    let pair = DaemonPair::restart(pair).await;
    let alice = pair
        .cli(
            &pair.alice_control,
            &["reveal", "7", "0", "0", "--allow-seed-reveal"],
        )
        .await;
    assert_eq!(parse_result(&alice), expected.to_hex());
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_nonzero_reveal_matches_reference() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "9"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "9"])
        .await;
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "9", "1", "1"]),
        pair.cli(&pair.bob_control, &["reveal", "9", "1", "1"])
    );
    let alice = parse_result(&alice);
    let bob = parse_result(&bob);
    assert_eq!(alice, bob);
    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 9, Index48::new(1).unwrap());
    assert_eq!(alice, expected.to_hex());

    let channels = pair.cli(&pair.alice_control, &["channels"]).await;
    assert!(channels.contains("known=1"), "{channels}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_precomputed_frontier_survives_restart() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "13"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "13"])
        .await;

    let alice_precompute = pair
        .cli(&pair.alice_control, &["precompute", "13", "1"])
        .await;
    assert!(alice_precompute.contains("nodes=1"), "{alice_precompute}");
    assert!(alice_precompute.contains("checked=1"), "{alice_precompute}");
    let alice_channels = pair.cli(&pair.alice_control, &["channels"]).await;
    let bob_channels = pair.cli(&pair.bob_control, &["channels"]).await;
    assert!(alice_channels.contains("frontier=1"), "{alice_channels}");
    assert!(bob_channels.contains("frontier=1"), "{bob_channels}");

    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 13, Index48::new(1).unwrap());
    assert!(!std::fs::read(pair.dir.path().join("alice.db"))
        .unwrap()
        .windows(expected.to_hex().len())
        .any(|window| window == expected.to_hex().as_bytes()));

    let pair = DaemonPair::restart(pair).await;
    let alice_precompute_again = pair
        .cli(&pair.alice_control, &["precompute", "13", "1"])
        .await;
    assert!(
        alice_precompute_again.contains("nodes=0"),
        "{alice_precompute_again}"
    );
    assert!(
        alice_precompute_again.contains("checked=0"),
        "{alice_precompute_again}"
    );
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "13", "1", "1"]),
        pair.cli(&pair.bob_control, &["reveal", "13", "1", "1"])
    );
    assert_eq!(parse_result(&alice), expected.to_hex());
    assert_eq!(parse_result(&bob), expected.to_hex());
    assert_eq!(parse_cache(&alice), Some(true));
    assert_eq!(parse_cache(&bob), Some(true));
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_precompute_persists_only_requested_leaf() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "16"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "16"])
        .await;

    let alice_precompute = pair
        .cli(&pair.alice_control, &["precompute", "16", "3"])
        .await;
    assert!(alice_precompute.contains("nodes=1"), "{alice_precompute}");
    assert!(alice_precompute.contains("checked=2"), "{alice_precompute}");

    let alice_channels = pair.cli(&pair.alice_control, &["channels"]).await;
    let bob_channels = pair.cli(&pair.bob_control, &["channels"]).await;
    assert_channel_contains(&alice_channels, 16, "frontier=1");
    assert_channel_contains(&bob_channels, 16, "frontier=1");

    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 16, Index48::new(3).unwrap());
    let pair = DaemonPair::restart(pair).await;
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "16", "3", "3"]),
        pair.cli(&pair.bob_control, &["reveal", "16", "3", "3"])
    );
    assert_eq!(parse_result(&alice), expected.to_hex());
    assert_eq!(parse_result(&bob), expected.to_hex());
    assert_eq!(parse_cache(&alice), Some(true));
    assert_eq!(parse_cache(&bob), Some(true));
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_reuses_live_session_prefix_between_precomputes() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "18"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "18"])
        .await;

    let first = pair
        .cli(&pair.alice_control, &["precompute", "18", "2"])
        .await;
    assert!(first.contains("nodes=1"), "{first}");
    assert!(first.contains("checked=1"), "{first}");

    let second = pair
        .cli(&pair.alice_control, &["precompute", "18", "3"])
        .await;
    assert!(second.contains("nodes=1"), "{second}");
    assert!(second.contains("checked=1"), "{second}");

    let alice_channels = pair.cli(&pair.alice_control, &["channels"]).await;
    let bob_channels = pair.cli(&pair.bob_control, &["channels"]).await;
    assert_channel_contains(&alice_channels, 18, "frontier=2");
    assert_channel_contains(&alice_channels, 18, "estimated=2");
    assert_channel_contains(&bob_channels, 18, "frontier=2");
    assert_channel_contains(&bob_channels, 18, "estimated=2");

    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 18, Index48::new(3).unwrap());
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "18", "3", "3"]),
        pair.cli(&pair.bob_control, &["reveal", "18", "3", "3"])
    );
    assert_eq!(parse_result(&alice), expected.to_hex());
    assert_eq!(parse_result(&bob), expected.to_hex());
    assert_eq!(parse_cache(&alice), Some(true));
    assert_eq!(parse_cache(&bob), Some(true));
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_peer_mtls_precompute_jobstream() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start_mtls().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "24"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "24"])
        .await;

    let out = pair
        .cli(&pair.alice_control, &["precompute", "24", "1"])
        .await;
    assert!(out.contains("nodes=1"), "{out}");
    assert!(out.contains("checked=1"), "{out}");

    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 24, Index48::new(1).unwrap());
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "24", "1", "1"]),
        pair.cli(&pair.bob_control, &["reveal", "24", "1", "1"])
    );
    assert_eq!(parse_result(&alice), expected.to_hex());
    assert_eq!(parse_result(&bob), expected.to_hex());
    assert_eq!(parse_cache(&alice), Some(true));
    assert_eq!(parse_cache(&bob), Some(true));
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_precompute_repairs_peer_frontier_rollback() {
    let _guard = daemon_pair_lock().await;
    let mut pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "14"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "14"])
        .await;

    let first = pair
        .cli(&pair.alice_control, &["precompute", "14", "1"])
        .await;
    assert!(first.contains("nodes=1"), "{first}");
    pair.kill_children().await;

    let bob_db = pair.dir.path().join("bob.db");
    std::fs::remove_file(&bob_db).unwrap();
    let pair = DaemonPair::start_with_dir_and_ports(pair.dir, pair.ports).await;
    pair.cli(&pair.bob_control, &["channel", "enable", "14"])
        .await;
    let repaired = pair
        .cli(&pair.alice_control, &["precompute", "14", "1"])
        .await;
    assert!(repaired.contains("nodes=1"), "{repaired}");

    let alice_channels = pair.cli(&pair.alice_control, &["channels"]).await;
    let bob_channels = pair.cli(&pair.bob_control, &["channels"]).await;
    assert_channel_contains(&alice_channels, 14, "frontier=1");
    assert_channel_contains(&bob_channels, 14, "frontier=1");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_background_precomputes_to_shared_target() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["config", "precompute", "1"])
        .await;
    pair.cli(&pair.bob_control, &["config", "precompute", "1"])
        .await;
    pair.cli(&pair.alice_control, &["channel", "enable", "15"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "15"])
        .await;

    pair.wait_channel_contains(&pair.alice_control, 15, "frontier=1")
        .await;
    pair.wait_channel_contains(&pair.bob_control, 15, "frontier=1")
        .await;
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;
    sleep(Duration::from_secs(1)).await;

    let expected =
        reference_for_channel(&hex(MASTER_A), &hex(MASTER_B), 15, Index48::new(1).unwrap());
    let (alice, bob) = tokio::join!(
        pair.cli(&pair.alice_control, &["reveal", "15", "1", "1"]),
        pair.cli(&pair.bob_control, &["reveal", "15", "1", "1"])
    );
    assert_eq!(parse_result(&alice), expected.to_hex());
    assert_eq!(parse_result(&bob), expected.to_hex());
    assert_eq!(parse_cache(&alice), Some(true));
    assert_eq!(parse_cache(&bob), Some(true));
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_precomputes_two_channels_over_jobstream() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["config", "workers", "2"])
        .await;
    pair.cli(&pair.bob_control, &["config", "workers", "2"])
        .await;
    for channel in ["20", "21"] {
        pair.cli(&pair.alice_control, &["channel", "enable", channel])
            .await;
        pair.cli(&pair.bob_control, &["channel", "enable", channel])
            .await;
    }

    let (alice_20, alice_21) = tokio::join!(
        pair.cli(&pair.alice_control, &["precompute", "20", "1"]),
        pair.cli(&pair.alice_control, &["precompute", "21", "1"])
    );
    for output in [alice_20, alice_21] {
        assert!(output.contains("nodes=1"), "{output}");
        assert!(output.contains("checked=1"), "{output}");
    }

    let alice_channels = pair.cli(&pair.alice_control, &["channels"]).await;
    let bob_channels = pair.cli(&pair.bob_control, &["channels"]).await;
    assert_channel_contains(&alice_channels, 20, "frontier=1");
    assert_channel_contains(&alice_channels, 21, "frontier=1");
    assert_channel_contains(&alice_channels, 20, "attempted=1");
    assert_channel_contains(&alice_channels, 21, "attempted=1");
    assert_channel_contains(&bob_channels, 20, "frontier=1");
    assert_channel_contains(&bob_channels, 21, "frontier=1");
    assert_channel_contains(&bob_channels, 20, "attempted=1");
    assert_channel_contains(&bob_channels, 21, "attempted=1");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_disable_channel_drops_live_sessions() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "26"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "26"])
        .await;

    let first = pair
        .cli(&pair.alice_control, &["precompute", "26", "1"])
        .await;
    assert!(first.contains("nodes=1"), "{first}");
    pair.wait_jobs_empty(&pair.alice_control).await;
    pair.wait_jobs_empty(&pair.bob_control).await;

    pair.wait_status_field(&pair.alice_control, "live_sessions", 1)
        .await;
    pair.wait_status_field(&pair.bob_control, "live_sessions", 1)
        .await;

    pair.cli(&pair.alice_control, &["channel", "disable", "26"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "disable", "26"])
        .await;
    pair.wait_status_field(&pair.alice_control, "live_sessions", 0)
        .await;
    pair.wait_status_field(&pair.bob_control, "live_sessions", 0)
        .await;

    pair.cli(&pair.alice_control, &["channel", "enable", "26"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "26"])
        .await;
    let second = pair
        .cli(&pair.alice_control, &["precompute", "26", "2"])
        .await;
    assert!(second.contains("nodes=1"), "{second}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_low_ram_warns_but_allows_one_worker() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.bob_control, &["config", "workers", "4"])
        .await;
    pair.cli(&pair.alice_control, &["config", "max-ram-mb", "1"])
        .await;
    pair.cli(&pair.bob_control, &["config", "max-ram-mb", "1"])
        .await;

    let alice_status = pair.cli(&pair.alice_control, &["status"]).await;
    let bob_status = pair.cli(&pair.bob_control, &["status"]).await;
    assert_eq!(status_field(&alice_status, "workers"), Some(4));
    assert_eq!(status_field(&bob_status, "workers"), Some(4));
    assert_eq!(status_field(&alice_status, "effective_workers"), Some(1));
    assert_eq!(status_field(&bob_status, "effective_workers"), Some(1));
    assert!(alice_status.contains("ram_warning=true"), "{alice_status}");
    assert!(bob_status.contains("ram_warning=true"), "{bob_status}");

    pair.cli(&pair.alice_control, &["channel", "enable", "27"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "27"])
        .await;
    let out = pair
        .cli(&pair.alice_control, &["precompute", "27", "1"])
        .await;
    assert!(out.contains("nodes=1"), "{out}");
    assert!(out.contains("checked=1"), "{out}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_precompute_refuses_delta_cap_overrun() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(
        &pair.alice_control,
        &["channel", "enable", "17", "0", "40", "1"],
    )
    .await;
    pair.cli(
        &pair.bob_control,
        &["channel", "enable", "17", "0", "40", "1"],
    )
    .await;
    let (alice, bob) = tokio::join!(
        pair.cli_maybe_fail(&pair.alice_control, &["precompute", "17", "3"]),
        pair.cli_maybe_fail(&pair.bob_control, &["precompute", "17", "3"])
    );
    assert!(!alice.status.success());
    assert!(!bob.status.success());
    assert!(
        String::from_utf8_lossy(&alice.stderr).contains("Delta lifetime checked-unit cap"),
        "{}",
        String::from_utf8_lossy(&alice.stderr)
    );
    let channels = pair.cli(&pair.alice_control, &["channels"]).await;
    assert!(channels.contains("estimated=0"), "{channels}");
    assert!(channels.contains("attempted=0"), "{channels}");
    assert!(channels.contains("failed=0"), "{channels}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_failed_precompute_attempt_is_counted() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(
        &pair.alice_control,
        &["channel", "enable", "19", "0", "40", "100"],
    )
    .await;
    pair.cli(
        &pair.bob_control,
        &["channel", "enable", "19", "0", "41", "100"],
    )
    .await;

    let alice = pair
        .cli_maybe_fail(&pair.alice_control, &["precompute", "19", "1"])
        .await;
    assert!(!alice.status.success());
    assert!(
        String::from_utf8_lossy(&alice.stderr).contains("security parameters do not match"),
        "{}",
        String::from_utf8_lossy(&alice.stderr)
    );
    let channels = pair.cli(&pair.alice_control, &["channels"]).await;
    assert!(channels.contains("estimated=0"), "{channels}");
    assert!(channels.contains("attempted=1"), "{channels}");
    assert!(channels.contains("failed=1"), "{channels}");
    pair.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_rejects_ahead_reveal_without_expected_index() {
    let _guard = daemon_pair_lock().await;
    let pair = DaemonPair::start().await;
    pair.cli(&pair.alice_control, &["channel", "enable", "11"])
        .await;
    pair.cli(&pair.bob_control, &["channel", "enable", "11"])
        .await;
    let (alice, bob) = tokio::join!(
        pair.cli_maybe_fail(&pair.alice_control, &["reveal", "11", "1", "2"]),
        pair.cli_maybe_fail(&pair.bob_control, &["reveal", "11", "1", "2"])
    );
    assert!(!alice.status.success());
    assert!(!bob.status.success());
    assert!(String::from_utf8_lossy(&alice.stderr).contains("requested index must match"));
    pair.stop().await;
}

struct DaemonPair {
    dir: TempDir,
    alice: ChildGuard,
    bob: ChildGuard,
    alice_control: PathBuf,
    bob_control: PathBuf,
    ports: Ports,
}

struct ControlHarnessClient {
    client: ControlServiceClient<Channel>,
    cookie: String,
}

impl ControlHarnessClient {
    async fn connect(control: &Path) -> Self {
        let (addr, cookie) = read_control_file(control).unwrap();
        let client = ControlServiceClient::connect(addr).await.unwrap();
        Self { client, cookie }
    }

    async fn reveal(
        &mut self,
        channel_index: u64,
        requested_index: u64,
        expected_next_index: u64,
        allow_seed_reveal: bool,
    ) -> RevealResponse {
        self.client
            .reveal(with_cookie(
                RevealRequest {
                    channel_index,
                    requested_index,
                    expected_next_index,
                    allow_seed_reveal,
                },
                &self.cookie,
            ))
            .await
            .unwrap()
            .into_inner()
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    fn vm_hwm_bytes(&self) -> Option<u64> {
        proc_status_kib(self.id()?, "VmHWM:").map(|kib| kib.saturating_mul(1024))
    }

    fn vm_rss_bytes(&self) -> Option<u64> {
        proc_status_kib(self.id()?, "VmRSS:").map(|kib| kib.saturating_mul(1024))
    }

    async fn kill_and_wait(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.child = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}

#[derive(Clone, Copy)]
struct Ports {
    alice_local: u16,
    alice_peer: u16,
    bob_local: u16,
    bob_peer: u16,
    mpc: u16,
}

impl DaemonPair {
    async fn start() -> Self {
        let dir = TempDir::new().unwrap();
        Self::start_with_dir(dir).await
    }

    async fn restart(mut old: Self) -> Self {
        old.kill_children().await;
        let dir = old.dir;
        Self::start_with_dir_and_ports(dir, old.ports).await
    }

    async fn start_with_dir(dir: TempDir) -> Self {
        let ports = Ports {
            alice_local: free_port(),
            alice_peer: free_port(),
            bob_local: free_port(),
            bob_peer: free_port(),
            mpc: free_port_range(16),
        };
        Self::start_with_dir_and_ports(dir, ports).await
    }

    async fn start_mtls() -> Self {
        let dir = TempDir::new().unwrap();
        let tls = generate_tls_files(dir.path());
        let ports = Ports {
            alice_local: free_port(),
            alice_peer: free_port(),
            bob_local: free_port(),
            bob_peer: free_port(),
            mpc: free_port_range(16),
        };
        Self::start_with_dir_ports_and_tls(dir, ports, Some(tls)).await
    }

    async fn start_with_dir_and_ports(dir: TempDir, ports: Ports) -> Self {
        Self::start_with_dir_ports_and_tls(dir, ports, None).await
    }

    async fn start_with_dir_ports_and_tls(
        dir: TempDir,
        ports: Ports,
        tls: Option<TlsFiles>,
    ) -> Self {
        let alice_control = dir.path().join("alice-control.json");
        let bob_control = dir.path().join("bob-control.json");
        let alice = spawn_daemon(dir.path(), 1, MASTER_A, ports, &alice_control, tls.as_ref());
        let bob = spawn_daemon(dir.path(), 2, MASTER_B, ports, &bob_control, tls.as_ref());
        let pair = Self {
            dir,
            alice,
            bob,
            alice_control,
            bob_control,
            ports,
        };
        pair.wait_ready().await;
        pair
    }

    async fn wait_ready(&self) {
        for control in [&self.alice_control, &self.bob_control] {
            timeout(Duration::from_secs(20), async {
                loop {
                    if control.exists() {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
        }
        for control in [&self.alice_control, &self.bob_control] {
            timeout(Duration::from_secs(20), async {
                loop {
                    if self
                        .cli_maybe_fail(control, &["status"])
                        .await
                        .status
                        .success()
                    {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
        }
    }

    async fn wait_channel_contains(&self, control: &Path, channel: u64, needle: &str) -> String {
        timeout(Duration::from_secs(120), async {
            loop {
                let channels = self.cli(control, &["channels"]).await;
                let prefix = format!("channel={channel} ");
                if channels
                    .lines()
                    .any(|line| line.starts_with(&prefix) && line.contains(needle))
                {
                    return channels;
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_frontier_total(&self, control: &Path, expected: usize, frontier: u64) -> String {
        timeout(Duration::from_secs(600), async {
            loop {
                let channels = self.cli(control, &["channels"]).await;
                let count = channels
                    .lines()
                    .filter(|line| line.contains(&format!("frontier={frontier}")))
                    .count();
                if count >= expected {
                    return channels;
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_jobs_empty(&self, control: &Path) {
        timeout(Duration::from_secs(120), async {
            loop {
                if self.cli(control, &["jobs"]).await.trim().is_empty() {
                    return;
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_status_field(&self, control: &Path, key: &str, value: u64) -> String {
        timeout(Duration::from_secs(120), async {
            loop {
                let status = self.cli(control, &["status"]).await;
                if status_field(&status, key) == Some(value) {
                    return status;
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn cli(&self, control: &Path, args: &[&str]) -> String {
        let out = self.cli_maybe_fail(control, args).await;
        assert!(
            out.status.success(),
            "cli failed for {:?}: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    async fn cli_maybe_fail(&self, control: &Path, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shachain-cli"));
        cmd.arg("--control-file").arg(control);
        cmd.args(args);
        timeout(Duration::from_secs(900), cmd.output())
            .await
            .unwrap()
            .unwrap()
    }

    async fn stop(mut self) {
        self.kill_children().await;
    }

    async fn kill_children(&mut self) {
        self.alice.kill_and_wait().await;
        self.bob.kill_and_wait().await;
        sleep(Duration::from_millis(250)).await;
    }
}

#[derive(Clone)]
struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn spawn_daemon(
    dir: &Path,
    role: u8,
    master: &str,
    ports: Ports,
    control: &Path,
    tls: Option<&TlsFiles>,
) -> ChildGuard {
    let name = if role == 1 { "alice" } else { "bob" };
    let (local_port, peer_port, remote_peer_port) = if role == 1 {
        (ports.alice_local, ports.alice_peer, ports.bob_peer)
    } else {
        (ports.bob_local, ports.bob_peer, ports.alice_peer)
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shachain-daemon"));
    cmd.arg("--role")
        .arg(role.to_string())
        .arg("--db")
        .arg(dir.join(format!("{name}.db")))
        .arg("--master-secret-hex")
        .arg(master)
        .arg("--listen-local")
        .arg(format!("127.0.0.1:{local_port}"))
        .arg("--listen-peer")
        .arg(format!("127.0.0.1:{peer_port}"))
        .arg("--peer")
        .arg(if tls.is_some() {
            format!("https://localhost:{remote_peer_port}")
        } else {
            format!("http://127.0.0.1:{remote_peer_port}")
        })
        .arg("--mpc-port")
        .arg(ports.mpc.to_string())
        .arg("--control-file")
        .arg(control)
        .arg("--cookie-file")
        .arg(dir.join(format!("{name}.cookie")))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(tls) = tls {
        cmd.arg("--peer-tls-cert")
            .arg(&tls.cert)
            .arg("--peer-tls-key")
            .arg(&tls.key)
            .arg("--peer-tls-ca")
            .arg(&tls.ca)
            .arg("--peer-tls-domain")
            .arg("localhost");
    }
    ChildGuard::new(cmd.spawn().unwrap())
}

fn generate_tls_files(dir: &Path) -> TlsFiles {
    let tls_dir = dir.join("tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    let ca_key = tls_dir.join("ca.key");
    let ca = tls_dir.join("ca.pem");
    let key = tls_dir.join("peer.key");
    let csr = tls_dir.join("peer.csr");
    let cert = tls_dir.join("peer.pem");
    let ext = tls_dir.join("peer.ext");
    std::fs::write(
        &ext,
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n",
    )
    .unwrap();
    openssl_cmd(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-keyout",
        ca_key.to_str().unwrap(),
        "-out",
        ca.to_str().unwrap(),
        "-subj",
        "/CN=shachain2pc-test-ca",
    ]);
    openssl_cmd(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key.to_str().unwrap(),
        "-out",
        csr.to_str().unwrap(),
        "-subj",
        "/CN=localhost",
    ]);
    openssl_cmd(&[
        "x509",
        "-req",
        "-in",
        csr.to_str().unwrap(),
        "-CA",
        ca.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        cert.to_str().unwrap(),
        "-days",
        "1",
        "-extfile",
        ext.to_str().unwrap(),
    ]);
    TlsFiles { cert, key, ca }
}

fn openssl_cmd(args: &[&str]) {
    let output = StdCommand::new("openssl").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "openssl {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn daemon_pair_lock() -> tokio::sync::MutexGuard<'static, ()> {
    DAEMON_PAIR_LOCK.lock().await
}

fn parse_result(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("RESULT "))
        .unwrap_or_else(|| panic!("missing RESULT in {output:?}"))
        .to_owned()
}

fn parse_cache(output: &str) -> Option<bool> {
    output.lines().find_map(|line| match line {
        "CACHE true" => Some(true),
        "CACHE false" => Some(false),
        _ => None,
    })
}

fn with_cookie<T>(message: T, cookie: &str) -> Request<T> {
    let mut req = Request::new(message);
    let value = MetadataValue::try_from(cookie).unwrap();
    req.metadata_mut().insert("x-shachain-cookie", value);
    req
}

fn status_field(output: &str, key: &str) -> Option<u64> {
    output.split_whitespace().find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name == key {
            value.parse().ok()
        } else {
            None
        }
    })
}

fn percentile(values: &mut [u64], pct: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let rank = ((values.len() - 1) * pct).div_ceil(100);
    values[rank.min(values.len() - 1)]
}

fn proc_status_kib(pid: u32, field: &str) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with(field))?;
    let mut parts = line.split_whitespace();
    let _name = parts.next()?;
    parts.next()?.parse().ok()
}

fn assert_channel_contains(channels: &str, channel: u64, needle: &str) {
    let prefix = format!("channel={channel} ");
    assert!(
        channels
            .lines()
            .any(|line| line.starts_with(&prefix) && line.contains(needle)),
        "missing {needle:?} for channel {channel} in {channels:?}"
    );
}

fn free_port_range(width: u16) -> u16 {
    for _ in 0..20_000 {
        let candidate = NEXT_PORT.fetch_add(width as usize, Ordering::Relaxed);
        let port = 20_000 + (candidate % 40_000) as u16;
        let listeners: Vec<_> = (0..width)
            .map(|offset| TcpListener::bind((Ipv4Addr::LOCALHOST, port + offset)))
            .collect::<std::result::Result<_, _>>()
            .unwrap_or_default();
        if listeners.len() == width as usize {
            return port;
        }
    }
    free_port()
}

fn free_port() -> u16 {
    for _ in 0..20_000 {
        let candidate = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let port = 20_000 + (candidate % 40_000) as u16;
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn hex(input: &str) -> Vec<u8> {
    (0..input.len() / 2)
        .map(|i| u8::from_str_radix(&input[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
