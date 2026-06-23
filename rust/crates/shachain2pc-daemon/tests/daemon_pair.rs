use shachain2pc_daemon::{channel_seed_share, reference_for_channel};
use shachain2pc_types::Index48;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const MASTER_A: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MASTER_B: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
static NEXT_PORT: AtomicUsize = AtomicUsize::new(23_000);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pair_seed_reveal_restart_and_local_cache() {
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
async fn daemon_pair_precompute_repairs_peer_frontier_rollback() {
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
async fn daemon_pair_precompute_refuses_delta_cap_overrun() {
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
    alice: Child,
    bob: Child,
    alice_control: PathBuf,
    bob_control: PathBuf,
    ports: Ports,
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

    async fn start_with_dir_and_ports(dir: TempDir, ports: Ports) -> Self {
        let alice_control = dir.path().join("alice-control.json");
        let bob_control = dir.path().join("bob-control.json");
        let alice = spawn_daemon(dir.path(), 1, MASTER_A, ports, &alice_control);
        let bob = spawn_daemon(dir.path(), 2, MASTER_B, ports, &bob_control);
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
        let _ = self.alice.kill().await;
        let _ = self.bob.kill().await;
        let _ = self.alice.wait().await;
        let _ = self.bob.wait().await;
        sleep(Duration::from_millis(250)).await;
    }
}

fn spawn_daemon(dir: &Path, role: u8, master: &str, ports: Ports, control: &Path) -> Child {
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
        .arg(format!("http://127.0.0.1:{remote_peer_port}"))
        .arg("--mpc-port")
        .arg(ports.mpc.to_string())
        .arg("--control-file")
        .arg(control)
        .arg("--cookie-file")
        .arg(dir.join(format!("{name}.cookie")))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().unwrap()
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
