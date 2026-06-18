use shachain2pc_circuit::{
    build_circuit_for_index, circuit_digest, load_bristol, to_emp_gate_array,
    DEFAULT_SHA256_COMPRESS_PATH,
};
use shachain2pc_emp_compat::{C2pc, C2pcCircuit, CompatError};
use shachain2pc_emp_wire::{EmpStream, EmpStreams, WireError};
use shachain2pc_types::{Index48, Role, Value32, VALUE_BITS};
use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use zeroize::Zeroize;

#[derive(Debug)]
enum PartyError {
    Usage(String),
    Parse(String),
    Circuit(shachain2pc_circuit::CircuitError),
    Compat(CompatError),
    Wire(WireError),
    Io(std::io::Error),
    CircuitMismatch,
    SeedRevealRefused,
}

impl fmt::Display for PartyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) | Self::Parse(msg) => f.write_str(msg),
            Self::Circuit(e) => write!(f, "{e}"),
            Self::Compat(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::CircuitMismatch => write!(
                f,
                "shachain2pc: circuit mismatch -- the two parties are not running the same agreed circuit (same index?)"
            ),
            Self::SeedRevealRefused => write!(
                f,
                "I=0 reveals the seed (root of all revocation secrets); re-run with --allow-seed-reveal to proceed"
            ),
        }
    }
}

impl std::error::Error for PartyError {}

impl From<shachain2pc_circuit::CircuitError> for PartyError {
    fn from(value: shachain2pc_circuit::CircuitError) -> Self {
        Self::Circuit(value)
    }
}

impl From<CompatError> for PartyError {
    fn from(value: CompatError) -> Self {
        Self::Compat(value)
    }
}

impl From<WireError> for PartyError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<std::io::Error> for PartyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
struct Args {
    role: Role,
    port: u16,
    index: Index48,
    share: Value32,
    peer_ip: IpAddr,
    allow_seed_reveal: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    match parse_args(env::args().collect()) {
        Ok(args) => match run_derivation(args).await {
            Ok(out) => {
                println!("RESULT {}", out.to_hex());
            }
            Err(e) => {
                eprintln!("ABORT: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("ABORT: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_derivation(args: Args) -> Result<Value32, PartyError> {
    ensure_index_allowed(args.index, args.allow_seed_reveal)?;

    let mut timing = PhaseTiming::new(args.role, args.index);
    let sha = load_bristol(default_sha256_compress_path())?;
    let circuit = build_circuit_for_index(args.index, &sha)?;
    let gate_arr = to_emp_gate_array(&circuit);
    let digest = circuit_digest(&circuit, &gate_arr);
    let c2pc_circuit = C2pcCircuit::from_circuit(&circuit)?;
    drop(gate_arr);
    drop(circuit);
    timing.mark("build_circuit");

    let mut streams = open_streams_after_digest(args.role, args.port, args.peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut c2pc = C2pc::new(&mut streams, args.role, c2pc_circuit).await?;
    streams.main.flush().await?;
    timing.mark("c2pc_setup");
    c2pc.function_independent(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("function_independent");
    c2pc.function_dependent(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("function_dependent");

    let mut input = vec![0u8; 2 * VALUE_BITS];
    let mut share_bits = args.share.to_bits_msb();
    match args.role {
        Role::Alice => input[VALUE_BITS..].copy_from_slice(&share_bits),
        Role::Bob => input[..VALUE_BITS].copy_from_slice(&share_bits),
    }
    share_bits.zeroize();
    let output = c2pc.online(&mut streams, &input, true).await?;
    input.zeroize();
    streams.main.flush().await?;
    timing.mark("online");
    Value32::from_bits_msb(&output).map_err(|e| PartyError::Parse(e.to_string()))
}

struct PhaseTiming {
    enabled: bool,
    role: Role,
    index: Index48,
    start: Instant,
    last: Instant,
}

impl PhaseTiming {
    fn new(role: Role, index: Index48) -> Self {
        let enabled = env::var("SHACHAIN2PC_PHASE_TIMING")
            .map(|value| !value.is_empty() && value != "0")
            .unwrap_or(false);
        let now = Instant::now();
        Self {
            enabled,
            role,
            index,
            start: now,
            last: now,
        }
    }

    fn mark(&mut self, phase: &str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        eprintln!(
            "TIMING role={} index={} phase={} phase_ms={:.3} total_ms={:.3}",
            self.role.party_id(),
            self.index.to_hex12(),
            phase,
            phase_ms,
            total_ms
        );
        self.last = now;
    }
}

fn ensure_index_allowed(index: Index48, allow_seed_reveal: bool) -> Result<(), PartyError> {
    // This is a deliberate Rust-only hardening divergence from the C++ demo,
    // which accepts I=0 silently. Index 0 is the shachain seed, not a normal
    // per-commitment reveal, so require an explicit local override.
    if index.get() == 0 && !allow_seed_reveal {
        Err(PartyError::SeedRevealRefused)
    } else {
        Ok(())
    }
}

fn default_sha256_compress_path() -> PathBuf {
    let cwd_path = PathBuf::from(DEFAULT_SHA256_COMPRESS_PATH);
    if cwd_path.exists() {
        cwd_path
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(DEFAULT_SHA256_COMPRESS_PATH)
    }
}

async fn open_streams_after_digest(
    role: Role,
    port: u16,
    peer_ip: IpAddr,
    digest: [u8; 32],
) -> Result<EmpStreams, PartyError> {
    // The C++ party exchanges the circuit digest on the main stream before it
    // constructs C2PC/Fpre, so the auxiliary streams must be opened after it.
    match role {
        Role::Alice => {
            let listener =
                TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)).await?;
            let mut main = accept_emp(&listener).await?;
            exchange_circuit_digest(&mut main, role, digest).await?;
            let fpre_io0 = accept_emp(&listener).await?;
            let fpre_io2_0 = accept_emp(&listener).await?;
            Ok(EmpStreams {
                main,
                fpre_io0,
                fpre_io2_0,
            })
        }
        Role::Bob => {
            let mut main = EmpStream::connect(peer_ip, port).await?;
            exchange_circuit_digest(&mut main, role, digest).await?;
            sleep(Duration::from_millis(1)).await;
            let fpre_io0 = EmpStream::connect(peer_ip, port).await?;
            sleep(Duration::from_millis(1)).await;
            let fpre_io2_0 = EmpStream::connect(peer_ip, port).await?;
            Ok(EmpStreams {
                main,
                fpre_io0,
                fpre_io2_0,
            })
        }
    }
}

async fn accept_emp(listener: &TcpListener) -> Result<EmpStream, PartyError> {
    loop {
        let (stream, _) = listener.accept().await?;
        match EmpStream::new(stream) {
            Ok(stream) => return Ok(stream),
            Err(_) => sleep(Duration::from_millis(1)).await,
        }
    }
}

async fn exchange_circuit_digest(
    stream: &mut EmpStream,
    role: Role,
    digest: [u8; 32],
) -> Result<(), PartyError> {
    let peer = match role {
        Role::Alice => {
            stream.send_data(&digest).await?;
            stream.flush().await?;
            recv_digest(stream).await?
        }
        Role::Bob => {
            let peer = recv_digest(stream).await?;
            stream.send_data(&digest).await?;
            stream.flush().await?;
            peer
        }
    };
    if peer == digest {
        Ok(())
    } else {
        Err(PartyError::CircuitMismatch)
    }
}

async fn recv_digest(stream: &mut EmpStream) -> Result<[u8; 32], PartyError> {
    Ok(stream
        .recv_data(32)
        .await?
        .try_into()
        .expect("digest length"))
}

fn parse_args(args: Vec<String>) -> Result<Args, PartyError> {
    let program = args.first().cloned().unwrap_or_else(|| "party".to_owned());
    let mut allow_seed_reveal = false;
    let mut positional = Vec::new();
    for arg in args.into_iter().skip(1) {
        if arg == "--allow-seed-reveal" {
            allow_seed_reveal = true;
        } else if arg.starts_with("--") {
            return Err(PartyError::Parse(format!("unknown flag: {arg}")));
        } else {
            positional.push(arg);
        }
    }
    if positional.len() < 4 || positional.len() > 5 {
        return Err(PartyError::Usage(usage(&program)));
    }
    let role_id = positional[0]
        .parse::<u8>()
        .map_err(|_| PartyError::Parse(format!("party must be 1 or 2, got {}", positional[0])))?;
    let role = Role::from_party_id(role_id).map_err(|e| PartyError::Parse(e.to_string()))?;
    let port = positional[1]
        .parse::<u16>()
        .map_err(|_| PartyError::Parse("port must be in 1..65535".to_owned()))?;
    if port == 0 {
        return Err(PartyError::Parse("port must be in 1..65535".to_owned()));
    }
    let index = Index48::from_hex(&positional[2]).map_err(|e| PartyError::Parse(e.to_string()))?;
    let share = Value32::from_hex(&positional[3]).map_err(|e| PartyError::Parse(e.to_string()))?;
    ensure_index_allowed(index, allow_seed_reveal)?;
    let peer_ip = if let Some(peer) = positional.get(4) {
        peer.parse()
            .map_err(|_| PartyError::Parse(format!("bad peer ip: {peer}")))?
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    Ok(Args {
        role,
        port,
        index,
        share,
        peer_ip,
        allow_seed_reveal,
    })
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} [--allow-seed-reveal] <1|2> <port> <I_hex> <share_hex> [peer_ip]\n  1 = ALICE (garbler, listens), 2 = BOB (evaluator, connects)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use shachain2pc_circuit::generate_from_seed;
    use std::net::TcpListener as StdTcpListener;
    use std::sync::OnceLock;
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    const SHARE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHARE_B: &str = "abababababababababababababababababababababababababababababababab";
    const INDEX_ZERO_RESULT: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";
    static PARTY_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
            assert_eq!(parsed.index.get(), 0);
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

    fn test_args(
        role: Role,
        port: u16,
        index: Index48,
        share: &str,
        allow_seed_reveal: bool,
    ) -> Args {
        Args {
            role,
            port,
            index,
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

    fn free_port() -> u16 {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
