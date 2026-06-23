use shachain2pc_daemon::{
    parse_addr, parse_master_secret_hex, parse_role, run_daemon, DaemonConfig, DaemonError,
    PeerTlsConfig,
};
use std::env;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("ABORT: {e}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<(), DaemonError> {
    let args = parse_args(env::args().collect())?;
    run_daemon(args.cfg, args.master_secret).await
}

struct ParsedArgs {
    cfg: DaemonConfig,
    master_secret: Vec<u8>,
}

fn parse_args(args: Vec<String>) -> Result<ParsedArgs, DaemonError> {
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| "shachain-daemon".to_owned());
    let mut role = None;
    let mut db = None;
    let mut master_secret_hex = None;
    let mut master_secret_stdin = false;
    let mut listen_local = None;
    let mut listen_peer = None;
    let mut peer = None;
    let mut peer_tls_cert = None;
    let mut peer_tls_key = None;
    let mut peer_tls_ca = None;
    let mut peer_tls_domain = None;
    let mut mpc_port = None;
    let mut max_ram_mb = 1024u64;
    let mut workers = 1u32;
    let mut precompute = 0u64;
    let mut control_file = None;
    let mut cookie_file = None;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--role" => role = Some(parse_role(take(&args, &mut i, arg)?)?),
            "--db" => db = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--master-secret-hex" => master_secret_hex = Some(take(&args, &mut i, arg)?.to_owned()),
            "--master-secret-stdin" => master_secret_stdin = true,
            "--listen-local" => listen_local = Some(parse_addr(take(&args, &mut i, arg)?)?),
            "--listen-peer" => listen_peer = Some(parse_addr(take(&args, &mut i, arg)?)?),
            "--peer" => peer = Some(take(&args, &mut i, arg)?.to_owned()),
            "--peer-tls-cert" => peer_tls_cert = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--peer-tls-key" => peer_tls_key = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--peer-tls-ca" => peer_tls_ca = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--peer-tls-domain" => peer_tls_domain = Some(take(&args, &mut i, arg)?.to_owned()),
            "--mpc-port" => {
                let value = take(&args, &mut i, arg)?
                    .parse::<u16>()
                    .map_err(|_| DaemonError::Parse("--mpc-port must be 1..65535".to_owned()))?;
                if value == 0 {
                    return Err(DaemonError::Parse("--mpc-port must be 1..65535".to_owned()));
                }
                mpc_port = Some(value);
            }
            "--max-ram-mb" => {
                max_ram_mb = take(&args, &mut i, arg)?
                    .parse()
                    .map_err(|_| DaemonError::Parse("--max-ram-mb must be numeric".to_owned()))?
            }
            "--workers" => {
                workers = take(&args, &mut i, arg)?
                    .parse::<u32>()
                    .map_err(|_| DaemonError::Parse("--workers must be numeric".to_owned()))?
                    .max(1)
            }
            "--precompute" => {
                precompute = take(&args, &mut i, arg)?
                    .parse()
                    .map_err(|_| DaemonError::Parse("--precompute must be numeric".to_owned()))?
            }
            "--control-file" => control_file = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--cookie-file" => cookie_file = Some(PathBuf::from(take(&args, &mut i, arg)?)),
            "--help" | "-h" => return Err(DaemonError::Usage(usage(&program))),
            _ => return Err(DaemonError::Usage(usage(&program))),
        }
        i += 1;
    }

    let master_secret = if master_secret_stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        parse_master_secret_hex(input.trim())?
    } else if let Some(hex) = master_secret_hex {
        parse_master_secret_hex(&hex)?
    } else {
        return Err(DaemonError::Usage(usage(&program)));
    };

    let peer_tls = match (
        peer_tls_cert,
        peer_tls_key,
        peer_tls_ca,
        peer_tls_domain,
    ) {
        (None, None, None, None) => None,
        (Some(cert_path), Some(key_path), Some(ca_path), Some(domain_name)) => {
            Some(PeerTlsConfig {
                cert_path,
                key_path,
                ca_path,
                domain_name,
            })
        }
        _ => {
            return Err(DaemonError::Usage(
                "--peer-tls-cert, --peer-tls-key, --peer-tls-ca and --peer-tls-domain must be provided together"
                    .to_owned(),
            ))
        }
    };

    let cfg = DaemonConfig {
        role: role.ok_or_else(|| DaemonError::Usage(usage(&program)))?,
        db_path: db.ok_or_else(|| DaemonError::Usage(usage(&program)))?,
        control_addr: listen_local.unwrap_or_else(|| localhost(0)),
        peer_addr: listen_peer.unwrap_or_else(|| localhost(0)),
        peer_url: peer,
        peer_tls,
        mpc_port: mpc_port.ok_or_else(|| DaemonError::Usage(usage(&program)))?,
        max_ram_bytes: max_ram_mb.saturating_mul(1024 * 1024),
        workers,
        precompute,
        control_file,
        cookie_file,
    };
    Ok(ParsedArgs { cfg, master_secret })
}

fn take<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, DaemonError> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| DaemonError::Usage(format!("{flag} requires a value")))
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} --role <1|2> --db <path> --master-secret-hex <hex>|--master-secret-stdin --listen-local <addr> --listen-peer <addr> --mpc-port <port> [--peer <url>] [--peer-tls-cert <pem> --peer-tls-key <pem> --peer-tls-ca <pem> --peer-tls-domain <name>] [--control-file <path>] [--cookie-file <path>] [--max-ram-mb <mb>] [--workers <n>] [--precompute <n>]"
    )
}
