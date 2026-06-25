use shachain2pc_daemon::pb::control_service_client::ControlServiceClient;
use shachain2pc_daemon::pb::{
    DisableChannelRequest, EnableChannelRequest, ListChannelsRequest, ListJobsRequest,
    PrecomputeRequest, RevealRequest, SetConfigRequest, StatusRequest,
};
use shachain2pc_daemon::{read_control_file, DaemonError};
use std::env;
use std::path::PathBuf;
use tonic::metadata::MetadataValue;
use tonic::Request;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("ABORT: {e}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<(), DaemonError> {
    let args: Vec<String> = env::args().collect();
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| "shachain-cli".to_owned());
    let mut control_file = None;
    let mut rest = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--control-file" {
            i += 1;
            control_file = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                DaemonError::Usage("--control-file requires a value".to_owned())
            })?));
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    let control_file = control_file.ok_or_else(|| DaemonError::Usage(usage(&program)))?;
    let (addr, cookie) = read_control_file(&control_file)?;
    let mut client = ControlServiceClient::connect(addr).await?;
    match rest.as_slice() {
        [cmd] if cmd == "status" => {
            let out = client
                .status(with_cookie(StatusRequest {}, &cookie)?)
                .await?
                .into_inner();
            println!(
                "role={} local={} peer={} ram={} workers={} effective_workers={} ram_workers_raw={} ram_warning={} precompute={} channels={} jobs={} live_sessions={} reserved_ram={} baseline_rss={} current_rss={} idle_session_estimate={} one_h_worker_estimate={}",
                out.role,
                out.local_addr,
                out.peer_addr,
                out.max_ram_bytes,
                out.workers,
                out.effective_workers,
                out.ram_limited_workers_raw,
                out.ram_overcommit_warning,
                out.precompute,
                out.channel_count,
                out.active_job_count,
                out.live_session_count,
                out.reserved_ram_bytes,
                out.baseline_daemon_rss_bytes,
                out.current_rss_bytes,
                out.idle_session_rss_estimate_bytes,
                out.one_h_worker_peak_rss_estimate_bytes
            );
        }
        [cmd, key, value] if cmd == "config" && key == "workers" => {
            let out = client
                .set_config(with_cookie(
                    SetConfigRequest {
                        max_ram_bytes: None,
                        workers: Some(parse_u32(value, "workers")?),
                        precompute: None,
                    },
                    &cookie,
                )?)
                .await?
                .into_inner();
            println!(
                "workers={} effective_workers={} ram_warning={}",
                out.workers, out.effective_workers, out.ram_overcommit_warning
            );
        }
        [cmd, key, value] if cmd == "config" && key == "precompute" => {
            let out = client
                .set_config(with_cookie(
                    SetConfigRequest {
                        max_ram_bytes: None,
                        workers: None,
                        precompute: Some(parse_u64(value, "precompute")?),
                    },
                    &cookie,
                )?)
                .await?
                .into_inner();
            println!(
                "precompute={} effective_workers={} ram_warning={}",
                out.precompute, out.effective_workers, out.ram_overcommit_warning
            );
        }
        [cmd, key, value] if cmd == "config" && key == "max-ram-mb" => {
            let out = client
                .set_config(with_cookie(
                    SetConfigRequest {
                        max_ram_bytes: Some(
                            parse_u64(value, "max-ram-mb")?.saturating_mul(1024 * 1024),
                        ),
                        workers: None,
                        precompute: None,
                    },
                    &cookie,
                )?)
                .await?
                .into_inner();
            println!(
                "max_ram_bytes={} effective_workers={} ram_warning={}",
                out.max_ram_bytes, out.effective_workers, out.ram_overcommit_warning
            );
        }
        [cmd, sub, channel] if cmd == "channel" && sub == "enable" => {
            enable_channel(&mut client, &cookie, channel, 0, 0, 0).await?;
        }
        [cmd, sub, channel, precompute, ssp_target, cap] if cmd == "channel" && sub == "enable" => {
            enable_channel(
                &mut client,
                &cookie,
                channel,
                parse_u64(precompute, "precompute")?,
                parse_u32(ssp_target, "ssp-target")?,
                parse_u64(cap, "delta-lifetime-checked-units-cap")?,
            )
            .await?;
        }
        [cmd, sub, channel] if cmd == "channel" && sub == "disable" => {
            let out = client
                .disable_channel(with_cookie(
                    DisableChannelRequest {
                        channel_index: parse_u64(channel, "channel")?,
                    },
                    &cookie,
                )?)
                .await?
                .into_inner();
            println!("channel={} enabled={}", out.channel_index, out.enabled);
        }
        [cmd, channel, index] if cmd == "precompute" => {
            let out = client
                .precompute(with_cookie(
                    PrecomputeRequest {
                        channel_index: parse_u64(channel, "channel")?,
                        target_index: parse_index(index)?,
                    },
                    &cookie,
                )?)
                .await?
                .into_inner();
            println!(
                "PRECOMPUTED channel={} target={} nodes={} checked={}",
                out.channel_index, out.target_index, out.nodes_stored, out.checked_units
            );
        }
        [cmd] if cmd == "channels" => {
            let out = client
                .list_channels(with_cookie(ListChannelsRequest {}, &cookie)?)
                .await?
                .into_inner();
            for channel in out.channels {
                println!(
                    "channel={} enabled={} frontier={} known={} estimated={} attempted={} failed={}",
                    channel.channel_index,
                    channel.enabled,
                    channel.frontier_nodes,
                    channel.known_secrets,
                    channel.estimated_checked_units,
                    channel.attempted_checked_units,
                    channel.failed_precompute_jobs
                );
            }
        }
        [cmd] if cmd == "jobs" => {
            let out = client
                .list_jobs(with_cookie(ListJobsRequest {}, &cookie)?)
                .await?
                .into_inner();
            for job in out.jobs {
                println!(
                    "job={} channel={} kind={} state={}",
                    job.job_id, job.channel_index, job.kind, job.state
                );
            }
        }
        [cmd, channel, index, expected] if cmd == "reveal" => {
            reveal(&mut client, &cookie, channel, index, expected, false).await?;
        }
        [cmd, channel, index, expected, flag]
            if cmd == "reveal" && flag == "--allow-seed-reveal" =>
        {
            reveal(&mut client, &cookie, channel, index, expected, true).await?;
        }
        _ => return Err(DaemonError::Usage(usage(&program))),
    }
    Ok(())
}

async fn reveal(
    client: &mut ControlServiceClient<tonic::transport::Channel>,
    cookie: &str,
    channel: &str,
    index: &str,
    expected: &str,
    allow_seed_reveal: bool,
) -> Result<(), DaemonError> {
    let out = client
        .reveal(with_cookie(
            RevealRequest {
                channel_index: parse_u64(channel, "channel")?,
                requested_index: parse_index(index)?,
                expected_next_index: parse_index(expected)?,
                allow_seed_reveal,
            },
            cookie,
        )?)
        .await?
        .into_inner();
    println!("RESULT {}", out.secret_hex);
    println!("CACHE {}", out.from_cache);
    println!("SOURCE {}", out.source);
    Ok(())
}

async fn enable_channel(
    client: &mut ControlServiceClient<tonic::transport::Channel>,
    cookie: &str,
    channel: &str,
    precompute: u64,
    ssp_target: u32,
    delta_lifetime_checked_units_cap: u64,
) -> Result<(), DaemonError> {
    let out = client
        .enable_channel(with_cookie(
            EnableChannelRequest {
                channel_index: parse_u64(channel, "channel")?,
                precompute,
                ssp_target,
                delta_lifetime_checked_units_cap,
            },
            cookie,
        )?)
        .await?
        .into_inner();
    println!("channel={} enabled={}", out.channel_index, out.enabled);
    Ok(())
}

fn with_cookie<T>(msg: T, cookie: &str) -> Result<Request<T>, DaemonError> {
    let mut req = Request::new(msg);
    let value = MetadataValue::try_from(cookie)
        .map_err(|_| DaemonError::Parse("cookie is not valid metadata".to_owned()))?;
    req.metadata_mut().insert("x-shachain-cookie", value);
    Ok(req)
}

fn parse_u64(input: &str, name: &str) -> Result<u64, DaemonError> {
    input
        .parse()
        .map_err(|_| DaemonError::Parse(format!("{name} must be numeric")))
}

fn parse_u32(input: &str, name: &str) -> Result<u32, DaemonError> {
    input
        .parse()
        .map_err(|_| DaemonError::Parse(format!("{name} must be numeric")))
}

fn parse_index(input: &str) -> Result<u64, DaemonError> {
    u64::from_str_radix(input, 16)
        .or_else(|_| input.parse())
        .map_err(|_| DaemonError::Parse(format!("bad index: {input}")))
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} --control-file <path> status|channels|jobs|config <workers|precompute|max-ram-mb> <value>|channel enable <id> [precompute ssp-target cap]|channel disable <id>|precompute <channel> <index>|reveal <channel> <index> <expected-next> [--allow-seed-reveal]"
    )
}
