#[derive(Clone)]
struct ControlApi {
    state: DaemonState,
}

#[tonic::async_trait]
impl ControlService for ControlApi {
    async fn status(
        &self,
        request: Request<pb::StatusRequest>,
    ) -> std::result::Result<Response<pb::StatusResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::StatusResponse {
            role: inner.cfg.role.party_id() as u32,
            local_addr: inner.cfg.control_addr.to_string(),
            peer_addr: inner
                .cfg
                .peer_url
                .clone()
                .unwrap_or_else(|| inner.cfg.peer_addr.to_string()),
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: resources.configured_workers,
            precompute: inner.cfg.precompute,
            channel_count: inner.db.channels.len() as u64,
            active_job_count: inner.active_jobs.len() as u64,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
            baseline_daemon_rss_bytes: resources.baseline_daemon_rss_bytes,
            current_rss_bytes: resources.current_rss_bytes,
            idle_session_rss_estimate_bytes: resources.idle_session_rss_estimate_bytes,
            one_h_worker_peak_rss_estimate_bytes: resources.one_h_worker_peak_rss_estimate_bytes,
            live_session_count: resources.live_session_count,
            reserved_ram_bytes: resources.reserved_ram_bytes,
        }))
    }

    async fn set_config(
        &self,
        request: Request<pb::SetConfigRequest>,
    ) -> std::result::Result<Response<pb::SetConfigResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        if let Some(v) = req.max_ram_bytes {
            inner.cfg.max_ram_bytes = v;
        }
        if let Some(v) = req.workers {
            inner.cfg.workers = v.max(1);
        }
        if let Some(v) = req.precompute {
            inner.cfg.precompute = v;
        }
        drop(inner);
        self.state.wake_scheduler();
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::SetConfigResponse {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            effective_workers: resources.effective_workers,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn enable_channel(
        &self,
        request: Request<pb::EnableChannelRequest>,
    ) -> std::result::Result<Response<pb::ChannelResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        let key = channel_key(req.channel_index);
        let default_precompute = if req.precompute == 0 {
            inner.cfg.precompute
        } else {
            req.precompute
        };
        let channel = inner
            .db
            .channels
            .entry(key)
            .or_insert_with(|| ChannelRecord {
                enabled: true,
                last_observed_next_reveal_index: None,
                precompute_target: default_precompute,
                ssp_target: if req.ssp_target == 0 {
                    DEFAULT_SSP_TARGET
                } else {
                    req.ssp_target
                },
                delta_lifetime_checked_units_cap: if req.delta_lifetime_checked_units_cap == 0 {
                    DEFAULT_DELTA_CAP
                } else {
                    req.delta_lifetime_checked_units_cap
                },
                frontier_nodes: BTreeMap::new(),
                known_secrets: BTreeMap::new(),
                estimated_checked_units: 0,
                attempted_checked_units: 0,
                failed_precompute_jobs: 0,
            });
        channel.enabled = true;
        channel.precompute_target = default_precompute;
        if req.ssp_target != 0 {
            channel.ssp_target = req.ssp_target;
        }
        if req.delta_lifetime_checked_units_cap != 0 {
            channel.delta_lifetime_checked_units_cap = req.delta_lifetime_checked_units_cap;
        }
        let response = channel_response(req.channel_index, channel);
        let mutations = vec![upsert_channel_mutation(req.channel_index, channel)];
        drop(inner);
        self.state
            .db_writer
            .write_batch(mutations, DbDurability::Immediate)
            .await
            .map_err(to_status)?;
        self.state.db_writer.flush().await.map_err(to_status)?;
        self.state.wake_scheduler();
        Ok(Response::new(response))
    }

    async fn disable_channel(
        &self,
        request: Request<pb::DisableChannelRequest>,
    ) -> std::result::Result<Response<pb::ChannelResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let mut inner = self.state.inner.lock().await;
        let key = channel_key(req.channel_index);
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == req.channel_index)
        {
            return Err(Status::failed_precondition(
                "channel has an active precompute job",
            ));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| Status::not_found("channel is not enabled"))?;
        channel.enabled = false;
        let drop_masks = channel
            .frontier_nodes
            .keys()
            .filter_map(|mask| mask.parse::<u64>().ok())
            .collect::<Vec<_>>();
        channel.frontier_nodes.clear();
        let response = channel_response(req.channel_index, channel);
        let mut mutations = vec![upsert_channel_mutation(req.channel_index, channel)];
        mutations.extend(
            drop_masks
                .into_iter()
                .map(|mask| delete_frontier_mutation(req.channel_index, mask)),
        );
        drop(inner);
        self.state
            .db_writer
            .write_batch(mutations, DbDurability::Immediate)
            .await
            .map_err(to_status)?;
        self.state.db_writer.flush().await.map_err(to_status)?;
        self.state.drop_precompute_session(req.channel_index).await;
        self.state.wake_scheduler();
        Ok(Response::new(response))
    }

    async fn reveal(
        &self,
        request: Request<pb::RevealRequest>,
    ) -> std::result::Result<Response<pb::RevealResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let req = request.into_inner();
        let out = self
            .state
            .reveal(
                req.channel_index,
                req.requested_index,
                req.expected_next_index,
                req.allow_seed_reveal,
            )
            .await
            .map_err(to_status)?;
        Ok(Response::new(out))
    }

    async fn list_channels(
        &self,
        request: Request<pb::ListChannelsRequest>,
    ) -> std::result::Result<Response<pb::ListChannelsResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let inner = self.state.inner.lock().await;
        let channels = inner
            .db
            .channels
            .iter()
            .filter_map(|(key, channel)| {
                key.parse::<u64>()
                    .ok()
                    .map(|index| channel_response(index, channel))
            })
            .collect();
        Ok(Response::new(pb::ListChannelsResponse { channels }))
    }

    async fn list_jobs(
        &self,
        request: Request<pb::ListJobsRequest>,
    ) -> std::result::Result<Response<pb::ListJobsResponse>, Status> {
        self.state.check_cookie(&request).await?;
        let inner = self.state.inner.lock().await;
        let jobs = inner
            .active_jobs
            .iter()
            .map(|(id, job)| pb::JobInfo {
                job_id: id.clone(),
                channel_index: job.channel_index,
                kind: format!("{} checked={}", job.kind, job.planned_checked_units),
                state: job.state.clone(),
            })
            .collect();
        Ok(Response::new(pb::ListJobsResponse { jobs }))
    }
}

#[derive(Clone)]
struct PeerApi {
    state: DaemonState,
}

#[tonic::async_trait]
impl PeerService for PeerApi {
    type JobStreamStream = ReceiverStream<std::result::Result<pb::JobFrame, Status>>;

    async fn hello(
        &self,
        _request: Request<pb::HelloRequest>,
    ) -> std::result::Result<Response<pb::HelloResponse>, Status> {
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::HelloResponse {
            role: inner.cfg.role.party_id() as u32,
            daemon_id: daemon_id(&inner.master_secret.0),
            protocol_version: PROTOCOL_VERSION,
        }))
    }

    async fn config(
        &self,
        _request: Request<pb::ConfigUpdate>,
    ) -> std::result::Result<Response<pb::ConfigUpdate>, Status> {
        let resources = self.state.resource_model().await;
        let inner = self.state.inner.lock().await;
        Ok(Response::new(pb::ConfigUpdate {
            max_ram_bytes: inner.cfg.max_ram_bytes,
            workers: inner.cfg.workers,
            precompute: inner.cfg.precompute,
            ssp_target: DEFAULT_SSP_TARGET,
            delta_lifetime_checked_units_cap: DEFAULT_DELTA_CAP,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn get_frontier(
        &self,
        request: Request<pb::GetFrontierRequest>,
    ) -> std::result::Result<Response<pb::GetFrontierResponse>, Status> {
        let resources = self.state.resource_model().await;
        let req = request.into_inner();
        let inner = self.state.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(req.channel_index)) else {
            return Ok(Response::new(pb::GetFrontierResponse {
                nodes: Vec::new(),
                channel_enabled: false,
                precompute: 0,
                ssp_target: 0,
                delta_lifetime_checked_units_cap: 0,
                workers: inner.cfg.workers,
                effective_workers: resources.effective_workers,
                ram_limited_workers_raw: resources.ram_limited_workers_raw,
                ram_overcommit_warning: resources.ram_overcommit_warning,
            }));
        };
        let nodes = channel
            .frontier_nodes
            .iter()
            .filter_map(|(mask, node)| {
                mask.parse::<u64>().ok().map(|mask| pb::FrontierNode {
                    mask,
                    public_binding_hex: node.public_binding_hex.clone(),
                })
            })
            .collect();
        Ok(Response::new(pb::GetFrontierResponse {
            nodes,
            channel_enabled: channel.enabled,
            precompute: channel.precompute_target,
            ssp_target: channel.ssp_target,
            delta_lifetime_checked_units_cap: channel.delta_lifetime_checked_units_cap,
            workers: inner.cfg.workers,
            effective_workers: resources.effective_workers,
            ram_limited_workers_raw: resources.ram_limited_workers_raw,
            ram_overcommit_warning: resources.ram_overcommit_warning,
        }))
    }

    async fn job_stream(
        &self,
        request: Request<Streaming<pb::JobFrame>>,
    ) -> std::result::Result<Response<Self::JobStreamStream>, Status> {
        let (descriptor, channel, stream, response) =
            open_peer_job_stream(request.into_inner()).await?;
        self.state
            .register_incoming_job_stream(descriptor, channel, stream)
            .await?;
        Ok(Response::new(response))
    }

    async fn reveal_cached(
        &self,
        request: Request<pb::RevealCachedRequest>,
    ) -> std::result::Result<Response<pb::RevealCachedResponse>, Status> {
        let out = self
            .state
            .handle_peer_cached_reveal(request.into_inner())
            .await
            .map_err(to_status)?;
        Ok(Response::new(out))
    }
}

async fn open_peer_job_stream(
    mut incoming: Streaming<pb::JobFrame>,
) -> std::result::Result<
    (
        GrpcJobDescriptor,
        u32,
        ChannelByteStream,
        ReceiverStream<std::result::Result<pb::JobFrame, Status>>,
    ),
    Status,
> {
    let start = incoming
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("missing JobStream start frame"))?;
    let descriptor = descriptor_from_job_frame(&start).map_err(Status::invalid_argument)?;
    let channel = validate_job_channel(start.channel).map_err(Status::invalid_argument)?;
    if !start.start {
        return Err(Status::invalid_argument(
            "first JobStream frame must be a start frame",
        ));
    }
    if !start.payload.is_empty() {
        return Err(Status::invalid_argument(
            "JobStream start frame must not carry payload",
        ));
    }

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (response_tx, response_rx) = mpsc::channel::<std::result::Result<pb::JobFrame, Status>>(64);

    let forward_descriptor = descriptor.clone();
    tokio::spawn(async move {
        while let Ok(Some(frame)) = incoming.message().await {
            if frame.start
                || frame.job_id != forward_descriptor.job_id
                || frame.channel != channel
                || !validate_job_payload_context(&frame, &forward_descriptor)
            {
                break;
            }
            if in_tx.send(frame.payload).await.is_err() {
                break;
            }
        }
    });

    let response_descriptor = descriptor.clone();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            for chunk in payload.chunks(JOBSTREAM_PAYLOAD_CHUNK_BYTES) {
                let frame = job_frame(&response_descriptor, channel, false, chunk.to_vec());
                if response_tx.send(Ok(frame)).await.is_err() {
                    return;
                }
            }
        }
    });

    Ok((
        descriptor,
        channel,
        ChannelByteStream::new(out_tx, in_rx),
        ReceiverStream::new(response_rx),
    ))
}

async fn open_peer_job_channel(
    peer_channel: Channel,
    descriptor: &GrpcJobDescriptor,
    channel: u32,
) -> Result<ChannelByteStream> {
    let channel =
        validate_job_channel(channel).map_err(|msg| DaemonError::Refused(msg.to_owned()))?;
    let (request_tx, request_rx) = mpsc::channel::<pb::JobFrame>(64);
    request_tx
        .send(job_frame(descriptor, channel, true, Vec::new()))
        .await
        .map_err(|_| DaemonError::Refused("JobStream request channel closed".to_owned()))?;
    let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
    let response = client
        .job_stream(ReceiverStream::new(request_rx))
        .await?
        .into_inner();

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);

    let request_descriptor = descriptor.clone();
    let request_tx_forward = request_tx.clone();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            for chunk in payload.chunks(JOBSTREAM_PAYLOAD_CHUNK_BYTES) {
                let frame = job_frame(&request_descriptor, channel, false, chunk.to_vec());
                if request_tx_forward.send(frame).await.is_err() {
                    return;
                }
            }
        }
    });

    let response_descriptor = descriptor.clone();
    tokio::spawn(async move {
        let mut response = response;
        while let Ok(Some(frame)) = response.message().await {
            if frame.start
                || frame.job_id != response_descriptor.job_id
                || frame.channel != channel
                || !validate_job_payload_context(&frame, &response_descriptor)
            {
                break;
            }
            if in_tx.send(frame.payload).await.is_err() {
                break;
            }
        }
    });

    Ok(ChannelByteStream::new(out_tx, in_rx))
}
