impl DaemonState {
    fn wake_scheduler(&self) {
        self.scheduler_notify.notify_one();
    }

    fn has_peer_channels(&self) -> bool {
        self.peer_channels
            .as_ref()
            .is_some_and(|channels| !channels.is_empty())
    }

    fn peer_channel_for_optional(&self, channel_index: u64) -> Option<Channel> {
        let channels = self.peer_channels.as_ref()?;
        if channels.is_empty() {
            return None;
        }
        let shard = channel_index as usize % channels.len();
        Some(channels[shard].clone())
    }

    fn peer_channel_for(&self, channel_index: u64) -> Result<Channel> {
        self.peer_channel_for_optional(channel_index)
            .ok_or_else(|| DaemonError::Refused("peer URL is not configured".to_owned()))
    }

    async fn resource_model(&self) -> ResourceModel {
        let outgoing = self.precompute_sessions.lock().await.len() as u64;
        let incoming = self.incoming_precompute_sessions.lock().await.len() as u64;
        let live_session_count = outgoing.saturating_add(incoming);
        let inner = self.inner.lock().await;
        resource_model(&inner, live_session_count)
    }

    async fn check_cookie<T>(&self, request: &Request<T>) -> std::result::Result<(), Status> {
        let cookie = request
            .metadata()
            .get("x-shachain-cookie")
            .ok_or_else(|| Status::unauthenticated("missing local cookie"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("bad local cookie"))?
            .to_owned();
        let expected = self.inner.lock().await.cookie.clone();
        if cookie == expected {
            Ok(())
        } else {
            Err(Status::unauthenticated("bad local cookie"))
        }
    }

    async fn register_incoming_job_stream(
        &self,
        descriptor: GrpcJobDescriptor,
        channel: u32,
        stream: ChannelByteStream,
    ) -> std::result::Result<(), Status> {
        let mut jobs = self.grpc_jobs.lock().await;
        let entry = jobs
            .entry(descriptor.job_id.clone())
            .or_insert_with(|| PendingGrpcJob {
                descriptor: descriptor.clone(),
                main: None,
                sibling: None,
            });
        if entry.descriptor != descriptor {
            return Err(Status::invalid_argument("JobStream descriptor mismatch"));
        }
        let slot = match channel {
            1 => &mut entry.main,
            2 => &mut entry.sibling,
            _ => return Err(Status::invalid_argument("JobStream channel must be 1 or 2")),
        };
        if slot.is_some() {
            return Err(Status::already_exists("duplicate JobStream channel"));
        }
        *slot = Some(stream);
        if entry.main.is_some() && entry.sibling.is_some() {
            let mut ready = jobs
                .remove(&descriptor.job_id)
                .expect("ready JobStream entry exists");
            let streams = Ag2pcStreams {
                main: ready.main.take().expect("main stream is ready"),
                sibling: ready.sibling.take().expect("sibling stream is ready"),
            };
            let state = self.clone();
            let channel_index = ready.descriptor.channel_index;
            let task_state = state.clone();
            let task = tokio::spawn(async move {
                let _ = task_state
                    .clone()
                    .run_incoming_precompute_session(ready.descriptor, streams)
                    .await;
                task_state
                    .unregister_incoming_precompute_session(channel_index)
                    .await;
            });
            let abort_handle = task.abort_handle();
            let old = {
                state
                    .incoming_precompute_sessions
                    .lock()
                    .await
                    .insert(channel_index, abort_handle)
            };
            if let Some(old) = old {
                old.abort();
            }
        }
        Ok(())
    }

    async fn run_incoming_precompute_session(
        self,
        descriptor: GrpcJobDescriptor,
        mut streams: Ag2pcStreams<ChannelByteStream>,
    ) -> Result<()> {
        let job = self.begin_incoming_precompute_session(&descriptor).await?;
        streams =
            match run_jobstream_session_handshake(self.role().await, &descriptor, streams).await {
                Ok(streams) => streams,
                Err(e) => return Err(e),
            };
        let role = self.role().await;
        let mut session = match PrecomputeSession::setup_with_streams_and_circuit(
            streams,
            role,
            job.share,
            job.delta,
            job.ssp,
            self.sha.clone(),
        )
        .await
        {
            Ok(session) => session,
            Err(e) => return Err(e.into()),
        };
        loop {
            let target_bytes = match session.streams_mut().main.recv_data(8).await {
                Ok(bytes) => bytes,
                Err(e) => return Err(e.into()),
            };
            let target_index = u64::from_le_bytes(
                target_bytes
                    .try_into()
                    .map_err(|_| DaemonError::Parse("bad precompute target command".to_owned()))?,
            );
            let index =
                Index48::new(target_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
            let planned_checked_units = session.planned_checked_units(index);
            let target_job = self
                .begin_incoming_precompute_target(&descriptor, index, planned_checked_units)
                .await?;
            let wires = match session.precompute_target(index).await {
                Ok(wires) => wires,
                Err(e) => {
                    self.finish_job(&target_job.job_id, true).await;
                    return Err(e.into());
                }
            };
            if let Err(e) = self
                .store_precomputed_target_wires_and_finish_job(
                    descriptor.channel_index,
                    &target_job.job_id,
                    planned_checked_units,
                    index.get(),
                    wires,
                )
                .await
            {
                self.finish_job(&target_job.job_id, true).await;
                return Err(e);
            }
        }
    }

    async fn role(&self) -> Role {
        self.inner.lock().await.cfg.role
    }

    async fn reveal(
        &self,
        channel_index: u64,
        requested_index: u64,
        expected_next_index: u64,
        allow_seed_reveal: bool,
    ) -> Result<pb::RevealResponse> {
        let index = Index48::new(requested_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        if index.get() == 0 && !allow_seed_reveal {
            return Err(DaemonError::Refused(
                "I=0 reveals the seed; pass allow_seed_reveal to proceed".to_owned(),
            ));
        }
        if let Some(secret) = self.derive_known(channel_index, index).await? {
            return Ok(reveal_response(channel_index, index, secret, true, "known"));
        }
        if requested_index != expected_next_index {
            return Err(DaemonError::Refused(
                "requested index must match expected_next_index unless locally derivable"
                    .to_owned(),
            ));
        }
        if let Some(node) = self.load_node(channel_index, index.get()).await? {
            match self
                .reveal_cached_node(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    &node,
                )
                .await
            {
                Ok(secret) => {
                    self.store_known_secret(channel_index, index, expected_next_index, secret)
                        .await?;
                    return Ok(reveal_response(
                        channel_index,
                        index,
                        secret,
                        true,
                        "frontier",
                    ));
                }
                Err(err) if is_cached_reveal_cache_miss(&err) => {}
                Err(err) => return Err(err),
            }
        }
        self.reconcile_with_peer(channel_index).await?;
        if let Some(node) = self.load_node(channel_index, index.get()).await? {
            let secret = self
                .reveal_cached_node(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    &node,
                )
                .await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            return Ok(reveal_response(
                channel_index,
                index,
                secret,
                true,
                "frontier",
            ));
        }
        if index.get() == 0 {
            let (node, root_from_cache) = self.ensure_root(channel_index).await?;
            let secret = self
                .reveal_cached_node(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    &node,
                )
                .await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            Ok(reveal_response(
                channel_index,
                index,
                secret,
                root_from_cache,
                if root_from_cache {
                    "frontier"
                } else {
                    "seed_root"
                },
            ))
        } else {
            let secret = self.run_full_derivation(channel_index, index).await?;
            self.store_known_secret(channel_index, index, expected_next_index, secret)
                .await?;
            Ok(reveal_response(
                channel_index,
                index,
                secret,
                false,
                "full_derivation",
            ))
        }
    }

    async fn run_scheduler_once(&self) -> Result<()> {
        if self.role().await != Role::Alice {
            return Ok(());
        }
        let candidates = self.scheduler_candidates().await;
        for channel_index in candidates {
            let state = self.clone();
            tokio::spawn(async move {
                state.run_scheduled_precompute(channel_index).await;
            });
        }
        Ok(())
    }

    async fn scheduler_candidates(&self) -> Vec<u64> {
        let resources = self.resource_model().await;
        let mut scheduled = self.scheduled_precompute_channels.lock().await;
        let mut full_reconcile_after = self.full_reconcile_after.lock().await;
        let inner = self.inner.lock().await;
        if inner.cfg.workers == 0 || inner.cfg.precompute == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let active_channels = inner
            .active_jobs
            .values()
            .map(|job| job.channel_index)
            .collect::<BTreeSet<_>>();
        let in_flight = active_channels.union(&*scheduled).count();
        let effective_workers = resources.effective_workers as usize;
        if in_flight >= effective_workers {
            return Vec::new();
        }
        let available = effective_workers - in_flight;
        let candidates = inner
            .db
            .channels
            .iter()
            .filter_map(|(key, channel)| {
                let channel_index = key.parse::<u64>().ok()?;
                if !channel.enabled || channel.precompute_target == 0 {
                    return None;
                }
                let local_precompute = channel.precompute_target.min(inner.cfg.precompute);
                if local_precompute == 0 {
                    return None;
                }
                let has_missing_frontier = (1..=local_precompute.min(MAX_INDEX)).any(|index| {
                    let key = node_key(index);
                    let (public, local) = binding_pair(&inner, channel_index, index);
                    !channel.frontier_nodes.get(&key).is_some_and(|record| {
                        record.public_binding_hex == to_hex(&public)
                            && record.local_binding_hex == to_hex(&local)
                    })
                });
                if !has_missing_frontier {
                    if full_reconcile_after
                        .get(&channel_index)
                        .is_some_and(|deadline| *deadline > now)
                    {
                        return None;
                    }
                }
                if active_channels.contains(&channel_index) || scheduled.contains(&channel_index) {
                    return None;
                }
                Some((channel_index, !has_missing_frontier))
            })
            .take(available)
            .collect::<Vec<_>>();
        for (channel_index, local_frontier_full) in &candidates {
            scheduled.insert(*channel_index);
            if *local_frontier_full {
                full_reconcile_after.insert(*channel_index, now + FULL_FRONTIER_RECONCILE_INTERVAL);
            }
        }
        candidates
            .into_iter()
            .map(|(channel_index, _)| channel_index)
            .collect()
    }

    async fn run_scheduled_precompute(&self, channel_index: u64) {
        let result = self.run_scheduled_precompute_inner(channel_index).await;
        self.scheduled_precompute_channels
            .lock()
            .await
            .remove(&channel_index);
        if matches!(result, Ok(true)) {
            self.wake_scheduler();
        }
    }

    async fn run_scheduled_precompute_inner(&self, channel_index: u64) -> Result<bool> {
        let Some(peer) = self.peer_frontier(channel_index).await? else {
            return Ok(false);
        };
        if !peer.channel_enabled {
            return Ok(false);
        }
        self.reconcile_with_peer(channel_index).await?;
        let effective_precompute = match self.effective_precompute_target(channel_index, peer).await
        {
            Ok(target) => target,
            Err(DaemonError::Refused(message))
                if message.contains("security parameters do not match") =>
            {
                let _ = self
                    .record_failed_precompute_attempt(channel_index, 1)
                    .await;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        if effective_precompute == 0 {
            return Ok(false);
        }
        if let Some(target) = self
            .next_missing_frontier(channel_index, effective_precompute)
            .await?
        {
            self.precompute_path_jobstream(channel_index, target)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn validate_peer_security_params(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<()> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if peer.ssp_target != channel.ssp_target
            || peer.delta_lifetime_checked_units_cap != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "peer channel security parameters do not match".to_owned(),
            ));
        }
        Ok(())
    }

    async fn effective_precompute_target(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<u64> {
        self.validate_peer_security_params(channel_index, peer)
            .await?;
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        Ok(channel
            .precompute_target
            .min(inner.cfg.precompute)
            .min(peer.precompute))
    }

    async fn next_missing_frontier(
        &self,
        channel_index: u64,
        effective_precompute: u64,
    ) -> Result<Option<u64>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        for index in 1..=effective_precompute.min(MAX_INDEX) {
            let key = node_key(index);
            let (public, local) = binding_pair(&inner, channel_index, index);
            let present = channel.frontier_nodes.get(&key).is_some_and(|record| {
                record.public_binding_hex == to_hex(&public)
                    && record.local_binding_hex == to_hex(&local)
            });
            if !present {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    async fn precompute_session_handle(
        &self,
        channel_index: u64,
        peer: PeerFrontierConfig,
    ) -> Result<PrecomputeSessionHandle> {
        {
            let mut sessions = self.precompute_sessions.lock().await;
            if let Some(handle) = sessions.get(&channel_index) {
                if !handle.tx.is_closed() {
                    return Ok(handle.clone());
                }
            }
            sessions.remove(&channel_index);
        }

        let (role, delta, ssp, ssp_target, cap, share, session_id) = {
            let mut inner = self.inner.lock().await;
            let key = channel_key(channel_index);
            let channel = inner
                .db
                .channels
                .get(&key)
                .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
            if !channel.enabled {
                return Err(DaemonError::Refused("channel is disabled".to_owned()));
            }
            if peer.ssp_target != channel.ssp_target
                || peer.delta_lifetime_checked_units_cap != channel.delta_lifetime_checked_units_cap
            {
                return Err(DaemonError::Refused(
                    "peer channel security parameters do not match".to_owned(),
                ));
            }
            let ssp_target = channel.ssp_target;
            let cap = channel.delta_lifetime_checked_units_cap;
            inner.next_job_id = inner.next_job_id.saturating_add(1);
            (
                inner.cfg.role,
                channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role),
                ssp_effective(ssp_target, cap),
                ssp_target,
                cap,
                channel_seed_share(&inner.master_secret.0, channel_index),
                format!("precompute-session-{}-{}", channel_index, inner.next_job_id),
            )
        };
        let descriptor = GrpcJobDescriptor {
            job_id: session_id,
            channel_index,
            target_index: 0,
            ssp: ssp as u32,
            ssp_target,
            delta_lifetime_checked_units_cap: cap,
            digest: job_digest(channel_index, "precompute-session", 0, 0, ssp as u32),
        };
        let mut streams = self.open_peer_job_streams(&descriptor).await?;
        streams = run_jobstream_session_handshake(role, &descriptor, streams).await?;
        let session = PrecomputeSession::setup_with_streams_and_circuit(
            streams,
            role,
            share,
            delta,
            ssp,
            self.sha.clone(),
        )
        .await?;
        let (tx, rx) = mpsc::channel(8);
        let handle = PrecomputeSessionHandle { tx };
        self.precompute_sessions
            .lock()
            .await
            .insert(channel_index, handle.clone());
        tokio::spawn(run_outgoing_precompute_session(session, rx));
        Ok(handle)
    }

    async fn drop_precompute_session(&self, channel_index: u64) {
        self.scheduled_precompute_channels
            .lock()
            .await
            .remove(&channel_index);
        self.full_reconcile_after
            .lock()
            .await
            .remove(&channel_index);
        self.precompute_sessions.lock().await.remove(&channel_index);
        if let Some(handle) = self
            .incoming_precompute_sessions
            .lock()
            .await
            .remove(&channel_index)
        {
            handle.abort();
        }
    }

    async fn unregister_incoming_precompute_session(&self, channel_index: u64) {
        self.incoming_precompute_sessions
            .lock()
            .await
            .remove(&channel_index);
    }

    async fn precompute_path_jobstream(
        &self,
        channel_index: u64,
        target_index: u64,
    ) -> Result<pb::PrecomputeResponse> {
        let index = Index48::new(target_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        let peer = match self.peer_frontier(channel_index).await? {
            Some(peer) if peer.channel_enabled => peer,
            Some(_) => {
                return Err(DaemonError::Refused(
                    "peer has not enabled this channel".to_owned(),
                ));
            }
            None => {
                return Err(DaemonError::Refused(
                    "peer URL is not configured".to_owned(),
                ))
            }
        };
        if let Err(e) = self
            .validate_peer_security_params(channel_index, peer)
            .await
        {
            let planned_checked_units = set_bits_desc(index.get()).len() as u64;
            self.record_failed_precompute_attempt(channel_index, planned_checked_units)
                .await?;
            return Err(e);
        }
        self.reconcile_with_peer(channel_index).await?;
        let session = self.precompute_session_handle(channel_index, peer).await?;
        let planned_checked_units = match session.plan(index).await {
            Ok(planned) => planned,
            Err(e) => {
                self.drop_precompute_session(channel_index).await;
                return Err(e);
            }
        };
        let job = match self
            .begin_precompute_jobstream(channel_index, index, peer, planned_checked_units)
            .await?
        {
            PrecomputeStart::AlreadyStored => {
                return Ok(pb::PrecomputeResponse {
                    channel_index,
                    target_index: index.get(),
                    nodes_stored: 0,
                    checked_units: 0,
                });
            }
            PrecomputeStart::Run(job) => job,
        };
        let wires = match session.precompute(index).await {
            Ok(wires) => wires,
            Err(e) => {
                self.drop_precompute_session(channel_index).await;
                self.finish_job(&job.job_id, true).await;
                return Err(e);
            }
        };
        let nodes_stored = match self
            .store_precomputed_target_wires_and_finish_job(
                channel_index,
                &job.job_id,
                job.planned_checked_units,
                index.get(),
                wires,
            )
            .await
        {
            Ok(nodes_stored) => nodes_stored,
            Err(e) => {
                self.finish_job(&job.job_id, true).await;
                return Err(e);
            }
        };
        Ok(pb::PrecomputeResponse {
            channel_index,
            target_index: index.get(),
            nodes_stored,
            checked_units: job.planned_checked_units,
        })
    }

    async fn reveal_cached_node(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        if index.get() == 0 {
            return self.reveal_persisted_node(channel_index, index, node).await;
        }
        match (self.role().await, self.has_peer_channels()) {
            (Role::Alice, true) => {
                self.reveal_cached_node_via_peer(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    node,
                )
                .await
            }
            (Role::Bob, true) => {
                self.await_incoming_cached_reveal(
                    channel_index,
                    index,
                    expected_next_index,
                    allow_seed_reveal,
                    node,
                )
                .await
            }
            _ => self.reveal_persisted_node(channel_index, index, node).await,
        }
    }

    async fn reveal_cached_node_via_peer(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        let (delta, ssp_target, cap, public_binding_hex) =
            self.reveal_node_context(channel_index, index.get()).await?;
        let local = reveal_node_local_share(node)?;
        let peer_channel = self.peer_channel_for(channel_index)?;
        let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
        let response = client
            .reveal_cached(pb::RevealCachedRequest {
                channel_index,
                requested_index: index.get(),
                expected_next_index,
                allow_seed_reveal,
                share_bits: local.share_bits,
                mac_digest: local.mac_digest.to_vec(),
                ssp_target,
                delta_lifetime_checked_units_cap: cap,
                public_binding_hex,
            })
            .await?
            .into_inner();
        let peer_digest = parse_mac_digest(response.mac_digest, "RevealCached response")?;
        let opened = reveal_node_from_peer_share(node, delta, &response.share_bits, peer_digest)?;
        Ok(opened.value)
    }

    async fn await_incoming_cached_reveal(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        allow_seed_reveal: bool,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        reveal_node_local_share(node)?;
        let key = RevealRequestKey {
            channel_index,
            requested_index: index.get(),
            expected_next_index,
            allow_seed_reveal,
        };
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_reveals.lock().await;
            if pending
                .insert(key, PendingReveal { response: tx })
                .is_some()
            {
                return Err(DaemonError::Refused(
                    "cached reveal is already pending".to_owned(),
                ));
            }
        }
        self.pending_reveal_notify.notify_waiters();
        match timeout(peer_reveal_wait(), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(DaemonError::Refused(
                "cached reveal peer handler stopped".to_owned(),
            )),
            Err(_) => {
                self.pending_reveals.lock().await.remove(&key);
                Err(DaemonError::Refused(
                    "timed out waiting for peer cached reveal".to_owned(),
                ))
            }
        }
    }

    async fn handle_peer_cached_reveal(
        &self,
        req: pb::RevealCachedRequest,
    ) -> Result<pb::RevealCachedResponse> {
        let key = RevealRequestKey {
            channel_index: req.channel_index,
            requested_index: req.requested_index,
            expected_next_index: req.expected_next_index,
            allow_seed_reveal: req.allow_seed_reveal,
        };
        let pending = self.take_pending_reveal(key).await?;
        match self.complete_peer_cached_reveal(req).await {
            Ok((response, value)) => {
                let _ = pending.response.send(Ok(value));
                Ok(response)
            }
            Err(err) => {
                let msg = err.to_string();
                let _ = pending.response.send(Err(DaemonError::Refused(msg)));
                Err(err)
            }
        }
    }

    async fn take_pending_reveal(&self, key: RevealRequestKey) -> Result<PendingReveal> {
        timeout(peer_reveal_wait(), async {
            loop {
                let notified = self.pending_reveal_notify.notified();
                if let Some(pending) = self.pending_reveals.lock().await.remove(&key) {
                    return pending;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| {
            DaemonError::Refused("cached reveal needs matching local authorization".to_owned())
        })
    }

    async fn complete_peer_cached_reveal(
        &self,
        req: pb::RevealCachedRequest,
    ) -> Result<(pb::RevealCachedResponse, Value32)> {
        let index =
            Index48::new(req.requested_index).map_err(|e| DaemonError::Parse(e.to_string()))?;
        if index.get() == 0 && !req.allow_seed_reveal {
            return Err(DaemonError::Refused(
                "I=0 reveals the seed; pass allow_seed_reveal to proceed".to_owned(),
            ));
        }
        if req.requested_index != req.expected_next_index {
            return Err(DaemonError::Refused(
                "requested index must match expected_next_index".to_owned(),
            ));
        }
        let peer_digest = parse_mac_digest(req.mac_digest, "RevealCached request")?;
        let node = self
            .load_node(req.channel_index, index.get())
            .await?
            .ok_or_else(|| DaemonError::NotFound("cached reveal node is not stored".to_owned()))?;
        let (delta, ssp_target, cap, public_binding_hex) = self
            .reveal_node_context(req.channel_index, index.get())
            .await?;
        if req.ssp_target != ssp_target
            || req.delta_lifetime_checked_units_cap != cap
            || req.public_binding_hex != public_binding_hex
        {
            return Err(DaemonError::Refused(
                "cached reveal binding does not match local channel".to_owned(),
            ));
        }
        let local = reveal_node_local_share(&node)?;
        let opened = reveal_node_from_peer_share(&node, delta, &req.share_bits, peer_digest)?;
        self.store_known_secret(
            req.channel_index,
            index,
            req.expected_next_index,
            opened.value,
        )
        .await?;
        Ok((
            pb::RevealCachedResponse {
                share_bits: local.share_bits,
                mac_digest: local.mac_digest.to_vec(),
            },
            opened.value,
        ))
    }

    async fn reveal_node_context(
        &self,
        channel_index: u64,
        mask: u64,
    ) -> Result<(Block, u32, u64, String)> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let delta = channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role);
        let (public, _) = binding_pair(&inner, channel_index, mask);
        Ok((
            delta,
            channel.ssp_target,
            channel.delta_lifetime_checked_units_cap,
            to_hex(&public),
        ))
    }

    async fn reveal_persisted_node(
        &self,
        channel_index: u64,
        index: Index48,
        node: &Ag2pcSecureWires,
    ) -> Result<Value32> {
        let (endpoint, delta, ssp) = self.job_context(channel_index).await?;
        let digest = job_digest(
            channel_index,
            "reveal",
            index.get(),
            index.get(),
            ssp as u32,
        );
        reveal_node_fast_job(endpoint, node, delta, digest)
            .await
            .map_err(Into::into)
    }

    async fn store_known_secret(
        &self,
        channel_index: u64,
        index: Index48,
        expected_next_index: u64,
        secret: Value32,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        let mut redundant = false;
        let mut drop_keys = Vec::new();
        for (stored_index_s, stored_secret_hex) in &channel.known_secrets {
            let Ok(stored_index) = stored_index_s.parse::<u64>() else {
                drop_keys.push(stored_index_s.clone());
                continue;
            };
            let stored_secret = Value32::from_hex(stored_secret_hex)
                .map_err(|e| DaemonError::Parse(e.to_string()))?;
            if derive_from_known(stored_index, stored_secret, index.get()) == Some(secret) {
                redundant = true;
                break;
            }
            if derive_from_known(index.get(), secret, stored_index) == Some(stored_secret) {
                drop_keys.push(stored_index_s.clone());
            }
        }
        if !redundant {
            for key in &drop_keys {
                channel.known_secrets.remove(key.as_str());
            }
            channel
                .known_secrets
                .insert(index.get().to_string(), secret.to_hex());
        }
        channel.frontier_nodes.remove(&node_key(index.get()));
        channel.last_observed_next_reveal_index = Some(expected_next_index.saturating_sub(1));
        let mut mutations = Vec::new();
        if !redundant {
            mutations.push(upsert_secret_mutation(
                channel_index,
                index.get(),
                secret.to_hex(),
            ));
            for key in drop_keys {
                if let Ok(index) = key.parse::<u64>() {
                    mutations.push(delete_secret_mutation(channel_index, index));
                }
            }
        }
        mutations.push(delete_frontier_mutation(channel_index, index.get()));
        mutations.push(upsert_channel_mutation(channel_index, channel));
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        self.wake_scheduler();
        Ok(())
    }

    async fn run_full_derivation(&self, channel_index: u64, index: Index48) -> Result<Value32> {
        let (role, port, peer_ip, share) = {
            let inner = self.inner.lock().await;
            let channel = inner
                .db
                .channels
                .get(&channel_key(channel_index))
                .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
            if !channel.enabled {
                return Err(DaemonError::Refused("channel is disabled".to_owned()));
            }
            let peer_ip = inner
                .cfg
                .peer_url
                .as_deref()
                .and_then(peer_ip_from_url)
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            (
                inner.cfg.role,
                inner.cfg.mpc_port,
                peer_ip,
                channel_seed_share(&inner.master_secret.0, channel_index),
            )
        };
        match run_party(PartyArgs {
            role,
            port,
            index_spec: IndexSpec::Single(index),
            share,
            peer_ip,
            allow_seed_reveal: false,
        })
        .await?
        {
            PartyOutput::Single(value) => Ok(value),
            PartyOutput::Range(_) => Err(DaemonError::Refused(
                "daemon full derivation fallback expected one output".to_owned(),
            )),
        }
    }

    async fn ensure_root(&self, channel_index: u64) -> Result<(Ag2pcSecureWires, bool)> {
        if let Some(node) = self.load_node(channel_index, 0).await? {
            return Ok((node, true));
        }
        let (endpoint, delta, ssp) = self.job_context(channel_index).await?;
        let share = self.channel_share(channel_index).await?;
        let digest = job_digest(channel_index, "root", 0, 0, ssp as u32);
        let root =
            run_seed_root_job_with_circuit(endpoint, share, delta, digest, ssp, self.sha.as_ref())
                .await?;
        self.store_node(channel_index, 0, &root).await?;
        Ok((root, false))
    }

    async fn job_context(&self, channel_index: u64) -> Result<(MpcTcpEndpoint, Block, usize)> {
        let inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let peer_ip = inner
            .cfg
            .peer_url
            .as_deref()
            .and_then(peer_ip_from_url)
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let endpoint = MpcTcpEndpoint {
            role: inner.cfg.role,
            port: inner.cfg.mpc_port,
            peer_ip,
        };
        let delta = channel_delta(&inner.master_secret.0, channel_index, inner.cfg.role);
        let ssp = ssp_effective(channel.ssp_target, channel.delta_lifetime_checked_units_cap);
        Ok((endpoint, delta, ssp))
    }

    async fn begin_precompute_jobstream(
        &self,
        channel_index: u64,
        index: Index48,
        peer: PeerFrontierConfig,
        planned_checked_units: u64,
    ) -> Result<PrecomputeStart> {
        let resources = self.resource_model().await;
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let key_node = node_key(index.get());
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let (public, local) = binding_pair(&inner, channel_index, index.get());
        if channel.frontier_nodes.get(&key_node).is_some_and(|record| {
            record.public_binding_hex == to_hex(&public)
                && record.local_binding_hex == to_hex(&local)
        }) {
            return Ok(PrecomputeStart::AlreadyStored);
        }
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == channel_index)
        {
            return Err(DaemonError::Refused(
                "channel already has an active precompute job".to_owned(),
            ));
        }
        let worker_count = resources
            .effective_workers
            .min(peer.effective_workers.min(peer.workers.max(1)));
        if worker_count == 0 {
            return Err(DaemonError::Refused(
                "no shared precompute worker is available".to_owned(),
            ));
        }
        if inner.active_jobs.len() >= worker_count as usize {
            return Err(DaemonError::Refused(
                "all shared precompute workers are busy".to_owned(),
            ));
        }
        let reserved: u64 = inner
            .active_jobs
            .values()
            .filter(|job| job.channel_index == channel_index)
            .map(|job| job.planned_checked_units)
            .sum();
        let used = channel
            .estimated_checked_units
            .saturating_add(reserved)
            .saturating_add(planned_checked_units);
        if used > channel.delta_lifetime_checked_units_cap {
            return Err(DaemonError::Refused(format!(
                "precompute would exceed Delta lifetime checked-unit cap: estimated={} reserved={} requested={} cap={}",
                channel.estimated_checked_units,
                reserved,
                planned_checked_units,
                channel.delta_lifetime_checked_units_cap
            )));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        inner.next_job_id = inner.next_job_id.saturating_add(1);
        let job_id = format!("precompute-{}-{}", channel_index, inner.next_job_id);
        inner.active_jobs.insert(
            job_id.clone(),
            JobRecord {
                channel_index,
                kind: "precompute".to_owned(),
                state: format!("grpc target={}", index.get()),
                planned_checked_units,
            },
        );
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after attempted counter update");
        let mutations = vec![upsert_channel_mutation(channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        Ok(PrecomputeStart::Run(PrecomputeJob {
            job_id,
            planned_checked_units,
        }))
    }

    async fn record_failed_precompute_attempt(
        &self,
        channel_index: u64,
        planned_checked_units: u64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let channel = inner
            .db
            .channels
            .get_mut(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        channel.failed_precompute_jobs = channel.failed_precompute_jobs.saturating_add(1);
        let mutations = vec![upsert_channel_mutation(channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn begin_incoming_precompute_session(
        &self,
        descriptor: &GrpcJobDescriptor,
    ) -> Result<IncomingPrecomputeSession> {
        let inner = self.inner.lock().await;
        let key = channel_key(descriptor.channel_index);
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        if descriptor.ssp_target != channel.ssp_target
            || descriptor.delta_lifetime_checked_units_cap
                != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "incoming JobStream security parameters do not match".to_owned(),
            ));
        }
        let ssp = ssp_effective(channel.ssp_target, channel.delta_lifetime_checked_units_cap);
        if descriptor.ssp != ssp as u32 {
            return Err(DaemonError::Refused(
                "incoming JobStream uses the wrong security parameter".to_owned(),
            ));
        }
        let expected_digest = job_digest(
            descriptor.channel_index,
            "precompute-session",
            0,
            0,
            descriptor.ssp,
        );
        if descriptor.digest != expected_digest {
            return Err(DaemonError::Refused(
                "incoming JobStream digest does not match local job".to_owned(),
            ));
        }
        if descriptor.target_index != 0 {
            return Err(DaemonError::Refused(
                "incoming precompute session must use target index 0".to_owned(),
            ));
        }
        let delta = channel_delta(
            &inner.master_secret.0,
            descriptor.channel_index,
            inner.cfg.role,
        );
        let share = channel_seed_share(&inner.master_secret.0, descriptor.channel_index);
        Ok(IncomingPrecomputeSession { delta, ssp, share })
    }

    async fn begin_incoming_precompute_target(
        &self,
        descriptor: &GrpcJobDescriptor,
        index: Index48,
        planned_checked_units: u64,
    ) -> Result<IncomingPrecomputeJob> {
        let resources = self.resource_model().await;
        let mut inner = self.inner.lock().await;
        let key = channel_key(descriptor.channel_index);
        let channel = inner
            .db
            .channels
            .get(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        if descriptor.ssp_target != channel.ssp_target
            || descriptor.delta_lifetime_checked_units_cap
                != channel.delta_lifetime_checked_units_cap
        {
            return Err(DaemonError::Refused(
                "incoming JobStream security parameters do not match".to_owned(),
            ));
        }
        if inner.active_jobs.len() >= resources.effective_workers as usize {
            return Err(DaemonError::Refused(
                "all local precompute workers are busy".to_owned(),
            ));
        }
        if inner
            .active_jobs
            .values()
            .any(|job| job.channel_index == descriptor.channel_index)
        {
            return Err(DaemonError::Refused(
                "channel already has an active precompute job".to_owned(),
            ));
        }
        let reserved: u64 = inner
            .active_jobs
            .values()
            .filter(|job| job.channel_index == descriptor.channel_index)
            .map(|job| job.planned_checked_units)
            .sum();
        let used = channel
            .estimated_checked_units
            .saturating_add(reserved)
            .saturating_add(planned_checked_units);
        if used > channel.delta_lifetime_checked_units_cap {
            return Err(DaemonError::Refused(
                "incoming JobStream would exceed Delta lifetime checked-unit cap".to_owned(),
            ));
        }
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        channel.attempted_checked_units = channel
            .attempted_checked_units
            .saturating_add(planned_checked_units);
        let job_id = format!("{}-target-{}", descriptor.job_id, index.get());
        inner.active_jobs.insert(
            job_id.clone(),
            JobRecord {
                channel_index: descriptor.channel_index,
                kind: "precompute".to_owned(),
                state: format!("grpc target={}", index.get()),
                planned_checked_units,
            },
        );
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after incoming attempted counter update");
        let mutations = vec![upsert_channel_mutation(descriptor.channel_index, channel)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        Ok(IncomingPrecomputeJob { job_id })
    }

    async fn open_peer_job_streams(
        &self,
        descriptor: &GrpcJobDescriptor,
    ) -> Result<Ag2pcStreams<ChannelByteStream>> {
        let peer_channel = self.peer_channel_for(descriptor.channel_index)?;
        let main = open_peer_job_channel(peer_channel.clone(), descriptor, 1).await?;
        let sibling = open_peer_job_channel(peer_channel, descriptor, 2).await?;
        Ok(Ag2pcStreams { main, sibling })
    }

    async fn channel_share(&self, channel_index: u64) -> Result<Value32> {
        let inner = self.inner.lock().await;
        Ok(channel_seed_share(&inner.master_secret.0, channel_index))
    }

    async fn load_node(&self, channel_index: u64, mask: u64) -> Result<Option<Ag2pcSecureWires>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        let Some(record) = channel.frontier_nodes.get(&node_key(mask)) else {
            return Ok(None);
        };
        let (public, local) = binding_pair(&inner, channel_index, mask);
        if record.public_binding_hex != to_hex(&public)
            || record.local_binding_hex != to_hex(&local)
        {
            return Ok(None);
        }
        Ok(Some(record.wires.to_secure_wires()))
    }

    async fn store_node(
        &self,
        channel_index: u64,
        mask: u64,
        wires: &Ag2pcSecureWires,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let (public, local) = binding_pair(&inner, channel_index, mask);
        let channel = inner
            .db
            .channels
            .get_mut(&channel_key(channel_index))
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        let record = WireRecord {
            public_binding_hex: to_hex(&public),
            local_binding_hex: to_hex(&local),
            wires: SerializableWires::from_secure_wires(wires),
        };
        channel
            .frontier_nodes
            .insert(node_key(mask), record.clone());
        let mutations = vec![upsert_frontier_mutation(channel_index, mask, record)];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn store_precomputed_target_wires_and_finish_job(
        &self,
        channel_index: u64,
        job_id: &str,
        planned_checked_units: u64,
        target_mask: u64,
        wires: Ag2pcSecureWires,
    ) -> Result<u64> {
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let (public, local) = binding_pair(&inner, channel_index, target_mask);
        let channel = inner
            .db
            .channels
            .get_mut(&key)
            .ok_or_else(|| DaemonError::NotFound("channel is not enabled".to_owned()))?;
        if !channel.enabled {
            return Err(DaemonError::Refused("channel is disabled".to_owned()));
        }
        let record = WireRecord {
            public_binding_hex: to_hex(&public),
            local_binding_hex: to_hex(&local),
            wires: SerializableWires::from_secure_wires(&wires),
        };
        channel
            .frontier_nodes
            .insert(node_key(target_mask), record.clone());
        if let Some(channel) = inner.db.channels.get_mut(&key) {
            channel.estimated_checked_units = channel
                .estimated_checked_units
                .saturating_add(planned_checked_units);
        }
        inner.active_jobs.remove(job_id);
        let channel = inner
            .db
            .channels
            .get(&key)
            .expect("channel exists after update");
        let mutations = vec![
            upsert_frontier_mutation(channel_index, target_mask, record),
            upsert_channel_mutation(channel_index, channel),
        ];
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await?;
        self.wake_scheduler();
        Ok(1)
    }

    async fn peer_frontier(&self, channel_index: u64) -> Result<Option<PeerFrontierConfig>> {
        Ok(self
            .peer_frontier_response(channel_index)
            .await?
            .map(|(_, config)| config))
    }

    async fn peer_frontier_response(
        &self,
        channel_index: u64,
    ) -> Result<Option<(pb::GetFrontierResponse, PeerFrontierConfig)>> {
        let Some(peer_channel) = self.peer_channel_for_optional(channel_index) else {
            return Ok(None);
        };
        let mut client = pb::peer_service_client::PeerServiceClient::new(peer_channel);
        let response = client
            .get_frontier(pb::GetFrontierRequest { channel_index })
            .await?
            .into_inner();
        let config = PeerFrontierConfig {
            channel_enabled: response.channel_enabled,
            precompute: response.precompute,
            workers: response.workers,
            effective_workers: response.effective_workers.max(1),
            ssp_target: response.ssp_target,
            delta_lifetime_checked_units_cap: response.delta_lifetime_checked_units_cap,
        };
        Ok(Some((response, config)))
    }

    async fn finish_job(&self, job_id: &str, failed: bool) {
        let mut inner = self.inner.lock().await;
        let mut mutations = Vec::new();
        if let Some(job) = inner.active_jobs.remove(job_id) {
            if failed {
                if let Some(channel) = inner.db.channels.get_mut(&channel_key(job.channel_index)) {
                    channel.failed_precompute_jobs =
                        channel.failed_precompute_jobs.saturating_add(1);
                    mutations.push(upsert_channel_mutation(job.channel_index, channel));
                }
            }
        }
        drop(inner);
        let _ = self
            .db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await;
        self.wake_scheduler();
    }

    async fn reconcile_with_peer(&self, channel_index: u64) -> Result<()> {
        let Some((response, _peer_config)) = self.peer_frontier_response(channel_index).await?
        else {
            return Ok(());
        };
        if !response.channel_enabled {
            return Ok(());
        }
        let peer: HashMap<u64, String> = response
            .nodes
            .into_iter()
            .map(|node| (node.mask, node.public_binding_hex))
            .collect();
        let mut inner = self.inner.lock().await;
        let key = channel_key(channel_index);
        let Some(channel) = inner.db.channels.get_mut(&key) else {
            return Ok(());
        };
        let mut drop_masks = Vec::new();
        for (mask_s, node) in &channel.frontier_nodes {
            let Ok(mask) = mask_s.parse::<u64>() else {
                drop_masks.push(mask_s.clone());
                continue;
            };
            if peer.get(&mask) != Some(&node.public_binding_hex) {
                drop_masks.push(mask_s.clone());
            }
        }
        let mut mutations = Vec::new();
        for mask in drop_masks {
            channel.frontier_nodes.remove(&mask);
            if let Ok(mask) = mask.parse::<u64>() {
                mutations.push(delete_frontier_mutation(channel_index, mask));
            }
        }
        drop(inner);
        self.db_writer
            .write_batch(mutations, DbDurability::Eventual)
            .await
    }

    async fn derive_known(
        &self,
        channel_index: u64,
        requested: Index48,
    ) -> Result<Option<Value32>> {
        let inner = self.inner.lock().await;
        let Some(channel) = inner.db.channels.get(&channel_key(channel_index)) else {
            return Ok(None);
        };
        for (index_s, secret_hex) in &channel.known_secrets {
            let Ok(from_index) = index_s.parse::<u64>() else {
                continue;
            };
            let secret =
                Value32::from_hex(secret_hex).map_err(|e| DaemonError::Parse(e.to_string()))?;
            if let Some(out) = derive_from_known(from_index, secret, requested.get()) {
                return Ok(Some(out));
            }
        }
        Ok(None)
    }
}

impl SerializableWires {
    fn from_secure_wires(wires: &Ag2pcSecureWires) -> Self {
        Self {
            lambda: wires.lambda.clone(),
            mac: wires
                .wire_bundle
                .iter()
                .map(|bundle| *bundle.mac.as_bytes())
                .collect(),
            key: wires
                .wire_bundle
                .iter()
                .map(|bundle| *bundle.key.as_bytes())
                .collect(),
        }
    }

    fn to_secure_wires(&self) -> Ag2pcSecureWires {
        Ag2pcSecureWires {
            lambda: self.lambda.clone(),
            wire_bundle: self
                .mac
                .iter()
                .zip(&self.key)
                .map(|(mac, key)| AShareBundle {
                    mac: Block::from_bytes(*mac),
                    key: Block::from_bytes(*key),
                })
                .collect(),
            label0: Vec::new(),
            eval_label: Vec::new(),
        }
    }
}
