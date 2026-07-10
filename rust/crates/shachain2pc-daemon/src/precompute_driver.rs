impl PrecomputeSessionHandle {
    async fn plan(&self, index: Index48) -> Result<u64> {
        let (response, rx) = oneshot::channel();
        self.tx
            .send(PrecomputeSessionCommand::Plan { index, response })
            .await
            .map_err(|_| DaemonError::Refused("precompute session is closed".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Refused("precompute session stopped".to_owned()))?
    }

    async fn precompute(&self, index: Index48) -> Result<Ag2pcSecureWires> {
        let (response, rx) = oneshot::channel();
        self.tx
            .send(PrecomputeSessionCommand::Precompute { index, response })
            .await
            .map_err(|_| DaemonError::Refused("precompute session is closed".to_owned()))?;
        rx.await
            .map_err(|_| DaemonError::Refused("precompute session stopped".to_owned()))?
    }
}

async fn run_outgoing_precompute_session(
    mut session: PrecomputeSession<ChannelByteStream>,
    mut rx: mpsc::Receiver<PrecomputeSessionCommand>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            PrecomputeSessionCommand::Plan { index, response } => {
                let _ = response.send(Ok(session.planned_checked_units(index)));
            }
            PrecomputeSessionCommand::Precompute { index, response } => {
                let target_bytes = index.get().to_le_bytes();
                let send_result = async {
                    session.streams_mut().main.send_data(&target_bytes).await?;
                    session.streams_mut().main.flush().await?;
                    Ok::<(), shachain2pc_emp_wire::WireError>(())
                }
                .await
                .map_err(DaemonError::from);
                let result = match send_result {
                    Ok(()) => session
                        .precompute_target(index)
                        .await
                        .map_err(DaemonError::from),
                    Err(e) => Err(e),
                };
                let failed = result.is_err();
                let _ = response.send(result);
                if failed {
                    break;
                }
            }
        }
    }
}
