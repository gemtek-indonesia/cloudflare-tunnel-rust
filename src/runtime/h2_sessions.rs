use super::*;

enum Phase {
    Registering,
    Admitted(Box<RegisteredConnection>),
    Finishing,
    Finished,
}

struct Attempt {
    scope: CancellationToken,
    phase: Phase,
    io_ended: Option<h2_control::Completion>,
    finish: Option<oneshot::Sender<()>>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.scope.cancel();
    }
}

pub(super) enum Completion {
    Registration(
        u32,
        std::result::Result<RegisteredConnection, RegistrationError>,
    ),
    Io(
        u32,
        std::result::Result<std::io::Result<h2_control::Completion>, tokio::task::JoinError>,
    ),
    Unregister(u32, std::result::Result<(), RegistrationError>),
}

pub(super) struct Controls {
    attempts: HashMap<u32, Attempt>,
    completions: JoinSet<Completion>,
    lease: Option<Lease>,
    last_error: Option<anyhow::Error>,
    address: SocketAddr,
    retries: u32,
}
impl Controls {
    pub(super) fn new(address: SocketAddr, retries: u32) -> Self {
        Self {
            attempts: HashMap::new(),
            completions: JoinSet::new(),
            lease: None,
            last_error: None,
            address,
            retries,
        }
    }

    pub(super) fn start(
        &mut self,
        runtime: &Arc<Runtime>,
        pending: &scope::PendingSessionContext,
        local_address: SocketAddr,
        receive: h2::RecvStream,
        send: h2::SendStream<Bytes>,
    ) {
        let id = receive.stream_id().as_u32();
        let (control, pump, finish) = h2_control::registration_bridge(receive, send);
        self.attempts.insert(
            id,
            Attempt {
                scope: pending.cancellation().child_token(),
                phase: Phase::Registering,
                io_ended: None,
                finish: Some(finish),
            },
        );
        let request = runtime.request(
            pending.index(),
            local_address,
            self.retries,
            pending.snapshot(),
        );
        let timeout = runtime.config.rpc_timeout;
        let metrics = runtime.context.metrics.clone();
        self.completions.spawn_local(async move {
            Completion::Registration(
                id,
                registration::register_connection(control, request, timeout, metrics).await,
            )
        });
        self.completions.spawn_local(async move {
            let mut pump = AbortTask(pump);
            Completion::Io(id, (&mut pump.0).await)
        });
    }

    fn unregister(&mut self, id: u32, grace: Duration) {
        let attempt = self.attempts.get_mut(&id).unwrap();
        if let Phase::Admitted(registered) = std::mem::replace(&mut attempt.phase, Phase::Finishing)
        {
            attempt.scope.cancel();
            let finish = attempt.finish.take();
            self.completions.spawn_local(async move {
                let result = (*registered).unregister(grace).await;
                if let Some(finish) = finish {
                    let _ = finish.send(());
                }
                Completion::Unregister(id, result)
            });
        }
    }

    pub(super) async fn complete(
        &mut self,
        completion: Completion,
        runtime: &Arc<Runtime>,
        pending: &scope::PendingSessionContext,
        tasks: &mut JoinSet<Result<()>>,
        reset_after: &mut Option<Instant>,
    ) -> Result<()> {
        let id = match &completion {
            Completion::Registration(id, _)
            | Completion::Io(id, _)
            | Completion::Unregister(id, _) => *id,
        };
        let Some(attempt) = self.attempts.get_mut(&id) else {
            return Ok(());
        };
        match completion {
            Completion::Registration(_, Ok(registered)) => {
                if !matches!(attempt.phase, Phase::Registering) {
                    return Ok(());
                }
                self.lease = Some(
                    runtime
                        .registered(
                            pending.index(),
                            EdgeProtocol::Http2,
                            self.address,
                            &registered,
                            pending,
                            SessionLiveness::Http2 {
                                control: attempt.scope.clone(),
                            },
                        )
                        .await?,
                );
                push_local_configuration(runtime, pending.index(), &registered, tasks).await?;
                attempt.phase = Phase::Admitted(Box::new(registered));
                *reset_after =
                    Some(Instant::now() + Duration::from_secs(4 * (1u64 << self.retries.min(31))));
                if matches!(attempt.io_ended, Some(h2_control::Completion::Reset)) {
                    self.lease = None;
                    self.unregister(id, runtime.config.grace_period);
                }
            }
            Completion::Registration(_, Err(error)) => {
                if !matches!(attempt.phase, Phase::Registering) {
                    return Ok(());
                }
                self.last_error = Some(runtime.registration_failure(error).into());
                attempt.phase = Phase::Finished;
                attempt.scope.cancel();
                if let Some(finish) = attempt.finish.take() {
                    let _ = finish.send(());
                }
            }
            Completion::Io(_, outcome) => {
                let end = match outcome {
                    Ok(Ok(end)) => end,
                    Ok(Err(error)) => {
                        if error
                            .get_ref()
                            .and_then(|cause| cause.downcast_ref::<h2::Error>())
                            .is_some_and(h2::Error::is_reset)
                        {
                            h2_control::Completion::Reset
                        } else {
                            runtime.warn(&format!("H2 control stream: {error}"));
                            h2_control::Completion::End
                        }
                    }
                    Err(error) => {
                        runtime.warn(&format!("H2 control task: {error}"));
                        h2_control::Completion::End
                    }
                };
                let reset = matches!(end, h2_control::Completion::Reset);
                attempt.io_ended = Some(end);
                if reset {
                    attempt.scope.cancel();
                    if matches!(attempt.phase, Phase::Admitted(_)) {
                        self.lease = None;
                        self.unregister(id, runtime.config.grace_period);
                    }
                }
            }
            Completion::Unregister(_, result) => {
                if !matches!(attempt.phase, Phase::Finishing) {
                    return Ok(());
                }
                if let Err(error) = result {
                    self.last_error = Some(
                        anyhow::Error::new(error).context("Error shutting down control stream"),
                    );
                }
                attempt.phase = Phase::Finished;
            }
        }
        if self.attempts.get(&id).is_some_and(|attempt| {
            matches!(attempt.phase, Phase::Finished) && attempt.io_ended.is_some()
        }) {
            self.attempts.remove(&id);
        }
        Ok(())
    }

    pub(super) fn has_completions(&self) -> bool {
        !self.completions.is_empty()
    }

    pub(super) async fn next(
        &mut self,
    ) -> Option<std::result::Result<Completion, tokio::task::JoinError>> {
        self.completions.join_next().await
    }

    pub(super) async fn closed(
        &mut self,
        runtime: &Arc<Runtime>,
        pending: &scope::PendingSessionContext,
        tasks: &mut JoinSet<Result<()>>,
        reset_after: &mut Option<Instant>,
        transport_error: anyhow::Error,
    ) -> Result<()> {
        pending.cancellation().cancel();
        while let Some(completion) = self.completions.try_join_next() {
            self.complete(completion?, runtime, pending, tasks, reset_after)
                .await?;
        }
        Err(self.last_error.take().unwrap_or(transport_error))
    }

    pub(super) fn start_shutdown(&mut self, grace: Duration) {
        self.lease = None;
        let admitted = self
            .attempts
            .iter()
            .filter_map(|(id, attempt)| matches!(attempt.phase, Phase::Admitted(_)).then_some(*id))
            .collect::<Vec<_>>();
        for id in admitted {
            self.unregister(id, grace);
        }
    }
}
