use anyhow::{Context, Result};
use cloudflare_tunnel_rust::{config::RunConfig, runtime};
use std::{future::Future, io, mem::MaybeUninit, ptr};
use tokio_util::sync::CancellationToken;

struct OriginalSignals {
    interrupt: libc::sigaction,
    terminate: libc::sigaction,
}
impl OriginalSignals {
    fn capture() -> io::Result<Self> {
        fn action(signal: libc::c_int) -> io::Result<libc::sigaction> {
            let mut action = MaybeUninit::zeroed();
            // Query the current disposition without installing a handler.
            if unsafe { libc::sigaction(signal, ptr::null(), action.as_mut_ptr()) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { action.assume_init() })
        }
        Ok(Self {
            interrupt: action(libc::SIGINT)?,
            terminate: action(libc::SIGTERM)?,
        })
    }
    fn restore(&self) -> io::Result<()> {
        let mut error = None;
        for (signal, action) in [
            (libc::SIGINT, &self.interrupt),
            (libc::SIGTERM, &self.terminate),
        ] {
            // Restore only the two dispositions captured before this CLI installs handlers.
            if unsafe { libc::sigaction(signal, action, ptr::null_mut()) } == -1 {
                error = Some(io::Error::last_os_error());
            }
        }
        error.map_or(Ok(()), Err)
    }
}

pub(crate) async fn run(config: RunConfig) -> Result<()> {
    let shutdown = CancellationToken::new();
    let force = CancellationToken::new();
    with_signals(
        runtime::run_controlled(config, shutdown.clone(), force),
        shutdown,
    )
    .await
}

async fn with_signals(
    connector: impl Future<Output = Result<()>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let original = OriginalSignals::capture().context("capture tunnel signal dispositions")?;
    let handlers = (|| {
        let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok::<_, io::Error>((interrupt, terminate))
    })();
    let (mut interrupt, mut terminate) = match handlers {
        Ok(handlers) => handlers,
        Err(error) => {
            original
                .restore()
                .context("restore tunnel signal dispositions after setup failure")?;
            return Err(error).context("install tunnel signal handlers");
        }
    };
    tokio::pin!(connector);
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {},
        _ = interrupt.recv() => {},
        _ = terminate.recv() => {},
        result = &mut connector => {
            original.restore().context("restore tunnel signal dispositions")?;
            return result;
        }
    };
    original
        .restore()
        .context("restore tunnel signal dispositions")?;
    drop(interrupt);
    drop(terminate);
    shutdown.cancel();
    connector.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::process::ExitStatusExt, process::Stdio, time::Duration};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "current_thread")]
    async fn signal_child() {
        let Ok(mode) = std::env::var("CLOUDFLARED_SIGNAL_FIXTURE") else {
            return;
        };
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let original = OriginalSignals::capture().unwrap();
        with_signals(
            async move {
                println!("signal_fixture_armed");
                std::io::stdout().flush().unwrap();
                if mode == "programmatic" {
                    let cancel = stop.clone();
                    tokio::spawn(async move { cancel.cancel() });
                }
                stop.cancelled().await;
                let restored = OriginalSignals::capture().unwrap();
                for (expected, actual) in [
                    (&original.interrupt, &restored.interrupt),
                    (&original.terminate, &restored.terminate),
                ] {
                    assert_eq!(actual.sa_sigaction, expected.sa_sigaction);
                    // libc may add its internal restorer; compare all public disposition flags.
                    let flags = libc::SA_NOCLDSTOP
                        | libc::SA_NOCLDWAIT
                        | libc::SA_SIGINFO
                        | libc::SA_ONSTACK
                        | libc::SA_RESTART
                        | libc::SA_NODEFER
                        | libc::SA_RESETHAND;
                    assert_eq!(actual.sa_flags & flags, expected.sa_flags & flags);
                    for signal in 1..=64 {
                        assert_eq!(
                            unsafe { libc::sigismember(&actual.sa_mask, signal) },
                            unsafe { libc::sigismember(&expected.sa_mask, signal) },
                        );
                    }
                }
                println!("signal_fixture_restored");
                std::io::stdout().flush().unwrap();
                let mut input = tokio::io::BufReader::new(tokio::io::stdin());
                let mut line = String::new();
                loop {
                    if input.read_line(&mut line).await.unwrap() == 0 {
                        return Ok(());
                    };
                    println!("signal_fixture_alive");
                    std::io::stdout().flush().unwrap();
                    line.clear();
                }
            },
            shutdown,
        )
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn original_signal_dispositions_are_restored_in_disposable_children() {
        for (programmatic, ignored, signal) in [
            (false, false, libc::SIGINT),
            (false, false, libc::SIGTERM),
            (true, false, libc::SIGTERM),
            (false, true, libc::SIGINT),
            (true, true, libc::SIGINT),
        ] {
            let binary = std::env::current_exe().unwrap();
            let mut command = if ignored {
                let mut command = tokio::process::Command::new("/bin/sh");
                command
                    .args([
                        "-c",
                        "trap '' INT; exec \"$0\" --exact tunnel_runner::tests::signal_child --nocapture",
                    ])
                    .arg(binary);
                command
            } else {
                let mut command = tokio::process::Command::new(binary);
                command.args([
                    "--exact",
                    "tunnel_runner::tests::signal_child",
                    "--nocapture",
                ]);
                command
            };
            command
                .env(
                    "CLOUDFLARED_SIGNAL_FIXTURE",
                    if programmatic {
                        "programmatic"
                    } else {
                        "signal"
                    },
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true);
            let mut child = command.spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
            async fn read_until(
                output: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
                expected: &str,
            ) {
                let mut line = String::new();
                loop {
                    line.clear();
                    assert_ne!(
                        output.read_line(&mut line).await.unwrap(),
                        0,
                        "child exited before lifecycle marker"
                    );
                    if line.trim() == expected {
                        return;
                    }
                }
            }
            let outcome = tokio::time::timeout(Duration::from_secs(5), async {
                read_until(&mut output, "signal_fixture_armed").await;
                if !programmatic {
                    assert_eq!(
                        unsafe { libc::kill(child.id().unwrap() as libc::pid_t, signal) },
                        0
                    );
                }
                read_until(&mut output, "signal_fixture_restored").await;
                if ignored {
                    assert_eq!(
                        unsafe { libc::kill(child.id().unwrap() as libc::pid_t, libc::SIGINT) },
                        0
                    );
                    input.write_all(b"prove alive\n").await.unwrap();
                    input.flush().await.unwrap();
                    read_until(&mut output, "signal_fixture_alive").await;
                }
                let terminate = if ignored { libc::SIGTERM } else { signal };
                assert_eq!(
                    unsafe { libc::kill(child.id().unwrap() as libc::pid_t, terminate) },
                    0
                );
                let status = child.wait().await.unwrap();
                assert_eq!(
                    status.signal(),
                    Some(terminate),
                    "must terminate by restored kernel signal action, not exit-code imitation"
                );
            })
            .await;
            if outcome.is_err() {
                child.kill().await.unwrap();
                child.wait().await.unwrap();
                panic!("owned signal child did not complete within its lifecycle deadline");
            }
        }
    }
}
