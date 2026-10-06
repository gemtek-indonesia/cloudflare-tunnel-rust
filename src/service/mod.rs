use crate::{administration::credentials::atomic_create, cli::Invocation};
use anyhow::{Context, Result, bail};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    OpenRc,
    SysV,
}

impl InitSystem {
    fn detect(root: &Path) -> Self {
        if rooted(root, "/run/systemd/system").is_dir() {
            Self::Systemd
        } else if rooted(root, "/run/openrc").is_dir()
            || rooted(root, "/run/openrc/softlevel").exists()
        {
            Self::OpenRc
        } else {
            Self::SysV
        }
    }
}

pub async fn execute(invocation: Invocation) -> Result<()> {
    let root = Path::new("/");
    let init = InitSystem::detect(root);
    let mut run = |program: &str, args: &[String]| -> Result<()> {
        let status = Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("cannot run {program}"))?;
        if !status.success() {
            bail!("{program} failed with {status}");
        }
        Ok(())
    };
    match invocation.command.as_str() {
        "service install" => {
            let binary = std::env::current_exe()?;
            let token = invocation.args.first().map(String::as_str);
            if invocation.args.len() > 1 {
                bail!("service install accepts at most one tunnel token");
            }
            let args = if let Some(token) = token {
                crate::config::credentials_from_token(token)?;
                vec![
                    "tunnel".into(),
                    "run".into(),
                    "--token-file".into(),
                    "/etc/cloudflared/token".into(),
                ]
            } else {
                if invocation.configuration.tunnel.is_empty()
                    || invocation.string("credentials-file").is_empty()
                {
                    bail!("configuration must contain tunnel and credentials-file");
                }
                vec![
                    "--config".into(),
                    "/etc/cloudflared/config.yml".into(),
                    "tunnel".into(),
                    "run".into(),
                ]
            };
            install(
                root,
                init,
                &binary,
                &args,
                token,
                invocation.configuration.source.as_deref(),
                &mut run,
            )?;
            println!("Linux service for cloudflared installed successfully");
        }
        "service uninstall" => {
            uninstall(root, init, &mut run)?;
            println!("Linux service for cloudflared uninstalled successfully");
        }
        _ => bail!("unsupported service command"),
    }
    Ok(())
}

fn rooted(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}
fn quote(value: &str) -> Result<String> {
    if value.contains(['\0', '\n', '\r']) {
        bail!("service argument contains unsupported control characters");
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
fn unit_quote(value: &str) -> Result<String> {
    if value.contains(['\0', '\n', '\r']) {
        bail!("service argument contains unsupported control characters");
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

pub fn render(
    init: InitSystem,
    binary: &Path,
    args: &[String],
) -> Result<Vec<(&'static str, String, u32)>> {
    let binary = binary
        .to_str()
        .context("service executable path is not UTF-8")?;
    let mut args = args.to_vec();
    args.insert(0, "--no-autoupdate".into());
    match init {
        InitSystem::Systemd => {
            let joined = args
                .iter()
                .map(|v| unit_quote(v))
                .collect::<Result<Vec<_>>>()?
                .join(" ");
            let template = include_str!("systemd.tmpl");
            let content = template
                .replace("{{ .Path }}", &unit_quote(binary)?)
                .replace(
                    " --no-autoupdate{{ range .ExtraArgs }} {{ . }}{{ end }}",
                    &format!(" {joined}"),
                );
            Ok(vec![(
                "/etc/systemd/system/cloudflared.service",
                content,
                0o644,
            )])
        }
        InitSystem::OpenRc => {
            let joined = args
                .iter()
                .map(|v| quote(v))
                .collect::<Result<Vec<_>>>()?
                .join(" ");
            let content = include_str!("openrc.tmpl")
                .replace(
                    "command=\"{{.Path}}\"",
                    &format!("command={}", quote(binary)?),
                )
                .replace(
                    "command_args=\"{{ range .ExtraArgs }} {{ . }}{{ end }}\"",
                    &format!("command_args={}", quote(&joined)?),
                );
            Ok(vec![
                (
                    "/etc/conf.d/cloudflared",
                    include_str!("openrc-conf.tmpl").into(),
                    0o644,
                ),
                ("/etc/init.d/cloudflared", content, 0o755),
            ])
        }
        InitSystem::SysV => {
            let joined = args
                .iter()
                .map(|v| quote(v))
                .collect::<Result<Vec<_>>>()?
                .join(" ");
            let binary = quote(binary)?;
            let content = format!(
                r#"#!/bin/sh
# chkconfig: 2345 99 01
# description: Cloudflare Tunnel client
### BEGIN INIT INFO
# Provides: cloudflared
# Required-Start:
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
pid_file=/var/run/cloudflared.pid
is_running() {{ [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; }}
case "$1" in
 start) if is_running; then echo "Already started"; else {binary} --pidfile "$pid_file" {joined} >>/var/log/cloudflared.log 2>>/var/log/cloudflared.err & echo $! >"$pid_file"; fi ;;
 stop) if is_running; then kill "$(cat "$pid_file")"; n=0; while is_running && [ "$n" -lt 10 ]; do sleep 1; n=$((n+1)); done; if is_running; then echo "Not stopped; may still be shutting down"; exit 1; fi; rm -f "$pid_file"; fi ;;
 restart) "$0" stop && "$0" start ;;
 status) if is_running; then echo Running; else echo Stopped; exit 1; fi ;;
 *) echo "Usage: $0 {{start|stop|restart|status}}"; exit 1 ;;
esac
"#
            );
            Ok(vec![("/etc/init.d/cloudflared", content, 0o755)])
        }
    }
}

pub fn install(
    root: &Path,
    init: InitSystem,
    binary: &Path,
    args: &[String],
    token: Option<&str>,
    source: Option<&Path>,
    run: &mut impl FnMut(&str, &[String]) -> Result<()>,
) -> Result<()> {
    let templates = render(init, binary, args)?;
    for (path, _, _) in &templates {
        if fs::symlink_metadata(rooted(root, path)).is_ok() {
            bail!(
                "cloudflared service is already installed; run cloudflared service uninstall first"
            );
        }
    }
    let config_dir = rooted(root, "/etc/cloudflared");
    if !config_dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&config_dir)?;
    }
    let mut created = Vec::new();
    let enabled_path = match init {
        InitSystem::Systemd => Some(rooted(
            root,
            "/etc/systemd/system/multi-user.target.wants/cloudflared.service",
        )),
        InitSystem::OpenRc => Some(rooted(root, "/etc/runlevels/default/cloudflared")),
        InitSystem::SysV => None,
    };
    let already_enabled = if let Some(path) = &enabled_path {
        match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).context("cannot inspect existing service enablement"),
        }
    } else {
        false
    };
    let mut enabled_here = false;
    let result = (|| -> Result<()> {
        if let Some(token) = token {
            let path = config_dir.join("token");
            atomic_create(&path, token.as_bytes(), 0o600)?;
            created.push(path);
        } else {
            let source = source.context("no configuration file found")?;
            let dest = config_dir.join("config.yml");
            if source != dest {
                atomic_create(&dest, &fs::read(source)?, 0o600)?;
                created.push(dest);
            }
        }
        for (path, body, mode) in &templates {
            let path = rooted(root, path);
            fs::create_dir_all(path.parent().unwrap())?;
            atomic_create(&path, body.as_bytes(), *mode)?;
            created.push(path);
        }
        match init {
            InitSystem::Systemd => {
                if !already_enabled {
                    run(
                        "systemctl",
                        &["enable".into(), "cloudflared.service".into()],
                    )?;
                    enabled_here = true;
                }
                run("systemctl", &["daemon-reload".into()])?;
                run("systemctl", &["start".into(), "cloudflared.service".into()])?;
            }
            InitSystem::OpenRc => {
                if !already_enabled {
                    run(
                        "rc-update",
                        &["add".into(), "cloudflared".into(), "default".into()],
                    )?;
                    enabled_here = true;
                }
                run("rc-service", &["cloudflared".into(), "start".into()])?;
            }
            InitSystem::SysV => {
                for level in [0, 1, 2, 3, 4, 5, 6] {
                    let dir = rooted(root, &format!("/etc/rc{level}.d"));
                    if dir.is_dir() {
                        let link = dir.join(if [0, 1, 6].contains(&level) {
                            "K02et"
                        } else {
                            "S50et"
                        });
                        if symlink("/etc/init.d/cloudflared", &link).is_ok() {
                            created.push(link);
                        }
                    }
                }
                run("service", &["cloudflared".into(), "start".into()])?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        if enabled_here {
            let reversal = match init {
                InitSystem::Systemd => run(
                    "systemctl",
                    &["disable".into(), "cloudflared.service".into()],
                ),
                InitSystem::OpenRc => run(
                    "rc-update",
                    &["del".into(), "cloudflared".into(), "default".into()],
                ),
                InitSystem::SysV => Ok(()),
            };
            if let Err(error) = reversal {
                cleanup_errors.push(format!("could not reverse new service enablement: {error}"));
            }
        }
        for path in created.into_iter().rev() {
            if let Err(error) = fs::remove_file(path) {
                cleanup_errors.push(format!("could not remove created service file: {error}"));
            }
        }
        if init == InitSystem::Systemd
            && enabled_here
            && let Err(error) = run("systemctl", &["daemon-reload".into()])
        {
            cleanup_errors.push(format!(
                "could not reload service manager after cleanup: {error}"
            ));
        }
        if cleanup_errors.is_empty() {
            return Err(error);
        }
        bail!(
            "{error}; rollback incomplete: {}",
            cleanup_errors.join("; ")
        );
    }
    Ok(())
}

pub fn uninstall(
    root: &Path,
    init: InitSystem,
    run: &mut impl FnMut(&str, &[String]) -> Result<()>,
) -> Result<()> {
    match init {
        InitSystem::Systemd => {
            let service = rooted(root, "/etc/systemd/system/cloudflared.service");
            if service.exists() {
                run(
                    "systemctl",
                    &["disable".into(), "cloudflared.service".into()],
                )?;
                run("systemctl", &["stop".into(), "cloudflared.service".into()])?;
                fs::remove_file(service)?;
            }
            for unit in ["cloudflared-update.timer", "cloudflared-update.service"] {
                let path = rooted(root, &format!("/etc/systemd/system/{unit}"));
                if path.exists() {
                    if unit.ends_with("timer") {
                        run("systemctl", &["stop".into(), unit.into()])?;
                    }
                    fs::remove_file(path)?;
                }
            }
            run("systemctl", &["daemon-reload".into()])?;
        }
        InitSystem::OpenRc => {
            let _ = run("rc-service", &["cloudflared".into(), "stop".into()]);
            let _ = run(
                "rc-update",
                &["del".into(), "cloudflared".into(), "default".into()],
            );
            for path in ["/etc/init.d/cloudflared", "/etc/conf.d/cloudflared"] {
                let path = rooted(root, path);
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
        }
        InitSystem::SysV => {
            run("service", &["cloudflared".into(), "stop".into()])?;
            fs::remove_file(rooted(root, "/etc/init.d/cloudflared"))?;
            for level in [0, 1, 2, 3, 4, 5, 6] {
                let path = rooted(
                    root,
                    &format!(
                        "/etc/rc{level}.d/{}",
                        if [0, 1, 6].contains(&level) {
                            "K02et"
                        } else {
                            "S50et"
                        }
                    ),
                );
                if fs::symlink_metadata(&path).is_ok() {
                    fs::remove_file(path)?;
                }
            }
        }
    }
    let token = rooted(root, "/etc/cloudflared/token");
    if token.exists() {
        fs::remove_file(token)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn service_files_commands_no_secret_in_unit_and_rollback() {
        for init in [InitSystem::Systemd, InitSystem::OpenRc, InitSystem::SysV] {
            let dir = std::env::temp_dir()
                .join(format!("cloudflared-service-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&dir).unwrap();
            let args = vec![
                "tunnel".into(),
                "run".into(),
                "--token-file".into(),
                "/etc/cloudflared/token".into(),
            ];
            let mut commands = Vec::new();
            let mut run = |cmd: &str, args: &[String]| {
                commands.push((cmd.to_owned(), args.to_vec()));
                Ok(())
            };
            install(
                &dir,
                init,
                Path::new("/usr/bin/cloudflared"),
                &args,
                Some("synthetic-token"),
                None,
                &mut run,
            )
            .unwrap();
            let token = rooted(&dir, "/etc/cloudflared/token");
            assert_eq!(
                fs::metadata(&token).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let unit = if init == InitSystem::Systemd {
                "/etc/systemd/system/cloudflared.service"
            } else {
                "/etc/init.d/cloudflared"
            };
            assert!(
                !fs::read_to_string(rooted(&dir, unit))
                    .unwrap()
                    .contains("synthetic-token")
            );
            assert!(
                install(
                    &dir,
                    init,
                    Path::new("/usr/bin/cloudflared"),
                    &args,
                    Some("replacement"),
                    None,
                    &mut run
                )
                .is_err()
            );
            assert_eq!(fs::read(&token).unwrap(), b"synthetic-token");
            uninstall(&dir, init, &mut run).unwrap();
            assert!(!token.exists());
            assert!(!rooted(&dir, unit).exists());
            let mut fail = |_: &str, _: &[String]| bail!("synthetic executor failure");
            assert!(
                install(
                    &dir,
                    init,
                    Path::new("/usr/bin/cloudflared"),
                    &args,
                    Some("synthetic-token"),
                    None,
                    &mut fail
                )
                .is_err()
            );
            assert!(!token.exists());
            assert!(!rooted(&dir, unit).exists());
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn openrc_paths_and_args_are_shell_literals() {
        let dir =
            std::env::temp_dir().join(format!("cloudflared-openrc-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("must-not-exist");
        let binary = format!(
            "/usr/bin/program `touch {}` $(touch {}) ' \" space",
            marker.display(),
            marker.display()
        );
        let arg = format!(
            "`touch {}` $(touch {}) ' \" space",
            marker.display(),
            marker.display()
        );
        let templates = render(
            InitSystem::OpenRc,
            Path::new(&binary),
            std::slice::from_ref(&arg),
        )
        .unwrap();
        let path = dir.join("service.sh");
        fs::write(&path, &templates[1].1).unwrap();
        let output = Command::new("sh")
            .args([
                "-c",
                ". \"$1\"; printf '%s\\n' \"$command\" \"$command_args\"",
                "test",
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(!marker.exists());
        let output = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.lines().next(), Some(binary.as_str()));
        assert!(output.contains("$(touch"));
        for invalid in ["/usr/bin/a\nb", "/usr/bin/a\0b"] {
            assert!(render(InitSystem::OpenRc, Path::new(invalid), &[]).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollback_preserves_old_enablement_and_reports_reversal_failure() {
        for init in [InitSystem::Systemd, InitSystem::OpenRc] {
            for (preexisting, reversal_fails) in [(false, false), (true, false), (false, true)] {
                let dir = std::env::temp_dir().join(format!(
                    "cloudflared-rollback-test-{}",
                    uuid::Uuid::new_v4()
                ));
                fs::create_dir(&dir).unwrap();
                let link = rooted(
                    &dir,
                    if init == InitSystem::Systemd {
                        "/etc/systemd/system/multi-user.target.wants/cloudflared.service"
                    } else {
                        "/etc/runlevels/default/cloudflared"
                    },
                );
                if preexisting {
                    fs::create_dir_all(link.parent().unwrap()).unwrap();
                    symlink("/existing/service", &link).unwrap();
                }
                let mut commands = Vec::new();
                let mut run = |program: &str, args: &[String]| {
                    commands.push(format!("{program} {}", args.join(" ")));
                    if args.iter().any(|arg| arg == "start") {
                        bail!("synthetic start failure");
                    }
                    if reversal_fails && args.iter().any(|arg| arg == "disable" || arg == "del") {
                        bail!("synthetic reversal failure");
                    }
                    Ok(())
                };
                let error = install(
                    &dir,
                    init,
                    Path::new("/usr/bin/cloudflared"),
                    &[],
                    Some("synthetic-token"),
                    None,
                    &mut run,
                )
                .unwrap_err()
                .to_string();
                let inverse = if init == InitSystem::Systemd {
                    "systemctl disable cloudflared.service"
                } else {
                    "rc-update del cloudflared default"
                };
                assert_eq!(
                    commands.iter().any(|command| command == inverse),
                    !preexisting
                );
                assert_eq!(error.contains("rollback incomplete"), reversal_fails);
                if preexisting {
                    assert_eq!(
                        fs::read_link(&link).unwrap(),
                        Path::new("/existing/service")
                    );
                }
                assert!(!rooted(&dir, "/etc/cloudflared/token").exists());
                fs::remove_dir_all(dir).unwrap();
            }
        }
    }
}
