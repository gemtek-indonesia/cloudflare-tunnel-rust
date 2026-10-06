use std::{
    ffi::OsStr,
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    path::Path,
};

pub(crate) fn notify_ready(address: Option<&OsStr>) -> io::Result<()> {
    let Some(address) = address else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    if let Some(name) = address.as_bytes().strip_prefix(b"@") {
        socket.send_to_addr(b"READY=1", &SocketAddr::from_abstract_name(name)?)?;
    } else {
        socket.send_to(b"READY=1", Path::new(address))?;
    }
    Ok(())
}

pub(crate) fn write_pid(path: &Path) -> io::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension(format!("{}.pid.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        write!(file, "{}", std::process::id())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_notification_path_and_abstract_socket() {
        let path =
            std::env::temp_dir().join(format!("cloudflared-notify-{}", uuid::Uuid::new_v4()));
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_millis(20)))
            .unwrap();
        let mut bytes = [0; 32];
        assert!(receiver.recv(&mut bytes).is_err());
        notify_ready(Some(path.as_os_str())).unwrap();
        let n = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"READY=1");
        std::fs::remove_file(path).unwrap();
        let name = format!("cloudflared-notify-{}", uuid::Uuid::new_v4());
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        notify_ready(Some(OsStr::new(&format!("@{name}")))).unwrap();
        let n = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"READY=1");
    }
}
