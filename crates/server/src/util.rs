use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use serde::Serialize;

// Linux flags used for descriptor-relative, no-follow ownership changes and writes. Keep
// these local instead of adding a dependency just for the setup/CLI syscall ABI.
// O_NOFOLLOW differs between architectures: 0o400000 on x86 and riscv64
// (asm-generic), 0o100000 on aarch64 (where 0o400000 means O_LARGEFILE).
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64"))]
pub(crate) const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW: i32 = 0o100000;
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64"))]
pub(crate) const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_DIRECTORY: i32 = 0o40000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64", target_arch = "aarch64")))]
compile_error!("tunnel-server: add this architecture's O_NOFOLLOW and O_DIRECTORY values");
pub(crate) const O_CLOEXEC: i32 = 0x80000;
const O_PATH: i32 = 0x200000;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Response/request body used throughout the server.
pub type Body = http_body_util::combinators::BoxBody<Bytes, BoxError>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub fn incoming(body: Incoming) -> Body {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

pub fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(body))
        .expect("valid response")
}

pub fn text_response(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(text))
        .expect("valid response")
}

/// Lowercased request host without port, from `Host` (HTTP/1.1) or the URI
/// authority (HTTP/2).
pub fn request_host<B>(req: &Request<B>) -> Option<String> {
    let raw = req
        .uri()
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).map(|s| s.to_string()))?;
    Some(strip_port(&raw).to_ascii_lowercase())
}

pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|i| &host[..=i]).unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

pub fn header_str(value: Option<&HeaderValue>) -> Option<&str> {
    value.and_then(|v| v.to_str().ok())
}

/// Atomically write `content` with `mode` if it differs from what is on disk.
/// Returns `true` when the file was (re)written.
pub fn write_if_changed(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<bool> {
    if let Ok(existing) = std::fs::read(path)
        && existing == content
    {
        crate::config::set_mode(path, mode)?;
        return Ok(false);
    }
    write_atomic(path, content, mode)?;
    Ok(true)
}

/// Write to `<path>.tmp` with `mode`, fsync, then rename over `path`.
/// The temp file is created fresh with `mode` from the start (some targets,
/// like the config, hold secrets in directories others may traverse), and
/// a leftover or pre-planted file or symlink at that name is never reused.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        // `mode` above is filtered by the umask; set it exactly.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Atomically replace a basename inside an already opened directory. Every
/// operation stays relative to that descriptor, even if the directory is moved.
pub(crate) fn write_atomic_in_dir(dir: &std::fs::File, name: &str, content: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        fn renameat(
            olddirfd: i32,
            oldpath: *const std::ffi::c_char,
            newdirfd: i32,
            newpath: *const std::ffi::c_char,
        ) -> i32;
        fn unlinkat(dirfd: i32, path: *const std::ffi::c_char, flags: i32) -> i32;
    }
    anyhow::ensure!(!name.is_empty() && !name.contains('/') && name != "." && name != "..", "expected a basename");
    let target = CString::new(name)?;
    // Independent writers must never remove or reuse each other's temp files.
    let tmp = CString::new(format!(".{name}.{:016x}.tmp", rand::random::<u64>()))?;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    const O_WRONLY: i32 = 1;
    // SAFETY: live directory fd and NUL-terminated basename. O_EXCL creates a
    // new inode; O_NOFOLLOW prevents following a pre-planted symlink.
    let fd =
        unsafe { openat(dir.as_raw_fd(), tmp.as_ptr(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| -> anyhow::Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(content)?;
        file.sync_all()?;
        // SAFETY: both basenames are NUL-terminated and the directory fd is live.
        if unsafe { renameat(dir.as_raw_fd(), tmp.as_ptr(), dir.as_raw_fd(), target.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dir.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // SAFETY: remove only our temporary basename relative to the pinned fd.
        let _ = unsafe { unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
    }
    result
}

/// Reject unsafe data paths before setup or privileged CLI work. System installs
/// deliberately support ONLY the default data directory: a config file cannot
/// authorize root to change ownership of a different tree. All existing path
/// components must be real directories; system parents must be root-owned and
/// not writable by another account. Rootless installs may use a dedicated path.
pub fn check_data_dir(path: &Path, privileged: bool) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let raw = path.as_os_str().as_bytes();
    anyhow::ensure!(path.is_absolute(), "data_dir must be absolute");
    anyhow::ensure!(
        raw[1..].split(|b| *b == b'/').all(|p| !p.is_empty() && p != b"." && p != b".."),
        "data_dir must be normalized, without empty, . or .. components"
    );
    let system_dirs = [
        "/",
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/var/lib",
        "/var/log",
        "/var/cache",
        "/var/tmp",
        "/home",
        "/root",
        "/run",
        "/tmp",
        "/opt",
        "/srv",
        "/mnt",
        "/media",
        "/lost+found",
    ];
    anyhow::ensure!(!system_dirs.iter().any(|p| path == Path::new(p)), "data_dir cannot be a system directory");
    for forbidden in
        ["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/dev", "/proc", "/sys"]
    {
        anyhow::ensure!(!path.starts_with(forbidden), "data_dir cannot be inside {forbidden}");
    }
    if privileged {
        anyhow::ensure!(
            path == Path::new(crate::config::DEFAULT_DATA_DIR),
            "root installs require data_dir = {}",
            crate::config::DEFAULT_DATA_DIR
        );
    }
    for component in path.ancestors() {
        match std::fs::symlink_metadata(component) {
            Ok(meta) => {
                anyhow::ensure!(
                    !meta.file_type().is_symlink() && meta.is_dir(),
                    "data_dir component {} must be a directory, not a symlink",
                    component.display()
                );
                if privileged && component != path {
                    anyhow::ensure!(
                        meta.uid() == 0 && meta.mode() & 0o022 == 0,
                        "data_dir parent {} must be root-owned and not group/world writable",
                        component.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn account_id(owner: &str, flag: &str) -> anyhow::Result<u32> {
    let out = std::process::Command::new("id").args([flag, "--", owner]).output()?;
    anyhow::ensure!(out.status.success(), "could not resolve service account {owner}");
    Ok(std::str::from_utf8(&out.stdout)?.trim().parse()?)
}

/// Resolve the named group itself, rather than assuming it is the account's
/// primary group (an existing service account can have a different primary gid).
fn group_id(group: &str) -> anyhow::Result<u32> {
    let out = std::process::Command::new("getent").args(["group", group]).output()?;
    anyhow::ensure!(out.status.success(), "could not resolve service group {group}");
    let record = std::str::from_utf8(&out.stdout)?;
    let gid = record.split(':').nth(2).ok_or_else(|| anyhow::anyhow!("invalid service group record"))?;
    Ok(gid.parse()?)
}

/// Restore the system config's root:service ownership after an atomic write.
/// The containing directory is root:service 0750, so the service cannot replace
/// either the config or its directory entry. Never operate through a symlink.
pub fn secure_system_config(path: &Path) -> anyhow::Result<()> {
    check_system_config_dir(path)?;
    let file = std::fs::OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)?; // O_NOFOLLOW
    anyhow::ensure!(file.metadata()?.is_file(), "config must be a regular file");
    set_owner_fd(&file, 0, group_id(crate::config::SERVICE_USER)?)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    Ok(())
}

/// Check before creating/replacing a system config, not only after writing it.
/// Missing directories may be created by root; existing parents must be trusted.
pub fn check_system_config_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(path.is_absolute(), "system config path must be absolute");
    anyhow::ensure!(
        !path.components().any(|c| c == std::path::Component::ParentDir),
        "system config path must not contain .."
    );
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("config has no parent"))?;
    for component in parent.ancestors() {
        let meta = match std::fs::symlink_metadata(component) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "config directory must not contain symlinks");
        anyhow::ensure!(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "config directory {} must be root-owned and not group/world writable",
            component.display()
        );
    }
    Ok(())
}

/// No pathname is resolved again after it is opened. O_PATH | O_NOFOLLOW pins
/// even a symlink itself, and fchownat(AT_EMPTY_PATH) changes that pinned inode.
/// Linux is required by the setup/systemd code already.
fn set_owner_fd(file: &std::fs::File, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn fchownat(dirfd: i32, path: *const std::ffi::c_char, owner: u32, group: u32, flags: i32) -> i32;
    }
    // SAFETY: the file descriptor is live; c"" is NUL-terminated. Linux flags
    // AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW operate on the descriptor itself.
    let result = unsafe { fchownat(file.as_raw_fd(), c"".as_ptr(), uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Recursively restore service ownership, without following symlinks or crossing
/// filesystems. The guard is inside the entry point so no privileged caller can
/// forget it. Directory descriptors prevent rename/symlink races during descent.
pub fn chown_recursive(path: &Path, owner: &str) -> anyhow::Result<()> {
    check_data_dir(path, crate::mode::uid() == 0)?;
    chown_tree_ids(path, account_id(owner, "-u")?, group_id(owner)?)
}

fn chown_tree_ids(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    }
    fn visit(file: std::fs::File, dev: u64, uid: u32, gid: u32) -> anyhow::Result<()> {
        let meta = file.metadata()?;
        if meta.dev() != dev {
            return Ok(());
        }
        // A hard-linked regular file could also live outside the data tree.
        anyhow::ensure!(!meta.is_file() || meta.nlink() == 1, "refusing to chown a hard-linked data file");
        if meta.is_dir() {
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))? {
                let name = std::ffi::CString::new(entry?.file_name().as_bytes())?;
                // SAFETY: live parent fd and NUL-terminated child basename;
                // O_PATH | O_NOFOLLOW | O_CLOEXEC opens no devices and follows no links.
                let fd = unsafe { openat(file.as_raw_fd(), name.as_ptr(), O_PATH | O_NOFOLLOW | O_CLOEXEC) };
                if fd < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::NotFound {
                        continue;
                    }
                    return Err(e.into());
                }
                // SAFETY: openat returned a new owned descriptor.
                visit(unsafe { std::fs::File::from_raw_fd(fd) }, dev, uid, gid)?;
            }
        }
        set_owner_fd(&file, uid, gid)?;
        Ok(())
    }
    let file = std::fs::OpenOptions::new().read(true).custom_flags(O_PATH | O_NOFOLLOW | O_CLOEXEC).open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.is_dir(), "data_dir must be a directory, not a symlink");
    visit(file, meta.dev(), uid, gid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::symlink;

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tunnel-util-{name}-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn data_dir_guard_rejects_system_relative_and_non_normal_paths() {
        for path in [
            "/",
            "/etc",
            "/etc/tunnel-server",
            "relative/tunnel",
            "/var/lib/../tunnel",
            "/var/lib/./tunnel",
            "/var//lib/tunnel",
            "/var/lib",
            "/home",
            "/tmp",
            "/proc/self",
        ] {
            assert!(check_data_dir(Path::new(path), false).is_err(), "accepted {path}");
        }
        #[cfg(target_os = "linux")]
        check_data_dir(Path::new(crate::config::DEFAULT_DATA_DIR), true).unwrap();
        assert!(check_data_dir(Path::new("/var/lib/other-tunnel"), true).is_err());
    }

    #[test]
    fn o_nofollow_matches_this_architecture() {
        let dir = test_dir("o-nofollow");
        let target = dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("link");
        symlink(&target, &link).unwrap();
        // Opening a symlink with O_NOFOLLOW fails with ELOOP; a wrong constant follows it.
        let err = std::fs::OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40), "ELOOP expected, got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn o_directory_matches_this_architecture() {
        let dir = test_dir("o-directory");
        std::fs::write(dir.join("file"), b"x").unwrap();
        assert!(std::fs::OpenOptions::new().read(true).custom_flags(O_DIRECTORY).open(&dir).is_ok());
        let err = std::fs::OpenOptions::new().read(true).custom_flags(O_DIRECTORY).open(dir.join("file")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(20), "ENOTDIR expected, got {err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_atomic_in_dir_stays_in_opened_directory_and_replaces_symlinks() {
        let dir = test_dir("atomic-dir");
        let certs = dir.join("certs");
        let moved = dir.join("moved");
        let outside = dir.join("outside");
        std::fs::create_dir(&certs).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"untouched").unwrap();
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            .open(&certs)
            .unwrap();
        symlink(outside.join("keep"), certs.join("key.pem")).unwrap();
        std::fs::rename(&certs, &moved).unwrap();
        symlink(&outside, &certs).unwrap();
        write_atomic_in_dir(&opened, "key.pem", b"new key", 0o640).unwrap();
        assert_eq!(std::fs::read(moved.join("key.pem")).unwrap(), b"new key");
        assert_eq!(std::fs::metadata(moved.join("key.pem")).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"untouched");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
        for name in ["", ".", "..", "../keep", "/keep", "nul\0name"] {
            assert!(write_atomic_in_dir(&opened, name, b"invalid", 0o600).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn data_dir_guard_rejects_symlink_and_symlinked_ancestor() {
        let dir = test_dir("guard");
        std::fs::create_dir(dir.join("real")).unwrap();
        symlink(dir.join("real"), dir.join("link")).unwrap();
        assert!(check_data_dir(&dir.join("link"), false).is_err());
        assert!(check_data_dir(&dir.join("link/child"), false).is_err());
        check_data_dir(&dir.join("real"), false).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn chown_tree_does_not_follow_file_directory_or_dangling_symlinks() {
        let dir = test_dir("nofollow");
        let data = dir.join("data");
        let outside = dir.join("outside");
        std::fs::create_dir_all(data.join("child")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), "outside").unwrap();
        std::fs::write(data.join("child/file"), "inside").unwrap();
        symlink(&outside, data.join("dir-link")).unwrap();
        symlink(outside.join("keep"), data.join("file-link")).unwrap();
        symlink(outside.join("missing"), data.join("dangling")).unwrap();
        let before = std::fs::metadata(outside.join("keep")).unwrap();
        let outside_before = std::fs::metadata(&outside).unwrap();
        let owner = std::fs::metadata(&data).unwrap();
        chown_tree_ids(&data, owner.uid(), owner.gid()).unwrap();
        let after = std::fs::metadata(outside.join("keep")).unwrap();
        let outside_after = std::fs::metadata(&outside).unwrap();
        // Even chown to the existing owner changes ctime if the target is touched.
        assert_eq!((before.ctime(), before.ctime_nsec()), (after.ctime(), after.ctime_nsec()));
        assert_eq!(
            (outside_before.ctime(), outside_before.ctime_nsec()),
            (outside_after.ctime(), outside_after.ctime_nsec())
        );
        assert!(std::fs::symlink_metadata(data.join("dir-link")).unwrap().file_type().is_symlink());
        assert!(chown_tree_ids(&data.join("dir-link"), owner.uid(), owner.gid()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn chown_tree_rejects_hard_links_outside_the_tree() {
        let dir = test_dir("hardlink");
        let data = dir.join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(dir.join("outside"), "outside").unwrap();
        std::fs::hard_link(dir.join("outside"), data.join("link")).unwrap();
        let owner = std::fs::metadata(&data).unwrap();
        assert!(chown_tree_ids(&data, owner.uid(), owner.gid()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
