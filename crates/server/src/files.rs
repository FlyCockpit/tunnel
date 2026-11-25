//! Safe file writes and ownership changes: atomic replacement, exact modes,
//! and descriptor-relative operations that never follow a symlink.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

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
pub(crate) const O_PATH: i32 = 0x200000;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Atomically write `content` with `mode` if it differs from what is on disk.
/// Returns `true` when the file was (re)written.
pub fn write_if_changed(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<bool> {
    if let Ok(existing) = std::fs::read(path)
        && existing == content
    {
        set_mode(path, mode)?;
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

/// Ensure a path has exactly `mode` permissions.
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Give the regular file at `path` exactly `mode` without following a symlink
/// there. `Ok(false)` when nothing is there or it is not a regular file (a
/// symlink is left alone). The inode is pinned with O_PATH: closing such a
/// descriptor drops none of this process's POSIX locks on the file (Linux), so
/// this is safe on a database another connection here has open.
pub(crate) fn set_mode_nofollow(path: &Path, mode: u32) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    let file = match std::fs::OpenOptions::new().read(true).custom_flags(O_PATH | O_NOFOLLOW | O_CLOEXEC).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(false);
    }
    if meta.permissions().mode() & 0o7777 != mode {
        // The /proc link names the pinned inode, not the path, which may have changed since.
        std::fs::set_permissions(format!("/proc/self/fd/{}", file.as_raw_fd()), std::fs::Permissions::from_mode(mode))?;
    }
    Ok(true)
}

pub(crate) fn account_id(owner: &str, flag: &str) -> anyhow::Result<u32> {
    let out = std::process::Command::new("id").args([flag, "--", owner]).output()?;
    anyhow::ensure!(out.status.success(), "could not resolve service account {owner}");
    Ok(std::str::from_utf8(&out.stdout)?.trim().parse()?)
}

/// Resolve the named group itself, rather than assuming it is the account's
/// primary group (an existing service account can have a different primary gid).
pub(crate) fn group_id(group: &str) -> anyhow::Result<u32> {
    let out = std::process::Command::new("getent").args(["group", group]).output()?;
    anyhow::ensure!(out.status.success(), "could not resolve service group {group}");
    let record = std::str::from_utf8(&out.stdout)?;
    let gid = record.split(':').nth(2).ok_or_else(|| anyhow::anyhow!("invalid service group record"))?;
    Ok(gid.parse()?)
}

/// No pathname is resolved again after it is opened. O_PATH | O_NOFOLLOW pins
/// even a symlink itself, and fchownat(AT_EMPTY_PATH) changes that pinned inode.
/// Linux is required by the setup/systemd code already.
pub(crate) fn set_owner_fd(file: &std::fs::File, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn fchownat(dirfd: i32, path: *const std::ffi::c_char, owner: u32, group: u32, flags: i32) -> i32;
    }
    // SAFETY: the file descriptor is live; c"" is NUL-terminated. Linux flags
    // AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW operate on the descriptor itself.
    let result = unsafe { fchownat(file.as_raw_fd(), c"".as_ptr(), uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

pub(crate) fn chown_tree_ids(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
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
    fn set_mode_nofollow_changes_regular_files_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("mode-nofollow");
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
        let file = dir.join("file");
        let outside = dir.join("outside");
        std::fs::write(&file, b"x").unwrap();
        std::fs::write(&outside, b"x").unwrap();
        for p in [&file, &outside] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        symlink(&outside, dir.join("link")).unwrap();
        assert!(set_mode_nofollow(&file, 0o600).unwrap());
        assert_eq!(mode(&file), 0o600);
        assert!(!set_mode_nofollow(&dir.join("link"), 0o600).unwrap());
        assert_eq!(mode(&outside), 0o644);
        assert!(!set_mode_nofollow(&dir.join("missing"), 0o600).unwrap());
        assert!(!set_mode_nofollow(&dir, 0o600).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
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
