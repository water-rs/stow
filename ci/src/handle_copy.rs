//! Copy of an already-opened (and verified) file to a new path.
//!
//! Every host copy of a build's output goes through [`copy_from_handle`], so
//! the bytes written are the bytes of the handle that was checked, never of
//! whatever the source path names by the time the copy runs.

use std::fs::File;
use std::path::Path;

/// Write the bytes of `source` to a new file at `destination` (which must not
/// exist), with its permissions. The filesystem clones the data where it can:
/// `fclonefileat` on macOS, `copy_file_range` (through `std::io::copy`) on
/// Linux. On macOS a plain copy happens only when the filesystem reports it
/// cannot clone (`ENOTSUP`, `EXDEV`); every other failure is an error.
///
/// # Errors
///
/// The destination existing, or any I/O failure.
pub fn copy_from_handle(source: &mut File, destination: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    if clone_handle(source, destination)? {
        return Ok(());
    }
    copy_bytes(source, destination)
}

fn copy_bytes(source: &mut File, destination: &Path) -> std::io::Result<()> {
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(source, &mut target)?;
    target.set_permissions(source.metadata()?.permissions())
}

/// Clone `source` to `destination`. `Ok(false)` means the filesystem cannot
/// clone this pair, so the caller copies.
#[cfg(target_os = "macos")]
fn clone_handle(source: &File, destination: &Path) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `source` is an open descriptor and `destination` a NUL-terminated
    // path that outlives the call; `AT_FDCWD` resolves it as an ordinary path.
    let status =
        unsafe { libc::fclonefileat(source.as_raw_fd(), libc::AT_FDCWD, destination.as_ptr(), 0) };
    if status == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOTSUP | libc::EXDEV) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};

    use super::copy_from_handle;

    #[test]
    fn copies_the_handle_bytes_and_refuses_an_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("source");
        std::fs::write(&path, b"handle bytes").expect("write");
        let mut source = std::fs::File::open(&path).expect("open");
        // The path is replaced after the handle was opened: the copy carries
        // the handle's bytes.
        std::fs::remove_file(&path).expect("remove");
        std::fs::write(&path, b"swapped bytes").expect("rewrite");

        let destination = dir.path().join("destination");
        copy_from_handle(&mut source, &destination).expect("copy");
        assert_eq!(std::fs::read(&destination).expect("read"), b"handle bytes");
        assert!(copy_from_handle(&mut source, &destination).is_err());

        let mut again = Vec::new();
        source.seek(SeekFrom::Start(0)).expect("rewind");
        source.read_to_end(&mut again).expect("read");
        assert_eq!(again, b"handle bytes");
    }
}
