//! What deleting a cache entry frees on disk (stow#1539).
//!
//! A cache entry's files are cloned into build directories on a
//! copy-on-write filesystem, and an entry stored from a local compile is
//! itself a clone of the compiler's output. Bytes another file still
//! shares stay allocated when the entry is deleted, so the eviction cap
//! counts an entry's size minus its shared bytes. The filesystem answers
//! which bytes are shared: APFS reports a file's private size, btrfs and
//! XFS flag shared extents in `FS_IOC_FIEMAP`. Every other filesystem has
//! no clones, so nothing on it is shared.

use std::io;
use std::path::Path;

/// The bytes of the regular files at `root` (one file, or every file
/// under a directory) that another file shares through a clone. Each
/// file counts at most its length, so the result never exceeds the
/// files' total length. A file missing when it is measured shares
/// nothing: another process removed it, and the bytes are gone with it.
pub fn shared_bytes(root: &Path) -> io::Result<u64> {
    if !platform::tracks_sharing(root)? {
        return Ok(0);
    }
    let mut shared = 0u64;
    for entry in walkdir::WalkDir::new(root) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => match error.into_io_error() {
                Some(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Some(error) => return Err(error),
                None => {
                    return Err(io::Error::other(format!(
                        "walk {} hit a symlink loop",
                        root.display()
                    )));
                }
            },
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let measured = entry
            .metadata()
            .map_err(io::Error::from)
            .and_then(|metadata| platform::file_shared_bytes(entry.path(), metadata.len()));
        match measured {
            Ok(bytes) => shared = shared.saturating_add(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(shared)
}

/// APFS: `getattrlist` with `ATTR_CMNEXT_PRIVATESIZE` returns the bytes
/// of a file no clone shares. A volume that does not track clones omits
/// the attribute from the returned set, and then the whole file is
/// private.
#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// The reply `getattrlist` writes for `ATTR_CMN_RETURNED_ATTRS` plus
    /// `ATTR_CMNEXT_PRIVATESIZE`: the reply length, the attribute set it
    /// returned, then the private size (`off_t`) when it is in that set.
    #[repr(C)]
    struct PrivateSizeReply {
        length: u32,
        returned: libc::attribute_set_t,
        private_size: libc::off_t,
    }

    /// Every entry lives on a volume `getattrlist` answers for; whether
    /// that volume tracks clones is read per file from the returned set.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) const fn tracks_sharing(_root: &Path) -> io::Result<bool> {
        Ok(true)
    }

    pub(super) fn file_shared_bytes(path: &Path, len: u64) -> io::Result<u64> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut request = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            // With `FSOPT_ATTR_CMN_EXTENDED` the fork group carries the
            // extended common attributes (`ATTR_CMNEXT_*`).
            forkattr: libc::ATTR_CMNEXT_PRIVATESIZE,
        };
        let mut reply = std::mem::MaybeUninit::<PrivateSizeReply>::zeroed();
        // SAFETY: `path` is NUL-terminated, `request` is a valid
        // `attrlist`, and `reply` is a writable buffer of the size passed.
        let status = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&raw mut request).cast(),
                reply.as_mut_ptr().cast(),
                size_of::<PrivateSizeReply>(),
                libc::FSOPT_ATTR_CMN_EXTENDED | libc::FSOPT_NOFOLLOW,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the buffer was zeroed, and `getattrlist` succeeded and
        // wrote at most its size; every field is plain data.
        let reply = unsafe { reply.assume_init() };
        if reply.returned.forkattr & libc::ATTR_CMNEXT_PRIVATESIZE == 0 {
            return Ok(0);
        }
        let private = u64::try_from(reply.private_size).map_err(|_| {
            io::Error::other(format!(
                "getattrlist returned a negative private size {} for {}",
                reply.private_size,
                path.to_string_lossy()
            ))
        })?;
        // An unshared file's private size is its allocation, which rounds
        // its length up to whole blocks; only the length is counted.
        Ok(len - private.min(len))
    }
}

/// btrfs and XFS: `FS_IOC_FIEMAP` flags each extent another file shares.
/// Every other Linux filesystem has no reflinks.
#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub(super) fn tracks_sharing(root: &Path) -> io::Result<bool> {
        let path = CString::new(root.as_os_str().as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `path` is NUL-terminated and `stat` is a writable
        // `statfs`.
        let status = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
        if status != 0 {
            let error = io::Error::last_os_error();
            // A root another process removed holds nothing shared.
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
        // SAFETY: `statfs` succeeded and filled the struct.
        let filesystem = unsafe { stat.assume_init() }.f_type;
        Ok(filesystem == libc::BTRFS_SUPER_MAGIC || filesystem == libc::XFS_SUPER_MAGIC)
    }

    pub(super) fn file_shared_bytes(path: &Path, len: u64) -> io::Result<u64> {
        let file = std::fs::File::open(path)?;
        let mut shared = 0u64;
        for extent in fiemap::Fiemap::new(&file) {
            let extent = extent?;
            if !extent.fe_flags.contains(fiemap::FiemapExtentFlags::SHARED) {
                continue;
            }
            // The last extent covers whole blocks past the end of the
            // file; only the file's own bytes are counted.
            let start = extent.fe_logical.min(len);
            let end = extent.fe_logical.saturating_add(extent.fe_length).min(len);
            shared = shared.saturating_add(end - start);
        }
        Ok(shared)
    }
}

/// Windows (NTFS has no clones) and every other platform: nothing is
/// shared, so an entry frees its file size.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use std::io;
    use std::path::Path;

    #[allow(clippy::unnecessary_wraps)]
    pub(super) const fn tracks_sharing(_root: &Path) -> io::Result<bool> {
        Ok(false)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) const fn file_shared_bytes(_path: &Path, _len: u64) -> io::Result<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::shared_bytes;

    /// A whole number of 4 KiB blocks, so an unshared file's allocation
    /// equals its length and a clone shares all of it.
    const FILE_LEN: usize = 256 * 1024;

    fn contents() -> Vec<u8> {
        (0..FILE_LEN)
            .map(|index| u8::try_from(index % 251).expect("byte"))
            .collect()
    }

    /// A file written byte by byte, and a second file holding the same
    /// bytes written separately, share nothing: deleting either frees its
    /// full size.
    #[test]
    fn a_plain_copy_shares_nothing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let original = tempdir.path().join("entry/libdemo.rlib");
        std::fs::create_dir_all(original.parent().expect("parent")).expect("create entry dir");
        std::fs::write(&original, contents()).expect("write original");
        std::fs::write(tempdir.path().join("copy.rlib"), contents()).expect("write copy");

        assert_eq!(shared_bytes(&original).expect("measure file"), 0);
        assert_eq!(
            shared_bytes(&tempdir.path().join("entry")).expect("measure dir"),
            0
        );
    }

    /// A root that does not exist holds nothing shared.
    #[test]
    fn a_missing_root_shares_nothing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            shared_bytes(&tempdir.path().join("gone")).expect("measure missing root"),
            0
        );
    }

    /// On APFS a clone shares every byte of the original until the clone
    /// is deleted; then the original frees its full size again.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_apfs_clone_shares_the_entry_until_it_is_deleted() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let entry = tempdir.path().join("entry");
        std::fs::create_dir_all(entry.join("files")).expect("create entry dir");
        let original = entry.join("files/libdemo.rlib");
        std::fs::write(&original, contents()).expect("write original");
        let small = entry.join("manifest.json");
        std::fs::write(&small, b"{}").expect("write manifest");
        assert_eq!(shared_bytes(&entry).expect("measure before clone"), 0);

        let clone = tempdir.path().join("target-debug-deps-libdemo.rlib");
        reflink_copy::reflink(&original, &clone).expect("clone on the APFS temp volume");
        assert_eq!(
            shared_bytes(&original).expect("measure cloned file"),
            u64::try_from(FILE_LEN).expect("len")
        );
        assert_eq!(
            shared_bytes(&entry).expect("measure cloned entry"),
            u64::try_from(FILE_LEN).expect("len"),
            "only the cloned file is shared; the manifest stays private"
        );

        std::fs::remove_file(&clone).expect("delete clone");
        assert_eq!(shared_bytes(&entry).expect("measure after delete"), 0);
    }
}
