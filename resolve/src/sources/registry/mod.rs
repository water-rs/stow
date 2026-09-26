//! A `Source` for registry-based packages.
//!
//! # What's a Registry?
//!
//! [Registries] are central locations where packages can be uploaded to,
//! discovered, and searched for. The purpose of a registry is to have a
//! location that serves as permanent storage for versions of a crate over time.
//!
//! Compared to git sources (see [`GitSource`]), a registry provides many
//! packages as well as many versions simultaneously. Git sources can also
//! have commits deleted through rebasings where registries cannot have their
//! versions deleted.
//!
//! In Cargo, [`RegistryData`] is an abstraction over each kind of actual
//! registry, and [`RegistrySource`] connects those implementations to
//! [`Source`] trait. Two prominent features these abstractions provide are
//!
//! * A way to query the metadata of a package from a registry. The metadata
//!   comes from the index.
//! * A way to download package contents (a.k.a source files) that are required
//!   when building the package itself.
//!
//! We'll cover each functionality later.
//!
//! [Registries]: https://doc.rust-lang.org/nightly/cargo/reference/registries.html
//! [`GitSource`]: super::GitSource
//!
//! # Different Kinds of Registries
//!
//! Cargo provides multiple kinds of registries. Each of them serves the index
//! and package contents in a slightly different way. Namely,
//!
//! * [`LocalRegistry`] --- Serves the index and package contents entirely on
//!   a local filesystem.
//! * [`RemoteRegistry`] --- Serves the index ahead of time from a Git
//!   repository, and package contents are downloaded as needed.
//! * [`HttpRegistry`] --- Serves both the index and package contents on demand
//!   over a HTTP-based registry API. This is the default starting from 1.70.0.
//!
//! Each registry has its own [`RegistryData`] implementation, and can be
//! created from either [`RegistrySource::local`] or [`RegistrySource::remote`].
//!
//! [`LocalRegistry`]: local::LocalRegistry
//! [`RemoteRegistry`]: remote::RemoteRegistry
//! [`HttpRegistry`]: http_remote::HttpRegistry
//!
//! # The Index of a Registry
//!
//! One of the major difficulties with a registry is that hosting so many
//! packages may quickly run into performance problems when dealing with
//! dependency graphs. It's infeasible for cargo to download the entire contents
//! of the registry just to resolve one package's dependencies, for example. As
//! a result, cargo needs some efficient method of querying what packages are
//! available on a registry, what versions are available, and what the
//! dependencies for each version is.
//!
//! To solve the problem, a registry must provide an index of package metadata.
//! The index of a registry is essentially an easily query-able version of the
//! registry's database for a list of versions of a package as well as a list
//! of dependencies for each version. The exact format of the index is
//! described later.
//!
//! See the [`index`] module for topics about the management, parsing, caching,
//! and versioning for the on-disk index.
//!
//! ## The Format of The Index
//!
//! The index is a store for the list of versions for all packages known, so its
//! format on disk is optimized slightly to ensure that `ls registry` doesn't
//! produce a list of all packages ever known. The index also wants to ensure
//! that there's not a million files which may actually end up hitting
//! filesystem limits at some point. To this end, a few decisions were made
//! about the format of the registry:
//!
//! 1. Each crate will have one file corresponding to it. Each version for a
//!    crate will just be a line in this file (see [`cargo_util_schemas::index::IndexPackage`] for its
//!    representation).
//! 2. There will be two tiers of directories for crate names, under which
//!    crates corresponding to those tiers will be located.
//!    (See [`crate::util::registry::make_dep_path`] for the implementation of
//!    this layout hierarchy.)
//!
//! As an example, this is an example hierarchy of an index:
//!
//! ```notrust
//! .
//! ├── 3
//! │   └── u
//! │       └── url
//! ├── bz
//! │   └── ip
//! │       └── bzip2
//! ├── config.json
//! ├── en
//! │   └── co
//! │       └── encoding
//! └── li
//!     ├── bg
//!     │   └── libgit2
//!     └── nk
//!         └── link-config
//! ```
//!
//! The root of the index contains a `config.json` file with a few entries
//! corresponding to the registry (see [`RegistryConfig`] below).
//!
//! Otherwise, there are three numbered directories (1, 2, 3) for crates with
//! names 1, 2, and 3 characters in length. The 1/2 directories simply have the
//! crate files underneath them, while the 3 directory is sharded by the first
//! letter of the crate name.
//!
//! Otherwise the top-level directory contains many two-letter directory names,
//! each of which has many sub-folders with two letters. At the end of all these
//! are the actual crate files themselves.
//!
//! The purpose of this layout is to hopefully cut down on `ls` sizes as well as
//! efficient lookup based on the crate name itself.
//!
//! See [The Cargo Book: Registry Index][registry-index] for the public
//! interface on the index format.
//!
//! [registry-index]: https://doc.rust-lang.org/nightly/cargo/reference/registry-index.html
//!
//! ## The Index Files
//!
//! Each file in the index is the history of one crate over time. Each line in
//! the file corresponds to one version of a crate, stored in JSON format (see
//! the [`cargo_util_schemas::index::IndexPackage`] structure).
//!
//! As new versions are published, new lines are appended to this file. **The
//! only modifications to this file that should happen over time are yanks of a
//! particular version.**
//!
//! # Downloading Packages
//!
//! The purpose of the index was to provide an efficient method to resolve the
//! dependency graph for a package. After resolution has been performed, we need
//! to download the contents of packages so we can read the full manifest and
//! build the source code.
//!
//! To accomplish this, [`RegistryData::download`] will "make" an HTTP request
//! per-package requested to download tarballs into a local cache. These
//! tarballs will then be unpacked into a destination folder.
//!
//! Note that because versions uploaded to the registry are frozen forever that
//! the HTTP download and unpacking can all be skipped if the version has
//! already been downloaded and unpacked. This caching allows us to only
//! download a package when absolutely necessary.
//!
//! # Filesystem Hierarchy
//!
//! Overall, the `$HOME/.cargo` looks like this when talking about the registry
//! (remote registries, specifically):
//!
//! ```notrust
//! # A folder under which all registry metadata is hosted (similar to
//! # $HOME/.cargo/git)
//! $HOME/.cargo/registry/
//!
//!     # For each registry that cargo knows about (keyed by hostname + hash)
//!     # there is a folder which is the checked out version of the index for
//!     # the registry in this location. Note that this is done so cargo can
//!     # support multiple registries simultaneously
//!     index/
//!         registry1-<hash>/
//!         registry2-<hash>/
//!         ...
//!
//!     # This folder is a cache for all downloaded tarballs (`.crate` file)
//!     # from a registry. Once downloaded and verified, a tarball never changes.
//!     cache/
//!         registry1-<hash>/<pkg>-<version>.crate
//!         ...
//!
//!     # Location in which all tarballs are unpacked. Each tarball is known to
//!     # be frozen after downloading, so transitively this folder is also
//!     # frozen once its unpacked (it's never unpacked again)
//!     # CAVEAT: They are not read-only. See rust-lang/cargo#9455.
//!     src/
//!         registry1-<hash>/<pkg>-<version>/...
//!         ...
//! ```
//!

use crate::util::filetime::FileTime;
use crate::util::fs::File;
use crate::util::fs::{self, OpenOptions};
use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::util::paths;
use crate::util::report::Level;
use anyhow::Context as _;
use flate2::read::DeflateDecoder;
use futures::FutureExt as _;
use futures::StreamExt as _;
use serde::Deserialize;
use serde::Serialize;
use tar::{Archive, EntryType};
use tracing::debug;

use crate::core::dependency::Dependency;
use crate::core::global_cache_tracker;
use crate::core::{Package, PackageId, SourceId};
use crate::sources::PathSource;
use crate::sources::source::MaybePackage;
use crate::sources::source::QueryKind;
use crate::sources::source::Source;
use crate::util::cache_lock::CacheLockMode;
use crate::util::interning::InternedString;
use crate::util::network::http_async::BodyStream;
use crate::util::{CargoResult, Filesystem, GlobalContext, LimitErrorReader, restricted_names};
use crate::util::{VersionExt, hex, sha256, tarball};

pub use cargo_util_schemas::index::RegistryConfig;

/// The `.cargo-ok` file is used to track if the source is already unpacked.
/// See [`RegistrySource::unpack_package`] for more.
///
/// Not to be confused with `.cargo-ok` file in git sources.
const PACKAGE_SOURCE_LOCK: &str = ".cargo-ok";

pub const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";
pub const CRATES_IO_HTTP_INDEX: &str = "sparse+https://index.crates.io/";
pub const CRATES_IO_REGISTRY: &str = "crates-io";
pub const CRATES_IO_DOMAIN: &str = "crates.io";

/// The content inside `.cargo-ok`.
/// See [`RegistrySource::unpack_package`] for more.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct LockMetadata {
    /// The version of `.cargo-ok` file
    v: u32,
}

/// A [`Source`] implementation for a local or a remote registry.
///
/// This contains common functionality that is shared between each registry
/// kind, with the registry-specific logic implemented as part of the
/// [`RegistryData`] trait referenced via the `ops` field.
///
/// For general concepts of registries, see the [module-level documentation](crate::sources::registry).
pub struct RegistrySource<'gctx> {
    /// A unique name of the source (typically used as the directory name
    /// where its cached content is stored).
    name: InternedString,
    /// The unique identifier of this source.
    source_id: SourceId,
    /// The path where crate files are extracted (`$CARGO_HOME/registry/src/$REG-HASH`).
    src_path: Filesystem,
    /// Local reference to [`GlobalContext`] for convenience.
    gctx: &'gctx GlobalContext,
    /// Abstraction for interfacing to the different registry kinds.
    ops: Box<dyn RegistryData + 'gctx>,
    /// Interface for managing the on-disk index.
    index: index::RegistryIndex<'gctx>,
    /// Yanked versions that have already been selected during queries.
    ///
    /// As of this writing, this is for not emitting the `--precise <yanked>`
    /// warning twice, with the assumption of (`dep.package_name()` + `--precise`
    /// version) being sufficient to uniquely identify the same query result.
    selected_precise_yanked: RefCell<HashSet<(InternedString, semver::Version)>>,
}

/// Result from loading data from a registry.
///
/// Not `Clone`/`Debug`: the `Streamed` body is a single-use trait object.
pub enum LoadResponse {
    /// The cache is valid. The cached data should be used.
    CacheValid,

    /// The cache is out of date. Returned data should be used.
    Data {
        raw_data: Vec<u8>,
        /// Version of this data to determine whether it is out of date.
        index_version: Option<String>,
    },

    /// The requested crate was found.
    NotFound,

    /// Fresh index data delivered as it arrives: the body streams through
    /// the parse rather than landing whole in the isolate. Produced only by
    /// [`http_remote::HttpRegistry`]; local and git registries always
    /// answer [`LoadResponse::Data`].
    Streamed {
        /// Response body, one `CargoResult<Vec<u8>>` chunk at a time.
        body: BodyStream,
        /// Version of this data to determine whether it is out of date.
        index_version: Option<String>,
    },
}

impl LoadResponse {
    /// Buffer a [`LoadResponse::Streamed`] body into [`LoadResponse::Data`]
    /// — the escape hatch for consumers that need the bytes whole
    /// (config.json, every non-index-file load). All other variants pass
    /// through unchanged.
    pub async fn into_buffered(self) -> CargoResult<LoadResponse> {
        match self {
            LoadResponse::Streamed {
                body,
                index_version,
            } => Ok(LoadResponse::Data {
                raw_data: tarball::collect_body(body).await?,
                index_version,
            }),
            other => Ok(other),
        }
    }
}

/// An abstract interface to handle both a local and remote registry.
///
/// This allows [`RegistrySource`] to abstractly handle each registry kind.
///
/// For general concepts of registries, see the [module-level documentation](crate::sources::registry).
#[async_trait::async_trait(?Send)]
pub trait RegistryData {
    /// Performs initialization for the registry.
    ///
    /// This should be safe to call multiple times, the implementation is
    /// expected to not do any work if it is already prepared.
    fn prepare(&self) -> CargoResult<()>;

    /// Returns the path to the index.
    ///
    /// Note that different registries store the index in different formats
    /// (remote = git, http & local = files).
    fn index_path(&self) -> &Filesystem;

    /// Returns the path of the directory that stores the cache of `.crate` files.
    ///
    /// The directory is currently expected to contain a flat list of all `.crate` files,
    /// named `<package-name>-<version>.crate`.
    fn cache_path(&self) -> &Filesystem;

    /// Loads the JSON for a specific named package from the index.
    ///
    /// * `root` is the root path to the index.
    /// * `path` is the relative path to the package to load (like `ca/rg/cargo`).
    /// * `index_version` is the version of the requested crate data currently
    ///    in cache. This is useful for checking if a local cache is outdated.
    async fn load(
        &self,
        root: &Path,
        path: &Path,
        index_version: Option<&str>,
    ) -> CargoResult<LoadResponse>;

    /// Loads the `config.json` file and returns it.
    ///
    /// Local registries don't have a config, and return `None`.
    async fn config(&self) -> CargoResult<Option<RegistryConfig>>;

    /// Invalidates locally cached data.
    fn invalidate_cache(&self);

    /// If quiet, the source should not display any progress or status messages.
    fn set_quiet(&mut self, quiet: bool);

    /// Is the local cached data up-to-date?
    fn is_updated(&self) -> bool;

    /// Prepare to start downloading a `.crate` file.
    ///
    /// Despite the name, this doesn't actually download anything. If the
    /// `.crate` is already downloaded, then it returns [`MaybeLock::Ready`].
    /// If it hasn't been downloaded, then it returns [`MaybeLock::Download`]
    /// which contains the URL to download. The [`crate::core::package::Downloads`]
    /// system handles the actual download process. After downloading, it
    /// calls [`Self::finish_download`] to save the downloaded file.
    ///
    /// `checksum` is currently only used by local registries to verify the
    /// file contents (because local registries never actually download
    /// anything). Remote registries will validate the checksum in
    /// `finish_download`. For already downloaded `.crate` files, it does not
    /// validate the checksum, assuming the filesystem does not suffer from
    /// corruption or manipulation.
    async fn download(&self, pkg: PackageId, checksum: &str) -> CargoResult<MaybeLock>;

    /// Finish a download by validating the `.crate` bytes and preparing them
    /// for unpacking. Host registry sources persist the bytes in the cache;
    /// memory-capped targets can keep them in a detached file instead.
    ///
    /// After [`crate::core::package::Downloads`] has finished a download,
    /// it will call this method. This is only relevant for remote registries.
    ///
    /// Returns a [`File`] handle to the `.crate` bytes, positioned at the start.
    async fn finish_download(
        &self,
        pkg: PackageId,
        checksum: &str,
        data: Vec<u8>,
    ) -> CargoResult<File>;

    /// Returns whether or not the `.crate` file is already downloaded.
    fn is_crate_downloaded(&self, _pkg: PackageId) -> bool {
        true
    }

    /// Validates that the global package cache lock is held.
    ///
    /// Given the [`Filesystem`], this will make sure that the package cache
    /// lock is held. If not, it will panic. See
    /// [`GlobalContext::acquire_package_cache_lock`] for acquiring the global lock.
    ///
    /// Returns the [`Path`] to the [`Filesystem`].
    fn assert_index_locked<'a>(&self, path: &'a Filesystem) -> &'a Path;
}

/// The status of [`RegistryData::download`] which indicates if a `.crate`
/// file has already been downloaded, or if not then the URL to download.
pub enum MaybeLock {
    /// The `.crate` file is already downloaded. [`File`] is a handle to the
    /// opened `.crate` file on the filesystem.
    Ready(File),
    /// The `.crate` file is not downloaded, here's the URL to download it from.
    ///
    /// `descriptor` is just a text string to display to the user of what is
    /// being downloaded.
    Download {
        url: String,
        descriptor: String,
        authorization: Option<String>,
    },
}

mod download;
mod http_remote;
#[doc(hidden)]
pub mod index;
pub use index::{IndexCachesRoot, IndexSummary};
mod local;
#[cfg(not(target_family = "wasm"))]
mod remote;

/// Generates a unique name for [`SourceId`] to have a unique path to put their
/// index files.
fn short_name(id: SourceId, is_shallow: bool) -> String {
    // CAUTION: This should not change between versions. If you change how
    // this is computed, it will orphan previously cached data, forcing the
    // cache to be rebuilt and potentially wasting significant disk space. If
    // you change it, be cautious of the impact. See `test_cratesio_hash` for
    // a similar discussion.
    let hash = hex::short_hash(&id);
    let ident = id.url().host_str().unwrap_or("").to_string();
    let mut name = format!("{}-{}", ident, hash);
    if is_shallow {
        name.push_str("-shallow");
    }
    name
}

impl<'gctx> RegistrySource<'gctx> {
    /// Creates a [`Source`] of a "remote" registry.
    /// It could be either an HTTP-based [`http_remote::HttpRegistry`] or
    /// a Git-based [`remote::RemoteRegistry`].
    pub fn remote(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
    ) -> CargoResult<RegistrySource<'gctx>> {
        assert!(source_id.is_remote_registry());
        let name = short_name(
            source_id,
            gctx.cli_unstable()
                .git
                .map_or(false, |features| features.shallow_index)
                && !source_id.is_sparse(),
        );
        let ops = if source_id.is_sparse() {
            Box::new(http_remote::HttpRegistry::new(source_id, gctx, &name)?) as Box<_>
        } else {
            // Git-based registry indexes require libgit2 checkouts, which
            // cannot exist on wasm32-unknown-unknown.
            Self::new_remote_registry(source_id, gctx, &name)?
        };

        Ok(RegistrySource::new(source_id, gctx, &name, ops))
    }

    /// Git-based registry indexes require real git checkouts (libgit2 or gix),
    /// which cannot exist on wasm32-unknown-unknown; sparse indexes are the
    /// only registry access there.
    #[cfg(not(target_family = "wasm"))]
    fn new_remote_registry(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
        name: &str,
    ) -> CargoResult<Box<dyn RegistryData + 'gctx>> {
        Ok(Box::new(remote::RemoteRegistry::new(source_id, gctx, name)))
    }

    /// See the non-wasm implementation.
    ///
    /// The object still has to *exist*: `SourceConfigMap::load` constructs
    /// the git-index source as `old_src` to read the capability answers
    /// [`RegistrySource`] itself reports (`supports_checksums`,
    /// `requires_precise`) before handing every operation to the sparse
    /// replacement. So on wasm this returns a shell that answers those
    /// questions and refuses everything else — any index operation reaching
    /// it is the bug the message names.
    #[cfg(target_family = "wasm")]
    fn new_remote_registry(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
        _name: &str,
    ) -> CargoResult<Box<dyn RegistryData + 'gctx>> {
        Ok(Box::new(UnsupportedRemoteRegistry {
            source_id,
            index_path: gctx.registry_index_path(),
            cache_path: gctx.registry_cache_path(),
        }))
    }

    /// Creates a [`Source`] of a local registry, with [`local::LocalRegistry`] under the hood.
    ///
    /// * `path` --- The root path of a local registry on the file system.
    pub fn local(
        source_id: SourceId,
        path: &Path,
        gctx: &'gctx GlobalContext,
    ) -> RegistrySource<'gctx> {
        let name = short_name(source_id, false);
        let ops = local::LocalRegistry::new(path, gctx, &name);
        RegistrySource::new(source_id, gctx, &name, Box::new(ops))
    }

    /// Creates a source of a registry. This is a inner helper function.
    ///
    /// * `name` --- Name of a path segment which may affect where `.crate`
    ///   tarballs, the registry index and cache are stored. Expect to be unique.
    /// * `ops` --- The underlying [`RegistryData`] type.
    fn new(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
        name: &str,
        ops: Box<dyn RegistryData + 'gctx>,
    ) -> RegistrySource<'gctx> {
        // Before starting to work on the registry, make sure that
        // `<cargo_home>/registry` is marked as excluded from indexing and
        // backups. Older versions of Cargo didn't do this, so we do it here
        // regardless of whether `<cargo_home>` exists.
        //
        // This does not use `create_dir_all_excluded_from_backups_atomic` for
        // the same reason: we want to exclude it even if the directory already
        // exists.
        //
        // IO errors in creating and marking it are ignored, e.g. in case we're on a
        // read-only filesystem.
        let registry_base = gctx.registry_base_path();
        let _ = registry_base.create_dir();
        crate::util::paths::exclude_from_backups_and_indexing(&registry_base.into_path_unlocked());

        RegistrySource {
            name: name.into(),
            src_path: gctx.registry_source_path().join(name),
            gctx,
            source_id,
            index: index::RegistryIndex::new(source_id, ops.index_path(), gctx),
            ops,
            selected_precise_yanked: RefCell::new(HashSet::new()),
        }
    }

    pub(crate) fn with_summary_source_id(mut self, id: SourceId) -> Self {
        self.index = index::RegistryIndex::new_with_summary_source_id(
            self.source_id,
            id,
            self.ops.index_path(),
            self.gctx,
        );
        self
    }

    /// Decode the [configuration](RegistryConfig) stored within the registry.
    ///
    /// This requires that the index has been at least checked out.
    pub async fn config(&self) -> CargoResult<Option<RegistryConfig>> {
        self.ops.config().await
    }

    /// Unpacks a downloaded package into a location where it's ready to be
    /// compiled.
    ///
    /// No action is taken if the source looks like it's already unpacked.
    ///
    /// # History of interruption detection with `.cargo-ok` file
    ///
    /// Cargo has always included a `.cargo-ok` file ([`PACKAGE_SOURCE_LOCK`])
    /// to detect if extraction was interrupted, but it was originally empty.
    ///
    /// In 1.34, Cargo was changed to create the `.cargo-ok` file before it
    /// started extraction to implement fine-grained locking. After it was
    /// finished extracting, it wrote two bytes to indicate it was complete.
    /// It would use the length check to detect if it was possibly interrupted.
    ///
    /// In 1.36, Cargo changed to not use fine-grained locking, and instead used
    /// a global lock. The use of `.cargo-ok` was no longer needed for locking
    /// purposes, but was kept to detect when extraction was interrupted.
    ///
    /// In 1.49, Cargo changed to not create the `.cargo-ok` file before it
    /// started extraction to deal with `.crate` files that inexplicably had
    /// a `.cargo-ok` file in them.
    ///
    /// In 1.64, Cargo changed to detect `.crate` files with `.cargo-ok` files
    /// in them in response to [CVE-2022-36113], which dealt with malicious
    /// `.crate` files making `.cargo-ok` a symlink causing cargo to write "ok"
    /// to any arbitrary file on the filesystem it has permission to.
    ///
    /// In 1.71, `.cargo-ok` changed to contain a JSON `{ v: 1 }` to indicate
    /// the version of it. A failure of parsing will result in a heavy-hammer
    /// approach that unpacks the `.crate` file again. This is in response to a
    /// security issue that the unpacking didn't respect umask on Unix systems.
    ///
    /// This is all a long-winded way of explaining the circumstances that might
    /// cause a directory to contain a `.cargo-ok` file that is empty or
    /// otherwise corrupted. Either this was extracted by a version of Rust
    /// before 1.34, in which case everything should be fine. However, an empty
    /// file created by versions 1.36 to 1.49 indicates that the extraction was
    /// interrupted and that we need to start again.
    ///
    /// Another possibility is that the filesystem is simply corrupted, in
    /// which case deleting the directory might be the safe thing to do. That
    /// is probably unlikely, though.
    ///
    /// To be safe, we delete the directory and start over again if an empty
    /// `.cargo-ok` file is found.
    ///
    /// [CVE-2022-36113]: https://blog.rust-lang.org/2022/09/14/cargo-cves.html#arbitrary-file-corruption-cve-2022-36113
    fn unpack_package(&self, pkg: PackageId, mut tarball: File) -> CargoResult<PathBuf> {
        let package_dir = format!("{}-{}", pkg.name(), pkg.version());
        let dst = self.src_path.join(&package_dir);
        let path = dst.join(PACKAGE_SOURCE_LOCK);
        let path = self
            .gctx
            .assert_package_cache_locked(CacheLockMode::DownloadExclusive, &path);
        let unpack_dir = path.parent().unwrap();
        match fs::read_to_string(path) {
            Ok(ok) => match serde_json::from_str::<LockMetadata>(&ok) {
                Ok(lock_meta) if lock_meta.v == 1 => {
                    self.gctx
                        .deferred_global_last_use()?
                        .mark_registry_src_used(global_cache_tracker::RegistrySrc {
                            encoded_registry_name: self.name,
                            package_dir: package_dir.into(),
                            size: None,
                        });
                    return Ok(unpack_dir.to_path_buf());
                }
                _ => {
                    if ok == "ok" {
                        tracing::debug!("old `ok` content found, clearing cache");
                    } else {
                        tracing::warn!("unrecognized .cargo-ok content, clearing cache: {ok}");
                    }
                    // See comment of `unpack_package` about why removing all stuff.
                    paths::remove_dir_all(dst.as_path_unlocked())?;
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("unable to read .cargo-ok file at {path:?}: {e}"),
        }
        dst.create_dir()?;

        // The resolve reads only `Cargo.toml`'s contents from an unpacked
        // registry package — everything else is existence checks and
        // directory listings (target autodiscovery). A manifest that
        // normalizes every target (all `auto*` off, each declared target
        // carrying `path`, `build` explicit) never triggers autodiscovery
        // when it loads, so the walk can stop at the manifest; otherwise
        // the remaining entries land as stubs, keeping the tree visible
        // without staging tens of MB per crate into the isolate's 128 MiB.
        let manifest = read_manifest_bytes(self.gctx, &mut tarball)?;
        let manifest_only = manifest.as_deref().is_some_and(manifest_is_normalized);
        let bytes_written = if let Some(manifest) = manifest.filter(|_| manifest_only) {
            // A normalized manifest unpacks to `Cargo.toml` alone — every
            // other entry is skipped and the walk ends at the manifest.
            // Its bytes are already in hand, so the archive is decoded
            // once rather than rewound and re-inflated up to the manifest.
            fs::write(unpack_dir.join("Cargo.toml"), &manifest)?;
            manifest.len() as u64
        } else {
            tarball
                .seek(io::SeekFrom::Start(0))
                .context("failed to rewind crate tarball")?;
            unpack(
                self.gctx,
                &mut tarball,
                unpack_dir,
                &|_| true,
                &|p| p == Path::new("Cargo.toml"),
                manifest_only,
            )?
        };
        update_mtime_for_generated_files(unpack_dir);

        // Now that we've finished unpacking, create and write to the lock file to indicate that
        // unpacking was successful.
        let mut ok = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to open `{}`", path.display()))?;

        let lock_meta = LockMetadata { v: 1 };
        write!(ok, "{}", serde_json::to_string(&lock_meta).unwrap())?;

        self.gctx
            .deferred_global_last_use()?
            .mark_registry_src_used(global_cache_tracker::RegistrySrc {
                encoded_registry_name: self.name,
                package_dir: package_dir.into(),
                size: Some(bytes_written),
            });

        Ok(unpack_dir.to_path_buf())
    }

    /// Unpacks the `.crate` tarball of the package in a given directory.
    ///
    /// Returns the path to the crate tarball directory,
    /// which is always `<unpack_dir>/<pkg>-<version>`.
    ///
    /// This holds some assumptions
    ///
    /// * The associated tarball already exists
    /// * If this is a local registry,
    ///   the package cache lock must be externally synchronized.
    ///   Cargo does not take care of it being locked or not.
    pub fn unpack_package_in(
        &self,
        pkg: &PackageId,
        unpack_dir: &Path,
        include: &dyn Fn(&Path) -> bool,
    ) -> CargoResult<PathBuf> {
        let path = self.ops.cache_path().join(pkg.tarball_name());
        let path = self.ops.assert_index_locked(&path);
        let dst = unpack_dir.join(format!("{}-{}", pkg.name(), pkg.version()));
        let mut tarball =
            paths::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        unpack(self.gctx, &mut tarball, &dst, include, &|_| true, false)?;
        update_mtime_for_generated_files(&dst);
        Ok(dst)
    }

    /// Turns the downloaded `.crate` tarball file into a [`Package`].
    ///
    /// This unconditionally sets checksum for the returned package, so it
    /// should only be called after doing integrity check. That is to say,
    /// you need to call either [`RegistryData::download`] or
    /// [`RegistryData::finish_download`] before calling this method.
    async fn get_pkg(&self, package: PackageId, path: &File) -> CargoResult<Package> {
        let path = self
            .unpack_package(package, path.clone())
            .with_context(|| format!("failed to unpack package `{}`", package))?;
        let src = PathSource::new(&path, self.source_id, self.gctx);
        src.load()?;
        let mut pkg = match src.download(package).await? {
            MaybePackage::Ready(pkg) => pkg,
            MaybePackage::Download { .. } => unreachable!(),
        };

        // After we've loaded the package configure its summary's `checksum`
        // field with the checksum we know for this `PackageId`.
        let cksum = self
            .index
            .hash(package, &*self.ops)
            .now_or_never()
            .expect("a downloaded dep now pending!?")
            .expect("summary not found");
        pkg.manifest_mut()
            .summary_mut()
            .set_checksum(cksum.to_string());
        pkg.manifest_mut().release_source();

        Ok(pkg)
    }
}

#[async_trait::async_trait(?Send)]
impl<'gctx> Source for RegistrySource<'gctx> {
    async fn query(
        &self,
        dep: &Dependency,
        kind: QueryKind,
        f: &mut dyn FnMut(IndexSummary),
    ) -> CargoResult<()> {
        let mut req = dep.version_req().clone();

        // Handle `cargo update --precise` here.
        if let Some((_, requested)) = self
            .source_id
            .precise_registry_version(dep.package_name().as_str())
            .filter(|(c, to)| {
                if to.is_prerelease() && self.gctx.cli_unstable().unstable_options {
                    req.matches_prerelease(c)
                } else {
                    req.matches(c)
                }
            })
        {
            req.precise_to(&requested);
        }

        let mut called = false;
        let callback = &mut |s| {
            called = true;
            f(s);
        };

        // If this is a locked dependency, then it came from a lock file and in
        // theory the registry is known to contain this version. If, however, we
        // come back with no summaries, then our registry may need to be
        // updated, so we fall back to performing a lazy update.
        if kind == QueryKind::Exact && req.is_locked() && !self.ops.is_updated() {
            debug!("attempting query without update");
            self.index
                .query_inner(dep.package_name(), &req, &*self.ops, &mut |is| {
                    match &is {
                        IndexSummary::Candidate(s) | IndexSummary::Yanked(s) if dep.matches(&s) => {
                            // We are looking for a package from a lock file so we do not care about yank
                            callback(is)
                        }
                        _ => {}
                    }
                })
                .await?;
            if called {
                return Ok(());
            } else {
                debug!("falling back to an update");
                self.invalidate_cache();
            }
        }

        let mut called = false;
        let callback = &mut |s| {
            called = true;
            f(s);
        };

        let mut precise_yanked_in_use = false;
        self.index
            .query_inner(dep.package_name(), &req, &*self.ops, &mut |s| {
                let matched = match kind {
                    QueryKind::Exact | QueryKind::RejectedVersions => {
                        let s = match &s {
                            IndexSummary::Candidate(s)
                            | IndexSummary::Yanked(s)
                            | IndexSummary::Offline(s)
                            | IndexSummary::Unsupported(s, _)
                            | IndexSummary::Invalid(s) => s,
                        };
                        if req.is_precise() && self.gctx.cli_unstable().unstable_options {
                            dep.matches_prerelease(&s)
                        } else {
                            dep.matches(&s)
                        }
                    }
                    QueryKind::AlternativeNames => true,
                    QueryKind::Normalized => true,
                };
                if !matched {
                    return;
                }
                match s {
                    s @ _ if kind == QueryKind::RejectedVersions => callback(s),
                    s @ IndexSummary::Candidate(_) => callback(s),
                    s @ IndexSummary::Yanked(_) => {
                        // HACK: While source knows nothing about yank policy,
                        // We still detect `cargo update --precise <yanked>`
                        // so we can warn about the user-visible selection.
                        //
                        // We should consider also move this out from source query.
                        if req.is_precise() {
                            precise_yanked_in_use = true;
                        }
                        callback(s);
                    }
                    IndexSummary::Unsupported(summary, v) => {
                        tracing::debug!(
                            "unsupported schema version {} ({} {})",
                            v,
                            summary.name(),
                            summary.version()
                        );
                    }
                    IndexSummary::Invalid(summary) => {
                        tracing::debug!("invalid ({} {})", summary.name(), summary.version());
                    }
                    IndexSummary::Offline(summary) => {
                        tracing::debug!("offline ({} {})", summary.name(), summary.version());
                    }
                }
            })
            .await?;
        if precise_yanked_in_use {
            let name = dep.package_name();
            let version = req
                .precise_version()
                .expect("--precise <yanked-version> in use");
            if self
                .selected_precise_yanked
                .borrow_mut()
                .insert((name, version.clone()))
            {
                let mut shell = self.gctx.shell();
                shell.print_report(
                    &[Level::WARNING
                        .secondary_title(format!(
                            "selected package `{name}@{version}` was yanked by the author"
                        ))
                        .element(
                            Level::HELP.message("if possible, try a compatible non-yanked version"),
                        )],
                    false,
                )?;
            }
        }
        if called {
            return Ok(());
        }
        if kind == QueryKind::AlternativeNames || kind == QueryKind::Normalized {
            // Attempt to handle misspellings by searching for a chain of related
            // names to the original name. The resolver will later
            // reject any candidates that have the wrong name, and with this it'll
            // have enough information to offer "a similar crate exists" suggestions.
            // For now we only try canonicalizing `-` to `_` and vice versa.
            // More advanced fuzzy searching become in the future.
            for name_permutation in [
                dep.package_name().replace('-', "_"),
                dep.package_name().replace('_', "-"),
            ] {
                let name_permutation = name_permutation.into();
                if name_permutation == dep.package_name() {
                    continue;
                }
                self.index
                    .query_inner(name_permutation, &req, &*self.ops, &mut |s| f(s))
                    .await?;
            }
        }
        Ok(())
    }

    fn supports_checksums(&self) -> bool {
        true
    }

    fn requires_precise(&self) -> bool {
        false
    }

    fn source_id(&self) -> SourceId {
        self.source_id
    }

    fn invalidate_cache(&self) {
        self.index.clear_summaries_cache();
        self.ops.invalidate_cache();
    }

    fn set_quiet(&mut self, quiet: bool) {
        self.ops.set_quiet(quiet);
    }

    async fn download(&self, package: PackageId) -> CargoResult<MaybePackage> {
        let hash = self.index.hash(package, &*self.ops).await?;
        match self.ops.download(package, &hash).await? {
            MaybeLock::Ready(file) => self.get_pkg(package, &file).await.map(MaybePackage::Ready),
            MaybeLock::Download {
                url,
                descriptor,
                authorization,
            } => Ok(MaybePackage::Download {
                url,
                descriptor,
                authorization,
            }),
        }
    }

    async fn finish_download(
        &self,
        package: PackageId,
        body: http::Response<BodyStream>,
    ) -> CargoResult<Package> {
        let hash = self.index.hash(package, &*self.ops).await?;
        #[cfg(not(target_family = "wasm"))]
        let file = {
            let data = tarball::collect_body(body.into_body()).await?;
            self.ops.finish_download(package, &hash, data).await?
        };
        #[cfg(target_family = "wasm")]
        let file = self.admit_streamed_crate(package, &hash, body).await?;
        // Keep the file alive through unpacking; it is detached from the VFS
        // on wasm and refers to the cached tarball on the host.
        let pkg = self.get_pkg(package, &file).await?;
        drop(file);
        Ok(pkg)
    }

    fn fingerprint(&self, pkg: &Package) -> CargoResult<String> {
        Ok(pkg.package_id().version().to_string())
    }

    fn describe(&self) -> String {
        self.source_id.display_index()
    }
}

/// wasm32-only stand-in for `remote::RemoteRegistry`.
///
/// See `RegistrySource::new_remote_registry`: the object exists so the
/// `RegistrySource` wrapper can answer `Source::supports_checksums` /
/// `requires_precise` for a git index that is being replaced by the sparse
/// one. Every `RegistryData` operation refuses — a git checkout cannot
/// exist on wasm32-unknown-unknown, and any call reaching here means an
/// index op escaped the sparse replacement.
#[cfg(target_family = "wasm")]
struct UnsupportedRemoteRegistry {
    source_id: SourceId,
    index_path: Filesystem,
    cache_path: Filesystem,
}

#[cfg(target_family = "wasm")]
impl UnsupportedRemoteRegistry {
    fn unsupported(&self) -> anyhow::Error {
        anyhow::anyhow!(
            "git-based registry index `{}` is not supported on wasm32; use a sparse index",
            self.source_id
        )
    }
}

#[cfg(target_family = "wasm")]
#[async_trait::async_trait(?Send)]
impl RegistryData for UnsupportedRemoteRegistry {
    fn prepare(&self) -> CargoResult<()> {
        Err(self.unsupported())
    }

    fn index_path(&self) -> &Filesystem {
        &self.index_path
    }

    fn cache_path(&self) -> &Filesystem {
        &self.cache_path
    }

    async fn load(
        &self,
        _root: &Path,
        _path: &Path,
        _index_version: Option<&str>,
    ) -> CargoResult<LoadResponse> {
        Err(self.unsupported())
    }

    async fn config(&self) -> CargoResult<Option<RegistryConfig>> {
        Err(self.unsupported())
    }

    fn invalidate_cache(&self) {}

    fn set_quiet(&mut self, _quiet: bool) {}

    fn is_updated(&self) -> bool {
        false
    }

    async fn download(&self, _pkg: PackageId, _checksum: &str) -> CargoResult<MaybeLock> {
        Err(self.unsupported())
    }

    async fn finish_download(
        &self,
        _pkg: PackageId,
        _checksum: &str,
        _data: Vec<u8>,
    ) -> CargoResult<File> {
        Err(self.unsupported())
    }

    fn is_crate_downloaded(&self, _pkg: PackageId) -> bool {
        false
    }

    fn assert_index_locked<'a>(&self, path: &'a Filesystem) -> &'a Path {
        // The wasm backend has no advisory locks to assert.
        path.as_path_unlocked()
    }
}

/// Get the maximum unpack size that Cargo permits
/// based on a given `size` of your compressed file.
///
/// Returns the larger one between `size * max compression ratio`
/// and a fixed max unpacked size.
///
/// In reality, the compression ratio usually falls in the range of 2:1 to 10:1.
/// We choose 20:1 to cover almost all possible cases hopefully.
/// Any ratio higher than this is considered as a zip bomb.
///
/// In the future we might want to introduce a configurable size.
///
/// Some of the real world data from common compression algorithms:
///
/// * <https://www.zlib.net/zlib_tech.html>
/// * <https://cran.r-project.org/web/packages/brotli/vignettes/brotli-2015-09-22.pdf>
/// * <https://blog.cloudflare.com/results-experimenting-brotli/>
/// * <https://tukaani.org/lzma/benchmarks.html>
fn max_unpack_size(gctx: &GlobalContext, size: u64) -> u64 {
    const SIZE_VAR: &str = "__CARGO_TEST_MAX_UNPACK_SIZE";
    const RATIO_VAR: &str = "__CARGO_TEST_MAX_UNPACK_RATIO";
    const MAX_UNPACK_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB
    const MAX_COMPRESSION_RATIO: usize = 20; // 20:1

    let max_unpack_size = if cfg!(debug_assertions) && gctx.get_env(SIZE_VAR).is_ok() {
        // For integration test only.
        gctx.get_env(SIZE_VAR)
            .unwrap()
            .parse()
            .expect("a max unpack size in bytes")
    } else {
        MAX_UNPACK_SIZE
    };
    let max_compression_ratio = if cfg!(debug_assertions) && gctx.get_env(RATIO_VAR).is_ok() {
        // For integration test only.
        gctx.get_env(RATIO_VAR)
            .unwrap()
            .parse()
            .expect("a max compression ratio in bytes")
    } else {
        MAX_COMPRESSION_RATIO
    };

    u64::max(max_unpack_size, size * max_compression_ratio as u64)
}

/// Set the current [`umask`] value for the given tarball. No-op on non-Unix
/// platforms.
///
/// On Windows, tar only looks at user permissions and tries to set the "read
/// only" attribute, so no-op as well.
///
/// [`umask`]: https://man7.org/linux/man-pages/man2/umask.2.html
#[allow(unused_variables)]
fn set_mask<R: Read>(tar: &mut Archive<R>) {
    #[cfg(unix)]
    tar.set_mask(crate::util::get_umask());
}

/// The deflate stream inside a gzip `.crate` archive, with the container's
/// crc32 never computed.
///
/// Every caller here sits behind `download`'s sha256 verification, which
/// hashes the archive's exact compressed bytes before any decoded content
/// is used — `GzDecoder`'s per-byte crc bookkeeping re-verifies what that
/// checksum already proves, so this decodes the deflate payload directly.
/// The sha256-then-decode order is the invariant: a decode path whose
/// bytes were not first checksum-verified (e.g. codeload git tarballs)
/// must keep `GzDecoder`.
fn verified_deflate_reader<'a>(
    tarball: &'a mut File,
) -> io::Result<DeflateDecoder<BufReader<&'a mut File>>> {
    let mut r = BufReader::new(tarball);
    let mut head = [0u8; 10];
    r.read_exact(&mut head)?;
    if head[0] != 0x1f || head[1] != 0x8b || head[2] != 0x08 || head[3] & 0xe0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a deflate-compressed gzip stream",
        ));
    }
    let flg = head[3];
    if flg & 0x04 != 0 {
        // FEXTRA: 2-byte little-endian length, then that many bytes.
        let mut xlen = [0u8; 2];
        r.read_exact(&mut xlen)?;
        io::copy(
            &mut (&mut r).take(u16::from_le_bytes(xlen) as u64),
            &mut io::sink(),
        )?;
    }
    for flag in [0x08, 0x10] {
        // FNAME, FCOMMENT: nul-terminated byte strings.
        if flg & flag != 0 {
            let mut discard = Vec::new();
            r.read_until(0, &mut discard)?;
            if discard.last() != Some(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated gzip header field",
                ));
            }
        }
    }
    if flg & 0x02 != 0 {
        // FHCRC: 2-byte header checksum.
        let mut hcrc = [0u8; 2];
        r.read_exact(&mut hcrc)?;
    }
    Ok(DeflateDecoder::new(r))
}

/// Unpack a tarball with zip bomb and overwrite protections.
///
/// Stow adaptation: the prefix/parent split is a parameter now — cargo
/// always derives `prefix` from `unpack_dir`'s name because a `.crate` is
/// named after its package directory. A codeload git tarball unpacks under
/// a `{repo}-{sha}` prefix that names the source, not the destination, so
/// [`git::codeload`] supplies both explicitly. Everything below is verbatim.
fn unpack(
    gctx: &GlobalContext,
    tarball: &mut File,
    unpack_dir: &Path,
    include: &dyn Fn(&Path) -> bool,
    keep_contents: &dyn Fn(&Path) -> bool,
    manifest_only: bool,
) -> CargoResult<u64> {
    let prefix = unpack_dir.file_name().unwrap().to_owned();
    let parent = unpack_dir.parent().unwrap().to_owned();
    unpack_prefixed(
        gctx,
        tarball,
        Path::new(&prefix),
        &parent,
        include,
        keep_contents,
        manifest_only,
    )
}

/// [`unpack`] with an explicit tarball top-level directory and destination
/// parent. `unpack_dir` becomes `parent.join(prefix)`.
///
/// `keep_contents` selects which regular files carry their real bytes into
/// the destination; files it rejects land as empty entries so paths, target
/// autodiscovery and directory listings are unchanged while contents the
/// consumer never reads cost nothing. Directories always materialize.
///
/// `manifest_only` applies when the caller has proven the manifest
/// declares every target explicitly: entries the manifest doesn't select
/// are skipped entirely (no stubs, no directory records), and the walk
/// ends once `Cargo.toml` is written — the archive tail is never
/// decompressed.
pub(crate) fn unpack_prefixed(
    gctx: &GlobalContext,
    tarball: &mut File,
    prefix: &Path,
    parent: &Path,
    include: &dyn Fn(&Path) -> bool,
    keep_contents: &dyn Fn(&Path) -> bool,
    manifest_only: bool,
) -> CargoResult<u64> {
    let mut tar = {
        let size_limit = max_unpack_size(gctx, tarball.metadata()?.len());
        let gz = verified_deflate_reader(tarball)?;
        let gz = LimitErrorReader::new(gz, size_limit);
        let mut tar = Archive::new(gz);
        set_mask(&mut tar);
        tar
    };
    let mut bytes_written = 0;
    for entry in tar.entries()? {
        let mut entry = entry.context("failed to iterate over archive")?;
        let entry_path = entry
            .path()
            .context("failed to read entry path")?
            .into_owned();

        // Adaptation: git tarballs (codeload) carry a `pax_global_header`
        // pseudo-entry next to the prefix; crates.io tarballs never do.
        if entry_path == Path::new("pax_global_header") {
            continue;
        }

        let rel_path = match entry_path.strip_prefix(prefix) {
            Ok(path) => {
                if !include(path) {
                    continue;
                }
                path
            }
            Err(_) => {
                // We're going to unpack this tarball into the global source
                // directory, but we want to make sure that it doesn't accidentally
                // (or maliciously) overwrite source code from other crates. Cargo
                // itself should never generate a tarball that hits this error, and
                // crates.io should also block uploads with these sorts of tarballs,
                // but be extra sure by adding a check here as well.
                anyhow::bail!(
                    "invalid tarball downloaded, contains \
                         a file at {entry_path:?} which isn't under {prefix:?}",
                )
            }
        };

        // Prevent unpacking symlinks and other unexpected entry types
        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Directory => {}
            t => anyhow::bail!(
                "invalid tarball downloaded, contains an entry at {entry_path:?} with invalid type {t:?}",
            ),
        }

        // Prevent unpacking the lockfile from the crate itself.
        if entry_path
            .file_name()
            .map_or(false, |p| p == PACKAGE_SOURCE_LOCK)
        {
            continue;
        }
        if manifest_only && !keep_contents(rel_path) {
            continue;
        }
        // Unpacking failed
        bytes_written += entry.size();
        let keep = entry.header().entry_type() == EntryType::Directory || keep_contents(rel_path);
        #[cfg(not(target_family = "wasm"))]
        let mut result = if keep {
            entry.unpack_in(parent).map_err(anyhow::Error::from)
        } else {
            unpack_stub(&entry_path, parent)
        };
        // `Entry::unpack_in` writes through `std::fs`; on wasm32 the ambient
        // VFS carries the same tree (and a memory tree needs no directory
        // records).
        #[cfg(target_family = "wasm")]
        let mut result = if keep {
            unpack_entry_vfs(&mut entry, parent)
        } else {
            unpack_stub(&entry_path, parent)
        };
        if cfg!(windows) && restricted_names::is_windows_reserved_path(&entry_path) {
            result = result.with_context(|| {
                format!(
                    "`{}` appears to contain a reserved Windows path, \
                        it cannot be extracted on Windows",
                    entry_path.display()
                )
            });
        }
        result.with_context(|| format!("failed to unpack entry at `{}`", entry_path.display()))?;
        if manifest_only && rel_path == Path::new("Cargo.toml") {
            // The manifest is the only entry carrying resolve input — the
            // rest of the archive is never decompressed.
            break;
        }
    }

    Ok(bytes_written)
}

/// Scan a `.crate` archive only until its `Cargo.toml`, returning the
/// manifest's bytes. Tarballs sort the manifest near the front, so the
/// scan decompresses a fraction of the archive. `None` when the archive
/// carries no manifest — the caller falls back to the stub path and the
/// resolve fails on the missing manifest as it would anyway.
fn read_manifest_bytes(gctx: &GlobalContext, tarball: &mut File) -> CargoResult<Option<Vec<u8>>> {
    let size_limit = max_unpack_size(gctx, tarball.metadata()?.len());
    let gz = verified_deflate_reader(tarball)?;
    let gz = LimitErrorReader::new(gz, size_limit);
    let mut tar = Archive::new(gz);
    for entry in tar.entries()? {
        let mut entry = entry.context("failed to iterate over archive")?;
        let entry_path = entry
            .path()
            .context("failed to read entry path")?
            .into_owned();
        // crates.io packs the manifest as `{prefix}/Cargo.toml`; a
        // `Cargo.toml` deeper in the tree belongs to a nested path.
        if entry.header().entry_type() != EntryType::Regular
            || entry_path.components().count() != 2
            || entry_path.file_name() != Some(std::ffi::OsStr::new("Cargo.toml"))
        {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        return Ok(Some(buf));
    }
    Ok(None)
}

/// Whether a published manifest declares every target itself: each
/// `auto*` flag off, every declared target carrying `name` + `path` —
/// the same condition `targets.rs::are_normalized_` applies per kind —
/// plus an explicit `build` (`normalize_build` probes `build.rs` on disk
/// when the key is absent). Manifests failing this load through
/// filesystem autodiscovery and still need the stub tree.
fn manifest_is_normalized(manifest: &[u8]) -> bool {
    let Ok(manifest) = std::str::from_utf8(manifest) else {
        return false;
    };
    let Ok(manifest) = toml::from_str::<toml::Table>(manifest) else {
        return false;
    };
    let Some(package) = manifest.get("package").and_then(|p| p.as_table()) else {
        return false;
    };
    for key in [
        "autolib",
        "autobins",
        "autoexamples",
        "autotests",
        "autobenches",
    ] {
        if package.get(key).and_then(|v| v.as_bool()) != Some(false) {
            return false;
        }
    }
    if !package.contains_key("build") {
        return false;
    }
    fn target_complete(target: &toml::Table) -> bool {
        target.contains_key("name") && target.contains_key("path")
    }
    ["lib", "bin", "example", "test", "bench"]
        .into_iter()
        .all(|key| {
            manifest.get(key).is_none_or(|targets| match targets {
                toml::Value::Table(target) => target_complete(target),
                toml::Value::Array(targets) => targets
                    .iter()
                    .all(|t| t.as_table().is_some_and(target_complete)),
                _ => false,
            })
        })
}

/// Materialize a file entry as an empty file — the path exists for target
/// autodiscovery and directory listings without carrying contents the
/// consumer never reads. The entry body is skipped, not read.
#[cfg(not(target_family = "wasm"))]
fn unpack_stub(entry_path: &Path, parent: &Path) -> anyhow::Result<bool> {
    let dst = parent.join(entry_path);
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&dst, b"")?;
    Ok(true)
}

/// [`unpack_stub`] over the ambient [`crate::util::fs::Vfs`].
#[cfg(target_family = "wasm")]
fn unpack_stub(entry_path: &Path, parent: &Path) -> anyhow::Result<bool> {
    let dst = parent.join(entry_path);
    if let Some(dir) = dst.parent() {
        crate::util::fs::create_dir_all(dir)?;
    }
    crate::util::fs::write(&dst, Vec::new())?;
    Ok(true)
}

/// `Entry::unpack_in` over the ambient [`crate::util::fs::Vfs`].
///
/// `tar` crate entries are limited to regular files and directories by the
/// caller's type check, so this reproduces `unpack_in`'s shape: directory
/// entries materialize their path (a no-op record on `MemoryVfs`), file
/// entries create the parent and write their contents. `std::fs` does not
/// exist on wasm32-unknown-unknown — `Entry::unpack_in` cannot run there.
#[cfg(target_family = "wasm")]
fn unpack_entry_vfs<R: std::io::Read>(
    entry: &mut tar::Entry<'_, R>,
    parent: &Path,
) -> anyhow::Result<bool> {
    let dst = parent.join(entry.path()?);
    if entry.header().entry_type() == EntryType::Directory {
        crate::util::fs::create_dir_all(&dst)?;
    } else {
        if let Some(dir) = dst.parent() {
            crate::util::fs::create_dir_all(dir)?;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        std::io::Read::read_to_end(entry, &mut buf)?;
        crate::util::fs::write(&dst, buf)?;
    }
    Ok(true)
}

/// Workaround for rust-lang/cargo#16237
///
/// Generated files should have the same deterministic mtime as other files.
/// However, since we forgot to set mtime for those files when uploading, they
/// always have older mtime (1973-11-29) that prevents zip from packing (requiring >1980)
///
/// This workaround updates mtime after we unpack the tarball at the destination.
fn update_mtime_for_generated_files(pkg_root: &Path) {
    const GENERATED_FILES: &[&str] = &["Cargo.lock", "Cargo.toml", ".cargo_vcs_info.json"];
    // Hardcoded value be removed once alexcrichton/tar-rs#420 is merged and released.
    // See also rust-lang/cargo#16237
    const DETERMINISTIC_TIMESTAMP: i64 = 1153704088;

    for file in GENERATED_FILES {
        let path = pkg_root.join(file);
        let mtime = FileTime::from_unix_time(DETERMINISTIC_TIMESTAMP, 0);
        if let Err(e) = crate::util::filetime::set_file_mtime(&path, mtime) {
            tracing::trace!("failed to set deterministic mtime for {path:?}: {e}");
        }
    }
}

/// What [`stage_crate_stream`] retained from a streamed `.crate` body: the
/// manifest's bytes (when the archive carries one) plus the relative paths
/// [`unpack_prefixed`] would have materialized — regular files as stubs,
/// directories as records — and the sha256 of the whole compressed body.
///
/// Target-independent: only the wasm download path calls it today, but the
/// logic is exercised natively by the unit tests below.
#[derive(Debug)]
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
struct StagedCrate {
    /// `{prefix}/Cargo.toml` bytes, `None` when the archive has no manifest.
    manifest: Option<Vec<u8>>,
    /// Regular files (excluding the manifest and `.cargo-ok`) to create as
    /// empty stubs — paths relative to the package directory.
    files: Vec<PathBuf>,
    /// Directory entries to materialize — paths relative to the package
    /// directory.
    dirs: Vec<PathBuf>,
    /// `unpack_prefixed`'s `bytes_written`: declared size of every staged
    /// entry (the manifest counts, `.cargo-ok` does not).
    bytes_written: u64,
    /// Hex sha256 over the full compressed body, tail drained and hashed
    /// even when the manifest walk stopped early.
    sha256: String,
}

/// A [`BodyStream`] as an [`futures::io::AsyncRead`] that hashes every raw
/// chunk the moment it arrives — bytes buffered downstream (BufReader,
/// gzip) are already counted, so draining the tail after an early stop
/// covers the whole body.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
struct HashingBody {
    body: BodyStream,
    sha: sha256::Sha256,
    pending: Vec<u8>,
    pos: usize,
}

#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
impl futures::io::AsyncRead for HashingBody {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        while self.pos == self.pending.len() {
            self.pending.clear();
            self.pos = 0;
            match self.body.poll_next_unpin(cx) {
                std::task::Poll::Ready(Some(Ok(chunk))) => {
                    self.sha.update(&chunk);
                    self.pending = chunk;
                    if self.pending.is_empty() {
                        continue;
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(io::Error::other(format!("{e:#}"))));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(0)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        let n = buf.len().min(self.pending.len() - self.pos);
        buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        std::task::Poll::Ready(Ok(n))
    }
}

/// One-pass version of [`RegistrySource::unpack_package`]'s read side over a
/// streamed `.crate` body: decodes `tar.gz` from the wire, keeps the
/// manifest's bytes and the path skeleton [`unpack_prefixed`] would write
/// (files as empty stubs, dirs as records, `.cargo-ok` skipped), and hashes
/// the compressed body as it flows.
///
/// Mirrors `read_manifest_bytes` + `unpack_prefixed` error deferral: a
/// manifest that normalizes every target ends the walk (violation records
/// gathered before it are discarded); otherwise the first archive-order
/// violation — a path outside `prefix` or a non-file/dir member — is the
/// error, exactly where the sequential walk would hit it.
///
/// The compressed tail is always drained after the walk (early stop or
/// clean end) so `sha256` covers every byte and the body — and the outbound
/// pool permit it holds — is fully consumed before returning.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
async fn stage_crate_stream(
    body: BodyStream,
    prefix: &Path,
    decompressed_limit: u64,
) -> CargoResult<StagedCrate> {
    let hashing = HashingBody {
        body,
        sha: sha256::Sha256::new(),
        pending: Vec::new(),
        pos: 0,
    };
    let reader = futures::io::BufReader::new(hashing);
    let gz = async_compression::futures::bufread::GzipDecoder::new(reader);
    let mut tar = tarball::TarGz::new(gz, decompressed_limit);

    let mut staged = StagedCrate {
        manifest: None,
        files: Vec::new(),
        dirs: Vec::new(),
        bytes_written: 0,
        sha256: String::new(),
    };
    // First violation seen before the manifest arrives — surfaced only if
    // the manifest proves not to be normalized (or never arrives).
    let mut deferred: Option<anyhow::Error> = None;
    // The manifest was found and is not normalized: violations error out
    // immediately from here on.
    let mut staging = false;
    // The manifest normalized every target — the walk stopped early and
    // deferred violations are discarded.
    let mut normalized = false;

    while let Some(entry) = tar.next().await? {
        // `unpack_prefixed` parity: git tarballs carry a `pax_global_header`
        // pseudo-entry next to the prefix.
        if entry.path == Path::new("pax_global_header") {
            tar.skip_body().await?;
            continue;
        }
        // `read_manifest_bytes` finds the manifest without checking the
        // prefix: two components, named `Cargo.toml`, regular file.
        if staged.manifest.is_none()
            && matches!(entry.member, tarball::TarMember::File)
            && entry.path.components().count() == 2
            && entry.path.file_name() == Some(std::ffi::OsStr::new("Cargo.toml"))
        {
            let mut manifest = Vec::with_capacity(entry.size as usize);
            tar.read_body(&mut manifest).await?;
            if manifest_is_normalized(&manifest) {
                // Every target is declared — nothing else is staged, and
                // violations gathered so far are discarded with the tree.
                staged.bytes_written = manifest.len() as u64;
                staged.manifest = Some(manifest);
                staged.files.clear();
                staged.dirs.clear();
                normalized = true;
                break;
            }
            if let Some(e) = deferred.take() {
                return Err(e);
            }
            // The manifest itself must sit under the prefix for the unpack
            // to proceed — the same violation the walk would report.
            if entry.path.strip_prefix(prefix).is_err() {
                anyhow::bail!(
                    "invalid tarball downloaded, contains \
                     a file at {:?} which isn't under {prefix:?}",
                    entry.path,
                );
            }
            staged.manifest = Some(manifest);
            staged.bytes_written += entry.size;
            staging = true;
            continue;
        }
        let violation = || -> Option<anyhow::Error> {
            if entry.path.strip_prefix(prefix).is_err() {
                return Some(anyhow::format_err!(
                    "invalid tarball downloaded, contains \
                     a file at {:?} which isn't under {prefix:?}",
                    entry.path,
                ));
            }
            match entry.member {
                tarball::TarMember::File | tarball::TarMember::Directory => None,
                _ => Some(anyhow::format_err!(
                    "invalid tarball downloaded, contains an entry at {:?} with invalid type {:?}",
                    entry.path,
                    entry.member,
                )),
            }
        }();
        if let Some(e) = violation {
            if staging {
                return Err(e);
            }
            if deferred.is_none() {
                deferred = Some(e);
            }
            tar.skip_body().await?;
            continue;
        }
        // Prevent unpacking the lockfile from the crate itself.
        if entry
            .path
            .file_name()
            .map_or(false, |p| p == PACKAGE_SOURCE_LOCK)
        {
            tar.skip_body().await?;
            continue;
        }
        let rel = entry.path.strip_prefix(prefix).unwrap();
        staged.bytes_written += entry.size;
        match entry.member {
            tarball::TarMember::Directory => staged.dirs.push(rel.to_path_buf()),
            tarball::TarMember::File => {
                // `unpack_prefixed` keeps contents only for the manifest —
                // every other file lands as an empty stub.
                if rel != Path::new("Cargo.toml") {
                    staged.files.push(rel.to_path_buf());
                }
            }
            _ => unreachable!("violation check above covers non-file/dir members"),
        }
        tar.skip_body().await?;
    }
    if !normalized {
        if let Some(e) = deferred.take() {
            return Err(e);
        }
    }

    // Drain the compressed tail so the checksum covers every byte and the
    // body's pool permit is released on a full read.
    let hashing = tar.into_inner().into_inner().into_inner();
    let mut sha = hashing.sha;
    let mut body = hashing.body;
    while let Some(chunk) = body.next().await {
        sha.update(&chunk?);
    }
    staged.sha256 = sha.finish_hex();
    Ok(staged)
}

/// [`download::finish_download`]'s streamed counterpart: the checksum is
/// verified before anything is written, then the staged tree lands in
/// `src_dir` exactly the way `unpack_package` writes it — dirs and stubs,
/// the manifest, `.cargo-ok` with [`LockMetadata`], the deterministic
/// mtimes — and the marker itself is returned as the `Ready` handle, so
/// `get_pkg` → `unpack_package` fast-paths on it without reading a tarball.
///
/// Target-independent; only the wasm `finish_download` arm calls it, and
/// the unit tests exercise it over the ambient VFS.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
fn admit_staged_crate(
    gctx: &GlobalContext,
    src_path: &Filesystem,
    encoded_registry_name: InternedString,
    pkg: PackageId,
    checksum: &str,
    staged: &StagedCrate,
) -> CargoResult<File> {
    if staged.sha256 != checksum {
        anyhow::bail!("failed to verify the checksum of `{pkg}`");
    }
    let package_dir = format!("{}-{}", pkg.name(), pkg.version());
    let dst = src_path.join(&package_dir);
    let ok_path = dst.join(PACKAGE_SOURCE_LOCK);
    let ok_path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &ok_path);
    let unpack_dir = ok_path.parent().unwrap();
    dst.create_dir()?;
    for rel in &staged.dirs {
        fs::create_dir_all(unpack_dir.join(rel))?;
    }
    for rel in &staged.files {
        let path = unpack_dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, Vec::new())?;
    }
    if let Some(manifest) = &staged.manifest {
        fs::write(unpack_dir.join("Cargo.toml"), manifest)?;
    }
    update_mtime_for_generated_files(unpack_dir);
    let mut ok = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&ok_path)
        .with_context(|| format!("failed to open `{}`", ok_path.display()))?;
    let lock_meta = LockMetadata { v: 1 };
    write!(ok, "{}", serde_json::to_string(&lock_meta).unwrap())?;
    gctx.deferred_global_last_use()?
        .mark_registry_src_used(global_cache_tracker::RegistrySrc {
            encoded_registry_name,
            package_dir: package_dir.into(),
            size: Some(staged.bytes_written),
        });
    paths::open(ok_path)
}

#[cfg(target_family = "wasm")]
impl<'gctx> RegistrySource<'gctx> {
    /// Stream a `.crate` response straight into the source tree: the body
    /// never exists whole — it is decoded off the wire, hashed, and the
    /// staged stubs are admitted by [`admit_staged_crate`] only after the
    /// checksum proves out.
    async fn admit_streamed_crate(
        &self,
        pkg: PackageId,
        checksum: &str,
        body: http::Response<BodyStream>,
    ) -> CargoResult<File> {
        let content_length = body
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let limit = content_length
            .map(|l| max_unpack_size(self.gctx, l))
            .unwrap_or_else(|| tarball::unpack_size_bound(None));
        let package_dir = format!("{}-{}", pkg.name(), pkg.version());
        let staged = stage_crate_stream(body.into_body(), Path::new(&package_dir), limit).await?;
        admit_staged_crate(self.gctx, &self.src_path, self.name, pkg, checksum, &staged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::EitherManifest;
    use crate::util::toml::read_manifest;
    use std::rc::Rc;

    /// Build `prefix/` entries into a gzipped `.crate`.
    fn fake_crate(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, format!("{prefix}/{name}"), *data)
                .unwrap();
        }
        let tar_bytes = tar.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    /// Unpack a `.crate` the way `unpack_package` decides: scan the
    /// manifest, then either the manifest-only walk or the sparse-stub
    /// one. Returns whether the manifest-only path ran.
    fn unpack_registry_fixture(
        gctx: &GlobalContext,
        crate_bytes: &[u8],
        dst_parent: &Path,
        prefix: &str,
    ) -> CargoResult<bool> {
        let crate_path = dst_parent.join(format!("{prefix}.crate"));
        fs::write(&crate_path, crate_bytes)?;
        let mut tarball = paths::open(&crate_path)?;
        let manifest_only = read_manifest_bytes(gctx, &mut tarball)?
            .is_some_and(|manifest| manifest_is_normalized(&manifest));
        tarball.seek(io::SeekFrom::Start(0))?;
        unpack(
            gctx,
            &mut tarball,
            &dst_parent.join(prefix),
            &|_| true,
            &|p| p == Path::new("Cargo.toml"),
            manifest_only,
        )?;
        Ok(manifest_only)
    }

    /// `(name, kind, package-relative source path)` per manifest target —
    /// the fields a resolve consumes; the absolute `src_path` embeds the
    /// extraction dir and can't compare across trees.
    fn fixture_targets(
        gctx: &GlobalContext,
        source_id: SourceId,
        dir: &Path,
    ) -> Vec<(String, String, PathBuf)> {
        let manifest = match read_manifest(&dir.join("Cargo.toml"), source_id, gctx)
            .expect("manifest loads")
        {
            EitherManifest::Real(m) => m,
            EitherManifest::Virtual(_) => panic!("a package dir is not virtual"),
        };
        manifest
            .targets()
            .iter()
            .map(|t| {
                (
                    t.name().to_string(),
                    format!("{:?}", t.kind()),
                    t.src_path()
                        .path()
                        .and_then(|p| p.strip_prefix(dir).ok().map(|p| p.to_path_buf()))
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    /// The manifest-only walk plus the scan's manifest read together must
    /// produce exactly the target set a full unpack produces — for a
    /// normalized manifest and for a non-normalized one alike.
    #[test]
    fn manifest_only_unpack_matches_full_unpack() {
        // Host `unpack` writes through `std::fs` (`Entry::unpack_in`), so
        // the ambient VFS is the OS filesystem here and every path is real.
        fs::set_vfs(Rc::new(crate::util::fs::OsVfs));
        let gctx = GlobalContext::default().unwrap();
        let source_id = SourceId::crates_io(&gctx).unwrap();
        let temp = std::env::temp_dir().join(format!("stow-unpack-{}", std::process::id()));
        std::fs::create_dir_all(temp.join("sparse")).unwrap();
        std::fs::create_dir_all(temp.join("full")).unwrap();
        let normalized_manifest = concat!(
            "[package]\n",
            "name = \"nrm\"\n",
            "version = \"1.0.0\"\n",
            "edition = \"2021\"\n",
            "autolib = false\n",
            "autobins = false\n",
            "autoexamples = false\n",
            "autotests = false\n",
            "autobenches = false\n",
            "build = false\n",
            "\n",
            "[lib]\n",
            "name = \"nrm\"\n",
            "path = \"src/lib.rs\"\n",
            "\n",
            "[[bin]]\n",
            "name = \"nrm-cli\"\n",
            "path = \"src/bin/nrm.rs\"\n",
        );
        let non_normalized_manifest =
            concat!("[package]\n", "name = \"old\"\n", "version = \"1.0.0\"\n",);
        let blob = vec![7u8; 1024 * 1024];
        for (prefix, manifest, expect_manifest_only) in [
            ("nrm-1.0.0", normalized_manifest, true),
            ("old-1.0.0", non_normalized_manifest, false),
        ] {
            let crate_bytes = fake_crate(
                prefix,
                &[
                    (".cargo_vcs_info.json", b"{}" as &[u8]),
                    ("Cargo.toml", manifest.as_bytes()),
                    ("Cargo.toml.orig", b"[package]\n"),
                    ("src/lib.rs", b"pub fn f() {}\n"),
                    ("src/bin/nrm.rs", b"fn main() {}\n"),
                    ("src/bin/extra.rs", b"fn main() {}\n"),
                    ("src/blob.bin", blob.as_slice()),
                    ("build.rs", b"fn main() {}\n"),
                ],
            );
            let manifest_only =
                unpack_registry_fixture(&gctx, &crate_bytes, &temp.join("sparse"), prefix).unwrap();
            assert_eq!(manifest_only, expect_manifest_only, "{prefix}");

            // The reference tree: every entry with real contents.
            let crate_path = temp.join("full").join(format!("{prefix}.crate"));
            fs::write(&crate_path, &crate_bytes).unwrap();
            let mut tarball = paths::open(&crate_path).unwrap();
            unpack(
                &gctx,
                &mut tarball,
                &temp.join("full").join(prefix),
                &|_| true,
                &|_| true,
                false,
            )
            .unwrap();

            assert!(
                fixture_targets(&gctx, source_id.clone(), &temp.join("sparse").join(prefix))
                    == fixture_targets(&gctx, source_id.clone(), &temp.join("full").join(prefix)),
                "{prefix}: target sets must match a full unpack"
            );
        }

        // And the normalized tree carries no stub entries at all — only
        // the manifest.
        let normalized_dir = temp.join("sparse").join("nrm-1.0.0");
        let mut total = 0;
        let mut entries = 0;
        let mut walk = vec![normalized_dir.clone()];
        while let Some(dir) = walk.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk.push(path);
                } else {
                    entries += 1;
                    total += path.metadata().unwrap().len();
                }
            }
        }
        assert_eq!(
            (entries, total),
            (1, normalized_manifest.len() as u64),
            "normalized manifests leave only Cargo.toml behind"
        );

        // The non-normalized tree still keeps every path as a stub.
        let non_normalized_dir = temp.join("sparse").join("old-1.0.0");
        assert!(non_normalized_dir.join("src/blob.bin").is_file());
        assert_eq!(
            std::fs::metadata(non_normalized_dir.join("src/blob.bin"))
                .unwrap()
                .len(),
            0
        );

        let _ = std::fs::remove_dir_all(&temp);
        fs::replace_vfs(None);
    }

    #[tokio::test]
    async fn registry_packages_release_manifest_source() {
        fs::set_vfs(Rc::new(crate::util::fs::OsVfs));
        let temp = std::env::temp_dir().join(format!(
            "stow-registry-release-source-{}",
            std::process::id()
        ));
        let registry = temp.join("registry");
        let cargo_home = temp.join("cargo-home");
        fs::create_dir_all(&temp).unwrap();
        let gctx = GlobalContext::new_for_resolve(
            temp.clone(),
            cargo_home,
            crate::util::shell::Shell::new(),
            crate::util::context::environment::Env::new(),
            false,
        )
        .unwrap();
        let index_path = registry.join("index/fa/tt/fatty");
        fs::create_dir_all(index_path.parent().unwrap()).unwrap();

        let manifest = concat!(
            "[package]\n",
            "name = \"fatty\"\n",
            "version = \"1.0.0\"\n",
            "edition = \"2021\"\n",
        );
        let crate_bytes = fake_crate(
            "fatty-1.0.0",
            &[
                ("Cargo.toml", manifest.as_bytes()),
                ("src/lib.rs", b"pub fn f() {}\n"),
            ],
        );
        let checksum = crate::util::sha256::Sha256::new()
            .update(&crate_bytes)
            .finish_hex();
        fs::write(
            &index_path,
            format!(
                "{{\"name\":\"fatty\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
            ),
        )
        .unwrap();
        fs::write(registry.join("fatty-1.0.0.crate"), crate_bytes).unwrap();

        let source_id = SourceId::for_local_registry(&registry).unwrap();
        let package_id = PackageId::try_new("fatty", "1.0.0", source_id).unwrap();
        let _lock = gctx
            .acquire_package_cache_lock(CacheLockMode::DownloadExclusive)
            .unwrap();
        let source = RegistrySource::local(source_id, &registry, &gctx);
        let package = match source.download(package_id).await.unwrap() {
            MaybePackage::Ready(package) => package,
            MaybePackage::Download { .. } => panic!("local registry requested a download"),
        };

        let manifest = package.manifest();
        assert!(manifest.contents().is_none());
        assert!(manifest.document().is_none());
        assert!(manifest.original_toml().is_none());
        assert_eq!(manifest.summary().package_id(), package_id);
        assert_eq!(manifest.summary().checksum(), Some(checksum.as_str()));

        let _ = std::fs::remove_dir_all(&temp);
        fs::replace_vfs(None);
    }

    /// A manifest declaring every target (`auto*` off, `build` explicit,
    /// `[lib]` with name+path) — `manifest_is_normalized` holds.
    const NORMALIZED_MANIFEST: &str = concat!(
        "[package]\n",
        "name = \"nrm\"\n",
        "version = \"1.0.0\"\n",
        "edition = \"2021\"\n",
        "autolib = false\n",
        "autobins = false\n",
        "autoexamples = false\n",
        "autotests = false\n",
        "autobenches = false\n",
        "build = false\n",
        "\n",
        "[lib]\n",
        "name = \"nrm\"\n",
        "path = \"src/lib.rs\"\n",
    );
    const PLAIN_MANIFEST: &str =
        concat!("[package]\n", "name = \"old\"\n", "version = \"1.0.0\"\n");

    /// A gzip'd `.crate` built in memory from `(name, entry_type, link,
    /// body)` members — `fake_crate` with dirs and symlinks too.
    fn stream_crate(entries: &[(&str, tar::EntryType, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, link, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    fn chunked_body(bytes: &[u8], chunk: usize) -> BodyStream {
        let chunks: Vec<CargoResult<Vec<u8>>> =
            bytes.chunks(chunk).map(|c| Ok(c.to_vec())).collect();
        tarball::body_stream(futures::stream::iter(chunks))
    }

    const PREFIX: &str = "pkg-1.0.0";

    async fn stage(bytes: &[u8]) -> CargoResult<StagedCrate> {
        stage_crate_stream(
            chunked_body(bytes, 977),
            Path::new(PREFIX),
            tarball::unpack_size_bound(Some(bytes.len() as u64)),
        )
        .await
    }

    #[tokio::test]
    async fn stage_normalized_manifest_stops_at_manifest() {
        let crate_bytes = stream_crate(&[
            (
                "pkg-1.0.0/Cargo.toml",
                tar::EntryType::Regular,
                None,
                NORMALIZED_MANIFEST.as_bytes(),
            ),
            (
                "pkg-1.0.0/src/lib.rs",
                tar::EntryType::Regular,
                None,
                b"pub fn f() {}\n",
            ),
            (
                "pkg-1.0.0/src/bin/x.rs",
                tar::EntryType::Regular,
                None,
                b"fn main() {}\n",
            ),
        ]);
        let staged = stage(&crate_bytes).await.unwrap();
        assert_eq!(
            staged.manifest.as_deref(),
            Some(NORMALIZED_MANIFEST.as_bytes())
        );
        assert!(staged.files.is_empty() && staged.dirs.is_empty());
        assert_eq!(staged.bytes_written, NORMALIZED_MANIFEST.len() as u64);
        assert_eq!(
            staged.sha256,
            sha256::Sha256::new().update(&crate_bytes).finish_hex(),
            "the compressed tail was drained and hashed past the manifest"
        );
    }

    #[tokio::test]
    async fn stage_non_normalized_stages_stub_tree() {
        let crate_bytes = stream_crate(&[
            ("pkg-1.0.0/.cargo-ok", tar::EntryType::Regular, None, b"ok"),
            (
                "pkg-1.0.0/Cargo.toml",
                tar::EntryType::Regular,
                None,
                PLAIN_MANIFEST.as_bytes(),
            ),
            ("pkg-1.0.0/src", tar::EntryType::Directory, None, b""),
            (
                "pkg-1.0.0/src/lib.rs",
                tar::EntryType::Regular,
                None,
                b"pub fn f() {}\n",
            ),
            (
                "pkg-1.0.0/sub/Cargo.toml",
                tar::EntryType::Regular,
                None,
                b"[package]\n",
            ),
        ]);
        let staged = stage(&crate_bytes).await.unwrap();
        assert_eq!(staged.manifest.as_deref(), Some(PLAIN_MANIFEST.as_bytes()));
        assert_eq!(
            staged.dirs,
            vec![PathBuf::from("src")],
            "dirs are recorded relative to the prefix"
        );
        assert_eq!(
            staged.files,
            vec![PathBuf::from("src/lib.rs"), PathBuf::from("sub/Cargo.toml"),],
            "every non-manifest file is a stub — a nested Cargo.toml too"
        );
        // `.cargo-ok` is skipped before `bytes_written`; the manifest counts.
        assert_eq!(
            staged.bytes_written,
            (PLAIN_MANIFEST.len() + b"pub fn f() {}\n".len() + b"[package]\n".len()) as u64
        );
        assert_eq!(
            staged.sha256,
            sha256::Sha256::new().update(&crate_bytes).finish_hex()
        );
    }

    #[tokio::test]
    async fn stage_defers_violations_until_the_manifest_decides() {
        fn entries(
            manifest: &[u8],
        ) -> Vec<(&'static str, tar::EntryType, Option<&'static str>, &[u8])> {
            vec![
                (
                    "other-1.0.0/evil.rs",
                    tar::EntryType::Regular,
                    None,
                    b"fn evil() {}\n",
                ),
                (
                    "pkg-1.0.0/Cargo.toml",
                    tar::EntryType::Regular,
                    None,
                    manifest,
                ),
            ]
        }
        // Normalized: the violation is discarded with the tree.
        let crate_bytes = stream_crate(&entries(NORMALIZED_MANIFEST.as_bytes()));
        let staged = stage(&crate_bytes).await.unwrap();
        assert_eq!(
            staged.manifest.as_deref(),
            Some(NORMALIZED_MANIFEST.as_bytes())
        );

        // Not normalized: the first archive-order violation is the error.
        let crate_bytes = stream_crate(&entries(PLAIN_MANIFEST.as_bytes()));
        let error = stage(&crate_bytes).await.unwrap_err();
        assert!(error.to_string().contains("isn't under"), "{error}");
    }

    #[tokio::test]
    async fn stage_rejects_non_file_members() {
        let crate_bytes = stream_crate(&[
            (
                "pkg-1.0.0/link.rs",
                tar::EntryType::Symlink,
                Some("src/lib.rs"),
                b"",
            ),
            (
                "pkg-1.0.0/Cargo.toml",
                tar::EntryType::Regular,
                None,
                PLAIN_MANIFEST.as_bytes(),
            ),
        ]);
        let error = stage(&crate_bytes).await.unwrap_err();
        assert!(error.to_string().contains("invalid type"), "{error}");
    }

    #[tokio::test]
    async fn stage_without_manifest_stages_stubs() {
        let crate_bytes = stream_crate(&[
            ("pkg-1.0.0/src", tar::EntryType::Directory, None, b""),
            (
                "pkg-1.0.0/src/lib.rs",
                tar::EntryType::Regular,
                None,
                b"pub fn f() {}\n",
            ),
        ]);
        let staged = stage(&crate_bytes).await.unwrap();
        assert!(staged.manifest.is_none());
        assert_eq!(staged.files, vec![PathBuf::from("src/lib.rs")]);
        assert_eq!(staged.dirs, vec![PathBuf::from("src")]);
        assert_eq!(
            staged.sha256,
            sha256::Sha256::new().update(&crate_bytes).finish_hex()
        );
    }

    #[tokio::test]
    async fn admit_rejects_a_checksum_mismatch_before_writing() {
        fs::set_vfs(Rc::new(crate::util::fs::OsVfs));
        let temp = std::env::temp_dir().join(format!("stow-admit-{}", std::process::id()));
        fs::create_dir_all(&temp).unwrap();
        let gctx = GlobalContext::default().unwrap();
        let _lock = gctx
            .acquire_package_cache_lock(CacheLockMode::DownloadExclusive)
            .unwrap();
        let src_path = Filesystem::new(temp.join("src"));
        let source_id = SourceId::crates_io(&gctx).unwrap();
        let package_id = PackageId::try_new("pkg", "1.0.0", source_id).unwrap();

        let crate_bytes = stream_crate(&[(
            "pkg-1.0.0/Cargo.toml",
            tar::EntryType::Regular,
            None,
            PLAIN_MANIFEST.as_bytes(),
        )]);
        let staged = stage(&crate_bytes).await.unwrap();
        let error = admit_staged_crate(
            &gctx,
            &src_path,
            "registry".into(),
            package_id,
            "0".repeat(64).as_str(),
            &staged,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("failed to verify the checksum"),
            "{error}"
        );
        assert!(
            !src_path.join("pkg-1.0.0").as_path_unlocked().exists(),
            "nothing is written before the checksum proves out"
        );

        // And the happy path writes the staged tree plus the marker.
        let checksum = staged.sha256.clone();
        let ok = admit_staged_crate(
            &gctx,
            &src_path,
            "registry".into(),
            package_id,
            &checksum,
            &staged,
        )
        .unwrap();
        drop(ok);
        let dst = src_path.join("pkg-1.0.0");
        assert_eq!(
            fs::read_to_string(dst.join("Cargo.toml").as_path_unlocked()).unwrap(),
            PLAIN_MANIFEST
        );
        let ok_contents =
            fs::read_to_string(dst.join(PACKAGE_SOURCE_LOCK).as_path_unlocked()).unwrap();
        assert_eq!(
            serde_json::from_str::<LockMetadata>(&ok_contents)
                .unwrap()
                .v,
            1
        );

        let _ = std::fs::remove_dir_all(&temp);
        fs::replace_vfs(None);
    }
}
