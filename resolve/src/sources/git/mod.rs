//! Home of the git sources.
//!
//! [`GitTreeSource`] resolves every https git remote over plain HTTPS —
//! codeload tarballs for github.com, a shallow smart-HTTP `fetch` for
//! every other host — and runs on wasm32, so the worker and hosts share
//! one code path. [`utils`] provides the libgit2/gitoxide fetch utilities
//! the registry index still uses (host-only), whereas [`oxide`] is the
//! counterpart for gitoxide integration. [`known_hosts`] is the
//! mitigation of [CVE-2022-46176].
//!
//! [CVE-2022-46176]: https://blog.rust-lang.org/2023/01/10/cve-2022-46176.html

pub use self::tree::GitTreeSource;
#[cfg(not(target_family = "wasm"))]
pub use self::utils::{fetch, resolve_ref};
#[cfg(not(target_family = "wasm"))]
mod known_hosts;
#[cfg(not(target_family = "wasm"))]
mod oxide;
mod pack;
mod tree;
#[cfg(not(target_family = "wasm"))]
mod utils;

/// For `-Zgitoxide` integration.
#[cfg(not(target_family = "wasm"))]
pub mod fetch {
    use crate::GlobalContext;
    use crate::core::features::GitFeatures;

    /// The kind remote repository to fetch.
    #[derive(Debug, Copy, Clone)]
    pub enum RemoteKind {
        /// A repository belongs to a git dependency.
        GitDependency,
        /// A repository belongs to a Cargo registry.
        Registry,
    }

    impl RemoteKind {
        /// Obtain the kind of history we would want for a fetch from our remote knowing if the target repo is already shallow
        /// via `repo_is_shallow` along with gitoxide-specific feature configuration via `config`.
        /// `rev_and_ref` is additional information that affects whether or not we may be shallow.
        pub(crate) fn to_shallow_setting(
            &self,
            repo_is_shallow: bool,
            gctx: &GlobalContext,
        ) -> gix::remote::fetch::Shallow {
            let has_feature = |cb: &dyn Fn(GitFeatures) -> bool| {
                gctx.cli_unstable()
                    .git
                    .map_or(false, |features| cb(features))
            };

            // maintain shallow-ness and keep downloading single commits, or see if we can do shallow clones
            if !repo_is_shallow {
                match self {
                    RemoteKind::GitDependency if has_feature(&|features| features.shallow_deps) => {
                    }
                    RemoteKind::Registry if has_feature(&|features| features.shallow_index) => {}
                    _ => return gix::remote::fetch::Shallow::NoChange,
                }
            };

            gix::remote::fetch::Shallow::DepthAtRemote(1.try_into().expect("non-zero"))
        }
    }

    pub type Error = gix::env::collate::fetch::Error<gix::refspec::parse::Error>;
}
