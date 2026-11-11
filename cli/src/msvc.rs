//! The MSVC toolchain a sandboxed Windows build sees, shared by the stow
//! CLI's sandbox and the CI phase sandbox.
//!
//! Inside a sandbox rustc's and the `cc` crate's own MSVC discovery cannot
//! run `vswhere.exe`, so the sandbox is handed the variables a Visual
//! Studio developer prompt sets instead. `find_msvc_tools` — which both
//! rustc and `cc` use — reads them: when `VCINSTALLDIR` is set and
//! `VSCMD_ARG_TGT_ARCH` names a different architecture from the one a
//! tool is asked for, it derives that architecture's tool directory,
//! `LIB`, `INCLUDE` and `PATH` from `VSINSTALLDIR` and puts them in front
//! of the inherited ones; for the same architecture it uses the
//! inherited environment. One host-architecture environment therefore
//! serves the host-side links of build scripts and proc macros and the
//! target-side link of a `cdylib` alike, with no compiler or linker named
//! in the cargo configuration or in `RUSTFLAGS`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use heel::Access;
use stow_types::env_name;

/// Spells the host's MSVC lookup as the variables a developer prompt sets:
/// the host architecture's `PATH`, `LIB` and `INCLUDE`, the install roots
/// (`VSINSTALLDIR`, `VCINSTALLDIR`, `VCToolsInstallDir`), the host
/// architecture as `VSCMD_ARG_TGT_ARCH`, and — when the host has a Windows
/// 10 SDK — `WindowsSdkDir` and `WindowsSDKVersion`, which let
/// `find_msvc_tools` locate the SDK of another architecture without a
/// second registry read and directory scan. A host that is already in a
/// developer prompt passes through, and so yields no entries; a host with
/// no MSVC installation yields none either, with a warning.
///
/// # Errors
///
/// The host linker is outside the Visual Studio 2017+ layout, so its
/// install roots cannot be spelled.
pub fn developer_environment() -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    if std::env::var_os("VCINSTALLDIR").is_some() {
        return Ok(Vec::new());
    }
    let Some(tool) = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe") else {
        tracing::warn!(
            arch = std::env::consts::ARCH,
            "no MSVC installation found for the host; a sandboxed build that links will fail"
        );
        return Ok(Vec::new());
    };
    let mut envs = tool.env().into_iter().cloned().collect::<Vec<_>>();
    envs.extend(developer_prompt_vars(tool.path())?);
    envs.extend(windows_sdk_vars());
    Ok(envs)
}

/// The MSVC toolchain and Windows SDK a `*-msvc` build's `cl.exe` and
/// `link.exe` live in — located the way rustc and the `cc` crate
/// locate them, so the usual Visual Studio install that is not on
/// `PATH` is still found. `find_tool` answers `None` for non-msvc
/// targets, so each target — or architecture — is simply asked: a cross
/// build passes both its target and its host, and gets the directories
/// the lookup reads or runs from for each.
pub fn toolchain_grants(targets: &[impl AsRef<str>]) -> Vec<(PathBuf, Access, &'static str)> {
    let mut grants = Vec::new();
    for target in targets {
        for name in ["cl.exe", "link.exe"] {
            let Some(tool) = find_msvc_tools::find_tool(target.as_ref(), name) else {
                continue;
            };
            if let Some(dir) = tool.path().parent() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ | Access::EXEC,
                    "the MSVC tool's own directory",
                ));
            }
            for (key, value) in tool.env() {
                let host = std::env::var_os(key);
                let access = if env_name::eq(key, "PATH") {
                    Access::READ | Access::EXEC
                } else {
                    Access::READ
                };
                for dir in added_entries(value, host.as_deref()) {
                    if dir.is_dir() {
                        grants.push((
                            dir,
                            access,
                            "a directory the MSVC toolchain's environment names",
                        ));
                    }
                }
            }
        }
    }
    if let Some(sdk) = find_msvc_tools::find_windows_sdk(std::env::consts::ARCH) {
        for dir in sdk.path() {
            if dir.is_dir() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ | Access::EXEC,
                    "a Windows SDK binary directory",
                ));
            }
        }
        for dir in sdk.libs().chain(sdk.include()) {
            if dir.is_dir() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ,
                    "a Windows SDK library or include directory",
                ));
            }
        }
    }
    grants
}

/// Returns only entries `find_msvc_tools` prepended to the host's value.
/// Host PATH/LIB/INCLUDE entries are not toolchain entries to grant.
fn added_entries(composed: &OsStr, host: Option<&OsStr>) -> Vec<PathBuf> {
    let host_entries = host
        .map(|host| std::env::split_paths(host).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut added = Vec::new();
    for entry in std::env::split_paths(composed) {
        if !host_entries.contains(&entry) && !added.contains(&entry) {
            added.push(entry);
        }
    }
    added
}

/// The installation roots the MSVC discovery locates for the host —
/// the Visual Studio root a `link.exe` in the VS 2017+ layout implies
/// and the Windows kit roots the discovered SDK dirs sit under —
/// persisted READ|EXEC on the identity so the toolchain ACL is written
/// once, not per build (stow#815). A `link.exe` outside the VS layout —
/// an SDK or LLVM linker — names no Visual Studio installation, so it
/// adds no root; the per-build grants still cover its directory.
pub fn identity_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(tool) = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe")
        && let Ok(layout) = visual_studio_layout(tool.path())
    {
        roots.push(layout.visual_studio_dir);
    }
    if let Some(sdk) = find_msvc_tools::find_windows_sdk(std::env::consts::ARCH) {
        for dir in sdk.path().chain(sdk.libs()).chain(sdk.include()) {
            if let Some(root) = windows_kit_root(dir)
                && !roots.contains(&root)
            {
                roots.push(root);
            }
        }
    }
    roots
}

/// The kit installation root a discovered Windows SDK directory lives
/// under: every dir the discovery reports sits in the kit's `bin`, `lib`
/// or `include` tree, so the root is the ancestor above that component —
/// whatever `KitsRoot10` or `InstallationFolder` the registry named,
/// never a hardcoded drive. A `bin`/`lib`/`include` at a drive root names
/// no installation, and a dir with none of those components is not an
/// SDK dir; both yield `None`.
fn windows_kit_root(dir: &Path) -> Option<PathBuf> {
    let mut root = PathBuf::new();
    for component in dir.components() {
        if component.as_os_str().to_str().is_some_and(|name| {
            ["bin", "lib", "include"]
                .iter()
                .any(|tree| name.eq_ignore_ascii_case(tree))
        }) {
            return root
                .components()
                .any(|part| matches!(part, std::path::Component::Normal(_)))
                .then_some(root);
        }
        root.push(component.as_os_str());
    }
    None
}

/// The directories the Visual Studio 2017+ layout a `link.exe` path
/// implies — `VC\Tools\MSVC\<version>\bin\Host<arch>\<arch>\link.exe`
/// under the installation root — validated component by component so a
/// linker outside that layout cannot masquerade as an installation
/// root.
struct VsLayout {
    /// `VSCMD_ARG_TGT_ARCH` — the `<arch>` leaf the linker serves.
    target_arch: OsString,
    /// `VCToolsInstallDir` — the `MSVC\<version>` directory.
    version_dir: PathBuf,
    /// `VCINSTALLDIR` — the `VC` directory.
    vc_dir: PathBuf,
    /// `VSINSTALLDIR` — the Visual Studio installation root.
    visual_studio_dir: PathBuf,
}

/// Reads the [`VsLayout`] a Visual Studio 2017+ linker path spells.
/// Paths outside that layout return an error.
fn visual_studio_layout(link: &Path) -> stow_types::error::Result<VsLayout> {
    let invalid_layout = || {
        stow_types::stow_error!(
            "the linker at {} is not in the Visual Studio 2017+ layout, so the sandbox cannot spell out its developer environment",
            link.display()
        )
    };
    let mut up = link.ancestors().skip(1);
    let (
        Some(target_dir),
        Some(host_dir),
        Some(bin_dir),
        Some(version_dir),
        Some(msvc_dir),
        Some(tools_dir),
        Some(vc_dir),
        Some(visual_studio_dir),
    ) = (
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
    )
    else {
        return Err(invalid_layout());
    };
    let Some(target_arch) = target_dir.file_name() else {
        return Err(invalid_layout());
    };
    let Some(host_name) = host_dir.file_name().and_then(OsStr::to_str) else {
        return Err(invalid_layout());
    };
    let is_host_dir = host_name
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Host"))
        && host_name.len() > 4;
    let is_component = |path: &Path, expected: &str| {
        path.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
    };
    if !is_component(link, "link.exe")
        || !is_host_dir
        || !is_component(bin_dir, "bin")
        || !is_component(msvc_dir, "MSVC")
        || !is_component(tools_dir, "Tools")
        || !is_component(vc_dir, "VC")
    {
        return Err(invalid_layout());
    }
    Ok(VsLayout {
        target_arch: target_arch.to_os_string(),
        version_dir: version_dir.to_path_buf(),
        vc_dir: vc_dir.to_path_buf(),
        visual_studio_dir: visual_studio_dir.to_path_buf(),
    })
}

/// A directory spelled the way a developer prompt does: with a trailing
/// backslash.
fn with_trailing_backslash(path: &Path) -> OsString {
    let mut value = path.as_os_str().to_os_string();
    value.push("\\");
    value
}

/// Derives developer-prompt variables from a Visual Studio 2017+ linker path.
/// Paths outside that layout return an error.
fn developer_prompt_vars(link: &Path) -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    let layout = visual_studio_layout(link)?;
    Ok(vec![
        (
            OsString::from("VSINSTALLDIR"),
            with_trailing_backslash(&layout.visual_studio_dir),
        ),
        (
            OsString::from("VCINSTALLDIR"),
            with_trailing_backslash(&layout.vc_dir),
        ),
        (
            OsString::from("VCToolsInstallDir"),
            with_trailing_backslash(&layout.version_dir),
        ),
        (OsString::from("VSCMD_ARG_TGT_ARCH"), layout.target_arch),
    ])
}

/// `WindowsSdkDir` and `WindowsSDKVersion` for the host's Windows 10 SDK,
/// spelled as `vcvarsall.bat` does. `find_msvc_tools` reads them before
/// it reads the registry key that names the SDK, so a lookup for another
/// architecture finds the same SDK without that key. Empty when the host
/// has no Windows 10 SDK.
fn windows_sdk_vars() -> Vec<(OsString, OsString)> {
    let Some(sdk) = find_msvc_tools::find_windows_sdk(std::env::consts::ARCH) else {
        return Vec::new();
    };
    let version = sdk.sdk_version();
    let Some(root) = sdk.libs().find_map(|lib| windows_sdk10_root(lib, version)) else {
        return Vec::new();
    };
    vec![
        (
            OsString::from("WindowsSdkDir"),
            with_trailing_backslash(&root),
        ),
        (
            OsString::from("WindowsSDKVersion"),
            OsString::from(format!("{version}\\")),
        ),
    ]
}

/// The Windows 10 SDK root a `lib\<version>\um\<arch>` directory belongs
/// to — the `WindowsSdkDir` that directory implies — or `None` for any
/// other directory.
fn windows_sdk10_root(lib: &Path, version: &str) -> Option<PathBuf> {
    let version_dir = lib
        .ancestors()
        .find(|dir| dir.file_name().is_some_and(|name| name == version))?;
    let lib_dir = version_dir.parent()?;
    if !lib_dir.file_name()?.eq_ignore_ascii_case("lib") || !lib.starts_with(version_dir.join("um"))
    {
        return None;
    }
    lib_dir.parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_entries_keeps_only_composed_paths_not_in_the_host() {
        let composed = std::env::join_paths([
            PathBuf::from("a"),
            PathBuf::from("b"),
            PathBuf::from("h1"),
            PathBuf::from("h2"),
        ])
        .unwrap();
        let host = std::env::join_paths([PathBuf::from("h1"), PathBuf::from("h2")]).unwrap();
        assert_eq!(
            added_entries(&composed, Some(&host)),
            vec![PathBuf::from("a"), PathBuf::from("b")]
        );
        assert_eq!(
            added_entries(&composed, None),
            vec![
                PathBuf::from("a"),
                PathBuf::from("b"),
                PathBuf::from("h1"),
                PathBuf::from("h2"),
            ]
        );
    }

    #[test]
    fn developer_prompt_vars_spells_the_visual_studio_layout() {
        let link =
            Path::new(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe");
        assert_eq!(
            developer_prompt_vars(link).unwrap(),
            vec![
                (
                    OsString::from("VSINSTALLDIR"),
                    OsString::from(r"C:\VS\2022\BuildTools\"),
                ),
                (
                    OsString::from("VCINSTALLDIR"),
                    OsString::from(r"C:\VS\2022\BuildTools\VC\"),
                ),
                (
                    OsString::from("VCToolsInstallDir"),
                    OsString::from(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\14.44.35207\"),
                ),
                (OsString::from("VSCMD_ARG_TGT_ARCH"), OsString::from("x64")),
            ]
        );
    }

    #[test]
    fn developer_prompt_vars_rejects_paths_outside_the_visual_studio_layout() {
        assert!(
            developer_prompt_vars(Path::new(r"C:\Program Files\Git\usr\bin\link.exe")).is_err()
        );
    }

    #[test]
    fn windows_kit_root_reads_the_kit_tree_boundary() {
        assert_eq!(
            windows_kit_root(Path::new(r"C:\Windows Kits\10\bin\10.0.26100.0\x64")),
            Some(PathBuf::from(r"C:\Windows Kits\10"))
        );
        assert_eq!(
            windows_kit_root(Path::new(r"D:\SDKs\8.1\Lib\winv6.3\um\x64")),
            Some(PathBuf::from(r"D:\SDKs\8.1"))
        );
        assert_eq!(
            windows_kit_root(Path::new(r"C:\Windows Kits\10\Include\10.0.26100.0\ucrt")),
            Some(PathBuf::from(r"C:\Windows Kits\10"))
        );
        // A kit tree directly at a drive root names no installation.
        assert_eq!(windows_kit_root(Path::new(r"C:\bin\x64")), None);
        // A dir outside the kit layout derives no root.
        assert_eq!(windows_kit_root(Path::new(r"C:\tools\rust")), None);
    }

    #[test]
    fn windows_sdk10_root_reads_the_um_library_directory() {
        let version = "10.0.26100.0";
        assert_eq!(
            windows_sdk10_root(
                Path::new(r"C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\um\x64"),
                version
            ),
            Some(PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10"))
        );
        // The universal CRT's library directory is not the SDK's `um` tree.
        assert_eq!(
            windows_sdk10_root(
                Path::new(r"C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\ucrt\x64"),
                version
            ),
            None
        );
        // A directory that does not carry the SDK version names no SDK.
        assert_eq!(
            windows_sdk10_root(Path::new(r"C:\Windows Kits\10\lib\winv6.3\um\x64"), version),
            None
        );
    }
}
