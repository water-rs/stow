# stow-oci

OCI registry push, pull and signing machinery shared by the
[stow](https://github.com/water-rs/stow) CLI, the trusted CI runner
(`stow-build`) and the operations CLI (`stow-admin`).

* Pushing content-addressed artifact bundles and the per-target signed
  artifact index to a registry (GHCR in production, the mock registry in
  local simulation).
* Pulling a tagged manifest, its digest-verified layers and the cosign
  signature materials the CLI verifies before trusting an index slice.
* Signing pushed artifacts with `cosign` under the trusted CI identity.

The crate carries no policy: which identity a signature must carry and what
a verified blob is used for is decided by the caller.
