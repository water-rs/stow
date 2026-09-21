# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/water-rs/stow/compare/stow-cli-v0.3.0...stow-cli-v0.3.1) - 2026-09-21

### Fixed

- stop a stale edge row and a mixed graph from breaking builds ([#242](https://github.com/water-rs/stow/pull/242))

## [0.3.0](https://github.com/water-rs/stow/compare/stow-cli-v0.2.0...stow-cli-v0.3.0) - 2026-09-21

### Fixed

- *(cli)* compare bundle configs structurally, not byte-for-byte ([#236](https://github.com/water-rs/stow/pull/236))

## [0.2.0](https://github.com/water-rs/stow/compare/stow-cli-v0.1.0...stow-cli-v0.2.0) - 2026-09-21

### Added

- [**breaking**] resolve artifacts against the local signed index ([#225](https://github.com/water-rs/stow/pull/225))
- *(stats)* privacy-preserving usage statistics and a public /stats page ([#220](https://github.com/water-rs/stow/pull/220))
- *(cli)* compile mock-key verification behind the mock-verify feature ([#204](https://github.com/water-rs/stow/pull/204))
- preheat the cache from stow predict and a Preheat workflow ([#74](https://github.com/water-rs/stow/pull/74))

### Fixed

- *(identity)* fold build-script cfgs and embed-bitcode into the compile key ([#206](https://github.com/water-rs/stow/pull/206))
- *(cli)* serve tuned dev profiles; strip joins the compile identity ([#201](https://github.com/water-rs/stow/pull/201))
- *(cli)* install the rustc wrapper under the user's data directory ([#199](https://github.com/water-rs/stow/pull/199))
- retry crate downloads with backoff and put timeouts on every CLI edge request ([#198](https://github.com/water-rs/stow/pull/198))
- *(cli)* pass unknown rustc args through and never strip manifests through the mirror symlink ([#196](https://github.com/water-rs/stow/pull/196))
- make predict actually redeem its minted miss admissions ([#160](https://github.com/water-rs/stow/pull/160))
- [**breaking**] store every artifact as a tag of one GHCR package ([#89](https://github.com/water-rs/stow/pull/89))
- follow cargo's workspace membership rules in the CLI ([#80](https://github.com/water-rs/stow/pull/80))
- Windows wrappers are executables, not batch files ([#78](https://github.com/water-rs/stow/pull/78))
- stow predict exits non-zero when prediction is unavailable; preheat fetches the registry first ([#77](https://github.com/water-rs/stow/pull/77))

### Other

- Cache waterui's full dependency closure on all twelve targets ([#104](https://github.com/water-rs/stow/pull/104))

## [0.1.0](https://github.com/water-rs/stow/releases/tag/stow-cli-v0.1.0) - 2026-09-18

### Added

- gate miss enqueue behind challenge + proof-of-work ([#50](https://github.com/water-rs/stow/pull/50))
- local artifact cache for remote-miss registry crates ([#37](https://github.com/water-rs/stow/pull/37))
- composite action that installs stow-cli and wires the wrappers ([#35](https://github.com/water-rs/stow/pull/35))
- split trusted CI into an untrusted build job and a credentialed publish job ([#24](https://github.com/water-rs/stow/pull/24))
- complete native and cc caching pipeline
- add signed artifact verification pipeline
- *(cli)* consume cached artifact bundles in rustc wrapper
- *(ci)* push planned artifacts to ghcr
- *(cli)* add edge artifact fetch command
- implement cloudflare edge watcher and build skeleton

### Fixed

- make the stale-marker materialization test independent of filesystem timestamp granularity ([#52](https://github.com/water-rs/stow/pull/52))
- treat cargo's -Z embed-metadata as compile identity, not custom codegen ([#45](https://github.com/water-rs/stow/pull/45))
- bind Sigstore verification to the Rekor entry and its integrated time ([#27](https://github.com/water-rs/stow/pull/27))
- write requested depfile on C/C++ cache hits ([#21](https://github.com/water-rs/stow/pull/21))
- reject undeclared bundle entries and rooted cache paths ([#23](https://github.com/water-rs/stow/pull/23))
- bind production identity to water-rs/stow and stow.waterui.dev ([#20](https://github.com/water-rs/stow/pull/20))
- make published crates publishable to crates.io ([#19](https://github.com/water-rs/stow/pull/19))
- *(cli)* bypass rustc probe invocations
- verify signed bundles offline

### Other

- update dependencies ([#56](https://github.com/water-rs/stow/pull/56))
- mock end-to-end lane for the trusted build path ([#49](https://github.com/water-rs/stow/pull/49))
- lint gates: clippy-clean stow-edge, workspace clippy + rustfmt in CI ([#54](https://github.com/water-rs/stow/pull/54))
- clippy-clean stow-cli for the workspace lint gate ([#43](https://github.com/water-rs/stow/pull/43))
- test on Windows and check the edge worker for wasm32 ([#29](https://github.com/water-rs/stow/pull/29))
- clippy-clean stow-types, stow-shim, stow-admin, stow-mock-registry ([#34](https://github.com/water-rs/stow/pull/34))
- Turn the prebuilt-deps path off by default
- Never attribute one crate version's artifact to another
- Never let the cache layer fail the build
- Wire CC and CXX through compiler-shaped shims
- Bound the pre-cargo phase and report what the cache served
- Carry the native OUT_DIR as its own compressed layer
- Support workspace inheritance in the manifest parser
- Stop identity mismatches from disabling the cache for the whole build
- Let graph analysis, not the resolver, decide the cargo passthrough
- Fix three defects that suppress cache hits and stall the build
- Refactor Trust Boundaries And Improve Cache Pipeline
- accelerate top-crate cached dependency checks
- checkpoint stow cache acceleration work
- Thread full artifact identity through pipeline; add admin crate
- migrate error handling from eyre to thiserror
- Replace cargo metadata with lockfile-based workspace dependency parsing.
- Bump state DB to v3 and update gitignore for test artifacts
- Refactor stow local cache state around sqlx
- Fix manifest-path check when invoked outside workspace
- Stream artifact fetch and use zenwave timeout middleware
- Rewrite native metadata paths during cache injection
- Handle C compiler response files in cc cache wrapper
- Reduce cache-hit overhead in stow check path
- Checkpoint current stow cache pipeline and mock registry work
- Fix exact artifact identity and cache key stability
- Protect stow cache against multi-process version races
- Implement edge graph analysis and local artifact cache
- Respect crate-type in artifact cache pipeline
- initial commit
