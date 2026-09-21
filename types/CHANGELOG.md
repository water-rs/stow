# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/water-rs/stow/compare/stow-types-v0.3.1...stow-types-v0.4.0) - 2026-09-21

### Fixed

- *(edge)* a malformed query string is a 400, not "no filter at all" ([#246](https://github.com/water-rs/stow/pull/246))
- *(preheat)* run the unattended top-100 wave, and name it for what it does ([#245](https://github.com/water-rs/stow/pull/245))

## [0.3.0](https://github.com/water-rs/stow/compare/stow-types-v0.2.0...stow-types-v0.3.0) - 2026-09-21

### Fixed

- *(cli)* compare bundle configs structurally, not byte-for-byte ([#236](https://github.com/water-rs/stow/pull/236))

## [0.2.0](https://github.com/water-rs/stow/compare/stow-types-v0.1.0...stow-types-v0.2.0) - 2026-09-21

### Added

- [**breaking**] resolve artifacts against the local signed index ([#225](https://github.com/water-rs/stow/pull/225))
- *(admin)* [**breaking**] operations CLI ([#221](https://github.com/water-rs/stow/pull/221))
- *(stats)* privacy-preserving usage statistics and a public /stats page ([#220](https://github.com/water-rs/stow/pull/220))
- *(index)* typed artifact index, admin export, signed publish workflow ([#218](https://github.com/water-rs/stow/pull/218))
- *(edge)* [**breaking**] bind artifact registration to the dispatched task's closure ([#219](https://github.com/water-rs/stow/pull/219))
- *(edge)* anonymous-traffic circuit breaker (panic switch) ([#217](https://github.com/water-rs/stow/pull/217))
- *(scheduler)* cap dispatch per runner family and start Windows legs first ([#215](https://github.com/water-rs/stow/pull/215))
- [**breaking**] publish bundles from the trusted CI job and stream them from the edge ([#212](https://github.com/water-rs/stow/pull/212))
- *(edge)* log every miss to Analytics Engine; persist only admitted misses in D1 ([#209](https://github.com/water-rs/stow/pull/209))
- assemble crate requests from what crates.io publishes ([#93](https://github.com/water-rs/stow/pull/93))
- Turnstile-admitted human request lane on the scheduler ([#72](https://github.com/water-rs/stow/pull/72))

### Fixed

- *(edge)* fetch bundle manifests by digest and verify them ([#208](https://github.com/water-rs/stow/pull/208))
- *(identity)* fold build-script cfgs and embed-bitcode into the compile key ([#206](https://github.com/water-rs/stow/pull/206))
- *(cli)* serve tuned dev profiles; strip joins the compile identity ([#201](https://github.com/water-rs/stow/pull/201))
- *(scheduler)* complete only the reported attempt ([#197](https://github.com/water-rs/stow/pull/197))
- refuse to queue a target no CI runner can build ([#106](https://github.com/water-rs/stow/pull/106))
- [**breaking**] store every artifact as a tag of one GHCR package ([#89](https://github.com/water-rs/stow/pull/89))
- never record rustc invocations that carry no -C metadata ([#83](https://github.com/water-rs/stow/pull/83))

### Other

- Drop Intel Mac, x86 Android, and 32-bit Android targets ([#146](https://github.com/water-rs/stow/pull/146))
- Replace shared scheduler/register secrets with GitHub identity auth ([#133](https://github.com/water-rs/stow/pull/133))
- Cache waterui's full dependency closure on all twelve targets ([#104](https://github.com/water-rs/stow/pull/104))

## [0.1.0](https://github.com/water-rs/stow/releases/tag/stow-types-v0.1.0) - 2026-09-18

### Added

- pull GHCR bundles through the anonymous registry token exchange ([#51](https://github.com/water-rs/stow/pull/51))
- gate miss enqueue behind challenge + proof-of-work ([#50](https://github.com/water-rs/stow/pull/50))
- migrate edge worker to skyzen 0.3 and add deploy workflow ([#42](https://github.com/water-rs/stow/pull/42))
- run untrusted cargo builds inside a heel sandbox with IPC capture ([#38](https://github.com/water-rs/stow/pull/38))
- local artifact cache for remote-miss registry crates ([#37](https://github.com/water-rs/stow/pull/37))
- split trusted CI into an untrusted build job and a credentialed publish job ([#24](https://github.com/water-rs/stow/pull/24))
- complete native and cc caching pipeline
- add signed artifact verification pipeline
- *(edge)* stream bundled artifact payloads

### Fixed

- treat cargo's -Z embed-metadata as compile identity, not custom codegen ([#45](https://github.com/water-rs/stow/pull/45))
- bind production identity to water-rs/stow and stow.waterui.dev ([#20](https://github.com/water-rs/stow/pull/20))
- make published crates publishable to crates.io ([#19](https://github.com/water-rs/stow/pull/19))
- verify signed bundles offline

### Other

- update dependencies ([#56](https://github.com/water-rs/stow/pull/56))
- mock end-to-end lane for the trusted build path ([#49](https://github.com/water-rs/stow/pull/49))
- test on Windows and check the edge worker for wasm32 ([#29](https://github.com/water-rs/stow/pull/29))
- clippy-clean stow-types, stow-shim, stow-admin, stow-mock-registry ([#34](https://github.com/water-rs/stow/pull/34))
- Carry the native OUT_DIR as its own compressed layer
- Fix three defects that suppress cache hits and stall the build
- Refactor Trust Boundaries And Improve Cache Pipeline
- checkpoint stow cache acceleration work
- Thread full artifact identity through pipeline; add admin crate
- migrate error handling from eyre to thiserror
- Audit codebase: fix correctness bugs, remove hidden fallbacks, enforce CI trust path
- Refactor stow local cache state around sqlx
- Checkpoint current stow cache pipeline and mock registry work
- Fix exact artifact identity and cache key stability
- Implement edge graph analysis and local artifact cache
- Respect crate-type in artifact cache pipeline
- Add edge worker, scheduler DO, and types crate
- initial commit
