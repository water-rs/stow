# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
