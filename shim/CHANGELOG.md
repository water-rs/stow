# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/water-rs/stow/compare/stow-shim-v0.1.0...stow-shim-v0.2.0) - 2026-09-21

### Added

- [**breaking**] resolve artifacts against the local signed index ([#225](https://github.com/water-rs/stow/pull/225))
- *(stats)* privacy-preserving usage statistics and a public /stats page ([#220](https://github.com/water-rs/stow/pull/220))
- [**breaking**] publish bundles from the trusted CI job and stream them from the edge ([#212](https://github.com/water-rs/stow/pull/212))

### Fixed

- *(cli)* install the rustc wrapper under the user's data directory ([#199](https://github.com/water-rs/stow/pull/199))
- bound resolve_lockfile's artifact load by seed coverage and dep closure ([#127](https://github.com/water-rs/stow/pull/127))
- Windows wrappers are executables, not batch files ([#78](https://github.com/water-rs/stow/pull/78))

## [0.1.0](https://github.com/water-rs/stow/releases/tag/stow-shim-v0.1.0) - 2026-09-18

### Fixed

- make published crates publishable to crates.io ([#19](https://github.com/water-rs/stow/pull/19))

### Other

- update dependencies ([#56](https://github.com/water-rs/stow/pull/56))
- test on Windows and check the edge worker for wasm32 ([#29](https://github.com/water-rs/stow/pull/29))
- clippy-clean stow-types, stow-shim, stow-admin, stow-mock-registry ([#34](https://github.com/water-rs/stow/pull/34))
- Wire CC and CXX through compiler-shaped shims
- Refactor Trust Boundaries And Improve Cache Pipeline
