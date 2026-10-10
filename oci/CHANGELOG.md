# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0](https://github.com/water-rs/stow/compare/stow-oci-v0.6.0...stow-oci-v0.7.0) - 2026-10-10

### Added

- [**breaking**] preheat the cache from GHCR, with records as the only record source ([#477](https://github.com/water-rs/stow/pull/477))

### Fixed

- *(oci)* retry cosign signing on failure ([#606](https://github.com/water-rs/stow/pull/606)) ([#607](https://github.com/water-rs/stow/pull/607))
- carry resolved dependency identity through the cache graph ([#594](https://github.com/water-rs/stow/pull/594))
- retry transient failures in the GitHub client and the registry session ([#490](https://github.com/water-rs/stow/pull/490))
- *(resolver)* [**breaking**] pin the probed rustc; let index-publish recover old slices and stop compiling stow-admin ([#480](https://github.com/water-rs/stow/pull/480))
- *(oci)* sign a manifest before its tag points at it ([#483](https://github.com/water-rs/stow/pull/483))
- *(scheduler)* [**breaking**] bound every scheduler request and alarm pass to its event, gated by workerd's billed counters ([#472](https://github.com/water-rs/stow/pull/472))
- *(oci)* upload blobs at the canonical path, and the mock refuses the double slash GHCR redirects ([#362](https://github.com/water-rs/stow/pull/362))

### Other

- *(deps)* bump sigstore from 0.13.0 to 0.14.0 ([#503](https://github.com/water-rs/stow/pull/503))

## [0.6.0](https://github.com/water-rs/stow/compare/stow-oci-v0.5.0...stow-oci-v0.6.0) - 2026-09-24

### Fixed

- *(oci)* [**breaking**] a registry session that honours GHCR's rate limit and pushes in the fewest requests ([#343](https://github.com/water-rs/stow/pull/343))

## [0.3.0](https://github.com/water-rs/stow/compare/stow-oci-v0.2.0...stow-oci-v0.3.0) - 2026-09-21

### Fixed

- *(oci)* sign in cosign's legacy layout; re-sign index slices missing their .sig tag ([#230](https://github.com/water-rs/stow/pull/230))

## [0.2.0](https://github.com/water-rs/stow/compare/stow-oci-v0.0.0...stow-oci-v0.2.0) - 2026-09-21

### Added

- [**breaking**] resolve artifacts against the local signed index ([#225](https://github.com/water-rs/stow/pull/225))
