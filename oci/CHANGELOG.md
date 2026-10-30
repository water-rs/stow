# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.0](https://github.com/water-rs/stow/compare/stow-oci-v0.12.1...stow-oci-v0.13.0) - 2026-10-30

### Fixed

- *(oci)* wait for a Rekor entry a 409 names to become readable ([#1120](https://github.com/water-rs/stow/pull/1120))

## [0.12.0](https://github.com/water-rs/stow/compare/stow-oci-v0.11.0...stow-oci-v0.12.0) - 2026-10-30

### Added

- *(oci)* sign in-process and bound GHCR writes ([#1107](https://github.com/water-rs/stow/pull/1107))
- *(ops)* refill the index report and the queue after a scheduler reset ([#1103](https://github.com/water-rs/stow/pull/1103))

## [0.11.0](https://github.com/water-rs/stow/compare/stow-oci-v0.10.0...stow-oci-v0.11.0) - 2026-10-29

### Added

- *(bundle)* store each node as one zstd stream and repack published bundles in place ([#1080](https://github.com/water-rs/stow/pull/1080))

## [0.9.1](https://github.com/water-rs/stow/compare/stow-oci-v0.9.0...stow-oci-v0.9.1) - 2026-10-28

### Fixed

- *(oci)* resolve the sigstore trust cache without HOME and keep one records_trust ([#1027](https://github.com/water-rs/stow/pull/1027))

## [0.8.0](https://github.com/water-rs/stow/compare/stow-oci-v0.7.0...stow-oci-v0.8.0) - 2026-10-26

### Added

- [**breaking**] one CI interface for build occupancy and task submission ([#899](https://github.com/water-rs/stow/pull/899))

### Fixed

- read a missing cache package as the empty index ([#939](https://github.com/water-rs/stow/pull/939))
- [**breaking**] record each row's direct child task ids and join substitution by task id ([#925](https://github.com/water-rs/stow/pull/925))
- *(oci)* load the Sigstore trust root through sigstore-trust-root ([#873](https://github.com/water-rs/stow/pull/873))

### Other

- [**breaking**] stop using D1 ([#905](https://github.com/water-rs/stow/pull/905))

## [0.7.0](https://github.com/water-rs/stow/compare/stow-oci-v0.6.0...stow-oci-v0.7.0) - 2026-10-22

### Added

- [**breaking**] preheat the cache from GHCR, with records as the only record source ([#477](https://github.com/water-rs/stow/pull/477))

### Fixed

- split the public cache into one GHCR package per rustc version ([#763](https://github.com/water-rs/stow/pull/763))
- move the cache to the stow-cache-2 package generation and drop registry gc (stow#758) ([#759](https://github.com/water-rs/stow/pull/759))
- identities and shapes are required everywhere; index format 5; registry gc (stow#730) ([#753](https://github.com/water-rs/stow/pull/753))
- *(oci)* a signature the publish just pushed is read with a bounded retry ([#712](https://github.com/water-rs/stow/pull/712))
- *(ci)* name a records artifact after the build that published it ([#663](https://github.com/water-rs/stow/pull/663))
- *(cli)* a build prints cargo's output and the summary line, nothing else ([#646](https://github.com/water-rs/stow/pull/646))
- *(cli)* return when cargo does, and keep a build's scratch files in one directory it removes ([#654](https://github.com/water-rs/stow/pull/654))
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
