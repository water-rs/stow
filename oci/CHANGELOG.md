# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/water-rs/stow/compare/stow-oci-v0.5.0...stow-oci-v0.6.0) - 2026-09-24

### Fixed

- *(oci)* [**breaking**] a registry session that honours GHCR's rate limit and pushes in the fewest requests ([#343](https://github.com/water-rs/stow/pull/343))

## [0.3.0](https://github.com/water-rs/stow/compare/stow-oci-v0.2.0...stow-oci-v0.3.0) - 2026-09-21

### Fixed

- *(oci)* sign in cosign's legacy layout; re-sign index slices missing their .sig tag ([#230](https://github.com/water-rs/stow/pull/230))

## [0.2.0](https://github.com/water-rs/stow/compare/stow-oci-v0.0.0...stow-oci-v0.2.0) - 2026-09-21

### Added

- [**breaking**] resolve artifacts against the local signed index ([#225](https://github.com/water-rs/stow/pull/225))
