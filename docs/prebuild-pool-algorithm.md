# Prebuild Pool Algorithm

## Goal

Stow does not try to prebuild every possible Rust compilation unit.
The goal is to spend a fixed compute and storage budget on the highest-value
artifacts that are most likely to produce public cache hits.

The algorithm is therefore designed around:

- a small, stable base pool
- a small number of high-signal overlays
- strict budgeted expansion instead of unconstrained combinatorics

The key idea is to approximate the public compile surface with a compact pool of
prebuilt artifacts, and then refine that pool using real-world feedback.

## Design Principles

- Respect resource limits. Compute and storage are finite.
- Prefer broad, reusable coverage over niche combinations.
- Preserve high-signal real workloads when they disagree with generic heuristics.
- Avoid combinatorial explosion by constraining feature profiles and version
  lines in the base pool.
- Allow controlled expansion from binary workloads and user miss feedback.

## Pool Structure

The global prebuild pool is built from three layers:

1. Base library pool
2. Binary-derived overlay
3. User-feedback overlay

These layers are additive, but they are not equally privileged. The base pool
is always present. The overlays compete for remaining budget.

## 1. Base Library Pool

The base pool starts from the top `N` popular library crates.

For each selected library crate, Stow generates a small fixed candidate set:

- two feature profiles:
  - `default`
  - `full`
- three semver-breaking version lines:
  - the latest three major lines for `>= 1.0`
  - the latest three minor lines for `< 1.0`

Examples:

- `1.8.x`, `1.7.x`, `1.6.x`
- `0.9.x`, `0.8.x`, `0.7.x`

This means the base library candidate count is:

`2 feature profiles * 3 version lines = 6`

Important:

- `6` is only the base candidate count for one popular library crate
- it is not the global upper bound of the total pool

The base pool exists to provide broad reusable coverage at low complexity.

## Version Representative Selection

Within one compatible semver line, Stow does not keep every patch release.

Instead, it keeps only the newest representative in that line.

Example:

- observed releases: `1.5.2`, `1.5.1`, `1.5.0`, `1.4.9`
- selected representatives:
  - `1.5.2`
  - `1.4.9`

The intermediate patch releases in the same compatible line are skipped:

- `1.5.1`
- `1.5.0`

Reason:

- semver guarantees compatibility within the same line
- keeping every patch release would waste storage and build budget
- the pool is optimized for representative coverage, not archival completeness

This representative rule applies to the base pool before scoring and admission.

## Feature Profiles

The base pool intentionally uses only two feature profiles:

- `default`
- `full`

This is the main anti-explosion mechanism.

Rationale:

- `default` covers the most common public dependency shape
- `full` covers crates whose ecosystems frequently enable most optional
  features together

Stow does not attempt to enumerate arbitrary feature subsets in the base pool.

## Version-Line Policy

The base pool operates on version lines rather than every patch release.

For pool construction, a "version line" means:

- `major` line when the crate is `>= 1.0`
- `minor` line when the crate is `< 1.0`

This reflects semver breakage boundaries:

- `1.x -> 2.x` is breaking
- `0.8 -> 0.9` is also breaking in practice

Patch releases are then selected within the chosen line according to the pool's
representative-selection policy.

In practice, this means:

- choose semver lines first
- then keep only the newest representative patch release in each line

## 2. Binary-Derived Overlay

The second layer starts from the most recent `M` popular binary crates.

These binaries provide a stronger signal than generic library popularity,
because they represent real end-user install and build workloads.

For each binary crate, Stow extracts its dependency libraries and feeds them
into the candidate pool.

This overlay is allowed to introduce candidates that the base pool would not
have generated, including:

- older locked versions
- exact versions pinned by a published `Cargo.lock`
- feature combinations that are neither plain `default` nor synthetic `full`
- crate-type combinations observed in the binary's actual build graph

This is critical because real binary workloads often differ from the
"latest compatible semver" view.

### Lockfile Rule

If a binary crate ships a published `Cargo.lock`, that lockfile is treated as
the authoritative dependency graph for the top-binaries pool.

Stow must not replace that graph with a fresh semver re-resolution.

Reason:

- `cargo install --locked` uses the published lockfile
- a synthetic "latest compatible" graph can drift far away from real install
  behavior
- once the graph drifts, artifact keys drift as well, and public cache hit rate
  collapses

## 3. User-Feedback Overlay

The third layer comes from real cache misses observed in the field.

User feedback is the highest-signal source because it reflects actual public
demand rather than inferred demand.

This overlay may introduce candidates outside both:

- the `default/full` base feature policy
- the top-library or top-binary popularity windows

However, user feedback is still budgeted. A miss does not automatically imply
permanent admission into the pool.

Instead, misses are turned into prioritized overlay candidates and ranked
against the rest of the queue.

## Candidate Identity

The pool should reason about candidates using a normalized semantic identity,
not raw "crate name only".

At minimum, the identity must distinguish:

- crate name
- exact version or chosen version line
- feature profile or exact feature set
- crate type
- target class

In other words, a candidate is not just "serde" or "clap".
It is closer to:

`(crate, version-line-or-exact-version, feature-profile-or-exact-set, crate-type, target-class)`

This lets the scheduler compare reusable base candidates and more specific
overlay candidates using one common abstraction.

## Budgeting Model

The pool is not allowed to expand indefinitely.

Instead, Stow should:

1. generate base candidates
2. generate top-binaries pool candidates
3. generate user-feedback overlay candidates
4. deduplicate and normalize them
5. score them
6. admit only the highest-value set that fits the budget

The budget may be expressed in terms of:

- total build jobs
- total artifact bytes
- total estimated compile time
- per-target quotas
- per-crate quotas

The implementation may use one or more of these simultaneously.

## Recommended Scoring Signals

Candidate ranking should combine signals from several sources:

- library popularity rank
- binary popularity rank
- binary recency
- observed user miss frequency
- observed geographic spread of misses
- expected artifact size
- expected compile cost
- target coverage value

This yields a score that favors artifacts which are both:

- likely to be reused
- efficient to keep in the pool

## Why the Layers Matter

The three-layer structure prevents two common failure modes:

### Failure mode 1: overfitting to abstract popularity

If Stow only prebuilds popular libraries from a synthetic semver-resolved pool,
it drifts away from real install behavior.

The top-binaries pool fixes this by injecting real dependency graphs from
popular binaries.

### Failure mode 2: unbounded specialization

If Stow blindly admits every miss and every observed feature combination, the
pool explodes.

The base pool keeps the system compact, while the overlays are budgeted and
scored rather than admitted automatically.

## Practical Interpretation

The intended behavior is:

- the base pool provides broad public coverage cheaply
- the top-binaries pool corrects the base pool toward real workloads
- the user-feedback overlay keeps the pool adaptive over time

So the system is not:

- "prebuild everything"
- "only prebuild default features"
- "only trust lockfiles"

It is:

- a compact popularity-based base
- corrected by real binary dependency graphs
- refined by real user miss data

## Non-Goals

This algorithm explicitly does not try to:

- enumerate all feature subsets
- build every patch version
- mirror crates.io entirely
- guarantee a hit for every locked binary install

The purpose is not completeness.
The purpose is the highest possible public hit rate per unit of compute and
storage.

## Summary

The base pool for a popular library crate is intentionally small:

- `2` feature profiles
- `3` semver-breaking version lines

But that is only the foundation.

The real pool is:

- base library pool
- plus top-binaries pools
- plus user-feedback overlays

All of it is budgeted, deduplicated, and ranked.

That is the core Stow strategy for producing the most valuable public prebuilt
artifacts under finite resources.
