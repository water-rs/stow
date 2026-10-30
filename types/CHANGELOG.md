# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.0](https://github.com/water-rs/stow/compare/stow-types-v0.12.1...stow-types-v0.13.0) - 2026-10-30

### Other

- drive the remaining scheduled workflows from the edge Cron Trigger ([#1122](https://github.com/water-rs/stow/pull/1122))

## [0.12.0](https://github.com/water-rs/stow/compare/stow-types-v0.11.0...stow-types-v0.12.0) - 2026-10-30

### Added

- *(edge)* dispatch the watchdog and the daily preheat from the Worker's Cron Trigger ([#1102](https://github.com/water-rs/stow/pull/1102))
- *(watchdog)* alert on a stale preheat and on stalled builds ([#1101](https://github.com/water-rs/stow/pull/1101))

## [0.11.0](https://github.com/water-rs/stow/compare/stow-types-v0.10.0...stow-types-v0.11.0) - 2026-10-29

### Added

- *(bundle)* store each node as one zstd stream and repack published bundles in place ([#1080](https://github.com/water-rs/stow/pull/1080))

### Fixed

- *(scheduler)* send full slice reports in parts the scheduler stages and applies with the last ([#1082](https://github.com/water-rs/stow/pull/1082))

## [0.10.0](https://github.com/water-rs/stow/compare/stow-types-v0.9.2...stow-types-v0.10.0) - 2026-10-29

### Added

- *(scheduler)* operators set the dispatch caps at runtime ([#1056](https://github.com/water-rs/stow/pull/1056))
- *(cli)* key remote git units and extra codegen flags in the local cache ([#1043](https://github.com/water-rs/stow/pull/1043))

### Fixed

- *(index)* recover index publish and report from partial failure ([#1069](https://github.com/water-rs/stow/pull/1069))
- *(cli)* key optimized check defaults, keep option order, recompute semantic candidate keys ([#1065](https://github.com/water-rs/stow/pull/1065))
- *(ci)* read rustc outputs through no-follow handles bound to their digests ([#1064](https://github.com/water-rs/stow/pull/1064))
- *(ci)* pack OUT_DIR through no-follow handles bound to capture digests ([#1062](https://github.com/water-rs/stow/pull/1062))
- *(watchdog)* judge usage on the billing month and trip only what the cost needs ([#1055](https://github.com/water-rs/stow/pull/1055))

## [0.9.0](https://github.com/water-rs/stow/compare/stow-types-v0.8.2...stow-types-v0.9.0) - 2026-10-28

### Added

- route every operator mutation through one traced workflow on main ([#1020](https://github.com/water-rs/stow/pull/1020))

## [0.8.2](https://github.com/water-rs/stow/compare/stow-types-v0.8.1...stow-types-v0.8.2) - 2026-10-28

### Fixed

- *(admin)* bound scheduler submit bodies by bytes ([#975](https://github.com/water-rs/stow/pull/975))

## [0.8.0](https://github.com/water-rs/stow/compare/stow-types-v0.7.0...stow-types-v0.8.0) - 2026-10-26

### Added

- *(edge)* uncached scheduler health endpoint ([#916](https://github.com/water-rs/stow/pull/916))
- [**breaking**] rank the preheat binary lane by 90-day downloads from the db dump ([#915](https://github.com/water-rs/stow/pull/915))
- [**breaking**] report inexact superset hits so the exact chain builds ([#913](https://github.com/water-rs/stow/pull/913))
- [**breaking**] serve a contained feature set from its smallest published superset ([#910](https://github.com/water-rs/stow/pull/910))
- [**breaking**] preheat reaches builds only through the scheduler ([#908](https://github.com/water-rs/stow/pull/908))
- [**breaking**] rank scheduler work by priority times time waited ([#906](https://github.com/water-rs/stow/pull/906))
- [**breaking**] run the scheduler on an in-memory graph with a flat log and snapshots ([#901](https://github.com/water-rs/stow/pull/901))
- [**breaking**] one CI interface for build occupancy and task submission ([#899](https://github.com/water-rs/stow/pull/899))
- [**breaking**] derive every cost limit from one 80% allowance line ([#897](https://github.com/water-rs/stow/pull/897))
- privacy-preserving usage statistics in Analytics Engine ([#896](https://github.com/water-rs/stow/pull/896))

### Fixed

- *(scheduler)* [**breaking**] keep the day meter exact across a wake ([#941](https://github.com/water-rs/stow/pull/941))
- read a missing cache package as the empty index ([#939](https://github.com/water-rs/stow/pull/939))
- *(preheat-cost)* carry the probe ledger across edge restarts ([#934](https://github.com/water-rs/stow/pull/934))
- [**breaking**] give an outcome-3 host node an edge to its same-feature target twin ([#930](https://github.com/water-rs/stow/pull/930))
- [**breaking**] record each row's direct child task ids and join substitution by task id ([#925](https://github.com/water-rs/stow/pull/925))
- repair the release gate legs the scheduler redesign broke ([#921](https://github.com/water-rs/stow/pull/921))
- *(admin)* settle a job row on its conclusion ([#864](https://github.com/water-rs/stow/pull/864))

### Other

- Cut a preheat wave to about one scheduler request per node ([#950](https://github.com/water-rs/stow/pull/950))
- [**breaking**] stop using D1 ([#905](https://github.com/water-rs/stow/pull/905))
- [**breaking**] dispatch every task as its own build-crate.yml run ([#894](https://github.com/water-rs/stow/pull/894))

## [0.7.0](https://github.com/water-rs/stow/compare/stow-types-v0.6.0...stow-types-v0.7.0) - 2026-10-22

### Added

- dispatch builds as batched matrix runs ([#835](https://github.com/water-rs/stow/pull/835))
- *(admin)* count preheat waves and daily resubmits in the monthly projection ([#828](https://github.com/water-rs/stow/pull/828))
- *(cli)* experimental heel sandbox around the user's cargo build ([#783](https://github.com/water-rs/stow/pull/783))
- *(admin)* daily digest of failed builds on the Daily failed builds issue ([#781](https://github.com/water-rs/stow/pull/781))
- *(cli)* read cargo's unit graph instead of hand-walking cargo metadata ([#551](https://github.com/water-rs/stow/pull/551)) ([#566](https://github.com/water-rs/stow/pull/566))
- *(scheduler)* deliver hourly sampled demand through a durable feed ([#563](https://github.com/water-rs/stow/pull/563))
- *(scheduler)* rank demand by build cost and enforce admission floor ([#534](https://github.com/water-rs/stow/pull/534))
- [**breaking**] the edge resolves nothing; delete stow-resolve and the Worker resolver ([#519](https://github.com/water-rs/stow/pull/519))
- resolve human requests in an Actions job; the edge resolves nothing on the request lane ([#516](https://github.com/water-rs/stow/pull/516))
- gate every change on its projected cost at launch traffic ([#505](https://github.com/water-rs/stow/pull/505))
- [**breaking**] preheat the cache from GHCR, with records as the only record source ([#477](https://github.com/water-rs/stow/pull/477))
- *(edge)* [**breaking**] dispatch freeze on systematic failure + self-metered cost trip ([#279](https://github.com/water-rs/stow/pull/279)) ([#470](https://github.com/water-rs/stow/pull/470))
- *(admin)* [**breaking**] resolve graphs natively with the cargo library in stow-admin ([#468](https://github.com/water-rs/stow/pull/468))
- *(edge,admin)* replace the panic switch with zone WAF maintenance rules ([#453](https://github.com/water-rs/stow/pull/453)) ([#469](https://github.com/water-rs/stow/pull/469))

### Fixed

- *(scheduler)* classify skipped legs whose job names GitHub left unrendered ([#840](https://github.com/water-rs/stow/pull/840))
- *(scheduler)* stop rewriting queue indexes on every transition ([#812](https://github.com/water-rs/stow/pull/812))
- *(scheduler)* decide the shape repair at the slice report, not the alarm ([#802](https://github.com/water-rs/stow/pull/802))
- *(edge,cli)* coverage counts a node only under its own dependency context ([#801](https://github.com/water-rs/stow/pull/801))
- *(scheduler)* a deduplicated submit writes no rows; drop request_count ([#791](https://github.com/water-rs/stow/pull/791))
- *(admin,edge)* resync a lagging slice with a full report on a generation conflict ([#782](https://github.com/water-rs/stow/pull/782))
- *(admin)* wait out GitHub's primary rate limit instead of failing ([#768](https://github.com/water-rs/stow/pull/768))
- split the public cache into one GHCR package per rustc version ([#763](https://github.com/water-rs/stow/pull/763))
- move the cache to the stow-cache-2 package generation and drop registry gc (stow#758) ([#759](https://github.com/water-rs/stow/pull/759))
- identities and shapes are required everywhere; index format 5; registry gc (stow#730) ([#753](https://github.com/water-rs/stow/pull/753))
- target-side nodes whose --extern closure holds a proc-macro publish the explicit --target shape (stow#736) ([#752](https://github.com/water-rs/stow/pull/752))
- *(types)* a shadow edge names only a same-feature twin (stow#722) ([#737](https://github.com/water-rs/stow/pull/737))
- *(ci)* a Windows task's C is compiled for its target, and no artifact carries another machine's objects ([#713](https://github.com/water-rs/stow/pull/713))
- *(admin)* a bound run whose title GitHub has not rendered yet is pending ([#707](https://github.com/water-rs/stow/pull/707))
- *(ci)* name a records artifact after the build that published it ([#663](https://github.com/water-rs/stow/pull/663))
- *(admin)* a unit published by two nodes keeps a row for each ([#665](https://github.com/water-rs/stow/pull/665))
- *(admin)* let the wave driver's GitHub reads wait out an outage ([#648](https://github.com/water-rs/stow/pull/648))
- *(ci)* label published rows with the cargo unit's feature set ([#611](https://github.com/water-rs/stow/pull/611)) ([#614](https://github.com/water-rs/stow/pull/614))
- *(types)* split a registry package dir on the first hyphen that leaves a semver ([#612](https://github.com/water-rs/stow/pull/612)) ([#613](https://github.com/water-rs/stow/pull/613))
- carry resolved dependency identity through the cache graph ([#594](https://github.com/water-rs/stow/pull/594))
- serve and publish crates whose [lib] name differs from the package name ([#583](https://github.com/water-rs/stow/pull/583))
- *(ci)* label published artifacts with the feature set rustc compiled ([#581](https://github.com/water-rs/stow/pull/581))
- *(edge)* report the scheduler budget's wall time instead of gating on it ([#580](https://github.com/water-rs/stow/pull/580))
- fence bounded build retries by execution generation ([#532](https://github.com/water-rs/stow/pull/532))
- *(cli)* retry transient failures when downloading mold ([#514](https://github.com/water-rs/stow/pull/514))
- *(resolver)* tasks resolve the deduped dependency identity a consumer's build computes ([#507](https://github.com/water-rs/stow/pull/507))
- decode Analytics Engine's quoted 64-bit integers with the column's type ([#497](https://github.com/water-rs/stow/pull/497))
- retry transient failures in the GitHub client and the registry session ([#490](https://github.com/water-rs/stow/pull/490))
- *(resolver)* [**breaking**] drop a crate's bundled lockfile like every other lane ([#484](https://github.com/water-rs/stow/pull/484))
- *(edge)* [**breaking**] drop the CI completion route and the probes of retired routes ([#479](https://github.com/water-rs/stow/pull/479))
- *(scheduler)* [**breaking**] bound every scheduler request and alarm pass to its event, gated by workerd's billed counters ([#472](https://github.com/water-rs/stow/pull/472))
- *(scheduler)* [**breaking**] move schema migrations off request code onto an operator route ([#459](https://github.com/water-rs/stow/pull/459))
- *(ci)* [**breaking**] cut build-wave latency and the failures behind it ([#462](https://github.com/water-rs/stow/pull/462))
- [**breaking**] host-side units are nodes of their own, built at the keys consumers compute ([#368](https://github.com/water-rs/stow/pull/368))

### Other

- add the Preheat cost test to the release gate ([#825](https://github.com/water-rs/stow/pull/825))
- one Traffic cost test with Worker CPU gated ([#792](https://github.com/water-rs/stow/pull/792))
- remove all migration code; a schema change is an operator reset ([#746](https://github.com/water-rs/stow/pull/746))
- *(edge)* maintain each queue node's unpublished-deps counter ([#529](https://github.com/water-rs/stow/pull/529))
- Bound scheduler dispatch and idle alarms; keep workerd gates event-scoped ([#528](https://github.com/water-rs/stow/pull/528))
- *(edge)* [**breaking**] serve bundles by digest without the D1 catalog lookup ([#467](https://github.com/water-rs/stow/pull/467))

## [0.6.0](https://github.com/water-rs/stow/compare/stow-types-v0.5.0...stow-types-v0.6.0) - 2026-09-24

### Added

- *(scheduler)* [**breaking**] release a dependent only when its dependencies are servable ([#341](https://github.com/water-rs/stow/pull/341))
- *(edge)* [**breaking**] resolve crate names into graph nodes inside the worker, with cargo's own resolver ([#337](https://github.com/water-rs/stow/pull/337))
- *(edge)* answer "is this crate cached?" in the browser from the index slice ([#329](https://github.com/water-rs/stow/pull/329))

### Fixed

- [**breaking**] Linux ELF artifacts link against a glibc 2.28 floor, and the index carries each row's min_glibc ([#350](https://github.com/water-rs/stow/pull/350))
- [**breaking**] build-order edges point at dependencies; host units and misses carry the identity their compile used ([#349](https://github.com/water-rs/stow/pull/349))
- *(ci)* [**breaking**] a build compiles its own crate or it fails — delete the dependency salvage ([#344](https://github.com/water-rs/stow/pull/344))
- *(preheat)* pace crates.io, mint OIDC per submit, accept cargo's feature grammar, resolve projects in the worker ([#339](https://github.com/water-rs/stow/pull/339))

## [0.5.0](https://github.com/water-rs/stow/compare/stow-types-v0.4.1...stow-types-v0.5.0) - 2026-09-22

### Added

- [**breaking**] every name source resolves into crate tasks through cargo metadata ([#310](https://github.com/water-rs/stow/pull/310))
- *(ci)* [**breaking**] build the cache with the cache ([#309](https://github.com/water-rs/stow/pull/309))
- *(ci)* [**breaking**] publish the dependencies a failed build compiled ([#307](https://github.com/water-rs/stow/pull/307))
- *(types)* [**breaking**] key a linked unit on its link options instead of refusing it ([#304](https://github.com/water-rs/stow/pull/304))
- *(cli)* pair stow with mold on Linux ([#281](https://github.com/water-rs/stow/pull/281))

### Other

- [**breaking**] a build task is one library or macro crate ([#305](https://github.com/water-rs/stow/pull/305))

## [0.4.1](https://github.com/water-rs/stow/compare/stow-types-v0.4.0...stow-types-v0.4.1) - 2026-09-21

### Fixed

- *(cli)* a prefetched candidate that describes another compile is not an error ([#256](https://github.com/water-rs/stow/pull/256))

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
