# Pinned source trees (`--source-trees`)

Some projects a lane resolves name Rust inputs their own git tree does
not carry. Bun's root `Cargo.toml` path-depends on `vendor/lolhtml`,
but that directory is populated by `scripts/build/deps/lolhtml.ts` from
a second repository (`oven-sh/lol-html`) before Cargo runs — it is not
a submodule and not committed.

`--source-trees <file>` is how an operator declares those missing
trees, on `stow-admin preheat projects submit` and
`stow-admin preheat manual` (with `--projects`; the flag is a clap
error with `--crates` or `--dirs` and without `--projects`). The
reviewed declaration for the current projects list lives in
[`preheat/source-trees.toml`](../preheat/source-trees.toml); it is a
file an operator passes explicitly — nothing applies it to a project
silently, and a project without a declaration resolves its ordinary
git tree.

## Schema

The reviewed declaration ships the real Bun mapping:

```toml
[[project]]
repo = "https://github.com/oven-sh/bun"      # normalized like projects.toml
commit = "c7b06d94bac19817ba34b6677bb1099fb4f6d2be"  # the checkout must sit here

[[project.source]]
destination = "vendor/lolhtml"               # project-relative
repo = "https://github.com/oven-sh/lol-html" # any git-compatible absolute URL
commit = "725ce499aa9b71e38b7a2d0a9fbb6d7294a4079e"  # fetched by exact commit
```

Validation happens once per command, before the resolve pool starts:

- every `[[project]]` must name a repository the input list
  (`projects.toml`/`--projects`) actually contains — a declaration for
  a project not being resolved is rejected, never ignored;
- duplicate project declarations, empty source sets, unknown fields,
  and overlapping or invalid destinations (traversal, absolute,
  drive-qualified, backslash, or a git-metadata component such as
  `.git`/`git~1` in any spelling) all fail the command;
- destinations that already hold a file tree or gitlink are never
  overwritten, and a symlink anywhere on a destination's path —
  inside the project or pointing out of it — is rejected.

## Semantics

- **Pin enforcement.** The project's fetched checkout must sit at the
  declared `[[project]]` commit before anything else happens — a
  declaration written for an older HEAD fails rather than dragging the
  project back. Each source is fetched by its exact commit the same
  way projects are (shallow fetch plus recursive submodules), and the
  checkout's `HEAD` must equal the declared commit.
- **Acquisition-only.** Source fetches run during the project's own
  resolve, inside its scratch checkout, before the workspace resolve
  reads the tree — the source's `Cargo.lock` files are dropped under
  the same rule as the project's. Nothing is persisted or cached
  between resolves; scheduler, serving, and idle costs are unchanged.
- **Concurrency.** All of a project's destinations are created and
  proven disjoint first (a declaration that aliases an existing or
  sibling destination never gets half-fetched), then independent
  source fetches fan out across at most four worker threads — so the
  four-lane project pool bounds source fetches at sixteen in flight.
- **Ordering.** The project's manifest is selected on its own
  checkout before any source lands, so an imported tree's
  manifest+lockfile pair can never displace the manifest the project
  itself selects.
