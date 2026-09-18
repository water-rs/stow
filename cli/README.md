# stow-cli

The user-facing CLI for [stow](https://github.com/water-rs/stow), a public
prebuilt cache for Rust. See the
[repository README](https://github.com/water-rs/stow) for the full story.

Install with `cargo install stow-cli`, then run `stow setup` inside a project
to point cargo's `rustc-wrapper` at stow. `stow check`, `stow build`, and
`stow test` are drop-in replacements for the equivalent cargo subcommands:
every dependency compilation is checked against the public cache, and signed
prebuilt artifacts are injected into the target directory on a hit.
