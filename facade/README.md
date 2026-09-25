# stow-facade

The tiny binary the `stow-rustc-wrapper`/`stow-cc`/`stow-cxx`/`stow-cc-launcher`
shims exec: one per compiler invocation, hundreds per build. It answers the
serve question from the map the supervising build computed once
(`STOW_SERVABLE_UNITS_JSON`, or the `STOW_SERVE_MAP_FILE` the driver fills in
the background while the index verifies), marks the compile with the
supervisor over a synchronous Unix-socket/loopback frame, runs the real
compiler, and reports the outcome — all without a tokio runtime, a config
load, or a plan round trip.

Invocations the map cannot answer (a covered unit, an unparseable probe) take
the one `Plan` frame that may block the compiler's start; invocations with no
supervisor environment at all delegate to `stow-runtime` — the full CLI beside
the facade — for the ordinary wrapper path.
