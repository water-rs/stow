#!/usr/bin/env bash
# Shared by the release workflow's tool builds and standalone mock drives.
# Sets BIN and GATE_TOOL_FILES for the requested, unchanged tool variant.
gate_tools() {
    local variant="$1" build_log="$2" runner="${3:-command}" profile
    local args=()
    GATE_TOOL_FILES=(stow-admin stow-build stow-mock-registry)
    case "$variant" in
        admin)
            profile=release
            args=(--release -p stow-admin)
            GATE_TOOL_FILES=(stow-admin)
            ;;
        production)
            profile=release
            args=(--release -p stow-admin -p stow-mock-registry -p stow-build)
            ;;
        preheat)
            profile=release
            args=(--release -p stow-cli --features stow-cli/mock-verify
                -p stow-build --features stow-build/mock-verify,stow-build/mock-compile
                -p stow-mock-registry -p stow-admin)
            GATE_TOOL_FILES+=(stow stow-cli cargo-stow)
            ;;
        mock)
            profile=debug
            args=(-p stow-cli --features mock-verify -p stow-build
                -p stow-mock-registry -p stow-admin)
            GATE_TOOL_FILES+=(stow stow-cli cargo-stow examples/demand_feed_fixture)
            ;;
        *) echo "unknown gate tool variant: $variant" >&2; return 1 ;;
    esac
    if [ -n "${STOW_GATE_BIN_DIR:-}" ]; then
        BIN="$(cd "$STOW_GATE_BIN_DIR" && pwd)" || return
    else
        "$runner" cargo build "${args[@]}" >"$build_log" 2>&1 || return
        if [ "$variant" = mock ]; then
            "$runner" cargo build -p stow-mock-registry --example demand_feed_fixture \
                >>"$build_log" 2>&1 || return
        fi
        BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/$profile"
        BIN="$(cd "$BIN" && pwd)" || return
    fi
    local tool
    for tool in "${GATE_TOOL_FILES[@]}"; do
        if [ ! -x "$BIN/$tool" ]; then
            echo "missing executable gate tool: $BIN/$tool" >&2
            return 1
        fi
    done
}
