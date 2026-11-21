#!/usr/bin/env bash
set -euo pipefail

if [ "${STOW_LOCAL_ONLY:-0}" = "1" ]; then
  if [ "$(uname -s)" = Darwin ]; then
    config_dir="$HOME/Library/Application Support/stow"
  elif [ -n "${XDG_CONFIG_HOME:-}" ] && [ "${XDG_CONFIG_HOME#/}" != "$XDG_CONFIG_HOME" ]; then
    config_dir="$XDG_CONFIG_HOME/stow"
  else
    config_dir="$HOME/.config/stow"
  fi
  config_file="$config_dir/config.toml"
  wanted=$'[cache]\nremote = false\n'
  if [ -e "$config_file" ] && [ "$(cat "$config_file")" != "$wanted" ]; then
    echo "::error::$config_file already exists with custom contents; refusing to overwrite it" >&2
    exit 1
  fi
  mkdir -p "$config_dir"
  printf '%s' "$wanted" > "$config_file"
fi

version="$STOW_VERSION"
if [ "$version" = latest ]; then
  # The newest installable release: release-plz pushes the tag before
  # cargo-dist has attached the archives, so a release without assets
  # is still in flight and is skipped.
  tag="$(gh api 'repos/water-rs/stow/releases?per_page=100' \
    --jq '[.[] | select(.draft == false and .prerelease == false) | select(any(.assets[]; .name | startswith("stow-cli-"))) | .tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))][0] // empty')"
  if [ -z "$tag" ]; then
    echo "::error::no installable v<version> release found on water-rs/stow" >&2
    exit 1
  fi
else
  version="${version#v}"
  tag="v${version}"
fi
version="${tag#v}"

case "${RUNNER_OS}-${RUNNER_ARCH}" in
  Linux-X64) target=x86_64-unknown-linux-gnu ;;
  Linux-ARM64) target=aarch64-unknown-linux-gnu ;;
  macOS-ARM64) target=aarch64-apple-darwin ;;
  *)
    echo "::error::no stow-cli release target for ${RUNNER_OS}-${RUNNER_ARCH}" >&2
    exit 1
    ;;
esac

archive="stow-cli-${target}.tar.xz"
workdir="$(mktemp -d)"
gh release download "$tag" --repo water-rs/stow --dir "$workdir" \
  --pattern "$archive" --pattern "${archive}.sha256"

# A corrupt binary is not a fallback case: abort on mismatch.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$workdir" && sha256sum -c "${archive}.sha256")
else
  (cd "$workdir" && shasum -a 256 -c "${archive}.sha256")
fi

dest="${RUNNER_TOOL_CACHE:?RUNNER_TOOL_CACHE is not set on this runner}/stow/${version}/${target}"
extract="$(mktemp -d)"
tar -xJf "${workdir}/${archive}" -C "$extract"
binary="$(find "$extract" -type f -name stow-cli -print -quit)"
if [ -z "$binary" ]; then
  echo "::error::${archive} contains no stow-cli binary" >&2
  exit 1
fi
mkdir -p "$dest"
cp -R "$(dirname "$binary")/." "${dest}/"
echo "$dest" >> "$GITHUB_PATH"

"$dest/stow" setup --github-env >> "$GITHUB_ENV"
# The linker selection cannot ride in the job environment (env
# rustflags would replace a project's configured rustflags
# wholesale), so setup also writes it into the runner's global
# cargo config — including the managed mold install on Linux —
# while leaving Cargo's standard `target/` layout untouched.
"$dest/stow" setup --no-build-dir --no-install-skill
