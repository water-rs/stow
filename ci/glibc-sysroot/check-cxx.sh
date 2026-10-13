#!/usr/bin/env bash
# Prove C++ goes through the glibc-2.28 sysroot shims end to
# end — era headers on the compile, era runtime on the link —
# in both spellings a build uses: the C++ driver compiling
# and linking its own TU, and the C driver linking a
# C++-compiled object the way rustc's link line does.
#
# Usage: ci/glibc-sysroot/check-cxx.sh <sysroot-dir>
#
# stow#693: both halves of this were silently broken on the
# ubuntu-24.04 runner — GCC 13 cannot parse libstdc++ 8's
# headers (`__remove_cv` became a built-in trait name there
# and stays an ordinary identifier in the era headers), and a
# C++ link resolved -lstdc++ to the runner's own
# libstdc++.so, whose glibc 2.33/2.34 needs the 2.28 sysroot
# cannot serve. Building is therefore not enough: every
# linked output is audited with readelf — no GLIBC_* version
# reference above 2.28, no GLIBCXX_3.4.* above 3.4.25
# (libstdc++ 8's ceiling), and libstdc++.so.6 present in
# NEEDED, since a link that went static or dropped the
# library would pass the version audit. The native
# executable is run; the aarch64 pair is checked only when
# wrappers.sh wrote it.
set -euo pipefail

sysroot="${1:?usage: check-cxx.sh <sysroot-dir>}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/tu.cc" <<'CPP'
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
static std::mutex lock;
int main() {
    auto words = std::make_unique<std::vector<std::string>>();
    std::thread worker([&] { std::lock_guard<std::mutex> guard(lock); words->push_back("stow"); });
    worker.join();
    return words->size() == 1 ? 0 : 1;
}
CPP

export PATH="$sysroot/bin:$PATH"

fail() {
    echo "check-cxx: $*" >&2
    exit 1
}

# True when version name $1 sorts strictly above the $2
# ceiling — `sort -V` orders the dotted fields.
version_over() {
    [ "$1" != "$2" ] \
        && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# Audit one linked output: refuse a GLIBC_ reference above
# 2.28 or a GLIBCXX_ reference above 3.4.25, refuse a missing
# libstdc++.so.6 NEEDED, and print the observed maxima.
audit() {
    local file="$1" arch="$2" step="$3"
    local glibc glibcxx
    glibc="$(readelf -V "$file" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu | tail -1 || true)"
    glibcxx="$(readelf -V "$file" | grep -o 'GLIBCXX_[0-9][0-9.]*' | sort -Vu | tail -1 || true)"
    if [ -n "$glibc" ] && version_over "$glibc" GLIBC_2.28; then
        fail "$file ($step): requires $glibc, above the GLIBC_2.28 floor"
    fi
    if [ -n "$glibcxx" ] && version_over "$glibcxx" GLIBCXX_3.4.25; then
        fail "$file ($step): requires $glibcxx, above GLIBCXX_3.4.25 (libstdc++ 8)"
    fi
    readelf -d "$file" | grep -q 'NEEDED.*libstdc++\.so\.6' \
        || fail "$file ($step): no libstdc++.so.6 in NEEDED — the link went static or dropped it"
    echo "check-cxx: $arch $(basename "$file"): highest GLIBC ${glibc:-none}, highest GLIBCXX ${glibcxx:-none}"
}

# Compile the TU through one architecture's shims and audit
# both linked outputs.
check_arch() {
    local arch="$1" cxx="$2" cc="$3"
    local exe="$tmp/$arch-exe" obj="$tmp/$arch.o" cc_exe="$tmp/$arch-cc"

    "$cxx" -std=c++17 -pthread -fuse-ld=mold -o "$exe" "$tmp/tu.cc" \
        || fail "$cxx ($arch): compile-and-link step failed"
    audit "$exe" "$arch" "$cxx link"

    "$cxx" -std=c++17 -fPIC -c -o "$obj" "$tmp/tu.cc" \
        || fail "$cxx ($arch): object-compile step failed"
    "$cc" -o "$cc_exe" "$obj" \
        -Wl,--as-needed -lstdc++ -lgcc_s -lpthread -lm -lc -fuse-ld=mold \
        || fail "$cc ($arch): link of the $cxx-compiled object failed"
    audit "$cc_exe" "$arch" "$cc link"
}

check_arch x86_64 g++ cc
# The g++-linked native executable must actually run: the
# audit reads the ELF, and this shows what it describes is a
# working program under the runner's own, newer runtime.
"$tmp/x86_64-exe" \
    || fail "$tmp/x86_64-exe (linked by g++) exited $?"
if [ -x "$sysroot/bin/aarch64-linux-gnu-g++" ]; then
    check_arch aarch64 aarch64-linux-gnu-g++ aarch64-linux-gnu-gcc
fi
