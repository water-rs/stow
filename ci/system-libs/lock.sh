#!/usr/bin/env bash
# Generate ci/system-libs/lock.txt: every deb the Linux build legs
# provision — the pkg-config system libraries of libs.txt, the aarch64
# cross toolchain and mold of toolchain-<target>.txt — resolved at one
# snapshot.ubuntu.com instant and pinned by sha256 (stow#850, stow#862).
#
# Usage: ci/system-libs/lock.sh <T> [<output>]
#
# <T> is a snapshot.ubuntu.com instant, e.g. 20261022T200000Z: one
# timestamp serving the amd64 and arm64 halves consistently, so every
# leg sees the same bytes and a Multi-Arch: same package is identical
# wherever the two builds share a path (checked below). <output>
# defaults to lock.txt next to this script.
#
# Everything runs against an isolated apt tree under mktemp: no root,
# none of the host's apt configuration, and an empty dpkg status, so
# every resolve is the full dependency closure from nothing and does
# not depend on what the runner image happens to have installed. Needs
# apt-get, dpkg-deb, pkg-config and GNU coreutils — any Ubuntu host.
set -euo pipefail
export LC_ALL=C

T="${1:?usage: lock.sh <snapshot-T> [<output>]}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${2:-$here/lock.txt}"
suite=noble
mirror="https://snapshot.ubuntu.com/ubuntu/$T"
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg

fail() { echo "lock.sh: $*" >&2; exit 1; }

[[ "$T" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    || fail "'$T' is not a snapshot.ubuntu.com instant (want e.g. 20261022T200000Z)"
for c in apt-get dpkg-deb pkg-config; do
    command -v "$c" > /dev/null || fail "needs $c — run on an Ubuntu $suite host"
done
[ -f "$keyring" ] || fail "$keyring missing — run on an Ubuntu host"

read_list() { grep -Ev '^[[:space:]]*(#|$)' "$1"; }
mapfile -t libs < <(read_list "$here/libs.txt")
mapfile -t tc_x64 < <(read_list "$here/toolchain-x86_64-unknown-linux-gnu.txt")
mapfile -t tc_a64 < <(read_list "$here/toolchain-aarch64-unknown-linux-gnu.txt")
[ "${#libs[@]}" -gt 0 ] || fail "libs.txt is empty"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- 1. Isolated apt tree ------------------------------------------
apt_dir="$work/apt"
mkdir -p "$apt_dir"/etc/sources.list.d "$apt_dir"/etc/preferences.d \
    "$apt_dir"/etc/trusted.gpg.d "$apt_dir"/state/lists/partial \
    "$apt_dir"/cache/archives/partial
: > "$apt_dir/state/status"   # empty dpkg status: nothing is installed
: > "$apt_dir/etc/sources.list"   # and no one-line sources

# One deb822 stanza is the design's single source line: both
# architectures, the three suites, and main+universe+restricted+
# multiverse — the components ports.sources.in uses today.
cat > "$apt_dir"/etc/sources.list.d/snapshot.sources <<EOF
Types: deb
URIs: $mirror
Suites: $suite $suite-updates $suite-security
Components: main universe restricted multiverse
Architectures: amd64 arm64
Signed-By: $keyring
EOF

# Command-line -o options land after apt has already read the host's
# /etc/apt config files — nothing on the command line un-reads them —
# so isolation is set leaf by leaf: sourcelist/sourceparts replace the
# host's sources (sources.list itself is left absent), preferences*
# drop any pins, trusted* empty the keyring dirs (the source line
# carries signed-by). Dir::State relocates the lists; its status leaf
# is dpkg's (an absolute default, so it is set on its own) and points
# at the empty file above so every resolve is the full closure.
# Dir::Cache relocates the pkgcache and archives. Host leftovers that
# could skew the result — APT::Default-Release, Install-Recommends —
# are pinned below.
apt_get() {
    apt-get \
        -o "Dir::Etc::sourcelist=$apt_dir/etc/sources.list" \
        -o "Dir::Etc::sourceparts=$apt_dir/etc/sources.list.d" \
        -o "Dir::Etc::preferences=$apt_dir/etc/preferences" \
        -o "Dir::Etc::preferencesparts=$apt_dir/etc/preferences.d" \
        -o "Dir::Etc::trusted=$apt_dir/etc/trusted.gpg" \
        -o "Dir::Etc::trustedparts=$apt_dir/etc/trusted.gpg.d" \
        -o "Dir::State=$apt_dir/state" \
        -o "Dir::State::status=$apt_dir/state/status" \
        -o "Dir::Cache=$apt_dir/cache" \
        -o "APT::Architecture=amd64" \
        -o "APT::Architectures=amd64" \
        -o "APT::Architectures::=arm64" \
        -o "APT::Default-Release=" \
        -o "Acquire::Retries=3" \
        "$@"
}

# apt verifies each suite's InRelease against the archive keyring.
apt_get update

# --- 2/3. Resolve each set from the empty status --------------------
# resolve <dir> <spec…>: --print-uris first records the pool URL and
# index sha256 of every deb the closure needs (it resolves identically
# and fetches nothing), then the download-only install fetches them
# into <dir>, apt checking the bytes against the index on the way.
resolve() {
    local dest="$1"; shift
    mkdir -p "$dest/partial"
    apt_get -o "Dir::Cache::archives=$dest" install \
        -y --download-only --no-install-recommends --print-uris "$@" \
        | sed -n "s/^'\([^']*\)' /\1 /p" \
        | awk '{url=$1; file=$2; sha="";
                for (i=3; i<=NF; i++) if ($i ~ /^SHA256:/) sha=substr($i, 8);
                print file "\t" url "\t" sha}' > "$dest.uris"
    apt_get -o "Dir::Cache::archives=$dest" install \
        -y --download-only --no-install-recommends "$@"
    rm -rf "$dest/partial" "$dest/lock"
    # A resolve must not accumulate state: keep the status empty for
    # the next one.
    : > "$apt_dir/state/status"
}

resolve "$work/res-libs-amd64" "${libs[@]/%/:amd64}"
resolve "$work/res-libs-arm64" "${libs[@]/%/:arm64}"
resolve "$work/res-tc-x86_64" "${tc_x64[@]}"
resolve "$work/res-tc-aarch64" "${tc_a64[@]}"

# Per-deb facts, keyed by basename — the name the lock records.
declare -A sha_of url_of pkg_of arch_of list_of
register_dir() {
    local dest="$1" deb base f u s
    for deb in "$dest"/*.deb; do
        base="$(basename "$deb")"
        [ -n "${sha_of[$base]:-}" ] && continue   # in both resolves; same T, same bytes
        f=""; u=""; s=""
        IFS=$'\t' read -r f u s < <(awk -F'\t' -v b="$base" '$1==b' "$dest.uris")
        [ "$f" = "$base" ] \
            || fail "apt fetched $base but --print-uris did not report it"
        case "$u" in
            "$mirror"/pool/*) ;;
            *) fail "$base resolves to $u — outside $mirror/pool";;
        esac
        sha_of[$base]="$(sha256sum "$deb" | awk '{print $1}')"
        [ -z "$s" ] || [ "$s" = "${sha_of[$base]}" ] \
            || fail "$base: index SHA256 $s != fetched bytes' sha256 ${sha_of[$base]}"
        url_of[$base]="$u"
        pkg_of[$base]="$(dpkg-deb -f "$deb" Package)"
        arch_of[$base]="$(dpkg-deb -f "$deb" Architecture)"
    done
}
for d in res-libs-amd64 res-libs-arm64 res-tc-x86_64 res-tc-aarch64; do
    register_dir "$work/$d"
done

marks="$work/marks"; : > "$marks"   # "<set>\t<deb basename>"

# The toolchain sets keep by package name (§6 step 3): the closure of
# the cross compilers is mostly the image's base system; only the
# packages that are the cross toolchain itself are locked.
for d in res-tc-x86_64 res-tc-aarch64; do
    set_name="toolchain-${d#res-tc-}-unknown-linux-gnu"
    n=0
    for deb in "$work/$d"/*.deb; do
        base="$(basename "$deb")"
        case "${pkg_of[$base]}" in
            *-aarch64-linux-gnu | *-aarch64-linux-gnu-base | *-arm64-cross | *-cross-base | mold)
                printf '%s\t%s\n' "$set_name" "$base" >> "$marks"
                n=$((n + 1));;
        esac
    done
    [ "$n" -gt 0 ] || fail "$set_name: the name filter kept nothing"
done

# --- The §5 filter on the library sets ------------------------------
# Keep a package only if a build can reach it: it ships a header or a
# .pc file, it owns the target of a kept dev .so symlink, or it ships
# an executable a kept .pc names (wayland-scanner, today). The runtime
# bulk — mesa, llvm, the arm64 libc — ships none of those and is
# dropped; nothing a build runs can name it.
#
# $work/pool.tsv is every file the libs resolves fetched:
# "<path>\t<deb basename>\t<mode>\t<symlink target>".
pool="$work/pool.tsv"; : > "$pool"
declare -A path_of
for d in res-libs-amd64 res-libs-arm64; do
    for deb in "$work/$d"/*.deb; do
        base="$(basename "$deb")"
        [ -n "${path_of[$base]:-}" ] && continue
        path_of[$base]="$deb"
        lst="$work/lst-$base"
        dpkg-deb -c "$deb" | awk '{
            mode=$1; path=$6; tgt="";
            if ($7 == "->") tgt=$8;
            sub(/^\.\//, "", path); sub(/\/$/, "", path);
            printf "%s\t%s\t%s\n", path, mode, tgt
        }' > "$lst"
        list_of[$base]="$lst"
        awk -F'\t' -v b="$base" '{printf "%s\t%s\t%s\t%s\n", $1, b, $2, $3}' \
            "$lst" >> "$pool"
    done
done

# owners <path>: basenames of pool debs shipping that file or symlink.
owners() { awk -F'\t' -v p="$1" '$1==p && $3 ~ /^[l-]/ {print $2}' "$pool" | sort -u; }
# owners_exec <path>: the same, only executable regular files.
owners_exec() { awk -F'\t' -v p="$1" '$1==p && $3 ~ /^-/ && $3 ~ /x/ {print $2}' "$pool" | sort -u; }

declare -A keep sets_of extracted
for base in "${!path_of[@]}"; do
    case "${arch_of[$base]}" in
        amd64) sets_of[$base]="libs-amd64";;
        arm64) sets_of[$base]="libs-arm64";;
        all)   sets_of[$base]="libs-amd64 libs-arm64";;
        *) fail "$base: unexpected Architecture: ${arch_of[$base]}";;
    esac
    if awk -F'\t' '$1 ~ /^usr\/include\// || $1 ~ /\.pc$/ {f=1} END {exit !f}' \
        "${list_of[$base]}"; then
        keep[$base]=1
    fi
done

merged="$work/root"; mkdir -p "$merged"
extract_new() {
    local base
    for base in "${!keep[@]}"; do
        if [ -z "${extracted[$base]:-}" ]; then
            dpkg-deb -x "${path_of[$base]}" "$merged"
            extracted[$base]=1
        fi
    done
}

# A dev .so symlink is relative (libfoo.so -> libfoo.so.3) or absolute;
# normalize its target to a pool path.
resolve_link() {
    case "$2" in
        /*) realpath -m -- "$2";;
        *)  realpath -m -- "/$(dirname "$1")/$2";;
    esac
}

extract_new
while :; do
    added=0
    # The target of a kept dev .so symlink: the runtime package owning
    # e.g. libssl.so.3 while the .so link lives in libssl-dev.
    for base in "${!keep[@]}"; do
        while IFS=$'\t' read -r path mode tgt; do
            case "$mode" in l*) ;; *) continue;; esac
            case "$path" in *.so) ;; *) continue;; esac
            res="$(resolve_link "$path" "$tgt")"
            while IFS= read -r o; do
                [ -n "${keep[$o]:-}" ] || { keep[$o]=1; added=1; }
            done < <(owners "${res#/}")
        done < "${list_of[$base]}"
    done
    # An executable a kept .pc names: pkg-config expands each variable
    # against the unrelocated prefix, so values come out as the /usr
    # paths the debs ship (e.g. wayland-scanner.pc's /usr/bin/
    # wayland-scanner, shipped by M-A:foreign libwayland-bin:amd64).
    pc_libdir="$(find "$merged" -type d -name pkgconfig | paste -sd:)"
    while IFS= read -r pc; do
        mod="$(basename "$pc" .pc)"
        vars="$(PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' \
            PKG_CONFIG_LIBDIR="$pc_libdir" \
            pkg-config --print-variables "$mod")" \
            || fail "$mod: pkg-config --print-variables failed while scanning executables"
        while IFS= read -r var; do
            val="$(PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' \
                PKG_CONFIG_LIBDIR="$pc_libdir" \
                pkg-config --variable="$var" "$mod")" \
                || fail "$mod: pkg-config --variable=$var failed while scanning executables"
            case "$val" in
                /*) while IFS= read -r o; do
                        [ -n "${keep[$o]:-}" ] || { keep[$o]=1; added=1; }
                    done < <(owners_exec "${val#/}");;
            esac
        done <<< "$vars"
    done < <(find "$merged" -type f -name '*.pc')
    [ "$added" -eq 0 ] && break
    extract_new
done
extract_new

for base in "${!keep[@]}"; do
    for s in ${sets_of[$base]}; do
        printf '%s\t%s\n' "$s" "$base" >> "$marks"
    done
done
cut -f1 "$marks" | grep -qx libs-amd64 || fail "libs-amd64 resolved to nothing"
cut -f1 "$marks" | grep -qx libs-arm64 || fail "libs-arm64 resolved to nothing"

# --- 4. The two architectures must agree on every shared path -------
# A T at which ports published a fix later than amd64 leaves an
# arch-independent file (usr/include/openssl/*.h, …) at two versions;
# fail and let the operator pick another T.
amd="$work/tree-amd64"; arm="$work/tree-arm64"
mkdir -p "$amd" "$arm"
for base in "${!keep[@]}"; do
    for s in ${sets_of[$base]}; do
        case "$s" in
            libs-amd64) dpkg-deb -x "${path_of[$base]}" "$amd";;
            libs-arm64) dpkg-deb -x "${path_of[$base]}" "$arm";;
        esac
    done
done
(cd "$amd" && find . \( -type f -o -type l \) -printf '%P\n' | sort) > "$work/paths-amd64"
(cd "$arm" && find . \( -type f -o -type l \) -printf '%P\n' | sort) > "$work/paths-arm64"
while IFS= read -r p; do
    a="$amd/$p"; b="$arm/$p"
    if [ -L "$a" ] || [ -L "$b" ]; then
        [ -L "$a" ] && [ -L "$b" ] && [ "$(readlink "$a")" = "$(readlink "$b")" ] \
            || fail "$p: amd64 and arm64 disagree (link vs file or different targets) at $T — pick another T"
    else
        cmp -s "$a" "$b" \
            || fail "$p differs between the amd64 and arm64 builds at $T — pick another T"
    fi
done < <(comm -12 "$work/paths-amd64" "$work/paths-arm64")

# --- 5. Self-check the relocated library root -----------------------
# The relocation install.sh applies on the leg: .pc variables whose
# value is /usr or under it name the root's usr/, absolute symlinks
# resolve inside it. One script — relocate.sh — does it for the
# generator's check and the leg alike, so the two cannot drift.
"$here/relocate.sh" "$merged"

pc_libdir="$(find "$merged" -type d -name pkgconfig | paste -sd:)"
while IFS= read -r pc; do
    mod="$(basename "$pc" .pc)"
    rel="${pc#"$merged"/}"
    sed "s|$merged||g" "$pc" | grep -q '/usr' \
        && fail "$rel still names /usr after relocation"
    flags="$(PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' \
        PKG_CONFIG_LIBDIR="$pc_libdir" \
        PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
        pkg-config --cflags --libs "$mod")" \
        || fail "$mod: pkg-config --cflags --libs failed under $pc_libdir"
    ldirs=("$merged/usr/lib" "$merged/usr/lib/"*/)
    for tok in $flags; do
        case "$tok" in
            -L*)
                d="${tok#-L}"
                [[ "$d" == "$merged/"* && -d "$d" ]] \
                    || fail "$mod: -L $d leaves the root"
                ldirs+=("$d");;
            -I*)
                d="${tok#-I}"
                [[ "$d" == "$merged/"* && -d "$d" ]] \
                    || fail "$mod: -I $d leaves the root";;
            /*)
                [[ "$tok" == "$merged/"* ]] \
                    || fail "$mod: $tok leaves the root";;
        esac
    done
    for tok in $flags; do
        case "$tok" in
            -l*)
                n="${tok#-l}"
                if [[ "$n" == :* ]]; then
                    names=("${n#:}")
                else
                    names=("lib$n.so" "lib$n.a")
                fi
                found=0
                for d in "${ldirs[@]}"; do
                    for f in "${names[@]}"; do
                        [ -e "$d/$f" ] && found=1
                    done
                done
                [ "$found" -eq 1 ] \
                    || fail "$mod: -l$n resolves to nothing under $merged";;
        esac
    done
done < <(find "$merged" -type f -name '*.pc' | sort)

# Every dev .so symlink resolves inside the root (the §5 filter kept
# each target's owner).
find "$merged" -type l -name '*.so' | while IFS= read -r l; do
    tgt="$(readlink "$l")"
    case "$tgt" in
        /*) res="$tgt";;
        *)  res="$(realpath -m "$(dirname "$l")/$tgt")";;
    esac
    { [[ "$res" == "$merged/"* ]] && [ -e "$res" ]; } \
        || fail "dev .so ${l#"$merged"/} -> $res leaves the root or dangles"
done

# --- 6. Write the lock ----------------------------------------------
# Header names the suite and T (the PR check parses '# snapshot:');
# then "<set> <sha256> <filename> <url>", sorted — byte-identical for a
# given T, so a lock bump's diff lists every version that moved.
{
    printf '# stow#850: every deb a Linux build leg provisions — the pkg-config\n'
    printf '# system libraries, the aarch64 cross toolchain and mold — resolved at\n'
    printf '# %s and pinned by sha256. Regenerate: ci/system-libs/lock.sh <T>.\n' "$mirror/"
    printf '# suite: %s\n' "$suite"
    printf '# snapshot: %s\n' "$T"
    sort -u "$marks" | while IFS=$'\t' read -r s base; do
        printf '%s %s %s %s\n' "$s" "${sha_of[$base]}" "$base" "${url_of[$base]}"
    done
} > "$out"
echo "lock.sh: wrote $out ($(grep -cv '^#' "$out") debs at $T)"