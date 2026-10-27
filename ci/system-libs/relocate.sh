#!/usr/bin/env bash
# Relocate an extracted system-libs tree: rewrite every .pc variable
# assignment whose value is exactly /usr or begins /usr/ so it names
# the root's own usr/, and repoint every absolute symlink inside the
# tree (stow#850).
#
# Usage: ci/system-libs/relocate.sh <tree> [<relocate-to>]
#
# <relocate-to> defaults to <tree>: lock.sh self-checks the root it
# extracted in place, while install.sh relocates its staging copy
# before the atomic mv — relocated paths must name the final root,
# never the staging dir (the same convention glibc-sysroot/install.sh
# keeps for its repointed symlinks).
#
# The rewrite keys on the assignment, not the variable name —
# prefix=/usr is not the only spelling: the arm64 alsa.pc carries
# a literal exec_prefix=/usr, which is what the self-check's "still
# names /usr" failure caught (run 39878359623). Single script both
# lock.sh and install.sh call, so the transform cannot drift.
set -euo pipefail

tree="${1:?usage: relocate.sh <tree> [<relocate-to>]}"
into="${2:-$tree}"
[ -d "$tree" ] || { echo "relocate.sh: $tree is not a directory" >&2; exit 1; }

find "$tree" -type l -lname '/*' | while IFS= read -r l; do
    ln -sfn "$into$(readlink "$l")" "$l"
done
find "$tree" -type f -name '*.pc' -print0 \
    | xargs -0 -r sed -i -E "s#^([A-Za-z_][A-Za-z0-9_.]*)=/usr(/|\$)#\1=$into/usr\2#"
