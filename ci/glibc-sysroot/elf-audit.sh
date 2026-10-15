# ELF version audits the check-*.sh scripts share. Sourced, not
# run.

# True when version name $1 sorts strictly above the $2
# ceiling — `sort -V` orders the dotted fields.
version_over() {
    [ "$1" != "$2" ] \
        && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# The highest version name starting with $2 (GLIBC_, GLIBCXX_)
# that ELF $1 references; empty when it references none.
highest_version() {
    readelf -V "$1" | grep -o "$2[0-9][0-9.]*" | sort -Vu | tail -1 || true
}
