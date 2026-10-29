#!/usr/bin/env bash
# Create the stable local code-signing identity scripts/signing-ld.sh
# signs with (docs/USAGE.md, "Local code signing"). Idempotent: an
# identity that already exists is kept, and only its partition list is
# re-applied. Run once per machine, then set
# STOW_LOCAL_SIGNING_IDENTITY to the same name.
#
# Usage: scripts/local-signing-identity.sh [identity-name]
#
# security set-key-partition-list prompts once for the login keychain
# password — the only interactive step; passing -k would put it in the
# process list.
set -euo pipefail

identity=${1:-stow-admin-local}
keychain="$HOME/Library/Keychains/login.keychain-db"

if security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\"" >/dev/null 2>&1; then
    echo "identity '$identity' already present in $keychain"
else
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # A self-signed EC P-256 certificate whose only use is code signing:
    # keyUsage=digitalSignature plus extendedKeyUsage=codeSigning (EKU
    # 1.3.6.1.5.5.7.3.3) is what `security find-identity -p codesigning`
    # and codesign require. The certificate never needs to be trusted —
    # a keychain ACL matches the code requirement's certificate leaf,
    # not a trust decision.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -days 3650 -nodes \
        -subj "/CN=$identity/" \
        -addext 'keyUsage=digitalSignature' \
        -addext 'extendedKeyUsage=codeSigning'
    openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" \
        -name "$identity" -out "$tmp/id.p12" -passout pass:
    # -T authorises /usr/bin/codesign in the imported key's application
    # ACL — necessary but not sufficient, hence the partition list below.
    security import "$tmp/id.p12" -k "$keychain" -P '' -T /usr/bin/codesign
    echo "imported identity '$identity' into $keychain"
fi

# Since macOS 10.12 a private key's partition list is a second ACL the
# import's -T list does not touch: without `apple:` in it codesign still
# prompts (man security, set-key-partition-list: "If you'd like to run
# /usr/bin/codesign with the key, 'apple:' must be an element of the
# partition list"). apple-tool: is what a fresh import writes, so it is
# kept; codesign: lets the tool self-identify. The match is scoped to
# this identity's signing-capable private key by label — a bare `-s`
# would rewrite the partition list of every key in the keychain.
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s -l "$identity" \
    "$keychain"

echo "done — export STOW_LOCAL_SIGNING_IDENTITY=$identity to sign every local macOS build in this repository"
