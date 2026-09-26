#!/bin/bash
# usage: native_after.sh <bin> <suffix>
BIN=$1; S=$2; cd ~/memprof
T9=aarch64-apple-darwin,aarch64-apple-ios,aarch64-apple-ios-sim,aarch64-linux-android,x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,x86_64-pc-windows-msvc,aarch64-pc-windows-msvc,wasm32-unknown-unknown
/usr/bin/time -v $BIN zed-industries/zed 933d8d93819c749a607e561883855a9b95c79cea x86_64-unknown-linux-gnu --replay zed-fixture --emit out/zed-$S.tsv > out/zed-$S.log 2>&1
/usr/bin/time -v $BIN sharkdp/bat 979ba22628bc9d8171f2cffca2bd5c90c9fc0a9e $T9 --replay bat-fixture --emit out/bat-$S.tsv > out/bat-$S.log 2>&1
/usr/bin/time -v $BIN rust-lang/rust-analyzer 1ad44dc58e65304b594063e70c144ecb58643671 $T9 --replay ra-fixture --emit out/ra-$S.tsv > out/ra-$S.log 2>&1
for x in zed bat ra; do echo "== $x"; grep -h "User time\|Maximum resident" out/$x-$S.log; grep -h '"label":"request_end"' out/$x-$S.log | python3 -c 'import sys,json;[print("native peak MiB %.1f"%(json.loads(l.split("MEMPROF ",1)[1])["peak"]/2**20)) for l in sys.stdin]'; cmp out/$x-base.tsv out/$x-$S.tsv && echo "$x: units/roots IDENTICAL ($(wc -c < out/$x-$S.tsv) bytes)"; done
