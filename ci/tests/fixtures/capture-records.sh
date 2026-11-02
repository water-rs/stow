#!/bin/sh
set -eu
[ "$1" = push-records ]
[ "$2" = --records ]
cp "$3" "$(dirname "$0")/captured-records.json"
