#!/usr/bin/env bash
set -euo pipefail

cargo build --release >/dev/null

./target/release/spectra --help >/dev/null
./target/release/spectra --version | grep -q '^spectra '

# Header-only little-endian PCAP: verifies CLI startup and JSON report output.
capture="$(mktemp --suffix=.pcap)"
trap 'rm -f "$capture"' EXIT
printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' >"$capture"
./target/release/spectra --json "$capture" | grep -q '"packets": 0'
