#!/usr/bin/env bash
set -euo pipefail
cargo build --release >/dev/null
./target/release/spectra --help >/dev/null
