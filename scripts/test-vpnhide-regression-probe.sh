#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CXX="${CXX:-c++}"
mkdir -p "$ROOT/build"
WORK="$(mktemp -d "$ROOT/build/vpnhide-regression-probe-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

"$CXX" \
  -std=c++17 -O2 -Wall -Wextra -Werror \
  -I"$ROOT/app/src/main/cpp" \
  "$ROOT/app/src/main/cpp/vpnhide_regression_probe.cpp" \
  "$ROOT/app/src/test/cpp/vpnhide_regression_probe_test.cpp" \
  -o "$WORK/vpnhide-regression-probe-test"

"$WORK/vpnhide-regression-probe-test"
