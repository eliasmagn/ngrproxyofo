#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<'EOF'
Usage:
  scripts/run-sdk-package-tests.sh <sdk-path> [<sdk-path>...]

Example:
  scripts/run-sdk-package-tests.sh \
    ~/sdk/openwrt-sdk-23.05.5-ath79-generic_gcc-12.3.0_musl.Linux-x86_64 \
    ~/sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64
EOF
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${ROOT_DIR}/luci-app-ngrproxy"

for sdk in "$@"; do
  echo "==> Testing in SDK: ${sdk}"
  [[ -d "${sdk}" ]] || { echo "SDK path not found: ${sdk}" >&2; exit 1; }

  pushd "${sdk}" >/dev/null
  mkdir -p package/local
  rm -rf package/local/luci-app-ngrproxy
  cp -a "${PKG_DIR}" package/local/luci-app-ngrproxy

  ./scripts/feeds update -a
  ./scripts/feeds install luci-base
  make defconfig
  make package/local/luci-app-ngrproxy/{clean,compile} V=s
  popd >/dev/null
done
