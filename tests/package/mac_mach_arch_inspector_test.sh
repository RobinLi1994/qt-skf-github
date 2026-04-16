#!/usr/bin/env bash
#
# 回归测试：验证 Mach-O 架构检查脚本会正确接受匹配架构，
# 并在架构不匹配时返回失败，供打包脚本在 CI 中直接复用。

set -euo pipefail

ROOT_DIR="${1:?repo root is required}"
INSPECTOR="${ROOT_DIR}/scripts/inspect_mac_mach_arch.sh"

run_expect_pass() {
    local binary_path="$1"
    local expected_arch="$2"

    bash "${INSPECTOR}" "${binary_path}" "${expected_arch}" >/dev/null
}

run_expect_fail() {
    local binary_path="$1"
    local expected_arch="$2"

    if bash "${INSPECTOR}" "${binary_path}" "${expected_arch}" >/dev/null 2>&1; then
        echo "expected inspection to fail: ${binary_path} (${expected_arch})" >&2
        exit 1
    fi
}

run_expect_pass "${ROOT_DIR}/resources/lib/mac/libgm3000.1.0_arm64.dylib" "arm64"
run_expect_pass "${ROOT_DIR}/resources/lib/mac/libgm3000.1.0_x86.dylib" "amd64"
run_expect_fail "${ROOT_DIR}/resources/lib/mac/libgm3000.1.0_arm64.dylib" "amd64"

echo "mac Mach-O arch inspector behaves as expected"
