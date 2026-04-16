#!/usr/bin/env bash
#
# 回归测试：约束“目标架构 -> 源 SKF 库”映射关系。
# 这里只验证选择器输出，不关心最终包内文件名是否统一重命名。

set -euo pipefail

ROOT_DIR="${1:?repo root is required}"
SELECTOR="${ROOT_DIR}/scripts/select_mac_skf_lib.sh"

expect_selected_lib() {
    local arch="$1"
    local expected="$2"
    local actual

    actual="$(bash "${SELECTOR}" "${arch}")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "unexpected library for arch ${arch}: got ${actual}, want ${expected}" >&2
        exit 1
    fi

    if [[ ! -f "${ROOT_DIR}/${actual}" ]]; then
        echo "selected library does not exist for arch ${arch}: ${actual}" >&2
        exit 1
    fi
}

expect_selected_lib "arm64" "resources/lib/mac/libgm3000.1.0_arm64.dylib"
expect_selected_lib "aarch64" "resources/lib/mac/libgm3000.1.0_arm64.dylib"
expect_selected_lib "amd64" "resources/lib/mac/libgm3000.1.0_x86.dylib"
expect_selected_lib "x86_64" "resources/lib/mac/libgm3000.1.0_x86.dylib"

echo "mac SKF library selector behaves as expected"
