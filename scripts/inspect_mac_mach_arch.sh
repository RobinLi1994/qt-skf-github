#!/usr/bin/env bash
#
# 读取 Mach-O 文件架构信息，并校验是否包含期望架构。
# 优先输出 `file` 结果；如果本机有 `lipo`，额外打印 `lipo -info`
# 方便在 GitLab 日志里直接确认主程序和内置驱动的实际架构。

set -euo pipefail

TARGET_PATH="${1:?target path is required}"
EXPECTED_ARCH="${2:?expected arch is required}"
LABEL="${3:-Mach-O binary}"

normalize_arch() {
    case "$1" in
        amd64)
            # GitLab / 打包脚本里统一用 amd64 命名，但 Mach-O 元数据里显示 x86_64
            echo "x86_64"
            ;;
        arm64|x86_64)
            echo "$1"
            ;;
        *)
            echo "unsupported macOS arch: $1" >&2
            exit 1
            ;;
    esac
}

EXPECTED_TOKEN="$(normalize_arch "${EXPECTED_ARCH}")"

if [ ! -f "${TARGET_PATH}" ]; then
    echo "ERROR: ${LABEL} not found: ${TARGET_PATH}" >&2
    exit 1
fi

FILE_OUTPUT="$(file "${TARGET_PATH}")"
echo "${LABEL} file: ${FILE_OUTPUT}"

LIPO_OUTPUT=""
if command -v lipo >/dev/null 2>&1; then
    # universal / thin 二进制都能从 lipo -info 获得更直观的输出
    LIPO_OUTPUT="$(lipo -info "${TARGET_PATH}" 2>&1 || true)"
    if [ -n "${LIPO_OUTPUT}" ]; then
        echo "${LABEL} lipo: ${LIPO_OUTPUT}"
    fi
fi

if printf '%s\n%s\n' "${FILE_OUTPUT}" "${LIPO_OUTPUT}" | grep -q "${EXPECTED_TOKEN}"; then
    echo "${LABEL} architecture verification PASSED: ${EXPECTED_TOKEN}"
else
    echo "ERROR: ${LABEL} architecture verification FAILED, expected ${EXPECTED_TOKEN}" >&2
    exit 1
fi
