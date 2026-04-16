#!/usr/bin/env bash
#
# 根据目标 macOS 架构选择“源”SKF 动态库。
# 注意：这里只决定从 resources/lib/mac/ 取哪一个文件；
# 打包脚本后续仍会统一把它拷贝成 Frameworks/libgm3000.dylib。

set -euo pipefail

ARCH="${1:-}"

case "${ARCH}" in
    arm64|aarch64)
        # Apple Silicon runner / 目标包：使用 arm64 专用库
        echo "resources/lib/mac/libgm3000.1.0_arm64.dylib"
        ;;
    amd64|x86_64)
        # Intel runner / 目标包：使用 x86_64 专用库
        echo "resources/lib/mac/libgm3000.1.0_x86.dylib"
        ;;
    *)
        echo "unsupported macOS arch: ${ARCH}" >&2
        exit 1
        ;;
esac
