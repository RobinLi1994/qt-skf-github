# 第三方依赖管理

本文件记录了项目使用的第三方依赖及其版本信息，确保构建的可重复性。

## ElaWidgetTools

**用途：** Fluent-UI 风格的 Qt6 组件库，提供现代化的 UI 界面

**集成方式：** CMake FetchContent（源码构建）

**版本信息：**
- 仓库: https://github.com/Liniyous/ElaWidgetTools
- Commit: `6d46c5a4fd95cc2ad76099f849e3fe2465dff5a3`
- 分支: main
- 锁定日期: 2026-02-11
- 构建类型: 静态库

**版本历史：**
| 日期 | Commit | 说明 |
|------|--------|------|
| 2026-02-11 | 6d46c5a4 | 初始版本锁定 |

**更新步骤：**

1. 检查上游更新
```bash
git ls-remote https://github.com/Liniyous/ElaWidgetTools.git HEAD
```

2. 在本地测试新版本
```bash
# 临时修改 CMakeLists.txt 中的 GIT_TAG
rm -rf build
make build
make run
```

3. 测试通过后更新 CMakeLists.txt 和本文档

4. 提交版本变更
```bash
git add CMakeLists.txt DEPENDENCIES.md
git commit -m "chore(deps): update ElaWidgetTools to [commit-hash]"
```

## Qt 6

**版本：** 6.10.2 (系统安装)

**必需组件：**
- Qt6::Core
- Qt6::Widgets
- Qt6::WidgetsPrivate
- Qt6::Network
- Qt6::HttpServer
- Qt6::Test (开发环境)

**安装方式：**
- macOS: 通过 Qt 官方安装程序安装
- 其他平台: 参考 README.md

## Inno Setup 6

**用途：** Windows 安装器打包，生成 `wekey-skf-windows-amd64-setup.exe`

**集成方式：**
- 优先使用仓库内 `tools/windows/inno/`
- 找不到时自动从 `PATH`、常见安装目录或 `INNO_SETUP_COMPILER` 发现 `ISCC.exe`

**注意事项：**
- `scripts/package_win.ps1` 会在生成 `dist/` 后调用 Inno Setup 编译安装器
- 若放入仓库，建议提交完整的 Inno Setup 编译目录，而不是只提交单个 `ISCC.exe`
- 更新 Inno Setup 版本后需要重新验证安装流程与卸载流程

## Microsoft Visual C++ Redistributable (x64)

**用途：** Windows 运行时依赖（MSVC 2015-2022 x64）

**集成方式：**
- 优先使用仓库内 `tools/windows/redist/vc_redist.x64.exe`
- 也可通过环境变量 `VC_REDIST_PATH` 覆盖
- 若仓库和环境变量都未提供，脚本会从 Visual Studio / Build Tools 的 MSVC Redist 目录自动发现
- 安装器启动时检查系统注册表，缺失时静默安装内置 redistributable

**版本策略：**
- 必须与当前 Qt/MSVC 构建链兼容
- 升级 redistributable 后需要重新验证安装器、主程序启动和卸载流程

## 依赖管理原则

1. **版本锁定：** 所有第三方依赖必须锁定到具体版本（commit hash 或 tag）
2. **文档更新：** 每次更新依赖都必须更新本文档
3. **测试验证：** 依赖更新前必须进行完整的编译和功能测试
4. **变更记录：** 在版本历史表中记录每次依赖变更的原因
