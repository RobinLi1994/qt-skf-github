# Repository Guidelines

## 项目结构与模块组织
- `src/` 为生产代码目录，按职责拆分，并在 `src/CMakeLists.txt` 中统一编排。
- 核心模块包括：`common/`、`config/`、`log/`、`plugin/`、`core/`、`api/`、`gui/`、`app/`（程序入口）。
- 静态资源位于 `resources/`（图标、平台元数据如 `Info.plist.in`、`app.rc`）。
- 构建与打包辅助脚本位于 `scripts/`。
- 设计说明与规格文档位于 `docs/`、`spec.md`、`plan.md`。
- 构建产物应放在 `build/`（或平台专用构建目录），不应作为源码提交。

## 构建、测试与开发命令
- `make configure`：在 `build/` 中生成 CMake 配置（需要时设置 `QT_DIR=/path/to/Qt`）。
- `make build`：默认进行 Debug 构建；`make release` 进行 Release 构建。
- `make run`：构建后启动 `wekey-skf`。
- `make test`：在 `build/` 中执行 CTest，并输出失败详情。
- `make asan`：启用 AddressSanitizer 做内存错误检查。
- `make format`：对 `src/`（以及存在时的 `tests/`）执行 `clang-format`。
- `make lint`：基于 `build/` 中编译数据库执行 `clang-tidy`。
- 打包命令：`make package-mac` 或 `make package-win`。

## 代码风格与命名约定
- 语言标准为 C++17（见 `CMakeLists.txt`）。
- 非 MSVC 编译器启用严格告警：`-Wall -Wextra -Wpedantic -Werror`。
- 使用仓库内 `.clang-format`（Google 基础风格、4 空格缩进、100 列限制、禁用 Tab）。
- 注释规范：新增或修改代码时，若业务意图、协议约束、数据格式、会话假设或兼容性处理不直观，必须补充简洁注释，优先说明“为什么这样做”与关键约束，避免只写逐行翻译式注释。
- 命名遵循现有代码模式：
  - 类型/类名：`PascalCase`（例如 `DeviceService`、`MainWindow`）。
  - 方法/变量：`camelCase`。
  - 文件命名：`Name.h` + `Name.cpp` 成对维护。

## 测试指南
- 测试运行器为 CTest（`ctest --output-on-failure`），Qt Test 通过 `ENABLE_TESTING` 启用。
- 新增自动化测试建议放在后续 `tests/` 目录，并在 CMake 中注册。
- 测试命名建议按功能与行为表达，例如：`test_device_service.cpp`，用例名 `DeviceService_HandlesHotplug`。
- 内置模块联调可在构建后执行：`bash test_builtin_module.sh`。

## 提交与合并请求规范
- 提交信息遵循仓库现有 Conventional Commits 风格：`feat(scope): ...`、`fix(scope): ...`、`chore(scope): ...`。
- `scope` 建议与模块对应（如 `gui`、`api`、`DeviceService`、`plugin`）。
- PR 至少应包含：
  - 变更摘要与修改动机。
  - 关联 issue/task（如有）。
  - 本地验证记录（如 `make build`、`make test`、打包验证）。
  - 涉及 `src/gui` 的改动需附截图或短录屏。

## 附加规则
- 日志规范：新增或修改日志时，需包含明确上下文（模块名、关键参数、错误码或异常原因），避免仅输出无意义文本；错误日志优先使用 `error` 级别，调试信息使用 `debug` 级别。
- 中文回答问题：在本仓库协作过程中，默认使用中文进行说明、评审意见与问题回复；仅在用户明确要求英文时切换语言。
