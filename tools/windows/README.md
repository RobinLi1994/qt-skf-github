# Windows 打包内置工具目录

Windows 打包脚本会优先使用仓库内工具，找不到时再回退到 runner 环境自动发现。

建议放置方式：

- `tools/windows/inno/`
  - 放完整的 Inno Setup 编译目录
  - 至少需要 `ISCC.exe` 以及它依赖的同目录资源文件
- `tools/windows/redist/vc_redist.x64.exe`
  - 放 Microsoft Visual C++ Redistributable x64 安装包

查找优先级：

1. 仓库内 `tools/windows/`
2. 环境变量覆盖（如 `INNO_SETUP_COMPILER`、`VC_REDIST_PATH`）
3. 系统 PATH、常见安装目录、Visual Studio / Build Tools 安装目录
