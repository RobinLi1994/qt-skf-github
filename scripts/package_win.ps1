# ==============================================================================
# Windows 打包脚本
#
# 构建 Release 版本并生成带安装器的 .exe 分发包
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts/package_win.ps1
# 依赖: cmake, Qt 6 (windeployqt), Inno Setup 6, vc_redist.x64.exe
# 工具优先级:
#   1. 仓库内 tools/windows/inno/ 与 tools/windows/redist/
#   2. 环境变量覆盖
#   3. 系统 PATH / 常见安装目录 / Visual Studio 安装目录自动发现
# ==============================================================================

$ErrorActionPreference = "Stop"

$AppName = "wekey-skf"
$DistDir = "dist"
# 优先使用 CI 传入的 PKG_ARCH，本地运行时默认 amd64
$PkgArch = if ($env:PKG_ARCH) { $env:PKG_ARCH } else { "amd64" }
$SetupName = "${AppName}-windows-${PkgArch}-setup.exe"
$SetupBaseName = [System.IO.Path]::GetFileNameWithoutExtension($SetupName)
$SourceRoot = (Get-Location).Path
$InstallerScript = Join-Path (Join-Path "scripts" "installer") "wekey-skf.iss"
$RepoWindowsToolsDir = Join-Path $SourceRoot "tools\windows"

function Resolve-ProjectVersion {
    $cmakeFile = Join-Path $SourceRoot "CMakeLists.txt"
    if (-not (Test-Path $cmakeFile)) {
        throw "CMakeLists.txt not found: $cmakeFile"
    }

    $content = Get-Content $cmakeFile -Raw
    $match = [regex]::Match(
        $content,
        "project\s*\(\s*wekey-skf\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)"
    )
    if (-not $match.Success) {
        throw "Failed to parse project version from CMakeLists.txt"
    }

    return $match.Groups[1].Value
}

function Resolve-Iscc {
    $repoCandidates = @(
        (Join-Path $RepoWindowsToolsDir "inno\ISCC.exe"),
        (Join-Path $RepoWindowsToolsDir "ISCC.exe"),
        (Join-Path $SourceRoot "tools\inno\ISCC.exe")
    )

    $repoIscc = Find-FirstExistingPath -Candidates $repoCandidates
    if ($repoIscc) {
        Write-Host "Using bundled Inno Setup compiler: $repoIscc"
        return $repoIscc
    }

    $candidates = @()

    if ($env:INNO_SETUP_COMPILER) {
        $candidates += $env:INNO_SETUP_COMPILER
    }

    $iscc = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($iscc) {
        $candidates += $iscc.Source
    }

    $candidates += @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path $candidate) {
            $resolvedPath = (Resolve-Path $candidate).Path
            Write-Host "Using system Inno Setup compiler: $resolvedPath"
            return $resolvedPath
        }
    }

    throw "Inno Setup compiler not found. Put the full compiler in tools/windows/inno/, set INNO_SETUP_COMPILER, or install Inno Setup on the runner."
}

function Find-FirstExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in ($Candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Require-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not $PathValue) {
        throw "${Description} is not set"
    }
    if (-not (Test-Path $PathValue)) {
        throw "${Description} not found: $PathValue"
    }

    return (Resolve-Path $PathValue).Path
}

function Find-VcRedistInVsInstallation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallationPath
    )

    $redistRoot = Join-Path $InstallationPath "VC\Redist\MSVC"
    if (-not (Test-Path $redistRoot)) {
        return $null
    }

    $matches = Get-ChildItem `
        -Path $redistRoot `
        -Filter "vc_redist.x64.exe" `
        -Recurse `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending

    if ($matches) {
        return $matches[0].FullName
    }

    return $null
}

function Resolve-VcRedist {
    $repoCandidates = @(
        (Join-Path $RepoWindowsToolsDir "redist\vc_redist.x64.exe"),
        (Join-Path $RepoWindowsToolsDir "vc_redist.x64.exe")
    )

    $repoRedist = Find-FirstExistingPath -Candidates $repoCandidates
    if ($repoRedist) {
        Write-Host "Using bundled VC++ redistributable: $repoRedist"
        return $repoRedist
    }

    if ($env:VC_REDIST_PATH) {
        $envRedist = Require-File -PathValue $env:VC_REDIST_PATH -Description "VC_REDIST_PATH"
        Write-Host "Using VC++ redistributable from VC_REDIST_PATH: $envRedist"
        return $envRedist
    }

    $vsWhereCandidates = @(
        "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
        "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
    )

    foreach ($vsWhere in ($vsWhereCandidates | Where-Object { Test-Path $_ } | Select-Object -Unique)) {
        $installations = & $vsWhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        foreach ($installationPath in ($installations | Where-Object { $_ })) {
            $resolvedRedist = Find-VcRedistInVsInstallation -InstallationPath $installationPath
            if ($resolvedRedist) {
                $resolvedPath = (Resolve-Path $resolvedRedist).Path
                Write-Host "Found VC++ redistributable via vswhere: $resolvedPath"
                return $resolvedPath
            }
        }
    }

    $vsBaseDirs = @(
        "C:\Program Files\Microsoft Visual Studio\2022",
        "C:\Program Files\Microsoft Visual Studio\2019",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019"
    )

    foreach ($baseDir in ($vsBaseDirs | Where-Object { Test-Path $_ } | Select-Object -Unique)) {
        $editionDirs = Get-ChildItem -Path $baseDir -Directory -ErrorAction SilentlyContinue
        foreach ($editionDir in $editionDirs) {
            $resolvedRedist = Find-VcRedistInVsInstallation -InstallationPath $editionDir.FullName
            if ($resolvedRedist) {
                $resolvedPath = (Resolve-Path $resolvedRedist).Path
                Write-Host "Found VC++ redistributable in Visual Studio directory: $resolvedPath"
                return $resolvedPath
            }
        }
    }

    throw "vc_redist.x64.exe not found. Put it in tools/windows/redist/, set VC_REDIST_PATH, or install Visual Studio/Build Tools with MSVC redist."
}

$AppVersion = Resolve-ProjectVersion
$IsccExe = Resolve-Iscc
$VcRedistPath = Resolve-VcRedist
$VcRedistFileName = Split-Path $VcRedistPath -Leaf
$InstallerScriptFull = Require-File -PathValue $InstallerScript -Description "Installer script"
$DistDirFull = Join-Path $SourceRoot $DistDir
$SetupPath = Join-Path $SourceRoot $SetupName

Write-Host "==> Windows Packaging: ${AppName} [${PkgArch}]"
Write-Host "Project version: ${AppVersion}"

# ==============================================================================
# 1. Release 构建（CI 环境中使用已有的 build 目录，跳过重新构建）
# ==============================================================================
Write-Host "--- Step 1: Release Build ---"
if ($env:CI -and (Test-Path "build")) {
    # CI 环境：直接使用 CI 已经构建好的产物
    $BuildDir = "build"
    Write-Host "CI environment detected, using existing build directory: $BuildDir"
} else {
    # 本地环境：执行完整构建
    $BuildDir = "build-release"
    cmake -B $BuildDir `
        -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_EXPORT_COMPILE_COMMANDS=OFF

    $Nproc = [Environment]::ProcessorCount
    cmake --build $BuildDir --config Release -j $Nproc
}

# ==============================================================================
# 2. 准备分发目录
# ==============================================================================
Write-Host "--- Step 2: Prepare Distribution ---"
if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Path $DistDir | Out-Null

$Binary = Join-Path $BuildDir "src/app/Release/${AppName}.exe"
if (-not (Test-Path $Binary)) {
    $Binary = Join-Path $BuildDir "src/app/${AppName}.exe"
}
if (-not (Test-Path $Binary)) {
    throw "Binary not found in build output: $BuildDir"
}

Copy-Item $Binary -Destination $DistDir

# ==============================================================================
# 3. windeployqt (打包 Qt 依赖)
# ==============================================================================
Write-Host "--- Step 3: Deploy Qt Dependencies ---"
$WinDeployQtExe = "C:\Qt\6.10.2\msvc2022_64\bin\windeployqt.exe"
$WinDeployQt = Get-Command windeployqt -ErrorAction SilentlyContinue
if ($WinDeployQt) {
    & $WinDeployQt.Source "--no-translations" "--no-opengl-sw" "${DistDir}/${AppName}.exe"
} elseif (Test-Path $WinDeployQtExe) {
    & $WinDeployQtExe "--no-translations" "--no-opengl-sw" "${DistDir}/${AppName}.exe"
} else {
    Write-Host "WARN: windeployqt not found, skipping Qt dependency bundling"
}

# ==============================================================================
# 4. 复制 OpenSSL DLL
# ==============================================================================
Write-Host "--- Step 4: Copy OpenSSL Libraries ---"
$OpenSSLPaths = @(
    $env:OPENSSL_ROOT_DIR,
    "C:\Program Files\OpenSSL",
    "C:\Program Files\OpenSSL-Win64",
    "C:\OpenSSL-Win64"
)
$OpenSSLFound = $false
foreach ($sslPath in $OpenSSLPaths) {
    if ($sslPath -and (Test-Path "$sslPath\bin\libcrypto-3-x64.dll")) {
        Write-Host "Found OpenSSL at: $sslPath"
        Copy-Item "$sslPath\bin\libcrypto-3-x64.dll" -Destination $DistDir
        Copy-Item "$sslPath\bin\libssl-3-x64.dll" -Destination $DistDir
        $OpenSSLFound = $true
        break
    }
}
if (-not $OpenSSLFound) {
    # 尝试从 PATH 中查找
    $cryptoDll = Get-Command "libcrypto-3-x64.dll" -ErrorAction SilentlyContinue
    if ($cryptoDll) {
        Write-Host "Found OpenSSL DLLs in PATH"
        Copy-Item $cryptoDll.Source -Destination $DistDir
        $sslDll = Get-Command "libssl-3-x64.dll" -ErrorAction SilentlyContinue
        if ($sslDll) {
            Copy-Item $sslDll.Source -Destination $DistDir
        }
    } else {
        Write-Host "WARN: OpenSSL DLLs not found, application may fail to start"
    }
}

# ==============================================================================
# 5. 嵌入内置 SKF 库到 exe 同目录
# ==============================================================================
Write-Host "--- Step 5: Embed Built-in SKF Library ---"
$SkfLibSrc = "resources\lib\win\mtoken_gm3000.dll"
if (Test-Path $SkfLibSrc) {
    Copy-Item $SkfLibSrc -Destination "${DistDir}\mtoken_gm3000.dll"
    Write-Host "Embedded SKF library: ${SkfLibSrc} -> ${DistDir}\mtoken_gm3000.dll"
} else {
    Write-Host "WARN: Built-in SKF library not found: ${SkfLibSrc}"
}

# ==============================================================================
# 6. 生成安装器
# ==============================================================================
Write-Host "--- Step 6: Build Installer ---"
if (Test-Path $SetupPath) {
    Remove-Item -Force $SetupPath
}

$IsccStdOut = Join-Path $env:TEMP "wekey-iscc-stdout.log"
$IsccStdErr = Join-Path $env:TEMP "wekey-iscc-stderr.log"
foreach ($path in @($IsccStdOut, $IsccStdErr)) {
    if (Test-Path $path) {
        Remove-Item -Force $path
    }
}

$IsccArguments = @(
    "/DSourceRoot=$SourceRoot",
    "/DDistDir=$DistDirFull",
    "/DAppVersion=$AppVersion",
    "/DOutputBaseFilename=$SetupBaseName",
    "/DVcRedistPath=$VcRedistPath",
    "/DVcRedistFileName=$VcRedistFileName",
    $InstallerScriptFull
)

Write-Host "ISCC executable: $IsccExe"
Write-Host "ISCC stdout log: $IsccStdOut"
Write-Host "ISCC stderr log: $IsccStdErr"

$IsccProcess = Start-Process `
    -FilePath $IsccExe `
    -ArgumentList $IsccArguments `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $IsccStdOut `
    -RedirectStandardError $IsccStdErr

if (Test-Path $IsccStdOut) {
    Get-Content $IsccStdOut | Write-Host
}
if (Test-Path $IsccStdErr) {
    Get-Content $IsccStdErr | Write-Host
}

if ($IsccProcess.ExitCode -ne 0) {
    throw "ISCC failed with exit code $($IsccProcess.ExitCode). stdout=$IsccStdOut stderr=$IsccStdErr"
}
if (-not (Test-Path $SetupPath)) {
    throw "Installer not found after build: $SetupPath"
}

Write-Host ""
Write-Host "==> Package created: ${SetupName} (arch=${PkgArch})"
Get-Item $SetupPath | Format-Table Name, Length
