#define MyAppName "wekey-skf"
#define MyAppPublisher "TrustAsia"
#define MyAppExeName "wekey-skf.exe"

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#ifndef SourceRoot
  #error SourceRoot is not defined. Pass /DSourceRoot=...
#endif

#ifndef DistDir
  #error DistDir is not defined. Pass /DDistDir=...
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "wekey-skf-windows-amd64-setup"
#endif

#ifndef VcRedistPath
  #error VcRedistPath is not defined. Pass /DVcRedistPath=...
#endif

#ifndef VcRedistFileName
  #error VcRedistFileName is not defined. Pass /DVcRedistFileName=...
#endif

[Setup]
AppId={{77F6C0B0-5749-40C1-BF94-08CB98D06EAA}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppVerName={#MyAppName} {#AppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir={#SourceRoot}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#SourceRoot}\resources\icons\app.ico
WizardStyle=modern
PrivilegesRequired=admin
SetupLogging=yes
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#VcRedistPath}"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 {#MyAppName}"; Flags: nowait postinstall skipifsilent; Check: CanLaunchInstalledApp

[Code]
var
  VcRuntimeError: string;
  VcRuntimeLogPath: string;
  VcRuntimeReadyForLaunch: Boolean;

function StripLeadingV(const Value: string): string;
begin
  Result := Trim(Value);
  if (Length(Result) > 0) and ((Result[1] = 'v') or (Result[1] = 'V')) then
  begin
    Delete(Result, 1, 1);
  end;
end;

function ReadInstalledVcRuntimeVersion(var Version: string): Boolean;
var
  Installed: Cardinal;
begin
  Result := False;
  Version := '';

  if not RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) then
  begin
    Log('VC Runtime registry key not found: HKLM64\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64');
    exit;
  end;

  if Installed <> 1 then
  begin
    Log(Format('VC Runtime registry found but Installed=%d', [Installed]));
    exit;
  end;

  if not RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Version', Version) then
  begin
    Log('VC Runtime registry found but Version value is missing.');
    Version := '';
    exit;
  end;

  Version := StripLeadingV(Version);
  if Version = '' then
  begin
    Log('VC Runtime registry found but Version value is empty.');
    exit;
  end;

  Result := True;
end;

function ReadBundledVcRuntimeVersion(const FileName: string; var Version: string): Boolean;
begin
  Result := False;
  Version := '';

  if not GetVersionNumbersString(FileName, Version) then
  begin
    Log(Format('Failed to read bundled VC Runtime file version: %s', [FileName]));
    exit;
  end;

  Version := StripLeadingV(Version);
  if Version = '' then
  begin
    Log('Bundled VC Runtime version not found in file metadata or strings.');
    exit;
  end;

  Result := True;
end;

function CompareVersionNumbers(const LeftVersion, RightVersion: string): Integer;
var
  LValue, RValue: string;
  LPart, RPart: string;
  LPos, RPos: Integer;
  LNum, RNum: Integer;
begin
  LValue := LeftVersion;
  RValue := RightVersion;

  while (True) do
  begin
    LPos := Pos('.', LValue);
    RPos := Pos('.', RValue);

    if LPos > 0 then
    begin
      LPart := Copy(LValue, 1, LPos - 1);
      Delete(LValue, 1, LPos);
    end
    else
    begin
      LPart := LValue;
      LValue := '';
    end;

    if RPos > 0 then
    begin
      RPart := Copy(RValue, 1, RPos - 1);
      Delete(RValue, 1, RPos);
    end
    else
    begin
      RPart := RValue;
      RValue := '';
    end;

    if LPart = '' then
      LNum := 0
    else
      LNum := StrToIntDef(LPart, 0);

    if RPart = '' then
      RNum := 0
    else
      RNum := StrToIntDef(RPart, 0);

    if LNum < RNum then
    begin
      Result := -1;
      exit;
    end;

    if LNum > RNum then
    begin
      Result := 1;
      exit;
    end;

    if (LValue = '') and (RValue = '') then
    begin
      Result := 0;
      exit;
    end;
  end;
end;

function IsVcRuntimeInstalled(): Boolean;
var
  Version: string;
begin
  Result := ReadInstalledVcRuntimeVersion(Version);
  if Result then
  begin
    Log(Format('Detected Visual C++ Runtime version: %s', [Version]));
  end;
end;

function TryInstallVcRuntime(): Boolean;
var
  ResultCode: Integer;
  RedistExe: string;
  InstalledVersion: string;
  BundledVersion: string;
  VersionCompare: Integer;
begin
  Result := False;
  VcRuntimeError := '';
  VcRuntimeLogPath := '';

  if ReadInstalledVcRuntimeVersion(InstalledVersion) then
  begin
    Log(Format('Installed Visual C++ Runtime version: %s', [InstalledVersion]));
  end;

  Log('Visual C++ Runtime not detected. Installing bundled redistributable.');
  ExtractTemporaryFile('{#VcRedistFileName}');
  RedistExe := ExpandConstant('{tmp}\{#VcRedistFileName}');

  if not FileExists(RedistExe) then
  begin
    VcRuntimeError := '未找到内置 Microsoft Visual C++ Runtime 安装程序，无法继续安装。';
    Log(VcRuntimeError);
    exit;
  end;

  if InstalledVersion <> '' then
  begin
    if ReadBundledVcRuntimeVersion(RedistExe, BundledVersion) then
    begin
      Log(Format('Bundled Visual C++ Runtime version: %s', [BundledVersion]));
      VersionCompare := CompareVersionNumbers(InstalledVersion, BundledVersion);
      if VersionCompare >= 0 then
      begin
        Log(Format('Installed Visual C++ Runtime version (%s) is same or newer than bundled version (%s); skipping installation.', [InstalledVersion, BundledVersion]));
        Result := True;
        exit;
      end;
    end
    else
    begin
      Log('Unable to detect bundled VC Runtime version; continue with installation.');
    end;
  end;

  VcRuntimeLogPath := ExpandConstant('{tmp}\vc_redist_install.log');
  if not Exec(RedistExe,
              Format('/install /quiet /norestart /log "%s"', [VcRuntimeLogPath]),
              '',
              SW_HIDE,
              ewWaitUntilTerminated,
              ResultCode) then
  begin
    VcRuntimeError := Format('无法启动内置 Microsoft Visual C++ Runtime 安装程序。日志：%s', [VcRuntimeLogPath]);
    Log(VcRuntimeError);
    exit;
  end;

  Log(Format('vc_redist exited with code %d, log=%s', [ResultCode, VcRuntimeLogPath]));

  if IsVcRuntimeInstalled() then
  begin
    if ResultCode = 3010 then
    begin
      Log('Visual C++ Runtime installed successfully and requested reboot. Continuing setup.');
    end;

    Result := True;
    exit;
  end;

  if VcRuntimeLogPath <> '' then
  begin
    VcRuntimeError := Format('Microsoft Visual C++ Runtime 安装失败，退出码=%d。日志：%s', [ResultCode, VcRuntimeLogPath]);
  end
  else
  begin
    VcRuntimeError := Format('Microsoft Visual C++ Runtime 安装失败，退出码=%d。', [ResultCode]);
  end;
  Log(VcRuntimeError);
end;

function CanLaunchInstalledApp(): Boolean;
begin
  // 自动启动主程序时不再重新探测运行库状态。
  // PrepareToInstall 已经完成了“已安装判断 / 尝试安装 / 失败继续安装”的全部决策，
  // 此处只复用当时得到的最终状态，避免失败后再次触发注册表检查或造成行为分叉。
  Result := VcRuntimeReadyForLaunch;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  NeedsRestart := False;
  VcRuntimeReadyForLaunch := False;

  // 只在安装开始前做一次完整判断：
  // 1. 若系统已有可用 VC Runtime，直接继续安装主程序；
  // 2. 若系统没有，则尝试安装内置 redist；
  // 3. 若尝试失败，给用户明确提示并继续安装主程序，不再重复检查。
  if TryInstallVcRuntime() then
  begin
    VcRuntimeReadyForLaunch := True;
    Result := '';
    exit;
  end;

  if VcRuntimeError = '' then
  begin
    VcRuntimeError := '未能安装 Microsoft Visual C++ Runtime。';
  end;

  Log('VC Runtime 安装失败，但将继续安装主程序，且后续不再重复检查运行库状态。');
  MsgBox(
    VcRuntimeError + #13#10#13#10 +
    '安装程序将继续安装 wekey-skf。' + #13#10 +
    '请在安装完成后手动安装 Microsoft Visual C++ Runtime，或者检查是否已经安装Microsoft Visual C++ Runtime，否则程序可能无法正常启动。',
    mbInformation,
    MB_OK);

  Result := '';
end;
