# Set up cv2pdb-strip support on Windows x64 agents.
#
# build-extra's please.sh runs cv2pdb-strip during the strip phase of
# build-mingw-w64-git. cv2pdb-strip loads mspdb140.dll via PATH
# lookup, and the DLL is part of the MSVC C++ toolchain
# (Microsoft.VisualStudio.Component.VC.Tools.x86.x64) which is not
# present on the 1ES image by default.
#
# Install VS 2022 Build Tools with that single component (the
# smallest selection that ships the DLL), locate mspdb140.dll via
# vswhere with a filesystem fallback, and prepend its directory to
# PATH for subsequent tasks via the `##vso[task.prependpath]` logging
# command.
#
# This script is intended to be invoked by a PowerShell@2 task with
# `filePath:`. It takes no arguments and writes diagnostics to stdout
# so install failures can be diagnosed from the task log.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$bootstrapper = "$env:TEMP\vs_BuildTools.exe"
Write-Host "Downloading VS 2022 Build Tools bootstrapper..."
Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' `
    -OutFile $bootstrapper

$vsArgs = @(
    '--quiet', '--wait', '--norestart', '--nocache',
    '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
)
Write-Host "Installing VS Build Tools (args: $($vsArgs -join ' '))..."
$start = Get-Date
$p = Start-Process -FilePath $bootstrapper -ArgumentList $vsArgs -Wait -PassThru
$elapsed = (Get-Date) - $start
Write-Host ("Installer exited with code {0} after {1:N0}s" -f `
    $p.ExitCode, $elapsed.TotalSeconds)

Write-Host ""
Write-Host "===== Installer logs in `$env:TEMP ====="
$logs = Get-ChildItem $env:TEMP -Filter 'dd_*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($logs) {
    foreach ($log in $logs | Select-Object -First 5) {
        Write-Host "----- $($log.FullName) (last 50 lines) -----"
        Get-Content $log.FullName -Tail 50 -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "(no dd_*.log files found in `$env:TEMP)"
}

Write-Host ""
Write-Host "===== vswhere -all -prerelease (every install) ====="
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Host "vswhere not found at $vswhere"
} else {
    & $vswhere -all -prerelease -format json |
        Out-String | Write-Host
}

Write-Host ""
Write-Host "===== Filesystem search for mspdb*.dll ====="
$roots = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio",
    "${env:ProgramFiles}\Microsoft Visual Studio"
) | Where-Object { Test-Path $_ }
$hits = foreach ($r in $roots) {
    Get-ChildItem -Path $r -Filter 'mspdb*.dll' -Recurse -File `
        -ErrorAction SilentlyContinue
}
if ($hits) {
    $hits | ForEach-Object { Write-Host $_.FullName }
} else {
    Write-Host "(no mspdb*.dll under any VS install root)"
}

# 3010 = reboot required, treated as success.
if ($p.ExitCode -notin 0,3010) {
    throw "VS Build Tools installer exited with code $($p.ExitCode)"
}

Write-Host ""
Write-Host "===== Locate mspdb140.dll via vswhere -find ====="
$mspdb = & $vswhere -latest `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\mspdb140.dll' |
    Select-Object -First 1
if (-not $mspdb) {
    # Fall back to filesystem hits we already have.
    $mspdb = $hits |
        Where-Object { $_.Name -ieq 'mspdb140.dll' } |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $mspdb) {
    throw "mspdb140.dll not found after install (see logs above)"
}
$dir = Split-Path -Parent $mspdb
Write-Host "Found mspdb140.dll at $mspdb"
Write-Host "##vso[task.prependpath]$dir"
