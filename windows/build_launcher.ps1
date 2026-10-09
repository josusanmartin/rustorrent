#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = 'x64',
    [string]$BuildDirectory,
    # The Cargo package version, shown in the executable's properties.
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+')]
    [string]$Version
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $PSScriptRoot '../target/windows-app' }
$buildRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BuildDirectory)
$sdkVersion = '1.0.3537.50'
$expectedHash = '5EA526BBD728ADDA0DA4D31219267E96460494A427E4894C4E09D9F320F4B9AA'
$sdkRoot = Join-Path $buildRoot 'sdk'
$archive = Join-Path $sdkRoot 'webview2.zip'
$sdk = Join-Path $sdkRoot $sdkVersion
New-Item -ItemType Directory -Force -Path $sdkRoot | Out-Null
if (-not (Test-Path -LiteralPath $sdk)) {
    if (-not (Test-Path -LiteralPath $archive)) {
        $uri = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$sdkVersion/microsoft.web.webview2.$sdkVersion.nupkg"
        Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
        throw "WebView2 SDK checksum mismatch. Remove $archive and retry."
    }
    # Extract beside the final folder so an interrupted run is not mistaken for a complete SDK.
    $partial = "$sdk.partial"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Recurse -Force }
    Expand-Archive -LiteralPath $archive -DestinationPath $partial
    Rename-Item -LiteralPath $partial -NewName $sdkVersion
}
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio C++ Build Tools and the Windows SDK.' }
$visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $visualStudio) { throw 'Visual Studio C++ Build Tools were not found.' }
$vcvars = Join-Path $visualStudio 'VC/Auxiliary/Build/vcvarsall.bat'
$vcArchitecture = if ($Architecture -eq 'arm64') { 'x64_arm64' } else { 'x64' }
$native = Join-Path $buildRoot "native/$Architecture"
New-Item -ItemType Directory -Force -Path $native | Out-Null
$resource = Join-Path $native 'Launcher.res'
$include = Join-Path $sdk 'build/native/include'
$library = Join-Path $sdk "build/native/$Architecture/WebView2LoaderStatic.lib"
$exe = Join-Path $native 'Rustorrent.exe'
$object = Join-Path $native 'Launcher.obj'
$numbers = ([regex]::Match($Version, '^(\d+)\.(\d+)\.(\d+)')).Groups
[IO.File]::WriteAllLines((Join-Path $native 'version.h'), @(
    "#define RUSTORRENT_VERSION_NUMBER $($numbers[1].Value),$($numbers[2].Value),$($numbers[3].Value),0",
    "#define RUSTORRENT_VERSION `"$Version`""
), [Text.UTF8Encoding]::new($false))
# Only compiler commands run through cmd; file operations use literal PowerShell paths.
$buildCommands = @(
    '@echo off',
    'chcp 65001 >nul',
    "call `"$vcvars`" $vcArchitecture >nul",
    'if errorlevel 1 exit /b 1',
    "rc.exe /nologo /i `"$native`" /fo `"$resource`" Launcher.rc",
    'if errorlevel 1 exit /b 1',
    "cl.exe /nologo /std:c++17 /EHsc /utf-8 /O1 /MT /W4 /WX /DUNICODE /D_UNICODE /I `"$include`" Launcher.cpp /Fo`"$object`" /Fe`"$exe`" /link /SUBSYSTEM:WINDOWS /MANIFEST:NO `"$resource`" `"$library`" user32.lib gdi32.lib shell32.lib ole32.lib winhttp.lib bcrypt.lib ws2_32.lib advapi32.lib",
    'exit /b %errorlevel%'
)
$buildScript = Join-Path $native 'build.cmd'
[IO.File]::WriteAllLines($buildScript, $buildCommands, [Text.UTF8Encoding]::new($false))
Push-Location $PSScriptRoot
try {
    & $env:ComSpec /d /c "`"$buildScript`"" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows launcher build failed.' }
} finally { Pop-Location }
Write-Host "Created $exe"
[pscustomobject]@{ Executable = $exe; Sdk = $sdk }
