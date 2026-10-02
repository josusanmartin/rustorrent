#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectDirectory = Split-Path $PSScriptRoot -Parent
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory 'target/windows-app/dist'
}
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$staging = $null
Push-Location $projectDirectory
try {
    $metadataJson = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Cargo metadata.' }
    $metadata = ($metadataJson -join "`n") | ConvertFrom-Json
    $package = $metadata.packages | Where-Object { $_.name -eq 'rustorrent' } | Select-Object -First 1
    if (-not $package) { throw 'Rustorrent package not found.' }

    & cargo build --locked --release --target $Target
    if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    $binary = Join-Path $metadata.target_directory "$Target/release/rustorrent.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Missing executable: $binary" }
    $architecture = if ($Target -eq 'aarch64-pc-windows-msvc') { 'arm64' } else { 'x64' }
    $windowsBuild = Join-Path $metadata.target_directory 'windows-app'
    $launcher = & (Join-Path $PSScriptRoot 'build_launcher.ps1') -Architecture $architecture -BuildDirectory $windowsBuild -Version $package.version

    $archiveName = "rustorrent-$($package.version)-$Target"
    # Use a fresh staging directory so older files cannot enter the archive.
    $staging = Join-Path $metadata.target_directory "windows-app/build/$([Guid]::NewGuid().ToString('N'))"
    $bundle = Join-Path $staging $archiveName
    New-Item -ItemType Directory -Path $bundle -Force | Out-Null
    Copy-Item -LiteralPath $binary -Destination (Join-Path $bundle 'rustorrent-bin.exe')
    Copy-Item -LiteralPath $launcher.Executable -Destination $bundle
    Copy-Item -LiteralPath (Join-Path $launcher.Sdk 'LICENSE.txt') -Destination (Join-Path $bundle 'WEBVIEW2_LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $launcher.Sdk 'NOTICE.txt') -Destination (Join-Path $bundle 'WEBVIEW2_NOTICE.txt')
    foreach ($name in @('LICENSE', 'THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_LICENSES.html')) {
        Copy-Item -LiteralPath (Join-Path $projectDirectory $name) -Destination $bundle
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $bundle
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    $archive = Join-Path $outputPath "$archiveName.zip"
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal -Force
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $archiveName.zip" | Set-Content -LiteralPath "$archive.sha256" -Encoding Ascii
    Write-Output "Created $archive"
    Write-Output "SHA256 $hash"
}
finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    Pop-Location
}
