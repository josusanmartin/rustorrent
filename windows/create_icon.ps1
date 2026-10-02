#Requires -Version 5.1
# Builds windows/AppIcon.ico from macos/AppIcon.svg. Windows icons fill their
# canvas and have no drop shadow, so the macOS grid margin and shadow are
# removed. Every frame is a 32-bit PNG with real transparency.
#
# Needs Google Chrome or Microsoft Edge to render the SVG (set CHROME to use
# another Chromium-based browser).
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Drawing

$svgPath = Join-Path $PSScriptRoot '../macos/AppIcon.svg'
$output = Join-Path $PSScriptRoot 'AppIcon.ico'
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

$browser = @(
    $env:CHROME,
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $browser) { throw 'Install Microsoft Edge or Google Chrome, or set CHROME.' }

$svg = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $svgPath).Path)
# The tile spans 100..924 on the 1024 px macOS canvas; keep a 16 px margin.
$windowsSvg = $svg.Replace('viewBox="0 0 1024 1024"', 'viewBox="84 84 856 856"').Replace('<g filter="url(#shadow)">', '<g>')
if ($windowsSvg -eq $svg -or $windowsSvg.Contains('url(#shadow)')) {
    throw 'macos/AppIcon.svg changed shape; update the viewBox and shadow edits in create_icon.ps1.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) "rustorrent-icon-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $page = Join-Path $work 'page.html'
    $screenshot = Join-Path $work 'master.png'
    [IO.File]::WriteAllText($page,
        '<html><style>body{margin:0}svg{display:block;width:1024px;height:1024px}</style><body>' + $windowsSvg,
        [Text.UTF8Encoding]::new($false))
    # Headless viewports are shorter than the window, so leave room and crop.
    $arguments = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=1',
        '--default-background-color=00000000', '--window-size=1024,1280',
        "--user-data-dir=`"$(Join-Path $work 'profile')`"", "--screenshot=`"$screenshot`"",
        ([Uri]$page).AbsoluteUri)
    Start-Process -FilePath $browser -ArgumentList $arguments -Wait -WindowStyle Hidden
    if (-not (Test-Path -LiteralPath $screenshot)) { throw "The browser did not render $svgPath." }

    $rendered = [Drawing.Bitmap]::new($screenshot)
    try {
        $master = $rendered.Clone([Drawing.Rectangle]::new(0, 0, 1024, 1024), [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    } finally { $rendered.Dispose() }
    if ($master.GetPixel(0, 0).A -ne 0) { throw 'The rendered icon has no transparent background.' }

    $frames = foreach ($size in $sizes) {
        $frame = [Drawing.Bitmap]::new($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [Drawing.Graphics]::FromImage($frame)
        $edges = [Drawing.Imaging.ImageAttributes]::new()
        try {
            $graphics.CompositingMode = [Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            # Without this, bicubic sampling past the edge darkens the border.
            $edges.SetWrapMode([Drawing.Drawing2D.WrapMode]::TileFlipXY)
            $graphics.DrawImage($master, [Drawing.Rectangle]::new(0, 0, $size, $size),
                0, 0, 1024, 1024, [Drawing.GraphicsUnit]::Pixel, $edges)
            $stream = [IO.MemoryStream]::new()
            $frame.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
            , $stream.ToArray()
        } finally { $edges.Dispose(); $graphics.Dispose(); $frame.Dispose() }
    }
    $master.Dispose()

    # An .ico file is a directory of (size, offset) entries followed by PNG frames.
    $file = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($file)
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dimension = [byte]($sizes[$i] % 256)
        $writer.Write($dimension); $writer.Write($dimension); $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$frames[$i].Length); $writer.Write([uint32]$offset)
        $offset += $frames[$i].Length
    }
    foreach ($frame in $frames) { $writer.Write($frame) }
    $writer.Flush()
    [IO.File]::WriteAllBytes($output, $file.ToArray())
    Write-Output "Wrote $output ($($file.Length) bytes)"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
