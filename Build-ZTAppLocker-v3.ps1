#Requires -Version 5.1
<#
.SYNOPSIS
    Compiles ZT-AppLocker v3.0 (ZeroTier Control Plane + Native WFP Kernel Enforcer)
#>

$ErrorActionPreference = "Stop"

$CscPath = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $CscPath)) {
    throw "Built-in .NET C# compiler not found at $CscPath"
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir   = Join-Path $RepoRoot "src"
$DistDir  = Join-Path $RepoRoot "dist"
if (-not (Test-Path $DistDir)) { New-Item -Path $DistDir -ItemType Directory -Force | Out-Null }

$IconPath    = Join-Path $DistDir "ZTAppLocker.ico"
$DistExePath = Join-Path $DistDir "ZT-AppLocker.exe"
$DesktopExe  = "$([Environment]::GetFolderPath('Desktop'))\ZT-AppLocker.exe"

# --- 1. GENERATE SHIELD + PADLOCK .ICO ---
Write-Host "[1/3] Generating Shield + Network Lock icon..." -ForegroundColor Cyan

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(64, 64)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

$shieldPts = @(
    (New-Object System.Drawing.Point(32, 4)),
    (New-Object System.Drawing.Point(56, 13)),
    (New-Object System.Drawing.Point(56, 33)),
    (New-Object System.Drawing.Point(32, 60)),
    (New-Object System.Drawing.Point(8, 33)),
    (New-Object System.Drawing.Point(8, 13))
)
$shieldPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$shieldPath.AddPolygon($shieldPts)

$gradBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Point(8, 4)),
    (New-Object System.Drawing.Point(56, 60)),
    [System.Drawing.Color]::FromArgb(0, 132, 235),
    [System.Drawing.Color]::FromArgb(0, 72, 155)
)
$g.FillPath($gradBrush, $shieldPath)

$borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 2.5)
$g.DrawPath($borderPen, $shieldPath)

$shacklePen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3.5)
$g.DrawArc($shacklePen, 24, 17, 16, 16, 180, 180)
$g.DrawLine($shacklePen, 24, 25, 24, 29)
$g.DrawLine($shacklePen, 40, 25, 40, 29)

$lockBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 200, 45))
$g.FillRectangle($lockBrush, 20, 29, 24, 18)

$keyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 35, 65))
$g.FillEllipse($keyBrush, 30, 34, 4, 4)
$g.FillRectangle($keyBrush, 31, 37, 2, 5)

$pngStream = New-Object System.IO.MemoryStream
$bmp.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngStream.ToArray()

$icoStream = New-Object System.IO.FileStream($IconPath, [System.IO.FileMode]::Create)
$bw = New-Object System.IO.BinaryWriter($icoStream)
$bw.Write([uint16]0)
$bw.Write([uint16]1)
$bw.Write([uint16]1)
$bw.Write([byte]64)
$bw.Write([byte]64)
$bw.Write([byte]0)
$bw.Write([byte]0)
$bw.Write([uint16]1)
$bw.Write([uint16]32)
$bw.Write([uint32]$pngBytes.Length)
$bw.Write([uint32]22)
$bw.Write($pngBytes)
$bw.Close()
$icoStream.Close()
$g.Dispose()
$bmp.Dispose()

# --- 2. COMPILE ALL MODULAR C# SOURCES ---
Write-Host "[2/3] Compiling modular C# v3.0 sources via csc.exe..." -ForegroundColor Cyan

$CsFiles = Get-ChildItem -Path $SrcDir -Filter "*.cs" | Select-Object -ExpandProperty FullName
if ($CsFiles.Count -eq 0) {
    throw "No .cs source files found in $SrcDir"
}

& $CscPath `
    /target:winexe `
    /platform:x64 `
    /optimize+ `
    /nologo `
    /win32icon:"$IconPath" `
    /out:"$DistExePath" `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Drawing.dll `
    /reference:System.Runtime.Serialization.dll `
    /reference:System.ServiceProcess.dll `
    /reference:System.Windows.Forms.dll `
    $CsFiles

if ($LASTEXITCODE -ne 0) {
    throw "C# compilation failed with exit code $LASTEXITCODE"
}

Copy-Item -Path $DistExePath -Destination $DesktopExe -Force
Write-Host "[3/3] SUCCESS! Built ZT-AppLocker v3.0 at:" -ForegroundColor Green
Write-Host "      - $DistExePath" -ForegroundColor Green
Write-Host "      - $DesktopExe" -ForegroundColor Green
