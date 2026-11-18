#Requires -Version 5.1
param(
    [switch]$UpdateZtCore,
    [switch]$CopyToDesktop
)

$ErrorActionPreference = "Stop"

$CscPath = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $CscPath)) {
    throw "Built-in .NET C# compiler not found at $CscPath"
}

$RepoRoot   = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir     = Join-Path $RepoRoot "src"
$DistDir    = Join-Path $RepoRoot "dist"
$CacheDir   = Join-Path $RepoRoot ".cache"
$PayloadDir = Join-Path $RepoRoot "embedded_zt"

foreach ($d in @($DistDir, $CacheDir, $PayloadDir)) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
}

$IconPath    = Join-Path $DistDir "ZTAppLocker.ico"
$DistExePath = Join-Path $DistDir "ZT-AppLocker.exe"
$DesktopExe  = "$([Environment]::GetFolderPath('Desktop'))\ZT-AppLocker.exe"

# --- 1. HARVEST OR FETCH LATEST HEADLESS ZEROTIER CORE + SIGNED TAP DRIVER ---
Write-Host "[1/4] Preparing self-contained ZeroTier core & signed TAP driver payload..." -ForegroundColor Cyan

$RequiredPayload = @("zerotier-one_x64.exe", "zttap300.sys", "zttap300.inf", "zttap300.cat", "WinDivert.dll", "WinDivert64.sys")
$MissingPayload = $RequiredPayload | Where-Object { -not (Test-Path (Join-Path $PayloadDir $_)) }

if ($UpdateZtCore -or $MissingPayload.Count -gt 0) {
    # First check if local ProgramData\ZeroTier\One already has them (unless -UpdateZtCore forced)
    $LocalZtData = "$env:ProgramData\ZeroTier\One"
    if (-not $UpdateZtCore -and (Test-Path $LocalZtData)) {
        foreach ($reqFile in $RequiredPayload) {
            $foundLocal = Get-ChildItem -Path $LocalZtData -Filter $reqFile -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundLocal) {
                Copy-Item -Path $foundLocal.FullName -Destination (Join-Path $PayloadDir $reqFile) -Force
            }
        }
    }

    $StillMissing = $RequiredPayload | Where-Object { -not (Test-Path (Join-Path $PayloadDir $_)) }
    if ($UpdateZtCore -or $StillMissing.Count -gt 0) {
        $MsiPath = Join-Path $CacheDir "ZeroTierOne.msi"
        $ExtractDir = Join-Path $CacheDir "msi_extract"
        if (Test-Path $ExtractDir) { Remove-Item $ExtractDir -Recurse -Force }

        Write-Host "      Downloading latest official ZeroTier One MSI from download.zerotier.com..." -ForegroundColor Yellow
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://download.zerotier.com/dist/ZeroTier%20One.msi" -OutFile $MsiPath -UseBasicParsing

        Write-Host "      Unpacking headless daemon & signed TAP driver via msiexec..." -ForegroundColor Yellow
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/a `"$MsiPath`" /qn TARGETDIR=`"$ExtractDir`"" -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "msiexec administrative unpack failed with exit code $($proc.ExitCode)"
        }

        foreach ($reqFile in $RequiredPayload) {
            $match = Get-ChildItem -Path $ExtractDir -Filter $reqFile -Recurse | Select-Object -First 1
            if (-not $match) {
                throw "Failed to locate $reqFile inside extracted ZeroTier MSI."
            }
            Copy-Item -Path $match.FullName -Destination (Join-Path $PayloadDir $reqFile) -Force
        }
    }
}

foreach ($reqFile in $RequiredPayload) {
    $full = Join-Path $PayloadDir $reqFile
    if (-not (Test-Path $full)) {
        throw "Required embedded payload file missing: $full"
    }
}

$ZtVer = (Get-Item (Join-Path $PayloadDir "zerotier-one_x64.exe")).VersionInfo.FileVersion
Write-Host "      Bundling ZeroTier Core v$ZtVer (headless daemon + signed zttap300 driver)" -ForegroundColor Green

# --- 2. GENERATE SHIELD + PADLOCK .ICO ---
Write-Host "[2/4] Generating Shield + Network Lock icon..." -ForegroundColor Cyan

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

# --- 3. COMPILE SINGLE-FILE SELF-CONTAINED EXECUTABLE ---
Write-Host "[3/4] Compiling ZT-AppLocker v4.0 with embedded ZeroTier resources..." -ForegroundColor Cyan

$CsFiles = Get-ChildItem -Path $SrcDir -Filter "*.cs" | Select-Object -ExpandProperty FullName
$ResourceArgs = $RequiredPayload | ForEach-Object {
    $p = Join-Path $PayloadDir $_
    "/resource:`"$p`",ZTAppLocker.embedded_zt.$_"
}

& $CscPath `
    /target:winexe `
    /platform:x64 `
    /optimize+ `
    /nologo `
    /win32icon:"$IconPath" `
    /out:"$DistExePath" `
    /reference:Microsoft.CSharp.dll `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Drawing.dll `
    /reference:System.Runtime.Serialization.dll `
    /reference:System.ServiceProcess.dll `
    /reference:System.Windows.Forms.dll `
    $ResourceArgs `
    $CsFiles

if ($LASTEXITCODE -ne 0) {
    throw "C# compilation failed with exit code $LASTEXITCODE"
}

if ($CopyToDesktop) {
    $DesktopDir = [Environment]::GetFolderPath('Desktop')
    if (-not [string]::IsNullOrWhiteSpace($DesktopDir) -and (Test-Path $DesktopDir)) {
        Copy-Item -Path $DistExePath -Destination $DesktopExe -Force
        Write-Host "      Copied build output to Desktop: $DesktopExe" -ForegroundColor Green
    }
}

$SizeMb = [math]::Round((Get-Item $DistExePath).Length / 1MB, 2)
Write-Host "[4/4] SUCCESS! Built self-contained ZT-AppLocker v4.0 ($SizeMb MB) at: $DistExePath" -ForegroundColor Green
