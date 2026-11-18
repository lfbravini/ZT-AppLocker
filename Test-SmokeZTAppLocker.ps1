#Requires -Version 5.1
<#
.SYNOPSIS
  Smoke checks for ZT-AppLocker v4 (service, policy, Guard log, optional CLI lock).

.DESCRIPTION
  Default mode is non-destructive: asserts Guard is running, summarizes policy/log,
  and runs --status via the built EXE when elevated.

  Full lock path (optional):
    .\Test-SmokeZTAppLocker.ps1 -ExePath C:\Windows\System32\curl.exe -NetworkId <16hex> -ApplyLock -UnlockAfter

  SplitTunnelEngine lives in ZTAppLockerGuard; after -ApplyLock the script waits for reconcile.
#>
param(
    [string]$AppPath = "",
    [string]$ExePath = "",
    [string]$NetworkId = "",
    [switch]$ApplyLock,
    [switch]$UnlockAfter,
    [switch]$BootGuard,
    [int]$ReconcileWaitSeconds = 18
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($AppPath)) {
    $AppPath = Join-Path $RepoRoot "dist\ZT-AppLocker.exe"
}

$PolicyPath = Join-Path $env:ProgramData "ZT-AppLocker\policy.json"
$LogPath = "C:\Program Files\ZT-AppLocker\ZTAppLockerGuard.log"
$script:failed = 0

function Write-Check {
    param(
        [bool]$Ok,
        [string]$Name,
        [string]$Detail = ""
    )
    $suffix = ""
    if ($Detail) { $suffix = " - $Detail" }
    if ($Ok) {
        Write-Host ("[PASS] {0}{1}" -f $Name, $suffix) -ForegroundColor Green
    }
    else {
        Write-Host ("[FAIL] {0}{1}" -f $Name, $suffix) -ForegroundColor Red
        $script:failed++
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "=== ZT-AppLocker smoke ===" -ForegroundColor Cyan
Write-Host "AppPath: $AppPath"

$isAdmin = Test-IsAdmin
Write-Check -Ok (Test-Path $AppPath) -Name "dist EXE present" -Detail $AppPath
if ($isAdmin) {
    Write-Check -Ok $true -Name "running elevated"
}
else {
    Write-Host "[WARN] Not elevated - CLI --status/--lock will be skipped (re-run from elevated PowerShell)." -ForegroundColor Yellow
}

$svc = Get-Service -Name "ZTAppLockerGuard" -ErrorAction SilentlyContinue
Write-Check -Ok ($null -ne $svc) -Name "ZTAppLockerGuard installed"
if ($svc) {
    Write-Check -Ok ($svc.Status -eq "Running") -Name "ZTAppLockerGuard running" -Detail $svc.Status.ToString()
}

Write-Check -Ok (Test-Path $LogPath) -Name "Guard log exists" -Detail $LogPath
if (Test-Path $LogPath) {
    $tail = Get-Content $LogPath -Tail 30 -ErrorAction SilentlyContinue
    $hasStart = @($tail | Where-Object { $_ -match "ZTAppLockerGuard v4\.0 started|SplitTunnelEngine relay active|WinDivert" })
    $firstHit = ""
    if ($hasStart.Count -gt 0) { $firstHit = [string]$hasStart[0] }
    Write-Check -Ok ($hasStart.Count -gt 0) -Name "Guard log shows start/SplitTunnel activity" -Detail $firstHit

    Write-Host "--- log tail ---" -ForegroundColor DarkGray
    $tail | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
}

if (Test-Path $PolicyPath) {
    Write-Check -Ok $true -Name "policy.json present" -Detail $PolicyPath
    try {
        $raw = Get-Content $PolicyPath -Raw
        Write-Host "--- policy ---" -ForegroundColor DarkGray
        Write-Host $raw -ForegroundColor DarkGray
    }
    catch { }
}
else {
    Write-Host "[INFO] policy.json not created yet (no locks applied)" -ForegroundColor Yellow
}

function Invoke-ZTCli {
    param(
        [string[]]$CliArgs,
        [string]$OutFile
    )
    $argList = @($CliArgs) + @("--out", $OutFile)
    if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }
    $proc = Start-Process -FilePath $AppPath -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    $text = ""
    if (Test-Path $OutFile) { $text = Get-Content $OutFile -Raw -ErrorAction SilentlyContinue }
    return @{ ExitCode = $proc.ExitCode; Text = $text }
}

if ($isAdmin) {
    Write-Host ""
    Write-Host "--- CLI --status ---" -ForegroundColor Cyan
    $statusFile = Join-Path $env:ProgramData "ZT-AppLocker\last-status.txt"
    $status = Invoke-ZTCli -CliArgs @("--status") -OutFile $statusFile
    Write-Host $status.Text
    Write-Check -Ok ($status.ExitCode -eq 0) -Name "CLI --status exit 0" -Detail ("exit={0}" -f $status.ExitCode)

    if ($ApplyLock) {
        if ([string]::IsNullOrWhiteSpace($ExePath) -or [string]::IsNullOrWhiteSpace($NetworkId)) {
            Write-Check -Ok $false -Name "ApplyLock requires -ExePath and -NetworkId"
        }
        else {
            Write-Host ""
            Write-Host "--- CLI --lock ---" -ForegroundColor Cyan
            $lockArgs = @("--lock", $ExePath, "--network", $NetworkId)
            if ($BootGuard) { $lockArgs += "--boot-guard" }
            $lockFile = Join-Path $env:ProgramData "ZT-AppLocker\last-lock.txt"
            $lock = Invoke-ZTCli -CliArgs $lockArgs -OutFile $lockFile
            Write-Host $lock.Text
            Write-Check -Ok ($lock.ExitCode -eq 0) -Name "CLI --lock" -Detail ("exit={0}" -f $lock.ExitCode)

            Write-Host ("Waiting {0}s for Guard reconcile; probing locked exe for traffic..." -f $ReconcileWaitSeconds) -ForegroundColor Yellow
            $deadline = (Get-Date).AddSeconds($ReconcileWaitSeconds)
            while ((Get-Date) -lt $deadline) {
                try {
                    Start-Process -FilePath $ExePath -ArgumentList @("-s","-m","3","-o","NUL","https://1.1.1.1/") -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
                } catch { }
                Start-Sleep -Seconds 3
            }

            if (Test-Path $PolicyPath) {
                $pol = Get-Content $PolicyPath -Raw
                $full = [IO.Path]::GetFullPath($ExePath)
                $exeLeaf = [IO.Path]::GetFileName($full)
                $polNorm = $pol -replace '\\\\', '\'
                $inPolicy = ($polNorm -like ("*{0}*" -f $full)) -or ($pol -match [regex]::Escape($exeLeaf))
                if ($NetworkId) { $inPolicy = $inPolicy -and ($pol -match [regex]::Escape($NetworkId)) }
                Write-Check -Ok $inPolicy -Name "policy contains locked exe" -Detail $pol
            }

            if (Test-Path $LogPath) {
                $post = Get-Content $LogPath -Tail 50
                $exeLeaf = [IO.Path]::GetFileName($ExePath)
                $cutoff = (Get-Date).AddMinutes(-10)
                $fresh = @()
                foreach ($line in $post) {
                    if ($line -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]') {
                        $ts = [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss", $null)
                        if ($ts -lt $cutoff) { continue }
                    }
                    if ($line -match [regex]::Escape($exeLeaf) -or
                        $line -match "SplitTunnel" -or
                        $line -match "Reconciled WFP lock") {
                        $fresh += $line
                    }
                }
                $lastHit = ""
                if ($fresh.Count -gt 0) { $lastHit = [string]$fresh[-1] }
                Write-Check -Ok ($fresh.Count -gt 0) -Name "Guard log shows recent SplitTunnel/WFP activity" -Detail $lastHit
                Write-Host "--- post-lock log tail ---" -ForegroundColor DarkGray
                $post | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
            }

            if ($UnlockAfter) {
                Write-Host ""
                Write-Host "--- CLI --unlock ---" -ForegroundColor Cyan
                $unlockFile = Join-Path $env:ProgramData "ZT-AppLocker\last-unlock.txt"
                $u = Invoke-ZTCli -CliArgs @("--unlock", $ExePath) -OutFile $unlockFile
                Write-Host $u.Text
                Write-Check -Ok ($u.ExitCode -eq 0) -Name "CLI --unlock" -Detail ("exit={0}" -f $u.ExitCode)
            }
        }
    }
    else {
        Write-Host ""
        Write-Host "[INFO] Skipping lock path (pass -ApplyLock -ExePath ... -NetworkId ... to exercise WFP)." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "[INFO] Skipping CLI commands (not elevated)." -ForegroundColor Yellow
}

Write-Host ""
if ($script:failed -eq 0) {
    Write-Host "SMOKE RESULT: PASS" -ForegroundColor Green
    exit 0
}
else {
    Write-Host ("SMOKE RESULT: FAIL ({0} check(s))" -f $script:failed) -ForegroundColor Red
    exit 1
}
