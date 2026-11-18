# ZT-AppLocker v4.0

Self-contained ZeroTier control-plane client with a native Windows Filtering Platform (WFP) kill-switch and WinDivert per-app split-tunnel relay. Built as a single x64 EXE on .NET Framework 4.x with no NuGet runtime dependencies.

## Requirements

- Windows x64
- Administrator elevation (UI, service install, WFP, WinDivert)
- Built-in C# compiler: `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`

## Build

```powershell
.\Build-ZTAppLocker-v4.ps1
.\Build-ZTAppLocker-v4.ps1 -UpdateZtCore      # refresh ZeroTier core / TAP / WinDivert payload
.\Build-ZTAppLocker-v4.ps1 -CopyToDesktop     # also copy dist\ZT-AppLocker.exe to Desktop
```

Output: `dist\ZT-AppLocker.exe`

Local-only build payloads (gitignored):

- `embedded_zt/` — ZeroTier headless daemon, signed TAP driver, WinDivert
- `.cache/` — MSI download/extract cache
- `dist/` — compiled binary and icon

## Install / run

```powershell
.\dist\ZT-AppLocker.exe              # elevated GUI + tray
.\dist\ZT-AppLocker.exe --install    # install ZTAppLockerGuard and shortcuts
.\dist\ZT-AppLocker.exe --uninstall  # remove service and clean install dir
.\dist\ZT-AppLocker.exe --service    # service entrypoint (SCM only)
```

| Item | Location |
|------|----------|
| Install dir | `C:\Program Files\ZT-AppLocker` |
| Guard service | `ZTAppLockerGuard` (LocalSystem) |
| Policy | `%ProgramData%\ZT-AppLocker\policy.json` |
| Guard log | `C:\Program Files\ZT-AppLocker\ZTAppLockerGuard.log` |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the WFP filter matrix, SplitTunnel ownership model, and routing helpers.

**SplitTunnel note:** `ZTAppLockerGuard` starts/stops `SplitTunnelEngine`; the GUI only calls `RefreshBindings()` after lock/unlock policy changes.

**Stable identities (do not rename casually):**

- UI single-instance mutex remains `ZTAppLocker_v3_UI_Mutex` for upgrade compatibility
- WFP GUID seed prefix remains `ZTAppLocker-v3:` so persistent filters are not orphaned

## Legacy scripts

`legacy/Deploy-Milestone*.ps1` are historical scaffold writers. **Do not run them** — they overwrite live sources and auto-push. Details: [legacy/README.md](legacy/README.md).

## CI

[`.github/workflows/build.yml`](.github/workflows/build.yml) builds on push/PR to `main`, on demand, and weekly with `-UpdateZtCore`.
