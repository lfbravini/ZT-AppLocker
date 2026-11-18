# Legacy scaffold scripts — do not run

These `Deploy-Milestone*.ps1` files are historical one-shot generators used to bootstrap early repo milestones.

They:

- Hardcode `C:\scripts\ZT-AppLocker`
- Unconditionally overwrite live `src/` and docs with older embedded snapshots
- Run `git commit` and `git push`

Re-running them will destroy post-v3 work (including WinDivert split-tunnel wiring).

**Supported build path:** `..\Build-ZTAppLocker-v4.ps1` and `.github/workflows/build.yml` only.
