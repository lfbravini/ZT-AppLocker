# ZT-AppLocker v4.0 - System Architecture & Engineering Blueprint

ZT-AppLocker is a self-contained ZeroTier management client, native Windows Filtering Platform (WFP) kernel kill-switch, and WinDivert per-app split-tunnel enforcer (`C#` / `.NET Framework 4.x`, zero NuGet runtime dependencies). The build embeds a private ZeroTier headless core, signed TAP driver, and WinDivert payload into a single x64 EXE.

## 1. High-Level System Topology

~~~text
+-----------------------------------------------------------------------------------+
|                        ZT-AppLocker.exe (Single-File x64 Binary)                  |
|                                                                                   |
|  +-----------------------------------+   +-------------------------------------+  |
|  |         GUI & Tray Console        |   |      Native Windows Service         |  |
|  |       (Elevated Interactive)      |   |   (ZTAppLockerGuard - LocalSystem)  |  |
|  |                                   |   |                                     |  |
|  | - Network Join / Leave / Config   |   | - IP Helper Interface Watcher       |  |
|  | - Per-App Network Assignment      |   | - ZeroTier Daemon Supervisor        |  |
|  | - Live Socket & Leak Auditor      |   | - Atomic WFP Sublayer Re-Binder     |  |
|  | - RefreshBindings() after locks   |   | - SplitTunnelEngine Start / Stop    |  |
|  +-----------------+-----------------+   +------------------+------------------+  |
|                    |                                        |                     |
|                    +-------------------+--------------------+                     |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  |                          Core Shared Engines (C#)                           |  |
|  |  ZeroTierApi | WfpEngine | SplitTunnelEngine | SocketManager | PolicyStore  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
          | HTTP 127.0.0.1:<port>     | WFP P/Invoke      | WinDivert P/Invoke
          v                           v                   v
+---------------------------+  +------------------+  +---------------------------+
| Embedded ZeroTier One     |  | BFE / WFP        |  | WinDivert relay + DNS NAT |
| zerotier-one_x64 + TAP    |  | ALE + transport   |  | per locked app / binding  |
+---------------------------+  +------------------+  +---------------------------+
~~~

## 2. WFP Sublayer Decision Matrix (`ZT_APPLOCKER_SUBLAYER`)

Every locked application is governed by a deterministic 3-tier filter stack across both `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`:

| Weight | Filter Role | Match Conditions | Action | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **15** | `Permit-Loopback` | `ALE_APP_ID == <ExeBlob>` AND `FLAGS has IS_LOOPBACK` | `PERMIT` | Preserves `127.0.0.1` / `::1` local IPC for Chromium/Electron helpers. |
| **10** | `Permit-ZT-Tunnel` | `ALE_APP_ID == <ExeBlob>` AND local address / interface on assigned ZT adapter | `PERMIT` | Allows outbound connections exclusively over the assigned ZeroTier path. |
| **1** | `Block-CatchAll` | `ALE_APP_ID == <ExeBlob>` | `BLOCK` | Fails closed across Ethernet, Wi-Fi, USB tethers, and newly attached NICs. |

### Hardening Extensions
- **Boot-Time Leak Guard (`FWPM_FILTER_FLAG_BOOTTIME`):** Blocks locked apps while `tcpip.sys` initializes before `ZTAppLockerGuard` starts.
- **Strict ZeroTier DNS Lock (`FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6`):** Blocks outbound TCP/UDP port 53 on any interface other than the ZeroTier path so Windows's shared `dnscache` (`svchost.exe`) cannot leak DNS queries over the ISP gateway.
- **Live Socket Sever (`iphlpapi.dll`):** Inspects active PID sockets via `GetExtendedTcpTable` and severs pre-existing non-ZeroTier TCP sessions via `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB`).

### Persistent identity note
WFP provider/filter GUID seeds still use the historical prefix `ZTAppLocker-v3:`. That string is a **stable filter identity**, not the product version. Renaming it would orphan existing persistent BFE filters on upgrade.

## 3. WinDivert Split-Tunnel (`SplitTunnelEngine`)

Ownership model:

- **`ZTAppLockerGuard`** calls `SplitTunnelEngine.Start()` on service start / network reconcile and `Stop()` on service stop.
- **GUI (`MainForm`)** calls `SplitTunnelEngine.RefreshBindings()` after lock, unlock, or unlock-all so PID/adapter maps track `policy.json` without owning engine lifetime.

The engine uses the embedded WinDivert driver/DLL to transparently relay locked-app traffic onto the assigned ZeroTier binding and apply DNS NAT as needed. WFP remains the fail-closed gate; WinDivert provides the transparent path when traffic is permitted toward the tunnel.

## 4. ZeroTier Control Plane & Routing Helpers (`ZeroTierApi`)

- Typed local REST client against the ZeroTier daemon (`/status`, `/peer`, `/network/{id}`).
- Embedded core install/extract via `EmbeddedZtManager` into the install directory `zt-core` payload.
- When `allowDefault` is enabled on a joined network, peer transport `/32` physical bypass routes are pinned so ZeroTier underlay peers remain reachable.
- On lock apply, a metric-500 managed-gateway fallback route can be provisioned so locked apps have a usable ZT default when the physical default would otherwise win.

## 5. Policy Store

Path: `%ProgramData%\ZT-AppLocker\policy.json`

Stores locked EXE paths, target ZeroTier network IDs, boot-time guard flags, and optional strict DNS lock settings. Guard reconciles WFP + SplitTunnel from this file on a timer and on network change events.

## 6. Build & Legacy Tooling

- **Supported build:** `Build-ZTAppLocker-v4.ps1` (optional `-UpdateZtCore`, `-CopyToDesktop`).
- **CI:** `.github/workflows/build.yml` produces `dist/ZT-AppLocker.exe`.
- **Legacy:** `legacy/Deploy-Milestone*.ps1` are historical scaffold writers that overwrite sources and auto-push. Do not run them.
