# ZT-AppLocker v3.0 - System Architecture & Engineering Blueprint

ZT-AppLocker is a self-contained ZeroTier management client and native Windows Filtering Platform (WFP) kernel kill-switch enforcer (`C#` / `.NET Framework 4.x`, zero external runtime dependencies).

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
|  +-----------------+-----------------+   +------------------+------------------+  |
|                    |                                        |                     |
|                    +-------------------+--------------------+                     |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  |                          Core Shared Engines (C#)                           |  |
|  |                                                                             |  |
|  |  +---------------------------------+   +---------------------------------+  |  |
|  |  |       ZeroTierControlPlane      |   |         WfpKernelEngine         |  |  |
|  |  | (Typed Local REST API Client)  |   |  (P/Invoke fwpuclnt & iphlpapi) |  |  |
|  |  |                                 |   |                                 |  |  |
|  |  | - GET  /status & /peer          |   | - Provider & Sublayer Owner     |  |  |
|  |  | - GET/POST/DELETE /network/{id} |   | - AppId + NET_LUID Filters      |  |  |
|  |  | - Service/Daemon Lifecycle      |   | - Boot-Time & DNS Leak Locks    |  |  |
|  |  +----------------+----------------+   +----------------+----------------+  |  |
|  +-------------------|-------------------------------------|-------------------+  |
+----------------------|-------------------------------------|----------------------+
                       | HTTP (127.0.0.1:<port>)             | Native Win32 P/Invoke
                       v                                     v
+-------------------------------------+   +-----------------------------------------+
|     ZeroTier One Core Engine        |   |     Windows Kernel Networking Stack     |
|  (Managed Service or Bundled Core)  |   |                                         |
|                                     |   |  +-----------------------------------+  |
| - 10-Digit Node Identity            |   |  | Base Filtering Engine (BFE / WFP) |  |
| - Virtual TAP Driver (zttap300.sys) |   |  | - ALE_AUTH_CONNECT_V4 / V6        |  |
| - Encrypted P2P / Relay Transport   |   |  | - OUTBOUND_TRANSPORT_V4 / V6      |  |
+-------------------------------------+   |  +-----------------------------------+  |
                                          |  +-----------------------------------+  |
                                          |  | TCP/IP Stack & Socket Table       |  |
                                          |  | - GetExtendedTcpTable / SetTcpEntry|  |
                                          |  +-----------------------------------+  |
                                          +-----------------------------------------+
~~~

## 2. WFP Sublayer Decision Matrix (`ZT_APPLOCKER_SUBLAYER`)

Every locked application is governed by a deterministic 3-tier filter stack across both `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`:

| Weight | Filter Role | Match Conditions | Action | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **15** | `Permit-Loopback` | `ALE_APP_ID == <ExeBlob>` AND `FLAGS has IS_LOOPBACK` | `PERMIT` | Preserves `127.0.0.1` / `::1` local IPC for Chromium/Electron helpers. |
| **10** | `Permit-ZT-Tunnel` | `ALE_APP_ID == <ExeBlob>` AND `IP_LOCAL_INTERFACE == <Target_NET_LUID>` | `PERMIT` | Allows outbound connections exclusively over the assigned ZeroTier `NET_LUID`. |
| **1** | `Block-CatchAll` | `ALE_APP_ID == <ExeBlob>` | `BLOCK` | Fails closed across Ethernet, Wi-Fi, USB tethers, and newly attached NICs. |

### Hardening Extensions
- **Boot-Time Leak Guard (`FWPM_FILTER_FLAG_BOOTTIME`):** Blocks locked apps while `tcpip.sys` initializes before `ZTAppLockerGuard` starts.
- **Strict ZeroTier DNS Lock (`FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6`):** Blocks outbound TCP/UDP port 53 on any interface other than the ZeroTier `NET_LUID` so Windows's shared `dnscache` (`svchost.exe`) cannot leak DNS queries over the ISP gateway.
- **Live Socket Sever (`iphlpapi.dll`):** Inspects active PID sockets via `GetExtendedTcpTable` and severs pre-existing non-ZeroTier TCP sessions via `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB`).
