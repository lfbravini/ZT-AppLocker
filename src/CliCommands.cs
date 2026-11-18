using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ZTAppLocker
{
    /// <summary>
    /// Headless ops for smoke tests and automation. WFP/policy apply immediately;
    /// SplitTunnelEngine runs inside ZTAppLockerGuard and refreshes on its reconcile timer.
    /// </summary>
    public static class CliCommands
    {
        /// <returns>Exit code if handled; -1 if args are not a CLI command.</returns>
        public static int TryRun(string[] args)
        {
            if (args == null || args.Length == 0)
                return -1;

            string cmd = args[0].ToLowerInvariant();
            switch (cmd)
            {
                case "--status":
                    return CmdStatus();
                case "--lock":
                    return CmdLock(args);
                case "--unlock":
                    return CmdUnlock(args);
                case "--unlock-all":
                    return CmdUnlockAll();
                default:
                    return -1;
            }
        }

        private static int CmdStatus()
        {
            Console.WriteLine("ZT-AppLocker v4.0 status");
            Console.WriteLine("  Service:     " + ServiceManager.GetServiceStatus());
            Console.WriteLine("  InstallDir:  " + ServiceManager.InstallDir);
            Console.WriteLine("  Policy:      " + PolicyStore.PolicyPath);
            Console.WriteLine("  GuardLog:    " + ServiceManager.LogFilePath);

            string ztMsg;
            bool ztOk = ZeroTierApi.EnsureDaemonServiceRunning(out ztMsg);
            Console.WriteLine("  ZeroTier:    " + (ztOk ? "OK" : "WARN") + " — " + ztMsg);

            List<ZtNetworkInfo> nets = ZeroTierApi.GetNetworks();
            Console.WriteLine("  Networks:    " + nets.Count);
            foreach (ZtNetworkInfo n in nets)
            {
                string guid = ZeroTierApi.ResolveAdapterGuidForNetwork(n) ?? "(no-adapter)";
                Console.WriteLine(string.Format("    - {0}  status={1}  ip={2}  adapter={3}",
                    n.Id,
                    n.Status ?? "?",
                    n.PrimaryIpv4 ?? "-",
                    guid));
            }

            AppLockerPolicy pol = PolicyStore.Load();
            Console.WriteLine("  StrictDns:   " + pol.StrictDnsLock + (string.IsNullOrEmpty(pol.DnsNetworkId) ? "" : " (" + pol.DnsNetworkId + ")"));
            Console.WriteLine("  LockedApps:  " + pol.LockedApps.Count);
            foreach (AppLockPolicyEntry e in pol.LockedApps)
            {
                Console.WriteLine(string.Format("    - {0} -> {1}  boot={2}  exists={3}",
                    e.ExePath,
                    e.NetworkId,
                    e.BootTimeGuard,
                    File.Exists(e.ExePath)));
            }

            if (File.Exists(ServiceManager.LogFilePath))
            {
                try
                {
                    string[] lines = File.ReadAllLines(ServiceManager.LogFilePath);
                    int take = Math.Min(8, lines.Length);
                    Console.WriteLine("  LogTail:");
                    for (int i = lines.Length - take; i < lines.Length; i++)
                        Console.WriteLine("    " + lines[i]);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("  LogTail:     (unreadable: " + ex.Message + ")");
                }
            }
            else
            {
                Console.WriteLine("  LogTail:     (missing)");
            }

            return 0;
        }

        private static int CmdLock(string[] args)
        {
            string exePath = GetOptionValue(args, "--lock");
            string networkId = GetNamedValue(args, "--network");
            bool bootGuard = HasFlag(args, "--boot-guard");

            if (string.IsNullOrWhiteSpace(exePath) || string.IsNullOrWhiteSpace(networkId))
            {
                Console.Error.WriteLine("Usage: ZT-AppLocker.exe --lock <exePath> --network <16-hex-id> [--boot-guard]");
                return 2;
            }

            exePath = Path.GetFullPath(exePath.Trim('"'));
            if (!File.Exists(exePath))
            {
                Console.Error.WriteLine("Executable not found: " + exePath);
                return 1;
            }

            networkId = networkId.Trim().ToLowerInvariant();
            if (networkId.Length != 16 || networkId.Any(c => "0123456789abcdef".IndexOf(c) < 0))
            {
                Console.Error.WriteLine("Network ID must be exactly 16 hexadecimal characters.");
                return 2;
            }

            string ztMsg;
            ZeroTierApi.EnsureDaemonServiceRunning(out ztMsg);
            Console.WriteLine(ztMsg);

            ZtNetworkInfo net = ZeroTierApi.GetNetworks()
                .FirstOrDefault(n => string.Equals(n.Id, networkId, StringComparison.OrdinalIgnoreCase));
            if (net == null)
            {
                Console.Error.WriteLine("Network " + networkId + " is not joined on this node. Join it in the UI (or via ZeroTier) first.");
                return 1;
            }

            string adapterGuid = ZeroTierApi.ResolveAdapterGuidForNetwork(net);
            if (string.IsNullOrWhiteSpace(adapterGuid))
            {
                Console.Error.WriteLine("Adapter not ready for network " + networkId + ". Wait until status is OK.");
                return 1;
            }

            try
            {
                WfpEngine.ApplyAppLock(exePath, adapterGuid, bootGuard);
                PolicyStore.UpsertAppLock(exePath, networkId, bootGuard);
                int severed = SocketManager.SeverNonCompliantSockets(exePath, adapterGuid);
                // Service-owned SplitTunnel refreshes on reconcile (~15s); nudge via policy is enough.
                Console.WriteLine(string.Format("Locked {0} -> network {1} (adapter {2}, severed {3} socket(s), bootGuard={4}).",
                    exePath, networkId, adapterGuid, severed, bootGuard));
                Console.WriteLine("Note: SplitTunnelEngine refresh occurs inside ZTAppLockerGuard within ~15s.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Lock failed: " + ex.Message);
                return 1;
            }
        }

        private static int CmdUnlock(string[] args)
        {
            string exePath = GetOptionValue(args, "--unlock");
            if (string.IsNullOrWhiteSpace(exePath))
            {
                Console.Error.WriteLine("Usage: ZT-AppLocker.exe --unlock <exePath>");
                return 2;
            }

            exePath = Path.GetFullPath(exePath.Trim('"'));
            try
            {
                WfpEngine.RemoveAppLock(exePath);
                PolicyStore.RemoveAppLock(exePath);
                Console.WriteLine("Unlocked WFP filters for " + exePath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Unlock failed: " + ex.Message);
                return 1;
            }
        }

        private static int CmdUnlockAll()
        {
            try
            {
                WfpEngine.PurgeAllWfpFilters();
                PolicyStore.ClearAllApps();
                Console.WriteLine("Purged all ZT-AppLocker WFP filters and cleared locked apps in policy.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Unlock-all failed: " + ex.Message);
                return 1;
            }
        }

        private static string GetOptionValue(string[] args, string option)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], option, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        return args[i + 1];
                    return null;
                }
            }
            return null;
        }

        private static string GetNamedValue(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        return args[i + 1];
                    return null;
                }
            }
            return null;
        }

        private static bool HasFlag(string[] args, string flag)
        {
            return args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
        }
    }
}
