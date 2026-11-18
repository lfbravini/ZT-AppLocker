using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Threading;

namespace ZTAppLocker
{
    public class GuardService : ServiceBase
    {
        public const string GuardServiceName = "ZTAppLockerGuard";
        private System.Threading.Timer _reconcileTimer;

        public GuardService()
        {
            this.ServiceName = GuardServiceName;
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            WriteServiceLog("ZTAppLockerGuard v3.0 started.");

            string ztMsg;
            ZeroTierApi.EnsureDaemonServiceRunning(out ztMsg);
            WriteServiceLog(ztMsg);

            ReconcilePolicyWithWfp(true);
            SplitTunnelEngine.Start();

            NetworkChange.NetworkAvailabilityChanged += (s, e) => ScheduleReconcile();
            NetworkChange.NetworkAddressChanged += (s, e) => ScheduleReconcile();

            _reconcileTimer = new System.Threading.Timer(_ => ReconcilePolicyWithWfp(false), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        private void ScheduleReconcile()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Thread.Sleep(1000);
                ReconcilePolicyWithWfp(true);
            SplitTunnelEngine.Start();
            });
        }

        public static void ReconcilePolicyWithWfp(bool verboseLog)
        {
            SplitTunnelEngine.RefreshBindings();
            AppLockerPolicy policy = PolicyStore.Load();
            if (policy.LockedApps.Count == 0 && !policy.StrictDnsLock)
                return;

            List<ZtNetworkInfo> networks = ZeroTierApi.GetNetworks();
            if (networks.Any(n => n.AllowDefault)) ZeroTierApi.EnsurePeerTransportBypassRoutes(true);

            foreach (AppLockPolicyEntry entry in policy.LockedApps)
            {
                if (string.IsNullOrWhiteSpace(entry.ExePath) || !File.Exists(entry.ExePath))
                    continue;

                ZtNetworkInfo targetNet = networks.FirstOrDefault(n =>
                    string.Equals(n.Id, entry.NetworkId, StringComparison.OrdinalIgnoreCase))
                    ?? networks.FirstOrDefault();

                string adapterGuid = ZeroTierApi.ResolveAdapterGuidForNetwork(targetNet);
                if (string.IsNullOrWhiteSpace(adapterGuid))
                    continue;

                try
                {
                    WfpEngine.ApplyAppLock(entry.ExePath, adapterGuid, entry.BootTimeGuard);
                    int severed = SocketManager.SeverNonCompliantSockets(entry.ExePath, adapterGuid);
                    if (verboseLog || severed > 0)
                    {
                        WriteServiceLog(string.Format("Reconciled WFP lock for {0} -> Network [{1}] (severed {2} leaked socket(s)).",
                            Path.GetFileName(entry.ExePath),
                            targetNet != null ? targetNet.Id : "default",
                            severed));
                    }
                }
                catch (Exception ex)
                {
                    WriteServiceLog("WFP reconcile error for " + Path.GetFileName(entry.ExePath) + ": " + ex.Message);
                }
            }

            if (policy.StrictDnsLock)
            {
                ZtNetworkInfo dnsNet = networks.FirstOrDefault(n =>
                    string.Equals(n.Id, policy.DnsNetworkId, StringComparison.OrdinalIgnoreCase))
                    ?? networks.FirstOrDefault();

                string dnsGuid = ZeroTierApi.ResolveAdapterGuidForNetwork(dnsNet);
                if (!string.IsNullOrWhiteSpace(dnsGuid))
                {
                    try { WfpEngine.SetStrictDnsLock(true, dnsGuid); }
                    catch (Exception ex) { WriteServiceLog("Strict DNS WFP error: " + ex.Message); }
                }
            }
        }

        protected override void OnStop()
        {
            SplitTunnelEngine.Stop();
            try { if (_reconcileTimer != null) _reconcileTimer.Dispose(); } catch { }
            WriteServiceLog("ZTAppLockerGuard v3.0 stopped.");
        }

        public static void WriteServiceLog(string message)
        {
            try
            {
                string dir = @"C:\Program Files\ZT-AppLocker";
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string logPath = Path.Combine(dir, "ZTAppLockerGuard.log");

                FileInfo fi = new FileInfo(logPath);
                if (fi.Exists && fi.Length > 1048576)
                {
                    string oldPath = logPath + ".old";
                    if (File.Exists(oldPath)) File.Delete(oldPath);
                    File.Move(logPath, oldPath);
                }

                string line = string.Format("[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}", DateTime.Now, message, Environment.NewLine);
                File.AppendAllText(logPath, line, System.Text.Encoding.UTF8);
            }
            catch { }
        }
    }
}
