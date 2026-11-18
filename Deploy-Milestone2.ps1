$ErrorActionPreference = "Stop"

$RepoDir = "C:\scripts\ZT-AppLocker"
if (-not (Test-Path "$RepoDir\.git")) {
    throw "Git repository not found at $RepoDir. Verify the directory exists."
}

New-Item -Path "$RepoDir\src" -ItemType Directory -Force | Out-Null
Set-Location $RepoDir

# ---------------------------------------------------------------------------
# 1. Write src\PolicyStore.cs (Shared JSON Policy & Per-App Network Mapping)
# ---------------------------------------------------------------------------
Write-Host "[1/4] Writing src\PolicyStore.cs..." -ForegroundColor Cyan

$PolicyStoreCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace ZTAppLocker
{
    [DataContract]
    public class AppLockPolicyEntry
    {
        [DataMember] public string ExePath { get; set; }
        [DataMember] public string NetworkId { get; set; }
        [DataMember] public bool BootTimeGuard { get; set; }
        [DataMember] public DateTime AddedUtc { get; set; }
    }

    [DataContract]
    public class AppLockerPolicy
    {
        [DataMember] public bool StrictDnsLock { get; set; }
        [DataMember] public string DnsNetworkId { get; set; }
        [DataMember] public List<AppLockPolicyEntry> LockedApps { get; set; }

        public AppLockerPolicy()
        {
            LockedApps = new List<AppLockPolicyEntry>();
        }
    }

    public static class PolicyStore
    {
        private static readonly object _fileLock = new object();

        public static string DataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZT-AppLocker"); }
        }

        public static string PolicyPath
        {
            get { return Path.Combine(DataDir, "policy.json"); }
        }

        public static AppLockerPolicy Load()
        {
            lock (_fileLock)
            {
                try
                {
                    if (!File.Exists(PolicyPath))
                        return new AppLockerPolicy();

                    byte[] bytes = File.ReadAllBytes(PolicyPath);
                    if (bytes.Length == 0)
                        return new AppLockerPolicy();

                    using (MemoryStream ms = new MemoryStream(bytes))
                    {
                        DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppLockerPolicy));
                        AppLockerPolicy pol = ser.ReadObject(ms) as AppLockerPolicy;
                        if (pol == null) pol = new AppLockerPolicy();
                        if (pol.LockedApps == null) pol.LockedApps = new List<AppLockPolicyEntry>();
                        return pol;
                    }
                }
                catch
                {
                    return new AppLockerPolicy();
                }
            }
        }

        public static void Save(AppLockerPolicy policy)
        {
            if (policy == null) return;
            if (policy.LockedApps == null) policy.LockedApps = new List<AppLockPolicyEntry>();

            lock (_fileLock)
            {
                if (!Directory.Exists(DataDir))
                    Directory.CreateDirectory(DataDir);

                string tmpPath = PolicyPath + ".tmp";
                using (FileStream fs = File.Create(tmpPath))
                {
                    DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppLockerPolicy));
                    ser.WriteObject(fs, policy);
                }
                if (File.Exists(PolicyPath))
                    File.Delete(PolicyPath);
                File.Move(tmpPath, PolicyPath);
            }
        }

        public static void UpsertAppLock(string exePath, string networkId, bool bootTimeGuard)
        {
            AppLockerPolicy pol = Load();
            pol.LockedApps.RemoveAll(a => string.Equals(a.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
            pol.LockedApps.Add(new AppLockPolicyEntry
            {
                ExePath = exePath,
                NetworkId = (networkId ?? "").Trim().ToLowerInvariant(),
                BootTimeGuard = bootTimeGuard,
                AddedUtc = DateTime.UtcNow
            });
            Save(pol);
        }

        public static void RemoveAppLock(string exePath)
        {
            AppLockerPolicy pol = Load();
            pol.LockedApps.RemoveAll(a => string.Equals(a.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
            Save(pol);
        }

        public static void ClearAllApps()
        {
            AppLockerPolicy pol = Load();
            pol.LockedApps.Clear();
            pol.StrictDnsLock = false;
            pol.DnsNetworkId = null;
            Save(pol);
        }

        public static void SetStrictDns(bool enabled, string networkId)
        {
            AppLockerPolicy pol = Load();
            pol.StrictDnsLock = enabled;
            pol.DnsNetworkId = enabled ? (networkId ?? "").Trim().ToLowerInvariant() : null;
            Save(pol);
        }
    }
}
'@

Set-Content -Path "$RepoDir\src\PolicyStore.cs" -Value $PolicyStoreCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 2. Write src\ZeroTierApi.cs (Typed ZeroTier REST Client & Daemon Control)
# ---------------------------------------------------------------------------
Write-Host "[2/4] Writing src\ZeroTierApi.cs and src\GuardService.cs..." -ForegroundColor Cyan

$ZeroTierApiCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.ServiceProcess;
using System.Text;

namespace ZTAppLocker
{
    [DataContract]
    public class ZtNodeStatus
    {
        [DataMember(Name = "address")] public string Address { get; set; }
        [DataMember(Name = "online")] public bool Online { get; set; }
        [DataMember(Name = "version")] public string Version { get; set; }
        [DataMember(Name = "tcpFallbackActive")] public bool TcpFallbackActive { get; set; }
    }

    [DataContract]
    public class ZtNetworkInfo
    {
        [DataMember(Name = "id")] public string Id { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "status")] public string Status { get; set; }
        [DataMember(Name = "type")] public string Type { get; set; }
        [DataMember(Name = "mac")] public string Mac { get; set; }
        [DataMember(Name = "mtu")] public int Mtu { get; set; }
        [DataMember(Name = "portDeviceName")] public string PortDeviceName { get; set; }
        [DataMember(Name = "allowManaged")] public bool AllowManaged { get; set; }
        [DataMember(Name = "allowGlobal")] public bool AllowGlobal { get; set; }
        [DataMember(Name = "allowDefault")] public bool AllowDefault { get; set; }
        [DataMember(Name = "allowDNS")] public bool AllowDNS { get; set; }
        [DataMember(Name = "assignedAddresses")] public List<string> AssignedAddresses { get; set; }

        public string PrimaryIpv4
        {
            get
            {
                if (AssignedAddresses == null) return "No IP";
                string v4 = AssignedAddresses.FirstOrDefault(a => a != null && a.Contains("."));
                return string.IsNullOrEmpty(v4) ? "Assigning..." : v4;
            }
        }

        public override string ToString()
        {
            string label = string.IsNullOrWhiteSpace(Name) ? "(Unnamed Network)" : Name;
            string flags = AllowDefault ? " [EXIT-TUNNEL]" : "";
            return string.Format("{0} - {1} [{2}] ({3}){4}", Id, label, Status ?? "UNKNOWN", PrimaryIpv4, flags);
        }
    }

    [DataContract]
    public class ZtPeerPath
    {
        [DataMember(Name = "active")] public bool Active { get; set; }
        [DataMember(Name = "address")] public string Address { get; set; }
        [DataMember(Name = "preferred")] public bool Preferred { get; set; }
    }

    [DataContract]
    public class ZtPeerInfo
    {
        [DataMember(Name = "address")] public string Address { get; set; }
        [DataMember(Name = "role")] public string Role { get; set; }
        [DataMember(Name = "latency")] public int Latency { get; set; }
        [DataMember(Name = "version")] public string Version { get; set; }
        [DataMember(Name = "paths")] public List<ZtPeerPath> Paths { get; set; }
    }

    public class ZtTelemetrySummary
    {
        public string NodeId { get; set; }
        public bool DaemonOnline { get; set; }
        public string Version { get; set; }
        public string LinkMode { get; set; }
        public string PeerSummary { get; set; }
    }

    public static class ZeroTierApi
    {
        private static string ZtDataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"ZeroTier\One"); }
        }

        public static bool EnsureDaemonServiceRunning(out string statusDetail)
        {
            string[] candidates = { "ZeroTierOneService", "ZeroTier One" };
            foreach (string svcName in candidates)
            {
                try
                {
                    using (ServiceController sc = new ServiceController(svcName))
                    {
                        var st = sc.Status;
                        if (st != ServiceControllerStatus.Running)
                        {
                            sc.Start();
                            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(12));
                        }
                        statusDetail = "ZeroTier Core Service (" + svcName + ") is Running.";
                        return true;
                    }
                }
                catch { }
            }

            statusDetail = "ZeroTier Windows Service not found. Install ZeroTier One core driver/service.";
            return false;
        }

        private static bool TryGetEndpoint(out string baseUrl, out string token)
        {
            baseUrl = null;
            token = null;
            try
            {
                string tokenPath = Path.Combine(ZtDataDir, "authtoken.secret");
                string portPath = Path.Combine(ZtDataDir, "zerotier-one.port");
                if (!File.Exists(tokenPath)) return false;

                token = File.ReadAllText(tokenPath).Trim();
                string port = File.Exists(portPath) ? File.ReadAllText(portPath).Trim() : "9993";
                baseUrl = string.Format("http://127.0.0.1:{0}", port);
                return !string.IsNullOrEmpty(token);
            }
            catch
            {
                return false;
            }
        }

        private static T SendJson<T>(string method, string path, string jsonBody = null) where T : class
        {
            string baseUrl, token;
            if (!TryGetEndpoint(out baseUrl, out token))
                return null;

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(baseUrl + path);
            req.Method = method;
            req.Headers["X-ZT1-Auth"] = token;
            req.Timeout = 2000;
            req.ReadWriteTimeout = 2000;

            if (jsonBody != null)
            {
                byte[] data = Encoding.UTF8.GetBytes(jsonBody);
                req.ContentType = "application/json";
                req.ContentLength = data.Length;
                using (Stream reqStream = req.GetRequestStream())
                {
                    reqStream.Write(data, 0, data.Length);
                }
            }

            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (Stream respStream = resp.GetResponseStream())
            {
                if (respStream == null) return null;
                DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));
                return ser.ReadObject(respStream) as T;
            }
        }

        public static ZtNodeStatus GetStatus()
        {
            try { return SendJson<ZtNodeStatus>("GET", "/status"); }
            catch { return null; }
        }

        public static List<ZtNetworkInfo> GetNetworks()
        {
            try { return SendJson<List<ZtNetworkInfo>>("GET", "/network") ?? new List<ZtNetworkInfo>(); }
            catch { return new List<ZtNetworkInfo>(); }
        }

        public static ZtNetworkInfo JoinOrConfigureNetwork(
            string networkId,
            bool? allowDefault = null,
            bool? allowManaged = null,
            bool? allowGlobal = null,
            bool? allowDns = null)
        {
            string cleanId = (networkId ?? "").Trim().ToLowerInvariant();
            if (cleanId.Length != 16)
                throw new ArgumentException("ZeroTier Network ID must be exactly 16 hexadecimal characters.");

            List<string> fields = new List<string>();
            if (allowDefault.HasValue) fields.Add("\"allowDefault\":" + (allowDefault.Value ? "true" : "false"));
            if (allowManaged.HasValue) fields.Add("\"allowManaged\":" + (allowManaged.Value ? "true" : "false"));
            if (allowGlobal.HasValue) fields.Add("\"allowGlobal\":" + (allowGlobal.Value ? "true" : "false"));
            if (allowDns.HasValue) fields.Add("\"allowDNS\":" + (allowDns.Value ? "true" : "false"));

            string body = "{" + string.Join(",", fields) + "}";
            return SendJson<ZtNetworkInfo>("POST", "/network/" + cleanId, body);
        }

        public static bool LeaveNetwork(string networkId)
        {
            string cleanId = (networkId ?? "").Trim().ToLowerInvariant();
            string baseUrl, token;
            if (!TryGetEndpoint(out baseUrl, out token)) return false;

            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(baseUrl + "/network/" + cleanId);
                req.Method = "DELETE";
                req.Headers["X-ZT1-Auth"] = token;
                req.Timeout = 2000;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return (int)resp.StatusCode >= 200 && (int)resp.StatusCode < 300;
                }
            }
            catch
            {
                return false;
            }
        }

        public static ZtTelemetrySummary GetTelemetrySummary()
        {
            ZtTelemetrySummary summary = new ZtTelemetrySummary
            {
                NodeId = "----------",
                DaemonOnline = false,
                Version = "--",
                LinkMode = "OFFLINE",
                PeerSummary = "Daemon Unreachable"
            };

            ZtNodeStatus st = GetStatus();
            if (st == null) return summary;

            summary.NodeId = st.Address ?? "----------";
            summary.DaemonOnline = st.Online;
            summary.Version = st.Version ?? "--";

            if (!st.Online)
            {
                summary.LinkMode = "OFFLINE";
                summary.PeerSummary = "Node Offline";
                return summary;
            }

            try
            {
                List<ZtPeerInfo> peers = SendJson<List<ZtPeerInfo>>("GET", "/peer") ?? new List<ZtPeerInfo>();
                bool foundDirect = false;
                bool foundRelay = false;
                int bestLatency = int.MaxValue;

                foreach (ZtPeerInfo p in peers)
                {
                    if (!string.Equals(p.Role, "LEAF", StringComparison.OrdinalIgnoreCase))
                        continue;

                    bool hasActivePath = p.Paths != null && p.Paths.Any(path => path.Active);
                    if (hasActivePath)
                    {
                        foundDirect = true;
                        if (p.Latency > 0 && p.Latency < bestLatency)
                            bestLatency = p.Latency;
                    }
                    else
                    {
                        foundRelay = true;
                    }
                }

                if (foundDirect)
                {
                    summary.LinkMode = "DIRECT";
                    summary.PeerSummary = bestLatency < int.MaxValue
                        ? string.Format("DIRECT ({0} ms)", bestLatency)
                        : "DIRECT (P2P)";
                }
                else if (foundRelay)
                {
                    summary.LinkMode = "RELAY";
                    summary.PeerSummary = "RELAY (Via Root)";
                }
                else
                {
                    summary.LinkMode = "IDLE";
                    summary.PeerSummary = "Online (No Active Leaf)";
                }
            }
            catch
            {
                summary.LinkMode = "ONLINE";
                summary.PeerSummary = "Online";
            }

            return summary;
        }

        public static string ResolveAdapterGuidForNetwork(ZtNetworkInfo net)
        {
            if (net == null) return null;

            List<NetworkInterface> ztNics = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni =>
                    (ni.Name != null && ni.Name.IndexOf("ZeroTier", StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (ni.Description != null && ni.Description.IndexOf("ZeroTier", StringComparison.OrdinalIgnoreCase) >= 0))
                .ToList();

            if (ztNics.Count == 0) return null;

            if (net.AssignedAddresses != null)
            {
                foreach (string cidr in net.AssignedAddresses)
                {
                    if (string.IsNullOrWhiteSpace(cidr)) continue;
                    string ipOnly = cidr.Split('/')[0].Trim();
                    foreach (NetworkInterface ni in ztNics)
                    {
                        bool hasIp = ni.GetIPProperties().UnicastAddresses
                            .Any(u => string.Equals(u.Address.ToString(), ipOnly, StringComparison.OrdinalIgnoreCase));
                        if (hasIp) return ni.Id;
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(net.Mac))
            {
                string targetMac = net.Mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
                foreach (NetworkInterface ni in ztNics)
                {
                    string nicMac = ni.GetPhysicalAddress().ToString().ToUpperInvariant();
                    if (nicMac == targetMac) return ni.Id;
                }
            }

            NetworkInterface upNic = ztNics.FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up);
            return (upNic ?? ztNics[0]).Id;
        }
    }
}
'@

Set-Content -Path "$RepoDir\src\ZeroTierApi.cs" -Value $ZeroTierApiCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 3. Write src\GuardService.cs (LocalSystem WFP Re-Binder & Daemon Supervisor)
# ---------------------------------------------------------------------------
$GuardServiceCode = @'
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
            });
        }

        public static void ReconcilePolicyWithWfp(bool verboseLog)
        {
            AppLockerPolicy policy = PolicyStore.Load();
            if (policy.LockedApps.Count == 0 && !policy.StrictDnsLock)
                return;

            List<ZtNetworkInfo> networks = ZeroTierApi.GetNetworks();

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
'@

Set-Content -Path "$RepoDir\src\GuardService.cs" -Value $GuardServiceCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 4. Compile Verification Gate & Git Push
# ---------------------------------------------------------------------------
Write-Host "[3/4] Running csc.exe compilation verification gate across all 5 core modules..." -ForegroundColor Cyan
$CscPath = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$TempDll = "$env:TEMP\ZTAppLocker_M2_Check.dll"
& $CscPath /target:library /platform:x64 /nologo `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Runtime.Serialization.dll `
    /reference:System.ServiceProcess.dll `
    /out:"$TempDll" `
    "src\WfpEngine.cs" "src\SocketManager.cs" "src\PolicyStore.cs" "src\ZeroTierApi.cs" "src\GuardService.cs"

if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed! Aborting Git commit and push."
}
Remove-Item $TempDll -Force -ErrorAction SilentlyContinue

Write-Host "[4/4] Staging, committing, and pushing Milestone 2 to GitHub..." -ForegroundColor Cyan
git add src/PolicyStore.cs src/ZeroTierApi.cs src/GuardService.cs
git commit -m "feat(control-plane): add PolicyStore, ZeroTier REST client, and event-driven GuardService"
git push

Write-Host "`nDONE! Milestone 2 verified and pushed to GitHub." -ForegroundColor Green