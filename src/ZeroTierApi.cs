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
