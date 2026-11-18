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
