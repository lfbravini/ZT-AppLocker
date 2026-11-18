using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ZTAppLocker
{
    public class WfpLockRecord
    {
        public string AppHash { get; set; }
        public string ExePath { get; set; }
        public string AdapterGuid { get; set; }
        public ulong InterfaceLuid { get; set; }
        public bool BootTimeProtected { get; set; }
    }

    public static class WfpEngine
    {
        public static readonly Guid ProviderGuid = new Guid("7E3B9A10-4C8D-4E21-9F6A-2D8B1C4E5A01");
        public static readonly Guid SublayerGuid = new Guid("7E3B9A10-4C8D-4E21-9F6A-2D8B1C4E5A02");

        private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        private static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = new Guid("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
        private static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V6 = new Guid("e1735b42-8000-483a-9934-1c2c8e8d6a1a");

        private static readonly Guid FWPM_CONDITION_ALE_APP_ID = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        private static readonly Guid FWPM_CONDITION_IP_LOCAL_INTERFACE = new Guid("4cd62a49-59c3-4969-b7f3-da5d32890a48");
        private static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
        private static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        private static readonly Guid FWPM_CONDITION_IP_PROTOCOL = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        private static readonly Guid FWPM_CONDITION_FLAGS = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");

        private const uint RPC_C_AUTHN_WINNT = 10;
        private const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
        private const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
        private const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;
        private const uint FWPM_FILTER_FLAG_BOOTTIME = 0x00000002;

        private const uint FWP_ACTION_BLOCK = 0x00001001;
        private const uint FWP_ACTION_PERMIT = 0x00001002;

        private const uint FWP_MATCH_EQUAL = 0;
        private const uint FWP_MATCH_NOT_EQUAL = 5;
        private const uint FWP_MATCH_FLAGS_ALL_SET = 7;

        private const uint FWP_UINT8 = 1;
        private const uint FWP_UINT16 = 2;
        private const uint FWP_UINT32 = 3;
        private const uint FWP_UINT64 = 4;
        private const uint FWP_BYTE_ARRAY16_TYPE = 11;
        private const uint FWP_BYTE_BLOB_TYPE = 12;

        private const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;
        private const uint FWP_E_ALREADY_EXISTS = 0x80320009;

        #region Pure Blittable x64 Native Structs (Zero CLR Mixed-Layout Marshaling)

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_DISPLAY_DATA0
        {
            public IntPtr name;
            public IntPtr description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_BYTE_BLOB
        {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_PROVIDER0
        {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public FWP_BYTE_BLOB providerData;
            public IntPtr serviceName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_SUBLAYER0
        {
            public Guid subLayerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public ushort weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_VALUE0
        {
            public uint type;
            private uint _pad;
            public ulong value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER_CONDITION0
        {
            public Guid fieldKey;
            public uint matchType;
            public FWP_VALUE0 conditionValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_ACTION0
        {
            public uint type;
            public Guid filterType;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER0
        {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWP_VALUE0 weight;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public FWPM_ACTION0 action;
            private uint _actionPad; // Align 8-byte union (rawContext/providerContextKey) to offset 152
            public Guid providerContextKey; // 16-byte union with UINT64 rawContext in fwpmtypes.h
            public IntPtr reserved;
            public ulong filterId;
            public FWP_VALUE0 effectiveWeight;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER_ENUM_TEMPLATE0
        {
            public IntPtr providerKey;
            public Guid layerKey;
            public uint enumType;
            public uint flags;
            public IntPtr providerContextTemplate;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public uint actionMask;
            public IntPtr calloutKey;
        }

        #endregion

        #region P/Invoke Declarations

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineOpen0(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint authnService,
            IntPtr authIdentity,
            IntPtr session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmProviderAdd0(IntPtr engineHandle, IntPtr provider, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, IntPtr subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterAdd0(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterCreateEnumHandle0(
            IntPtr engineHandle,
            ref FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate,
            out IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterEnum0(
            IntPtr engineHandle,
            IntPtr enumHandle,
            uint numEntriesRequested,
            out IntPtr entries,
            out uint numEntriesReturned);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmGetAppIdFromFileName0(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            out IntPtr appId);

        [DllImport("iphlpapi.dll")]
        private static extern uint ConvertInterfaceGuidToLuid(ref Guid interfaceGuid, out ulong interfaceLuid);

        #endregion

        public static ulong ResolveInterfaceLuid(string adapterGuidString)
        {
            if (string.IsNullOrWhiteSpace(adapterGuidString))
                throw new ArgumentException("Adapter GUID is empty.");

            Guid guid = new Guid(adapterGuidString);
            ulong luid;
            uint err = ConvertInterfaceGuidToLuid(ref guid, out luid);
            if (err != 0)
                throw new InvalidOperationException("ConvertInterfaceGuidToLuid failed with Win32 error " + err);
            return luid;
        }

        public static string ComputeAppHash(string exePath)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(exePath.Trim().ToLowerInvariant()));
                return BitConverter.ToString(bytes).Replace("-", "").Substring(0, 16);
            }
        }

        private static Guid DeriveDeterministicGuid(string seed)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes("ZTAppLocker-v3:" + seed));
                return new Guid(hash);
            }
        }

        public static void EnsureProviderAndSublayer(IntPtr engine)
        {
            IntPtr pProviderKey = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr pProvName = Marshal.StringToHGlobalUni("ZT-AppLocker Kernel Provider");
            IntPtr pProvDesc = Marshal.StringToHGlobalUni("Native WFP ZeroTier Kill-Switch & Leak Prevention Provider");
            IntPtr pProvStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_PROVIDER0)));

            IntPtr pSubName = Marshal.StringToHGlobalUni("ZT-AppLocker Enforcement Sublayer");
            IntPtr pSubDesc = Marshal.StringToHGlobalUni("Per-application interface binding, boot-time guard, and DNS leak locks");
            IntPtr pSubStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_SUBLAYER0)));

            try
            {
                Marshal.StructureToPtr(ProviderGuid, pProviderKey, false);

                FWPM_PROVIDER0 provider = new FWPM_PROVIDER0
                {
                    providerKey = ProviderGuid,
                    displayData = new FWPM_DISPLAY_DATA0 { name = pProvName, description = pProvDesc },
                    flags = FWPM_PROVIDER_FLAG_PERSISTENT
                };
                Marshal.StructureToPtr(provider, pProvStruct, false);
                uint err = FwpmProviderAdd0(engine, pProvStruct, IntPtr.Zero);
                if (err != 0 && err != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmProviderAdd0 failed: 0x" + err.ToString("X8"));

                FWPM_SUBLAYER0 sublayer = new FWPM_SUBLAYER0
                {
                    subLayerKey = SublayerGuid,
                    displayData = new FWPM_DISPLAY_DATA0 { name = pSubName, description = pSubDesc },
                    flags = FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey = pProviderKey,
                    weight = 0x7FFF
                };
                Marshal.StructureToPtr(sublayer, pSubStruct, false);
                err = FwpmSubLayerAdd0(engine, pSubStruct, IntPtr.Zero);
                if (err != 0 && err != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmSubLayerAdd0 failed: 0x" + err.ToString("X8"));
            }
            finally
            {
                Marshal.FreeHGlobal(pSubStruct);
                Marshal.FreeHGlobal(pSubDesc);
                Marshal.FreeHGlobal(pSubName);
                Marshal.FreeHGlobal(pProvStruct);
                Marshal.FreeHGlobal(pProvDesc);
                Marshal.FreeHGlobal(pProvName);
                Marshal.FreeHGlobal(pProviderKey);
            }
        }

        public static void EnsureZeroTierFallbackRoute(string zeroTierAdapterGuid)
        {
            try
            {
                Guid targetGuid = new Guid(zeroTierAdapterGuid);
                int ifIndex = -1;
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    Guid g;
                    if (Guid.TryParse(nic.Id, out g) && g == targetGuid)
                    {
                        var props = nic.GetIPProperties().GetIPv4Properties();
                        if (props != null) ifIndex = props.Index;
                        break;
                    }
                }
                if (ifIndex <= 0) return;

                string secretPath = @"C:\ProgramData\ZeroTier\One\authtoken.secret";
                if (!File.Exists(secretPath)) return;
                string token = File.ReadAllText(secretPath).Trim();

                var req = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:9993/network");
                req.Headers["X-ZT1-Auth"] = token;
                req.Timeout = 2000;
                string json;
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                {
                    json = sr.ReadToEnd();
                }

                // Extract managed 0.0.0.0/0 gateway ("target":"0.0.0.0/0","via":"<ip>")
                var m = System.Text.RegularExpressions.Regex.Match(
                    json,
                    "\"target\"\\s*:\\s*\"0\\.0\\.0\\.0/0\"\\s*,\\s*\"via\"\\s*:\\s*\"([0-9\\.]+)\""
                );
                if (!m.Success) return;
                string gatewayIp = m.Groups[1].Value;

                // Ensure high-metric (500) fallback 0.0.0.0/0 route exists on the live ZeroTier interface
                string ps = string.Format(
                    "$r = Get-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue; " +
                    "if (-not ($r | Where-Object {{ $_.NextHop -eq '{1}' }})) {{ " +
                    "  Remove-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue; " +
                    "  New-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -NextHop '{1}' -RouteMetric 500 -PolicyStore ActiveStore | Out-Null; " +
                    "}}",
                    ifIndex, gatewayIp
                );
                var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"" + ps + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(5000);
                }
            }
            catch { }
        }

        public static void ApplyAppLock(string exePath, string zeroTierAdapterGuid, bool includeBootTimeGuard = true)
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                throw new FileNotFoundException("Target executable not found.", exePath);

            EnsureZeroTierFallbackRoute(zeroTierAdapterGuid);
            ulong ztLuid = ResolveInterfaceLuid(zeroTierAdapterGuid);
            string appHash = ComputeAppHash(exePath);
            string leaf = Path.GetFileName(exePath);

            IntPtr appIdBlobPtr = IntPtr.Zero;
            uint err = FwpmGetAppIdFromFileName0(exePath, out appIdBlobPtr);
            if (err != 0 || appIdBlobPtr == IntPtr.Zero)
                throw new InvalidOperationException("FwpmGetAppIdFromFileName0 failed: 0x" + err.ToString("X8"));

            IntPtr engine = IntPtr.Zero;
            try
            {
                err = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
                if (err != 0)
                    throw new InvalidOperationException("FwpmEngineOpen0 failed: 0x" + err.ToString("X8"));

                err = FwpmTransactionBegin0(engine, 0);
                if (err != 0)
                    throw new InvalidOperationException("FwpmTransactionBegin0 failed: 0x" + err.ToString("X8"));

                try
                {
                    EnsureProviderAndSublayer(engine);
                    DeleteAppFiltersInTransaction(engine, appHash);

                    AddAppFilterSet(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, "V4", appHash, leaf, exePath, appIdBlobPtr, ztLuid, FWPM_FILTER_FLAG_PERSISTENT);
                    AddAppFilterSet(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, "V6", appHash, leaf, exePath, appIdBlobPtr, ztLuid, FWPM_FILTER_FLAG_PERSISTENT);

                    if (includeBootTimeGuard)
                    {
                        AddSingleFilter(engine,
                            DeriveDeterministicGuid(appHash + ":BOOT_V4"),
                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            string.Format("ZT-AppLocker [{0}] Boot-Time Block V4", leaf),
                            exePath,
                            FWPM_FILTER_FLAG_BOOTTIME,
                            1,
                            FWP_ACTION_BLOCK,
                            new[] { MakeAppIdCondition(appIdBlobPtr) });

                        AddSingleFilter(engine,
                            DeriveDeterministicGuid(appHash + ":BOOT_V6"),
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            string.Format("ZT-AppLocker [{0}] Boot-Time Block V6", leaf),
                            exePath,
                            FWPM_FILTER_FLAG_BOOTTIME,
                            1,
                            FWP_ACTION_BLOCK,
                            new[] { MakeAppIdCondition(appIdBlobPtr) });
                    }

                    err = FwpmTransactionCommit0(engine);
                    if (err != 0)
                        throw new InvalidOperationException("FwpmTransactionCommit0 failed: 0x" + err.ToString("X8"));
                }
                catch
                {
                    FwpmTransactionAbort0(engine);
                    throw;
                }
            }
            finally
            {
                if (appIdBlobPtr != IntPtr.Zero) FwpmFreeMemory0(ref appIdBlobPtr);
                if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
            }
        }

        public static void SetStrictDnsLock(bool enabled, string zeroTierAdapterGuid)
        {
            IntPtr engine = IntPtr.Zero;
            uint err = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
            if (err != 0)
                throw new InvalidOperationException("FwpmEngineOpen0 failed: 0x" + err.ToString("X8"));

            try
            {
                err = FwpmTransactionBegin0(engine, 0);
                if (err != 0)
                    throw new InvalidOperationException("FwpmTransactionBegin0 failed: 0x" + err.ToString("X8"));

                try
                {
                    EnsureProviderAndSublayer(engine);

                    string[] dnsKeys = { "DNS_UDP_V4", "DNS_TCP_V4", "DNS_UDP_V6", "DNS_TCP_V6" };
                    foreach (string k in dnsKeys)
                    {
                        Guid g = DeriveDeterministicGuid("GLOBAL:" + k);
                        FwpmFilterDeleteByKey0(engine, ref g);
                    }

                    if (enabled)
                    {
                        EnsureZeroTierFallbackRoute(zeroTierAdapterGuid);
            ulong ztLuid = ResolveInterfaceLuid(zeroTierAdapterGuid);
                        IntPtr luidPtr = Marshal.AllocHGlobal(sizeof(ulong));
                        try
                        {
                            Marshal.WriteInt64(luidPtr, unchecked((long)ztLuid));

                            AddDnsBlockFilter(engine, "DNS_UDP_V4", FWPM_LAYER_OUTBOUND_TRANSPORT_V4, 17, luidPtr);
                            AddDnsBlockFilter(engine, "DNS_TCP_V4", FWPM_LAYER_OUTBOUND_TRANSPORT_V4, 6, luidPtr);
                            AddDnsBlockFilter(engine, "DNS_UDP_V6", FWPM_LAYER_OUTBOUND_TRANSPORT_V6, 17, luidPtr);
                            AddDnsBlockFilter(engine, "DNS_TCP_V6", FWPM_LAYER_OUTBOUND_TRANSPORT_V6, 6, luidPtr);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(luidPtr);
                        }
                    }

                    err = FwpmTransactionCommit0(engine);
                    if (err != 0)
                        throw new InvalidOperationException("FwpmTransactionCommit0 failed: 0x" + err.ToString("X8"));
                }
                catch
                {
                    FwpmTransactionAbort0(engine);
                    throw;
                }
            }
            finally
            {
                if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
            }
        }

        private static void AddDnsBlockFilter(IntPtr engine, string keyName, Guid layer, byte ipProtocol, IntPtr ztLuidPtr)
        {
            var conds = new[]
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT8, value = ipProtocol }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT16, value = 53 }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType = FWP_MATCH_NOT_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT64, value = unchecked((ulong)ztLuidPtr.ToInt64()) }
                }
            };

            AddSingleFilter(engine,
                DeriveDeterministicGuid("GLOBAL:" + keyName),
                layer,
                "ZT-AppLocker Strict DNS Leak Block (" + keyName + ")",
                "Blocks outbound DNS port 53 outside ZeroTier interface",
                FWPM_FILTER_FLAG_PERSISTENT,
                12,
                FWP_ACTION_BLOCK,
                conds);
        }

        private static List<IPAddress> GetAdapterLocalAddresses(string adapterGuidString, AddressFamily family)
        {
            var result = new List<IPAddress>();
            Guid targetGuid = new Guid(adapterGuidString);
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                Guid nicGuid;
                if (Guid.TryParse(nic.Id, out nicGuid) && nicGuid == targetGuid)
                {
                    foreach (UnicastIPAddressInformation uni in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == family)
                            result.Add(uni.Address);
                    }
                }
            }
            return result;
        }

        private static void AddAppFilterSet(
            IntPtr engine,
            Guid layer,
            string tag,
            string appHash,
            string leaf,
            string exePath,
            IntPtr appIdBlobPtr,
            ulong ztLuid,
            uint flags)
        {
            // Clean up any legacy ALLOW_V4/V6 single filter key and indexed allow keys
            Guid legacyAllow = DeriveDeterministicGuid(appHash + ":ALLOW_" + tag);
            FwpmFilterDeleteByKey0(engine, ref legacyAllow);
            for (int idx = 0; idx < 8; idx++)
            {
                Guid idxAllow = DeriveDeterministicGuid(string.Format("{0}:ALLOW_{1}_{2}", appHash, tag, idx));
                FwpmFilterDeleteByKey0(engine, ref idxAllow);
            }

            // 1. Permit Loopback (only supported on ALE_AUTH_CONNECT layers; OUTBOUND_TRANSPORT does not have FWPM_CONDITION_FLAGS)
            if (layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6)
            {
                AddSingleFilter(engine,
                    DeriveDeterministicGuid(appHash + ":LOOP_" + tag),
                    layer,
                    string.Format("ZT-AppLocker [{0}] Permit Loopback {1}", leaf, tag),
                    exePath,
                    flags,
                    15,
                    FWP_ACTION_PERMIT,
                    new[]
                    {
                        MakeAppIdCondition(appIdBlobPtr),
                        new FWPM_FILTER_CONDITION0
                        {
                            fieldKey = FWPM_CONDITION_FLAGS,
                            matchType = FWP_MATCH_FLAGS_ALL_SET,
                            conditionValue = new FWP_VALUE0 { type = FWP_UINT32, value = FWP_CONDITION_FLAG_IS_LOOPBACK }
                        }
                    });
            }

            // 2. Permit outbound traffic bound to the ZeroTier virtual adapter's assigned IP(s)
            // Note: ALE_AUTH_CONNECT supports FWPM_CONDITION_IP_LOCAL_ADDRESS (whereas IP_LOCAL_INTERFACE is transport-layer only)
            AddressFamily family = (tag == "V4") ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            string adapterGuid = ResolveAdapterGuidFromLuid(ztLuid);
            List<IPAddress> ztAddrs = GetAdapterLocalAddresses(adapterGuid, family);

            for (int i = 0; i < ztAddrs.Count; i++)
            {
                IPAddress ip = ztAddrs[i];
                if (family == AddressFamily.InterNetwork)
                {
                    byte[] bytes = ip.GetAddressBytes();
                    // WFP expects host-order UINT32 for IPv4 addresses
                    uint hostOrderIp = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];

                    AddSingleFilter(engine,
                        DeriveDeterministicGuid(string.Format("{0}:ALLOW_{1}_{2}", appHash, tag, i)),
                        layer,
                        string.Format("ZT-AppLocker [{0}] Permit ZeroTier {1} ({2})", leaf, tag, ip),
                        exePath,
                        flags,
                        10,
                        FWP_ACTION_PERMIT,
                        new[]
                        {
                            MakeAppIdCondition(appIdBlobPtr),
                            new FWPM_FILTER_CONDITION0
                            {
                                fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                                matchType = FWP_MATCH_EQUAL,
                                conditionValue = new FWP_VALUE0 { type = FWP_UINT32, value = hostOrderIp }
                            }
                        });
                }
                else
                {
                    byte[] bytes16 = ip.GetAddressBytes();
                    IntPtr addr16Ptr = Marshal.AllocHGlobal(16);
                    try
                    {
                        Marshal.Copy(bytes16, 0, addr16Ptr, 16);
                        AddSingleFilter(engine,
                            DeriveDeterministicGuid(string.Format("{0}:ALLOW_{1}_{2}", appHash, tag, i)),
                            layer,
                            string.Format("ZT-AppLocker [{0}] Permit ZeroTier {1} ({2})", leaf, tag, ip),
                            exePath,
                            flags,
                            10,
                            FWP_ACTION_PERMIT,
                            new[]
                            {
                                MakeAppIdCondition(appIdBlobPtr),
                                new FWPM_FILTER_CONDITION0
                                {
                                    fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                                    matchType = FWP_MATCH_EQUAL,
                                    conditionValue = new FWP_VALUE0 { type = FWP_BYTE_ARRAY16_TYPE, value = unchecked((ulong)addr16Ptr.ToInt64()) }
                                }
                            });
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(addr16Ptr);
                    }
                }
            }

            // 3. Delete any legacy ALE_AUTH_CONNECT catch-all block so outbound packets reach SplitTunnelEngine WinDivert layer
            // (SplitTunnelEngine enforces fail-closed ZeroTier interface binding per-PID; Boot-Time Guard still blocks at boot)
            Guid legacyBlock = DeriveDeterministicGuid(appHash + ":BLOCK_" + tag);
            FwpmFilterDeleteByKey0(engine, ref legacyBlock);
        }

        private static string ResolveAdapterGuidFromLuid(ulong luid)
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ResolveInterfaceLuid(nic.Id) == luid)
                        return nic.Id;
                }
                catch { }
            }
            throw new InvalidOperationException("Unable to map ZeroTier interface LUID back to adapter GUID.");
        }

        private static FWPM_FILTER_CONDITION0 MakeAppIdCondition(IntPtr appIdBlobPtr)
        {
            return new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_ALE_APP_ID,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0
                {
                    type = FWP_BYTE_BLOB_TYPE,
                    value = unchecked((ulong)appIdBlobPtr.ToInt64())
                }
            };
        }

        private static void AddSingleFilter(
            IntPtr engine,
            Guid filterKey,
            Guid layerKey,
            string name,
            string description,
            uint flags,
            byte weightValue,
            uint actionType,
            FWPM_FILTER_CONDITION0[] conditions)
        {
            int condSize = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));
            IntPtr condArrayPtr = Marshal.AllocHGlobal(condSize * conditions.Length);
            IntPtr providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr namePtr = Marshal.StringToHGlobalUni(name);
            IntPtr descPtr = Marshal.StringToHGlobalUni(description);
            IntPtr filterPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_FILTER0)));

            try
            {
                Marshal.StructureToPtr(ProviderGuid, providerKeyPtr, false);
                for (int i = 0; i < conditions.Length; i++)
                {
                    IntPtr dest = IntPtr.Add(condArrayPtr, i * condSize);
                    Marshal.StructureToPtr(conditions[i], dest, false);
                }

                FWPM_FILTER0 filter = new FWPM_FILTER0
                {
                    filterKey = filterKey,
                    displayData = new FWPM_DISPLAY_DATA0 { name = namePtr, description = descPtr },
                    flags = flags,
                    providerKey = providerKeyPtr,
                    layerKey = layerKey,
                    subLayerKey = SublayerGuid,
                    weight = new FWP_VALUE0 { type = FWP_UINT8, value = weightValue },
                    numFilterConditions = (uint)conditions.Length,
                    filterCondition = condArrayPtr,
                    action = new FWPM_ACTION0 { type = actionType }
                };

                Marshal.StructureToPtr(filter, filterPtr, false);

                ulong filterId;
                uint err = FwpmFilterAdd0(engine, filterPtr, IntPtr.Zero, out filterId);
                if (err != 0)
                    throw new InvalidOperationException(string.Format("FwpmFilterAdd0 ({0}) failed: 0x{1:X8}", name, err));
            }
            finally
            {
                Marshal.FreeHGlobal(filterPtr);
                Marshal.FreeHGlobal(descPtr);
                Marshal.FreeHGlobal(namePtr);
                Marshal.FreeHGlobal(condArrayPtr);
                Marshal.FreeHGlobal(providerKeyPtr);
            }
        }

        public static void RemoveAppLock(string exePath)
        {
            string appHash = ComputeAppHash(exePath);
            IntPtr engine = IntPtr.Zero;
            uint err = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
            if (err != 0) return;

            try
            {
                if (FwpmTransactionBegin0(engine, 0) == 0)
                {
                    DeleteAppFiltersInTransaction(engine, appHash);
                    FwpmTransactionCommit0(engine);
                }
            }
            finally
            {
                FwpmEngineClose0(engine);
            }
        }

        private static void DeleteAppFiltersInTransaction(IntPtr engine, string appHash)
        {
            string[] suffixes = { "LOOP_V4", "ALLOW_V4", "ALLOW_V4_0", "ALLOW_V4_1", "ALLOW_V4_2", "BLOCK_V4", "LOOP_V6", "ALLOW_V6", "ALLOW_V6_0", "ALLOW_V6_1", "ALLOW_V6_2", "BLOCK_V6", "BOOT_V4", "BOOT_V6" };
            foreach (string s in suffixes)
            {
                Guid g = DeriveDeterministicGuid(appHash + ":" + s);
                FwpmFilterDeleteByKey0(engine, ref g);
            }
        }

        public static void PurgeAllWfpFilters()
        {
            IntPtr engine = IntPtr.Zero;
            uint err = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
            if (err != 0) return;

            try
            {
                if (FwpmTransactionBegin0(engine, 0) != 0) return;

                try
                {
                    DeleteAllFiltersInLayer(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4);
                    DeleteAllFiltersInLayer(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6);
                    DeleteAllFiltersInLayer(engine, FWPM_LAYER_OUTBOUND_TRANSPORT_V4);
                    DeleteAllFiltersInLayer(engine, FWPM_LAYER_OUTBOUND_TRANSPORT_V6);

                    Guid subKey = SublayerGuid;
                    FwpmSubLayerDeleteByKey0(engine, ref subKey);
                    FwpmTransactionCommit0(engine);
                }
                catch
                {
                    FwpmTransactionAbort0(engine);
                }
            }
            finally
            {
                FwpmEngineClose0(engine);
            }
        }

        private static void DeleteAllFiltersInLayer(IntPtr engine, Guid layerKey)
        {
            IntPtr providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr enumHandle = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(ProviderGuid, providerKeyPtr, false);
                FWPM_FILTER_ENUM_TEMPLATE0 tmpl = new FWPM_FILTER_ENUM_TEMPLATE0
                {
                    providerKey = providerKeyPtr,
                    layerKey = layerKey,
                    enumType = 0,
                    actionMask = 0xFFFFFFFF
                };

                if (FwpmFilterCreateEnumHandle0(engine, ref tmpl, out enumHandle) != 0)
                    return;

                IntPtr entriesPtr;
                uint count;
                if (FwpmFilterEnum0(engine, enumHandle, 512, out entriesPtr, out count) == 0 && count > 0)
                {
                    try
                    {
                        for (int i = 0; i < count; i++)
                        {
                            IntPtr filterPtr = Marshal.ReadIntPtr(entriesPtr, i * IntPtr.Size);
                            FWPM_FILTER0 f = (FWPM_FILTER0)Marshal.PtrToStructure(filterPtr, typeof(FWPM_FILTER0));
                            if (f.subLayerKey == SublayerGuid)
                            {
                                Guid k = f.filterKey;
                                FwpmFilterDeleteByKey0(engine, ref k);
                            }
                        }
                    }
                    finally
                    {
                        FwpmFreeMemory0(ref entriesPtr);
                    }
                }
            }
            finally
            {
                if (enumHandle != IntPtr.Zero) FwpmFilterDestroyEnumHandle0(engine, enumHandle);
                Marshal.FreeHGlobal(providerKeyPtr);
            }
        }
    }
}




