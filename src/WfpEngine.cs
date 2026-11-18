using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
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

        private const uint FWP_UINT8 = 2;
        private const uint FWP_UINT16 = 3;
        private const uint FWP_UINT32 = 4;
        private const uint FWP_UINT64 = 5;
        private const uint FWP_BYTE_BLOB_TYPE = 13;

        private const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;
        private const uint FWP_E_ALREADY_EXISTS = 0x80320009;

        #region Native Structs (x64 Aligned)

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_DISPLAY_DATA0
        {
            public string name;
            public string description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_BYTE_BLOB
        {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_PROVIDER0
        {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public FWP_BYTE_BLOB providerData;
            public string serviceName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_SUBLAYER0
        {
            public Guid subLayerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public ushort weight;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct FWP_VALUE0
        {
            [FieldOffset(0)] public uint type;
            [FieldOffset(8)] public byte uint8;
            [FieldOffset(8)] public ushort uint16;
            [FieldOffset(8)] public uint uint32;
            [FieldOffset(8)] public IntPtr uint64Ptr;
            [FieldOffset(8)] public IntPtr byteBlobPtr;
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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
            public ulong rawContext;
            public ulong providerContextPad; // 16-byte union with GUID providerContextKey in fwpmtypes.h
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
        private static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

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
            try
            {
                Marshal.StructureToPtr(ProviderGuid, pProviderKey, false);

                FWPM_PROVIDER0 provider = new FWPM_PROVIDER0
                {
                    providerKey = ProviderGuid,
                    displayData = new FWPM_DISPLAY_DATA0
                    {
                        name = "ZT-AppLocker Kernel Provider",
                        description = "Native WFP ZeroTier Kill-Switch & Leak Prevention Provider"
                    },
                    flags = FWPM_PROVIDER_FLAG_PERSISTENT
                };
                uint err = FwpmProviderAdd0(engine, ref provider, IntPtr.Zero);
                if (err != 0 && err != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmProviderAdd0 failed: 0x" + err.ToString("X8"));

                FWPM_SUBLAYER0 sublayer = new FWPM_SUBLAYER0
                {
                    subLayerKey = SublayerGuid,
                    displayData = new FWPM_DISPLAY_DATA0
                    {
                        name = "ZT-AppLocker Enforcement Sublayer",
                        description = "Per-application interface binding, boot-time guard, and DNS leak locks"
                    },
                    flags = FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey = pProviderKey,
                    weight = 0x7FFF
                };
                err = FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero);
                if (err != 0 && err != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmSubLayerAdd0 failed: 0x" + err.ToString("X8"));
            }
            finally
            {
                Marshal.FreeHGlobal(pProviderKey);
            }
        }

        public static void ApplyAppLock(string exePath, string zeroTierAdapterGuid, bool includeBootTimeGuard = true)
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                throw new FileNotFoundException("Target executable not found.", exePath);

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
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT8, uint8 = ipProtocol }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT16, uint16 = 53 }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType = FWP_MATCH_NOT_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_UINT64, uint64Ptr = ztLuidPtr }
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
            IntPtr luidPtr = Marshal.AllocHGlobal(sizeof(ulong));
            try
            {
                Marshal.WriteInt64(luidPtr, unchecked((long)ztLuid));

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
                            conditionValue = new FWP_VALUE0 { type = FWP_UINT32, uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK }
                        }
                    });

                AddSingleFilter(engine,
                    DeriveDeterministicGuid(appHash + ":ALLOW_" + tag),
                    layer,
                    string.Format("ZT-AppLocker [{0}] Permit ZeroTier {1}", leaf, tag),
                    exePath,
                    flags,
                    10,
                    FWP_ACTION_PERMIT,
                    new[]
                    {
                        MakeAppIdCondition(appIdBlobPtr),
                        new FWPM_FILTER_CONDITION0
                        {
                            fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE,
                            matchType = FWP_MATCH_EQUAL,
                            conditionValue = new FWP_VALUE0 { type = FWP_UINT64, uint64Ptr = luidPtr }
                        }
                    });

                AddSingleFilter(engine,
                    DeriveDeterministicGuid(appHash + ":BLOCK_" + tag),
                    layer,
                    string.Format("ZT-AppLocker [{0}] Catch-All Block {1}", leaf, tag),
                    exePath,
                    flags,
                    1,
                    FWP_ACTION_BLOCK,
                    new[] { MakeAppIdCondition(appIdBlobPtr) });
            }
            finally
            {
                Marshal.FreeHGlobal(luidPtr);
            }
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
                    byteBlobPtr = appIdBlobPtr
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
                    displayData = new FWPM_DISPLAY_DATA0 { name = name, description = description },
                    flags = flags,
                    providerKey = providerKeyPtr,
                    layerKey = layerKey,
                    subLayerKey = SublayerGuid,
                    weight = new FWP_VALUE0 { type = FWP_UINT8, uint8 = weightValue },
                    numFilterConditions = (uint)conditions.Length,
                    filterCondition = condArrayPtr,
                    action = new FWPM_ACTION0 { type = actionType }
                };

                ulong filterId;
                uint err = FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out filterId);
                if (err != 0)
                    throw new InvalidOperationException(string.Format("FwpmFilterAdd0 ({0}) failed: 0x{1:X8}", name, err));
            }
            finally
            {
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
            string[] suffixes = { "LOOP_V4", "ALLOW_V4", "BLOCK_V4", "LOOP_V6", "ALLOW_V6", "BLOCK_V6", "BOOT_V4", "BOOT_V6" };
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


