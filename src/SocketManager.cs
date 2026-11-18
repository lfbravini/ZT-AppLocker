using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ZTAppLocker
{
    public class LiveSocketInfo
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public bool IsCompliant { get; set; }
    }

    public static class SocketManager
    {
        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_ESTAB = 5;
        private const int MIB_TCP_STATE_DELETE_TCB = 12;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tblClass,
            uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int SetTcpEntry(ref MIB_TCPROW pTcpRow);

        public static HashSet<string> GetAllowedZeroTierIpv4Set(string specificAdapterGuid = null)
        {
            HashSet<string> allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "127.0.0.1",
                "0.0.0.0"
            };

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                bool isZt = (ni.Name != null && ni.Name.IndexOf("ZeroTier", StringComparison.OrdinalIgnoreCase) >= 0) ||
                            (ni.Description != null && ni.Description.IndexOf("ZeroTier", StringComparison.OrdinalIgnoreCase) >= 0);

                if (!isZt) continue;
                if (!string.IsNullOrWhiteSpace(specificAdapterGuid) &&
                    !string.Equals(ni.Id.Trim('{', '}'), specificAdapterGuid.Trim('{', '}'), StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        allowed.Add(ua.Address.ToString());
                }
            }
            return allowed;
        }

        public static List<LiveSocketInfo> InspectProcessSockets(string exePath, string specificAdapterGuid = null)
        {
            List<LiveSocketInfo> results = new List<LiveSocketInfo>();
            string procName = Path.GetFileNameWithoutExtension(exePath);
            HashSet<int> targetPids = new HashSet<int>(
                Process.GetProcessesByName(procName).Select(p => p.Id));

            if (targetPids.Count == 0)
                return results;

            HashSet<string> allowedIps = GetAllowedZeroTierIpv4Set(specificAdapterGuid);

            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                uint ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int rowCount = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                for (int i = 0; i < rowCount; i++)
                {
                    MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    int pid = unchecked((int)row.dwOwningPid);
                    if (!targetPids.Contains(pid)) continue;

                    string localIp = new IPAddress(row.dwLocalAddr).ToString();
                    string remoteIp = new IPAddress(row.dwRemoteAddr).ToString();
                    int localPort = ntohs((ushort)row.dwLocalPort);
                    int remotePort = ntohs((ushort)row.dwRemotePort);

                    bool compliant = allowedIps.Contains(localIp) || remoteIp == "127.0.0.1" || remoteIp == "0.0.0.0";

                    results.Add(new LiveSocketInfo
                    {
                        Pid = pid,
                        ProcessName = procName,
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        State = FormatTcpState(row.dwState),
                        IsCompliant = compliant
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return results;
        }

        public static int SeverNonCompliantSockets(string exePath, string specificAdapterGuid = null)
        {
            string procName = Path.GetFileNameWithoutExtension(exePath);
            HashSet<int> targetPids = new HashSet<int>(
                Process.GetProcessesByName(procName).Select(p => p.Id));

            if (targetPids.Count == 0)
                return 0;

            HashSet<string> allowedIps = GetAllowedZeroTierIpv4Set(specificAdapterGuid);
            int severedCount = 0;

            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                uint ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return 0;

                int rowCount = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                for (int i = 0; i < rowCount; i++)
                {
                    MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    int pid = unchecked((int)row.dwOwningPid);
                    if (!targetPids.Contains(pid)) continue;
                    if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

                    string localIp = new IPAddress(row.dwLocalAddr).ToString();
                    string remoteIp = new IPAddress(row.dwRemoteAddr).ToString();

                    if (!allowedIps.Contains(localIp) && remoteIp != "127.0.0.1")
                    {
                        MIB_TCPROW killRow = new MIB_TCPROW
                        {
                            dwState = MIB_TCP_STATE_DELETE_TCB,
                            dwLocalAddr = row.dwLocalAddr,
                            dwLocalPort = row.dwLocalPort,
                            dwRemoteAddr = row.dwRemoteAddr,
                            dwRemotePort = row.dwRemotePort
                        };
                        if (SetTcpEntry(ref killRow) == 0)
                            severedCount++;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return severedCount;
        }

        private static ushort ntohs(ushort netshort)
        {
            return (ushort)(((netshort & 0xFF) << 8) | ((netshort >> 8) & 0xFF));
        }

        private static string FormatTcpState(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RCVD";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "STATE_" + state;
            }
        }
    }
}
