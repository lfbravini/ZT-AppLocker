using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace ZTAppLocker
{
    public static class SplitTunnelEngine
    {
        private const int WINDIVERT_LAYER_NETWORK = 0;
        private const int WINDIVERT_LAYER_SOCKET = 3;
        private const ulong WINDIVERT_FLAG_SNIFF = 1;
        private const ulong WINDIVERT_FLAG_RECV_ONLY = 4;
        private const int WINDIVERT_EVENT_SOCKET_BIND = 10;
        private const int WINDIVERT_EVENT_SOCKET_CONNECT = 11;

        [StructLayout(LayoutKind.Explicit, Size = 80)]
        private struct WINDIVERT_ADDRESS
        {
            [FieldOffset(0)] public long Timestamp;
            [FieldOffset(8)] public byte Layer;
            [FieldOffset(9)] public byte Event;
            [FieldOffset(10)] public byte Flags;
            [FieldOffset(16)] public uint NetworkIfIdx;
            [FieldOffset(20)] public uint NetworkSubIfIdx;
            [FieldOffset(16)] public uint SocketProcessId;
            [FieldOffset(20)] public ushort SocketLocalPort;
            [FieldOffset(22)] public ushort SocketRemotePort;
            [FieldOffset(24)] public byte SocketProtocol;

            public bool Outbound
            {
                get { return (Flags & 0x02) != 0; }
                set { if (value) Flags |= 0x02; else Flags &= unchecked((byte)~0x02); }
            }

            public bool Loopback
            {
                get { return (Flags & 0x04) != 0; }
                set { if (value) Flags |= 0x04; else Flags &= unchecked((byte)~0x04); }
            }

            public bool Impostor
            {
                get { return (Flags & 0x08) != 0; }
                set { if (value) Flags |= 0x08; else Flags &= unchecked((byte)~0x08); }
            }

            public bool IPv6 { get { return (Flags & 0x10) != 0; } }
        }

        private class NatEntry
        {
            public uint OrigSrcIp;
            public uint OrigDstIp;
            public ushort OrigDstPort;
            public ZtAdapterBinding Binding;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, uint packetLen, out uint pRecvLen, ref WINDIVERT_ADDRESS pAddr);

        [DllImport("WinDivert.dll", EntryPoint = "WinDivertSend", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, uint packetLen, out uint pSendLen, ref WINDIVERT_ADDRESS pAddr);

        [DllImport("WinDivert.dll", EntryPoint = "WinDivertHelperCalcChecksums", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool WinDivertHelperCalcChecksums(byte[] pPacket, uint packetLen, ref WINDIVERT_ADDRESS pAddr, ulong flags);

        [DllImport("WinDivert.dll", EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool WinDivertClose(IntPtr handle);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

        private static readonly object _sync = new object();
        private static bool _running = false;
        private static IntPtr _netHandle = new IntPtr(-1);
        private static IntPtr _sockHandle = new IntPtr(-1);
        private static TcpListener _tcpRelay;
        private static UdpClient _udpRelay;
        private static ushort _relayPort = 0;
        private static int _loggedFirstTcp = 0;
        private static int _loggedFirstUdp = 0;

        private static readonly ConcurrentDictionary<uint, ZtAdapterBinding> _pidBindings = new ConcurrentDictionary<uint, ZtAdapterBinding>();
        private static volatile Dictionary<string, ZtAdapterBinding> _exeBindings = new Dictionary<string, ZtAdapterBinding>(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<ushort, uint> _tcpPortPid = new ConcurrentDictionary<ushort, uint>();
        private static readonly ConcurrentDictionary<ushort, uint> _udpPortPid = new ConcurrentDictionary<ushort, uint>();
        private static readonly ConcurrentDictionary<ushort, NatEntry> _tcpNat = new ConcurrentDictionary<ushort, NatEntry>();
        private static readonly ConcurrentDictionary<ushort, NatEntry> _udpNat = new ConcurrentDictionary<ushort, NatEntry>();
        private static readonly ConcurrentDictionary<ushort, UdpClient> _udpUpstreamByClientPort = new ConcurrentDictionary<ushort, UdpClient>();

        public static string WdCoreDir
        {
            get { return Path.Combine(ServiceManager.InstallDir, "wd-core"); }
        }

        public static void EnsureExtracted()
        {
            Directory.CreateDirectory(WdCoreDir);
            Assembly asm = Assembly.GetExecutingAssembly();
            string[] resNames = asm.GetManifestResourceNames();
            foreach (string fileName in new[] { "WinDivert.dll", "WinDivert64.sys" })
            {
                string dest = Path.Combine(WdCoreDir, fileName);
                if (File.Exists(dest)) continue;
                string match = resNames.FirstOrDefault(r => r.EndsWith(fileName, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    using (Stream s = asm.GetManifestResourceStream(match))
                    using (FileStream fs = File.Create(dest))
                    {
                        if (s != null) s.CopyTo(fs);
                    }
                }
            }
            SetDllDirectory(WdCoreDir);
        }

        public static void RefreshBindings()
        {
            try
            {
                AppLockerPolicy policy = PolicyStore.Load();
                var newExeMap = new Dictionary<string, ZtAdapterBinding>(StringComparer.OrdinalIgnoreCase);
                var netCache = new Dictionary<string, ZtAdapterBinding>(StringComparer.OrdinalIgnoreCase);

                foreach (AppLockPolicyEntry entry in policy.LockedApps)
                {
                    if (string.IsNullOrWhiteSpace(entry.ExePath)) continue;
                    string normExe = NormalizePath(entry.ExePath);
                    string netId = (entry.NetworkId ?? "").Trim();
                    if (string.IsNullOrEmpty(netId)) continue;

                    ZtAdapterBinding binding;
                    if (!netCache.TryGetValue(netId, out binding))
                    {
                        binding = ZeroTierApi.ResolveNetworkBinding(netId);
                        netCache[netId] = binding;
                        if (binding != null && binding.IsReady && binding.ManagedGatewayIpv4 != null)
                        {
                            EnsureInterfaceFallbackRoute(binding.InterfaceIndex, binding.ManagedGatewayIpv4.ToString());
                        }
                    }

                    newExeMap[normExe] = binding;
                }

                _exeBindings = newExeMap;

                var activePids = new HashSet<uint>();
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        uint pid = (uint)p.Id;
                        string procPath = NormalizePath(p.MainModule.FileName);
                        ZtAdapterBinding b;
                        if (newExeMap.TryGetValue(procPath, out b))
                        {
                            _pidBindings[pid] = b;
                            activePids.Add(pid);
                        }
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }

                foreach (uint existingPid in _pidBindings.Keys.ToList())
                {
                    if (!activePids.Contains(existingPid))
                    {
                        ZtAdapterBinding removed;
                        _pidBindings.TryRemove(existingPid, out removed);
                    }
                }
            }
            catch { }
        }

        private static void EnsureInterfaceFallbackRoute(int ifIndex, string gatewayIp)
        {
            try
            {
                string ps = string.Format(
                    "$r = Get-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue; " +
                    "if (-not ($r | Where-Object {{ $_.NextHop -eq '{1}' }})) {{ " +
                    "  Remove-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue; " +
                    "  New-NetRoute -InterfaceIndex {0} -DestinationPrefix '0.0.0.0/0' -NextHop '{1}' -RouteMetric 500 -PolicyStore ActiveStore | Out-Null; " +
                    "}}",
                    ifIndex, gatewayIp
                );
                var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"" + ps + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (var p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(4000);
                }
            }
            catch { }
        }

        public static void Start()
        {
            lock (_sync)
            {
                if (_running) return;
                EnsureExtracted();
                RefreshBindings();

                _tcpRelay = new TcpListener(IPAddress.Loopback, 0);
                _tcpRelay.Start(256);
                _relayPort = (ushort)((IPEndPoint)_tcpRelay.LocalEndpoint).Port;
                _udpRelay = new UdpClient(new IPEndPoint(IPAddress.Loopback, _relayPort));

                IntPtr invalid = new IntPtr(-1);
                _sockHandle = WinDivertOpen("ip", WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
                _netHandle = WinDivertOpen("ip and (tcp or udp)", WINDIVERT_LAYER_NETWORK, -100, 0);

                if (_netHandle == invalid)
                {
                    GuardService.WriteServiceLog("WinDivert NETWORK handle failed: Win32=" + Marshal.GetLastWin32Error());
                    if (_sockHandle != invalid) { WinDivertClose(_sockHandle); _sockHandle = invalid; }
                    try { _tcpRelay.Stop(); } catch { }
                    try { _udpRelay.Close(); } catch { }
                    return;
                }

                _running = true;
                GuardService.WriteServiceLog("SplitTunnelEngine relay active on 127.0.0.1:" + _relayPort);

                if (_sockHandle != invalid)
                    new Thread(SocketMonitorLoop) { IsBackground = true, Name = "ZT-WD-Socket" }.Start();

                new Thread(TcpAcceptLoop) { IsBackground = true, Name = "ZT-Relay-TCP" }.Start();
                new Thread(UdpRelayLoop) { IsBackground = true, Name = "ZT-Relay-UDP" }.Start();
                new Thread(NetworkRedirectLoop) { IsBackground = true, Name = "ZT-WD-Network" }.Start();
                new Thread(() =>
                {
                    while (_running)
                    {
                        Thread.Sleep(2500);
                        if (_running) RefreshBindings();
                    }
                }) { IsBackground = true, Name = "ZT-WD-Refresh" }.Start();
            }
        }

        public static void Stop()
        {
            lock (_sync)
            {
                _running = false;
                IntPtr invalid = new IntPtr(-1);
                if (_sockHandle != invalid) { try { WinDivertClose(_sockHandle); } catch { } _sockHandle = invalid; }
                if (_netHandle != invalid) { try { WinDivertClose(_netHandle); } catch { } _netHandle = invalid; }
                try { if (_tcpRelay != null) _tcpRelay.Stop(); } catch { }
                try { if (_udpRelay != null) _udpRelay.Close(); } catch { }
                foreach (var kv in _udpUpstreamByClientPort)
                {
                    try { kv.Value.Close(); } catch { }
                }
                _udpUpstreamByClientPort.Clear();
            }
        }

        private static void SocketMonitorLoop()
        {
            byte[] dummy = new byte[128];
            WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();
            while (_running)
            {
                uint recvLen;
                if (!WinDivertRecv(_sockHandle, dummy, (uint)dummy.Length, out recvLen, ref addr))
                {
                    if (!_running) break;
                    Thread.Sleep(2);
                    continue;
                }

                if (addr.Event == WINDIVERT_EVENT_SOCKET_BIND || addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT)
                {
                    uint pid = addr.SocketProcessId;
                    if (pid <= 4) continue;

                    if (!_pidBindings.ContainsKey(pid))
                        TryClassifyPid(pid);

                    if (_pidBindings.ContainsKey(pid) && addr.SocketLocalPort != 0)
                    {
                        ushort hostPort = (ushort)IPAddress.NetworkToHostOrder((short)addr.SocketLocalPort);
                        if (hostPort != 0)
                        {
                            if (addr.SocketProtocol == 6) _tcpPortPid[hostPort] = pid;
                            else if (addr.SocketProtocol == 17) _udpPortPid[hostPort] = pid;
                        }
                    }
                }
            }
        }

        private static void TryClassifyPid(uint pid)
        {
            try
            {
                using (Process p = Process.GetProcessById((int)pid))
                {
                    string norm = NormalizePath(p.MainModule.FileName);
                    ZtAdapterBinding b;
                    if (_exeBindings.TryGetValue(norm, out b))
                    {
                        _pidBindings[pid] = b;
                    }
                }
            }
            catch { }
        }

        private static uint LookupOwnerPidForPort(bool isTcp, ushort localPort)
        {
            uint cached;
            if (isTcp && _tcpPortPid.TryGetValue(localPort, out cached) && _pidBindings.ContainsKey(cached))
                return cached;
            if (!isTcp && _udpPortPid.TryGetValue(localPort, out cached) && _pidBindings.ContainsKey(cached))
                return cached;

            if (isTcp)
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
                if (size > 0)
                {
                    IntPtr buf = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) == 0)
                        {
                            int count = Marshal.ReadInt32(buf);
                            IntPtr row = IntPtr.Add(buf, 4);
                            for (int i = 0; i < count; i++)
                            {
                                uint pid = (uint)Marshal.ReadInt32(row, 20);
                                if (_pidBindings.ContainsKey(pid))
                                {
                                    int netPort = Marshal.ReadInt32(row, 8) & 0xFFFF;
                                    ushort hostPort = (ushort)IPAddress.NetworkToHostOrder((short)netPort);
                                    _tcpPortPid[hostPort] = pid;
                                    if (hostPort == localPort) return pid;
                                }
                                row = IntPtr.Add(row, 24);
                            }
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
            }
            else
            {
                int size = 0;
                GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1, 0);
                if (size > 0)
                {
                    IntPtr buf = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (GetExtendedUdpTable(buf, ref size, false, 2, 1, 0) == 0)
                        {
                            int count = Marshal.ReadInt32(buf);
                            IntPtr row = IntPtr.Add(buf, 4);
                            for (int i = 0; i < count; i++)
                            {
                                uint pid = (uint)Marshal.ReadInt32(row, 8);
                                if (_pidBindings.ContainsKey(pid))
                                {
                                    int netPort = Marshal.ReadInt32(row, 4) & 0xFFFF;
                                    ushort hostPort = (ushort)IPAddress.NetworkToHostOrder((short)netPort);
                                    _udpPortPid[hostPort] = pid;
                                    if (hostPort == localPort) return pid;
                                }
                                row = IntPtr.Add(row, 12);
                            }
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
            }
            return 0;
        }

        private static bool IsPrivateRfc1918(uint ipv4HostOrder)
        {
            byte b0 = (byte)(ipv4HostOrder >> 24);
            byte b1 = (byte)(ipv4HostOrder >> 16);
            if (b0 == 10) return true;
            if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
            if (b0 == 192 && b1 == 168) return true;
            return false;
        }

        private static IPAddress UintToIp(uint hostOrderIp)
        {
            return new IPAddress(new[]
            {
                (byte)(hostOrderIp >> 24),
                (byte)(hostOrderIp >> 16),
                (byte)(hostOrderIp >> 8),
                (byte)hostOrderIp
            });
        }

        private static void NetworkRedirectLoop()
        {
            byte[] packet = new byte[65535];
            WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();

            while (_running)
            {
                uint recvLen;
                if (!WinDivertRecv(_netHandle, packet, (uint)packet.Length, out recvLen, ref addr))
                {
                    if (!_running) break;
                    Thread.Sleep(2);
                    continue;
                }

                uint sendLen;
                if (_pidBindings.IsEmpty || recvLen < 20 || addr.IPv6)
                {
                    WinDivertSend(_netHandle, packet, recvLen, out sendLen, ref addr);
                    continue;
                }

                int ihl = (packet[0] & 0x0F) * 4;
                byte proto = packet[9];
                if ((proto != 6 && proto != 17) || recvLen < ihl + 4)
                {
                    WinDivertSend(_netHandle, packet, recvLen, out sendLen, ref addr);
                    continue;
                }

                uint srcIp = ((uint)packet[12] << 24) | ((uint)packet[13] << 16) | ((uint)packet[14] << 8) | packet[15];
                uint dstIp = ((uint)packet[16] << 24) | ((uint)packet[17] << 16) | ((uint)packet[18] << 8) | packet[19];
                ushort srcPort = (ushort)((packet[ihl] << 8) | packet[ihl + 1]);
                ushort dstPort = (ushort)((packet[ihl + 2] << 8) | packet[ihl + 3]);

                // 1. Return path from local relay (127.0.0.1:_relayPort -> 127.0.0.1:clientPort)
                if (srcIp == 0x7F000001 && dstIp == 0x7F000001 && srcPort == _relayPort)
                {
                    NatEntry nat;
                    bool found = (proto == 6) ? _tcpNat.TryGetValue(dstPort, out nat) : _udpNat.TryGetValue(dstPort, out nat);
                    if (found && nat != null)
                    {
                        packet[12] = (byte)(nat.OrigDstIp >> 24);
                        packet[13] = (byte)(nat.OrigDstIp >> 16);
                        packet[14] = (byte)(nat.OrigDstIp >> 8);
                        packet[15] = (byte)nat.OrigDstIp;

                        packet[16] = (byte)(nat.OrigSrcIp >> 24);
                        packet[17] = (byte)(nat.OrigSrcIp >> 16);
                        packet[18] = (byte)(nat.OrigSrcIp >> 8);
                        packet[19] = (byte)nat.OrigSrcIp;

                        packet[ihl] = (byte)(nat.OrigDstPort >> 8);
                        packet[ihl + 1] = (byte)nat.OrigDstPort;

                        addr.Loopback = true;
                        addr.Impostor = true;
                        WinDivertHelperCalcChecksums(packet, recvLen, ref addr, 0);
                    }
                    WinDivertSend(_netHandle, packet, recvLen, out sendLen, ref addr);
                    continue;
                }

                // Ignore unrelated loopback traffic
                if (addr.Loopback || srcIp == 0x7F000001 || dstIp == 0x7F000001)
                {
                    WinDivertSend(_netHandle, packet, recvLen, out sendLen, ref addr);
                    continue;
                }

                // 2. Outbound packets from locked PIDs -> divert onto Loopback 127.0.0.1:_relayPort
                if (addr.Outbound)
                {
                    uint ownerPid = LookupOwnerPidForPort(proto == 6, srcPort);
                    if (ownerPid != 0)
                    {
                        ZtAdapterBinding binding;
                        if (!_pidBindings.TryGetValue(ownerPid, out binding) || binding == null || !binding.IsReady)
                        {
                            continue;
                        }

                        var nat = new NatEntry
                        {
                            OrigSrcIp = srcIp,
                            OrigDstIp = dstIp,
                            OrigDstPort = dstPort,
                            Binding = binding
                        };

                        if (proto == 6) _tcpNat[srcPort] = nat;
                        else _udpNat[srcPort] = nat;

                        packet[12] = 127; packet[13] = 0; packet[14] = 0; packet[15] = 1;
                        packet[16] = 127; packet[17] = 0; packet[18] = 0; packet[19] = 1;
                        packet[ihl + 2] = (byte)(_relayPort >> 8);
                        packet[ihl + 3] = (byte)_relayPort;

                        addr.Loopback = true;
                        addr.Outbound = true;
                        addr.Impostor = true;
                        WinDivertHelperCalcChecksums(packet, recvLen, ref addr, 0);
                    }
                }

                WinDivertSend(_netHandle, packet, recvLen, out sendLen, ref addr);
            }
        }

        private static void TcpAcceptLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _tcpRelay.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(_ => HandleTcpClient(client));
                }
                catch
                {
                    if (!_running) break;
                    Thread.Sleep(10);
                }
            }
        }

        private static void HandleTcpClient(TcpClient client)
        {
            TcpClient upstream = null;
            try
            {
                client.NoDelay = true;
                ushort clientPort = (ushort)((IPEndPoint)client.Client.RemoteEndPoint).Port;
                NatEntry nat;
                if (!_tcpNat.TryGetValue(clientPort, out nat) || nat == null || nat.Binding == null || !nat.Binding.IsReady)
                {
                    client.Close();
                    return;
                }

                IPAddress dstIp = UintToIp(nat.OrigDstIp);
                upstream = new TcpClient(AddressFamily.InterNetwork);
                upstream.NoDelay = true;
                upstream.Client.Bind(new IPEndPoint(nat.Binding.LocalIpv4, 0));
                upstream.Connect(dstIp, nat.OrigDstPort);

                if (Interlocked.Exchange(ref _loggedFirstTcp, 1) == 0)
                {
                    GuardService.WriteServiceLog(string.Format("SplitTunnel TCP active: {0} -> {1}:{2} via ZT {3}",
                        nat.Binding.LocalIpv4, dstIp, nat.OrigDstPort, nat.Binding.NetworkId));
                }

                NetworkStream cStream = client.GetStream();
                NetworkStream uStream = upstream.GetStream();

                Thread t1 = new Thread(() => PumpStream(cStream, uStream)) { IsBackground = true };
                t1.Start();
                PumpStream(uStream, cStream);
            }
            catch { }
            finally
            {
                try { if (upstream != null) upstream.Close(); } catch { }
                try { client.Close(); } catch { }
            }
        }

        private static void PumpStream(Stream src, Stream dst)
        {
            byte[] buf = new byte[16384];
            try
            {
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    dst.Write(buf, 0, n);
                    dst.Flush();
                }
            }
            catch { }
            finally
            {
                try { dst.Close(); } catch { }
            }
        }

        private static void UdpRelayLoop()
        {
            while (_running)
            {
                try
                {
                    IPEndPoint clientEp = new IPEndPoint(IPAddress.Any, 0);
                    byte[] data = _udpRelay.Receive(ref clientEp);
                    ushort clientPort = (ushort)clientEp.Port;

                    NatEntry nat;
                    if (!_udpNat.TryGetValue(clientPort, out nat) || nat == null || nat.Binding == null || !nat.Binding.IsReady)
                        continue;

                    IPAddress targetIp = (nat.OrigDstPort == 53 && IsPrivateRfc1918(nat.OrigDstIp))
                        ? IPAddress.Parse("1.1.1.1")
                        : UintToIp(nat.OrigDstIp);

                    if (Interlocked.Exchange(ref _loggedFirstUdp, 1) == 0)
                    {
                        GuardService.WriteServiceLog(string.Format("SplitTunnel UDP/DNS active: {0} -> {1}:{2} via ZT {3}",
                            nat.Binding.LocalIpv4, targetIp, nat.OrigDstPort, nat.Binding.NetworkId));
                    }

                    UdpClient up = _udpUpstreamByClientPort.GetOrAdd(clientPort, _ =>
                    {
                        var u = new UdpClient(new IPEndPoint(nat.Binding.LocalIpv4, 0));
                        new Thread(() => UdpUpstreamReceiveLoop(clientPort, u)) { IsBackground = true }.Start();
                        return u;
                    });

                    up.Send(data, data.Length, new IPEndPoint(targetIp, nat.OrigDstPort));
                }
                catch
                {
                    if (!_running) break;
                    Thread.Sleep(5);
                }
            }
        }

        private static void UdpUpstreamReceiveLoop(ushort clientPort, UdpClient up)
        {
            try
            {
                up.Client.ReceiveTimeout = 15000;
                while (_running)
                {
                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp = up.Receive(ref remote);
                    _udpRelay.Send(resp, resp.Length, new IPEndPoint(IPAddress.Loopback, clientPort));
                }
            }
            catch { }
            finally
            {
                UdpClient removed;
                _udpUpstreamByClientPort.TryRemove(clientPort, out removed);
                try { up.Close(); } catch { }
            }
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try { return Path.GetFullPath(path.Trim('"')); }
            catch { return path.Trim('"'); }
        }
    }
}