using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;

namespace ZTAppLocker
{
    public static class EmbeddedZtManager
    {
        public const string TunnelServiceName = "ZTAppLockerTunnel";
        public const int ControlPort = 9994;
        public const string OfficialMsiUrl = "https://download.zerotier.com/dist/ZeroTier%20One.msi";

        public static string CoreDir
        {
            get { return Path.Combine(ServiceManager.InstallDir, "zt-core"); }
        }

        public static string DataDir
        {
            get { return Path.Combine(PolicyStore.DataDir, "zt-data"); }
        }

        public static string DaemonExePath
        {
            get { return Path.Combine(CoreDir, "zerotier-one_x64.exe"); }
        }

        public static string TapInfPath
        {
            get { return Path.Combine(CoreDir, "zttap300.inf"); }
        }

        public static bool IsPrivateTunnelInstalled()
        {
            try
            {
                using (ServiceController sc = new ServiceController(TunnelServiceName))
                {
                    var s = sc.Status;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static string GetPrivateTunnelStatus()
        {
            try
            {
                using (ServiceController sc = new ServiceController(TunnelServiceName))
                {
                    return sc.Status.ToString();
                }
            }
            catch
            {
                return "NotInstalled";
            }
        }

        public static void ExtractEmbeddedPayload(bool overwriteExisting)
        {
            if (!Directory.Exists(CoreDir))
                Directory.CreateDirectory(CoreDir);
            if (!Directory.Exists(DataDir))
                Directory.CreateDirectory(DataDir);

            Assembly asm = Assembly.GetExecutingAssembly();
            string[] resNames = asm.GetManifestResourceNames();

            string[] expectedFiles = { "zerotier-one_x64.exe", "zttap300.sys", "zttap300.inf", "zttap300.cat" };
            foreach (string fileName in expectedFiles)
            {
                string destPath = Path.Combine(CoreDir, fileName);
                if (!overwriteExisting && File.Exists(destPath))
                    continue;

                string resMatch = resNames.FirstOrDefault(r =>
                    r.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r, fileName, StringComparison.OrdinalIgnoreCase));

                if (resMatch == null)
                    throw new InvalidOperationException("Embedded resource missing from binary: " + fileName);

                using (Stream s = asm.GetManifestResourceStream(resMatch))
                using (FileStream fs = File.Create(destPath))
                {
                    s.CopyTo(fs);
                }
            }
        }

        public static void InstallTapDriver()
        {
            if (!File.Exists(TapInfPath))
                throw new FileNotFoundException("TAP driver INF not found.", TapInfPath);

            // pnputil.exe is built into Windows System32 on all Win10/11 x64 systems
            RunProcess("pnputil.exe", string.Format("/add-driver \"{0}\" /install", TapInfPath), 30000);
        }

        public static void ProvisionAndStartPrivateTunnel(bool overwriteBinaries, out string statusDetail)
        {
            try
            {
                // Suppress any external ZeroTier tray UI if present on the machine
                SuppressExternalZeroTierUi();

                ExtractEmbeddedPayload(overwriteBinaries);
                InstallTapDriver();

                string binPath = string.Format("\"{0}\" -C -p{1} \"{2}\"", DaemonExePath, ControlPort, DataDir);
                string escapedBinPath = binPath.Replace("\"", "\\\"");

                if (!IsPrivateTunnelInstalled())
                {
                    RunProcess("sc.exe", string.Format("create {0} binPath= \"{1}\" start= auto DisplayName= \"ZT-AppLocker Embedded ZeroTier Core\"",
                        TunnelServiceName, escapedBinPath), 15000);
                    RunProcess("sc.exe", string.Format("description {0} \"Self-contained headless ZeroTier One transport engine managed exclusively by ZT-AppLocker.\"",
                        TunnelServiceName), 10000);
                    RunProcess("sc.exe", string.Format("failure {0} reset= 86400 actions= restart/3000/restart/3000/restart/3000",
                        TunnelServiceName), 10000);
                }
                else
                {
                    RunProcess("sc.exe", string.Format("config {0} binPath= \"{1}\" start= auto",
                        TunnelServiceName, escapedBinPath), 15000);
                }

                using (ServiceController sc = new ServiceController(TunnelServiceName))
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                    }
                }

                // Wait briefly for authtoken.secret generation and lock down ACLs to SYSTEM + Admins
                for (int i = 0; i < 20; i++)
                {
                    string tokenPath = Path.Combine(DataDir, "authtoken.secret");
                    if (File.Exists(tokenPath))
                    {
                        HardenDataDirectoryAcl();
                        break;
                    }
                    Thread.Sleep(250);
                }

                statusDetail = "Embedded ZeroTier Core (ZTAppLockerTunnel) is Running on port " + ControlPort + ".";
            }
            catch (Exception ex)
            {
                statusDetail = "Embedded ZeroTier setup error: " + ex.Message;
                throw;
            }
        }

        public static void StopAndRemovePrivateTunnel(bool removeTapDriver)
        {
            try
            {
                using (ServiceController sc = new ServiceController(TunnelServiceName))
                {
                    if (sc.Status != ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    }
                }
            }
            catch { }

            RunProcess("sc.exe", "delete " + TunnelServiceName, 10000);

            if (removeTapDriver && File.Exists(TapInfPath))
            {
                try { RunProcess("pnputil.exe", string.Format("/delete-driver \"{0}\" /uninstall /force", TapInfPath), 20000); }
                catch { }
            }
        }

        public static void SuppressExternalZeroTierUi()
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName("zerotier_desktop_ui"))
                {
                    try { p.Kill(); } catch { }
                }
            }
            catch { }
        }

        public static void HardenDataDirectoryAcl()
        {
            try
            {
                if (!Directory.Exists(DataDir)) return;
                DirectorySecurity ds = new DirectorySecurity();
                ds.SetAccessRuleProtection(true, false);

                SecurityIdentifier sysSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

                ds.AddAccessRule(new FileSystemAccessRule(sysSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

                Directory.SetAccessControl(DataDir, ds);
            }
            catch { }
        }

        public static string UpdateEmbeddedCoreFromOfficialRelease()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)3072;

            string tempRoot = Path.Combine(Path.GetTempPath(), "ZTAppLocker_CoreUpdate_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tempRoot);
            string msiPath = Path.Combine(tempRoot, "ZeroTierOne.msi");
            string extractDir = Path.Combine(tempRoot, "extracted");

            try
            {
                using (WebClient wc = new WebClient())
                {
                    wc.Headers["User-Agent"] = "ZT-AppLocker-Updater/4.0";
                    wc.DownloadFile(OfficialMsiUrl, msiPath);
                }

                // Administrative MSI unpack (silent, no installation onto host OS)
                RunProcess("msiexec.exe", string.Format("/a \"{0}\" /qn TARGETDIR=\"{1}\"", msiPath, extractDir), 60000);

                string newExe = Directory.GetFiles(extractDir, "zerotier-one_x64.exe", SearchOption.AllDirectories).FirstOrDefault();
                string newSys = Directory.GetFiles(extractDir, "zttap300.sys", SearchOption.AllDirectories).FirstOrDefault();
                string newInf = Directory.GetFiles(extractDir, "zttap300.inf", SearchOption.AllDirectories).FirstOrDefault();
                string newCat = Directory.GetFiles(extractDir, "zttap300.cat", SearchOption.AllDirectories).FirstOrDefault();

                if (newExe == null || newSys == null || newInf == null || newCat == null)
                    throw new InvalidOperationException("Downloaded MSI did not contain expected ZeroTier x64 core/TAP files.");

                string newVer = FileVersionInfo.GetVersionInfo(newExe).FileVersion ?? "Updated";

                // Stop private tunnel service cleanly while preserving zt-data identity & networks
                try
                {
                    using (ServiceController sc = new ServiceController(TunnelServiceName))
                    {
                        if (sc.Status != ServiceControllerStatus.Stopped)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                        }
                    }
                }
                catch { }

                if (!Directory.Exists(CoreDir)) Directory.CreateDirectory(CoreDir);
                File.Copy(newExe, Path.Combine(CoreDir, "zerotier-one_x64.exe"), true);
                File.Copy(newSys, Path.Combine(CoreDir, "zttap300.sys"), true);
                File.Copy(newInf, Path.Combine(CoreDir, "zttap300.inf"), true);
                File.Copy(newCat, Path.Combine(CoreDir, "zttap300.cat"), true);

                InstallTapDriver();

                using (ServiceController sc = new ServiceController(TunnelServiceName))
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                }

                return "Embedded ZeroTier Core updated to v" + newVer + " and restarted cleanly (Node ID & networks preserved).";
            }
            finally
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }

        private static void RunProcess(string fileName, string args, int timeoutMs)
        {
            ProcessStartInfo psi = new ProcessStartInfo(fileName, args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit(timeoutMs);
            }
        }
    }
}

