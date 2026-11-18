using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace ZTAppLocker
{
    public static class ServiceManager
    {
        public const string InstallDir = @"C:\Program Files\ZT-AppLocker";
        public static string InstalledExePath { get { return Path.Combine(InstallDir, "ZT-AppLocker.exe"); } }
        public static string LogFilePath { get { return Path.Combine(InstallDir, "ZTAppLockerGuard.log"); } }

        private static string PublicDesktopShortcut
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "ZT-AppLocker.lnk"); }
        }
        private static string StartMenuShortcut
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "ZT-AppLocker.lnk"); }
        }

        public static string GetServiceStatus()
        {
            try
            {
                using (ServiceController sc = new ServiceController(GuardService.GuardServiceName))
                {
                    return sc.Status.ToString();
                }
            }
            catch
            {
                return "NotInstalled";
            }
        }

        public static bool InstallAndStart(out string message)
        {
            try
            {
                if (!Directory.Exists(InstallDir))
                    Directory.CreateDirectory(InstallDir);

                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                if (!string.Equals(currentExe, InstalledExePath, StringComparison.OrdinalIgnoreCase))
                {
                    if (GetServiceStatus() != "NotInstalled")
                    {
                        StopServiceIfRunning();
                        Thread.Sleep(800);
                    }
                    File.Copy(currentExe, InstalledExePath, true);
                }

                string ztDetail;
                EmbeddedZtManager.ProvisionAndStartPrivateTunnel(false, out ztDetail);

                string binPath = string.Format("\"{0}\" --service", InstalledExePath);

                if (GetServiceStatus() == "NotInstalled")
                {
                    RunSc(string.Format("create {0} binPath= \"{1}\" start= auto DisplayName= \"ZT-AppLocker Kernel Kill-Switch Guard\"",
                        GuardService.GuardServiceName, binPath.Replace("\"", "\\\"")));
                    RunSc(string.Format("description {0} \"Manages embedded ZeroTier tunnel and enforces native WFP per-application kill-switches.\"",
                        GuardService.GuardServiceName));
                    RunSc(string.Format("failure {0} reset= 86400 actions= restart/5000/restart/5000/restart/5000",
                        GuardService.GuardServiceName));
                }
                else
                {
                    RunSc(string.Format("config {0} binPath= \"{1}\" start= auto",
                        GuardService.GuardServiceName, binPath.Replace("\"", "\\\"")));
                }

                using (ServiceController sc = new ServiceController(GuardService.GuardServiceName))
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                    }
                }

                CreateShortcut(PublicDesktopShortcut, InstalledExePath, "ZT-AppLocker v4.0 - Self-Contained ZeroTier & WFP Kill-Switch");
                CreateShortcut(StartMenuShortcut, InstalledExePath, "ZT-AppLocker v4.0 - Self-Contained ZeroTier & WFP Kill-Switch");

                message = "ZT-AppLocker v4.0 installed: Embedded ZeroTier Core + TAP Driver + Kernel WFP Guard are active.";
                return true;
            }
            catch (Exception ex)
            {
                message = "Service installation failed: " + ex.Message;
                return false;
            }
        }

        public static bool UninstallAndClean(bool purgeWfpFilters, out string message)
        {
            try
            {
                StopServiceIfRunning();
                EmbeddedZtManager.StopAndRemovePrivateTunnel(purgeWfpFilters);
                RunSc("delete " + GuardService.GuardServiceName);

                if (purgeWfpFilters)
                {
                    WfpEngine.PurgeAllWfpFilters();
                    PolicyStore.ClearAllApps();
                }

                try { if (File.Exists(PublicDesktopShortcut)) File.Delete(PublicDesktopShortcut); } catch { }
                try { if (File.Exists(StartMenuShortcut)) File.Delete(StartMenuShortcut); } catch { }

                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                if (!string.Equals(currentExe, InstalledExePath, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        if (Directory.Exists(InstallDir))
                            Directory.Delete(InstallDir, true);
                    }
                    catch { }
                }

                message = purgeWfpFilters
                    ? "Guard service, embedded ZeroTier tunnel, TAP driver, and WFP filters purged cleanly."
                    : "Guard service and embedded ZeroTier tunnel uninstalled cleanly (WFP filters preserved).";
                return true;
            }
            catch (Exception ex)
            {
                message = "Uninstall error: " + ex.Message;
                return false;
            }
        }

        private static void CreateShortcut(string shortcutPath, string targetPath, string description)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                dynamic shell = Activator.CreateInstance(shellType);
                dynamic shortcut = shell.CreateShortcut(shortcutPath);
                shortcut.TargetPath = targetPath;
                shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath);
                shortcut.Description = description;
                shortcut.IconLocation = targetPath + ",0";
                shortcut.Save();
            }
            catch { }
        }

        private static void StopServiceIfRunning()
        {
            try
            {
                using (ServiceController sc = new ServiceController(GuardService.GuardServiceName))
                {
                    if (sc.Status != ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    }
                }
            }
            catch { }
        }

        private static void RunSc(string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo("sc.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit(10000);
            }
        }
    }
}
