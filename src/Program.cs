using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("ZT-AppLocker")]
[assembly: AssemblyDescription("ZeroTier Network Control Plane, Native WFP Kernel Kill-Switch & Live Socket Auditor")]
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")]

namespace ZTAppLocker
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length > 0)
            {
                string arg = args[0].ToLowerInvariant();
                if (arg == "--service")
                {
                    ServiceBase.Run(new GuardService());
                    return 0;
                }
                if (arg == "--install")
                {
                    if (!IsAdministrator()) { RelaunchAsAdmin("--install"); return 0; }
                    string msg;
                    bool ok = ServiceManager.InstallAndStart(out msg);
                    Console.WriteLine(msg);
                    return ok ? 0 : 1;
                }
                if (arg == "--uninstall")
                {
                    if (!IsAdministrator()) { RelaunchAsAdmin("--uninstall"); return 0; }
                    string msg;
                    bool ok = ServiceManager.UninstallAndClean(false, out msg);
                    Console.WriteLine(msg);
                    return ok ? 0 : 1;
                }
            }

            if (!IsAdministrator())
            {
                RelaunchAsAdmin("");
                return 0;
            }

            bool createdNew;
            using (Mutex singleInstance = new Mutex(true, "Global\\ZTAppLocker_v3_UI_Mutex", out createdNew))
            {
                if (!createdNew)
                {
                    MessageBox.Show("ZT-AppLocker is already running (check your System Tray).", "Already Running", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
            return 0;
        }

        public static bool IsAdministrator()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public static void RelaunchAsAdmin(string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
            }
            catch { }
        }
    }
}
