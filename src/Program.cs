using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("ZT-AppLocker")]
[assembly: AssemblyDescription("ZeroTier Network Control Plane, Native WFP Kernel Kill-Switch & Live Socket Auditor")]
[assembly: AssemblyVersion("4.0.0.0")]
[assembly: AssemblyFileVersion("4.0.0.0")]

namespace ZTAppLocker
{
    static class Program
    {
        private const int AttachParentProcess = -1;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

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

                if (IsHeadlessCommand(arg))
                {
                    EnsureConsole();
                    if (!IsAdministrator())
                    {
                        RelaunchAsAdmin(string.Join(" ", QuoteArgs(args)));
                        return 0;
                    }

                    string outPath = GetNamedArg(args, "--out");
                    TextWriter fileWriter = null;
                    if (!string.IsNullOrWhiteSpace(outPath))
                    {
                        try
                        {
                            string dir = Path.GetDirectoryName(Path.GetFullPath(outPath));
                            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                                Directory.CreateDirectory(dir);
                            fileWriter = new StreamWriter(outPath, false, System.Text.Encoding.UTF8) { AutoFlush = true };
                            Console.SetOut(new TeeTextWriter(Console.Out, fileWriter));
                            Console.SetError(new TeeTextWriter(Console.Error, fileWriter));
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine("Failed to open --out file: " + ex.Message);
                        }
                    }

                    try
                    {
                        if (arg == "--help" || arg == "-h" || arg == "/?")
                        {
                            PrintUsage();
                            return 0;
                        }
                        if (arg == "--install")
                        {
                            string msg;
                            bool ok = ServiceManager.InstallAndStart(out msg);
                            Console.WriteLine(msg);
                            return ok ? 0 : 1;
                        }
                        if (arg == "--uninstall")
                        {
                            string msg;
                            bool ok = ServiceManager.UninstallAndClean(false, out msg);
                            Console.WriteLine(msg);
                            return ok ? 0 : 1;
                        }

                        int cliCode = CliCommands.TryRun(args);
                        if (cliCode >= 0)
                            return cliCode;

                        Console.Error.WriteLine("Unknown command: " + args[0]);
                        PrintUsage();
                        return 2;
                    }
                    finally
                    {
                        if (fileWriter != null) fileWriter.Dispose();
                    }
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

        private static bool IsHeadlessCommand(string arg)
        {
            return arg == "--install"
                || arg == "--uninstall"
                || arg == "--status"
                || arg == "--lock"
                || arg == "--unlock"
                || arg == "--unlock-all"
                || arg == "--help"
                || arg == "-h"
                || arg == "/?";
        }

        private static void PrintUsage()
        {
            Console.WriteLine("ZT-AppLocker v4.0");
            Console.WriteLine("  (no args)                         Elevated GUI");
            Console.WriteLine("  --install | --uninstall           Service lifecycle");
            Console.WriteLine("  --status                          Service, ZT, policy, log tail");
            Console.WriteLine("  --lock <exe> --network <id> [--boot-guard]");
            Console.WriteLine("  --unlock <exe>");
            Console.WriteLine("  --unlock-all");
            Console.WriteLine("  --out <file>                      Also write CLI stdout/stderr to file");
            Console.WriteLine("  --service                         SCM entrypoint");
        }

        private static string GetNamedArg(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)
                    && i + 1 < args.Length
                    && !args[i + 1].StartsWith("--"))
                {
                    return args[i + 1];
                }
            }
            return null;
        }

        private sealed class TeeTextWriter : TextWriter
        {
            private readonly TextWriter _a;
            private readonly TextWriter _b;
            public TeeTextWriter(TextWriter a, TextWriter b) { _a = a; _b = b; }
            public override System.Text.Encoding Encoding { get { return _a.Encoding; } }
            public override void Write(char value) { _a.Write(value); _b.Write(value); }
            public override void Write(string value) { _a.Write(value); _b.Write(value); }
            public override void WriteLine(string value) { _a.WriteLine(value); _b.WriteLine(value); }
            public override void Flush() { _a.Flush(); _b.Flush(); }
        }

        private static void EnsureConsole()
        {
            if (!AttachConsole(AttachParentProcess))
                AllocConsole();

            try
            {
                var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(stdout);
                var stderr = new StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
                Console.SetError(stderr);
            }
            catch { }
        }

        private static string[] QuoteArgs(string[] args)
        {
            string[] quoted = new string[args.Length];
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i] ?? "";
                if (a.IndexOf(' ') >= 0 && !a.StartsWith("\""))
                    quoted[i] = "\"" + a + "\"";
                else
                    quoted[i] = a;
            }
            return quoted;
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
