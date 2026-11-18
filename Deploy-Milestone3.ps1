$ErrorActionPreference = "Stop"

$RepoDir = "C:\scripts\ZT-AppLocker"
if (-not (Test-Path "$RepoDir\.git")) {
    throw "Git repository not found at $RepoDir. Verify the directory exists."
}

New-Item -Path "$RepoDir\src" -ItemType Directory -Force | Out-Null
Set-Location $RepoDir

# ---------------------------------------------------------------------------
# 1. Write src\ServiceManager.cs
# ---------------------------------------------------------------------------
Write-Host "[1/5] Writing src\ServiceManager.cs and src\Program.cs..." -ForegroundColor Cyan

$ServiceManagerCode = @'
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

                string binPath = string.Format("\"{0}\" --service", InstalledExePath);

                if (GetServiceStatus() == "NotInstalled")
                {
                    RunSc(string.Format("create {0} binPath= \"{1}\" start= auto DisplayName= \"ZT-AppLocker Kernel Kill-Switch Guard\"",
                        GuardService.GuardServiceName, binPath.Replace("\"", "\\\"")));
                    RunSc(string.Format("description {0} \"Manages ZeroTier network binding and enforces native WFP per-application kill-switches.\"",
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

                CreateShortcut(PublicDesktopShortcut, InstalledExePath, "ZT-AppLocker v3.0 - ZeroTier Client & WFP Kill-Switch");
                CreateShortcut(StartMenuShortcut, InstalledExePath, "ZT-AppLocker v3.0 - ZeroTier Client & WFP Kill-Switch");

                message = "ZTAppLockerGuard v3.0 installed to C:\\Program Files\\ZT-AppLocker, started, and shortcuts updated.";
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
                    ? "Windows Service, shortcuts, and all WFP kernel filters purged cleanly."
                    : "Windows Service and shortcuts uninstalled cleanly (WFP filters preserved).";
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
'@

Set-Content -Path "$RepoDir\src\ServiceManager.cs" -Value $ServiceManagerCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 2. Write src\Program.cs
# ---------------------------------------------------------------------------
$ProgramCode = @'
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
'@

Set-Content -Path "$RepoDir\src\Program.cs" -Value $ProgramCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 3. Write src\MainForm.cs (Unified ZeroTier Client + WFP Kill-Switch Console)
# ---------------------------------------------------------------------------
Write-Host "[2/5] Writing src\MainForm.cs..." -ForegroundColor Cyan

$MainFormCode = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace ZTAppLocker
{
    public class ActiveLockDisplayItem
    {
        public AppLockPolicyEntry Policy { get; set; }
        public string NetworkLabel { get; set; }
        public string StatusTag { get; set; }

        public override string ToString()
        {
            string bootTag = Policy.BootTimeGuard ? "[BOOT-GUARD]" : "[RUNTIME]";
            return string.Format("{0} {1} {2}  -->  ZT [{3}]  ({4})",
                StatusTag,
                bootTag,
                Path.GetFileName(Policy.ExePath),
                NetworkLabel,
                Policy.ExePath);
        }
    }

    public class ProcessCandidate
    {
        public string ExeName { get; set; }
        public string ExePath { get; set; }
        public override string ToString()
        {
            return string.Format("{0}  -  {1}", ExeName, ExePath);
        }
    }

    public class MainForm : Form
    {
        private Panel pnlTopStatus, pnlZeroTier, pnlHardening;
        private Label lblNodeStatus, lblDaemonDetail, lblSvcStatus, lblStatus;
        private Button btnStartZtDaemon, btnInstallSvc, btnUninstallSvc, btnViewLog;
        private TextBox txtNetworkId;
        private ComboBox cmbNetworks;
        private CheckBox chkAllowDefault, chkAllowDns, chkStrictDnsLock, chkBootTimeGuard, chkMinimizeToTray;
        private ListBox lstQueue, lstActive;

        private NotifyIcon _trayIcon;
        private ToolStripMenuItem _trayNodeHeader;
        private ToolStripMenuItem _trayNetDetail;
        private System.Windows.Forms.Timer _refreshTimer;
        private bool _allowRealClose = false;
        private bool _suppressUiEvents = false;
        private string _lastStateHash = "";

        private static readonly HashSet<string> ProtectedBinaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "zerotier-one_x64.exe", "zerotier-one_x86.exe", "zerotier_desktop_ui.exe",
            "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe",
            "smss.exe", "system", "explorer.exe", "dwm.exe", "zt-applocker.exe"
        };

        public MainForm()
        {
            Text = "ZT-AppLocker v3.0 | ZeroTier Control Plane & Native WFP Kernel Kill-Switch";
            Icon appIcon = null;
            try { appIcon = Icon.ExtractAssociatedIcon(Process.GetCurrentProcess().MainModule.FileName); } catch { }
            if (appIcon != null) Icon = appIcon;

            Size = new Size(760, 835);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            Font = new Font("Segoe UI", 9.5f);

            // System Tray Setup
            ContextMenuStrip trayMenu = new ContextMenuStrip();
            _trayNodeHeader = new ToolStripMenuItem("ZeroTier Node: Checking...") { Enabled = false, Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
            _trayNetDetail = new ToolStripMenuItem("Active Tunnel: --") { Enabled = false };
            trayMenu.Items.Add(_trayNodeHeader);
            trayMenu.Items.Add(_trayNetDetail);
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("Open ZT-AppLocker Console", null, (s, e) => RestoreFromTray());
            trayMenu.Items.Add("Reconcile WFP Filters Now", null, (s, e) => { GuardService.ReconcilePolicyWithWfp(false); RefreshAll(true); });
            trayMenu.Items.Add("Audit Live Sockets", null, (s, e) => { RestoreFromTray(); AuditSockets_Click(s, e); });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("Exit Console", null, (s, e) => { _allowRealClose = true; Application.Exit(); });

            _trayIcon = new NotifyIcon
            {
                Icon = appIcon ?? SystemIcons.Shield,
                Text = "ZT-AppLocker v3.0: Initializing...",
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            _trayIcon.DoubleClick += (s, e) => RestoreFromTray();

            // 1. Top Banner: ZeroTier Core + Guard Service Status
            pnlTopStatus = new Panel { Location = new Point(16, 12), Size = new Size(712, 56), BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(240, 246, 252) };
            lblNodeStatus = new Label { Location = new Point(10, 6), Size = new Size(390, 20), Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), UseMnemonic = false };
            lblDaemonDetail = new Label { Location = new Point(10, 28), Size = new Size(390, 20), Font = new Font("Segoe UI", 8.5f), ForeColor = Color.DimGray, UseMnemonic = false };

            btnStartZtDaemon = new Button { Text = "Start ZT Core", Location = new Point(402, 12), Size = new Size(92, 30), Visible = false };
            btnInstallSvc = new Button { Text = "Install Guard", Location = new Point(402, 12), Size = new Size(100, 30) };
            btnUninstallSvc = new Button { Text = "Uninstall", Location = new Point(508, 12), Size = new Size(88, 30) };
            btnViewLog = new Button { Text = "Guard Log", Location = new Point(602, 12), Size = new Size(98, 30) };

            btnStartZtDaemon.Click += (s, e) =>
            {
                string msg;
                bool ok = ZeroTierApi.EnsureDaemonServiceRunning(out msg);
                MessageBox.Show(msg, "ZeroTier Core Service", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                RefreshAll(true);
            };
            btnInstallSvc.Click += (s, e) =>
            {
                string msg;
                bool ok = ServiceManager.InstallAndStart(out msg);
                MessageBox.Show(msg, "Guard Service Installer", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Information);
                RefreshAll(true);
            };
            btnUninstallSvc.Click += (s, e) =>
            {
                var res = MessageBox.Show("Uninstall the ZTAppLockerGuard service and shortcuts?\n\nClick YES to also purge all WFP kernel filters, or NO to keep existing WFP locks.",
                    "Uninstall Guard Service", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (res == DialogResult.Cancel) return;
                string msg;
                ServiceManager.UninstallAndClean(res == DialogResult.Yes, out msg);
                MessageBox.Show(msg, "Uninstall Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshAll(true);
            };
            btnViewLog.Click += (s, e) => ShowLogViewer();

            pnlTopStatus.Controls.AddRange(new Control[] { lblNodeStatus, lblDaemonDetail, btnStartZtDaemon, btnInstallSvc, btnUninstallSvc, btnViewLog });
            Controls.Add(pnlTopStatus);

            // 2. Section 1: Embedded ZeroTier Network Control Plane
            pnlZeroTier = new Panel { Location = new Point(16, 76), Size = new Size(712, 114), BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(248, 250, 252) };
            pnlZeroTier.Controls.Add(new Label
            {
                Text = "1. ZeroTier Network Control Plane (Join, Leave & Configure Exit Tunnel):",
                Location = new Point(10, 8),
                Size = new Size(690, 20),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                UseMnemonic = false
            });

            pnlZeroTier.Controls.Add(new Label { Text = "16-Digit Network ID:", Location = new Point(10, 38), Size = new Size(128, 22), UseMnemonic = false });
            txtNetworkId = new TextBox { Location = new Point(140, 35), Size = new Size(175, 25), MaxLength = 16, Font = new Font("Consolas", 10f) };
            Button btnJoinNet = new Button { Text = "Join Network", Location = new Point(322, 34), Size = new Size(105, 27), BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            Button btnLeaveNet = new Button { Text = "Leave Selected", Location = new Point(434, 34), Size = new Size(110, 27) };
            Button btnRefreshNet = new Button { Text = "Refresh", Location = new Point(550, 34), Size = new Size(74, 27) };

            btnJoinNet.Click += JoinNetwork_Click;
            btnLeaveNet.Click += LeaveNetwork_Click;
            btnRefreshNet.Click += (s, e) => RefreshAll(true);

            pnlZeroTier.Controls.Add(new Label { Text = "Active Network:", Location = new Point(10, 74), Size = new Size(102, 22), UseMnemonic = false });
            cmbNetworks = new ComboBox { Location = new Point(115, 71), Size = new Size(365, 28), DropDownStyle = ComboBoxStyle.DropDownList };
            cmbNetworks.SelectedIndexChanged += (s, e) => SyncNetworkCheckboxesFromSelection();

            chkAllowDefault = new CheckBox { Text = "Exit Tunnel (allowDefault)", Location = new Point(490, 66), Size = new Size(210, 20), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), ForeColor = Color.FromArgb(16, 110, 16) };
            chkAllowDns = new CheckBox { Text = "Managed ZT DNS (allowDNS)", Location = new Point(490, 87), Size = new Size(210, 20), Font = new Font("Segoe UI", 8.5f) };

            chkAllowDefault.CheckedChanged += (s, e) => UpdateSelectedNetworkFlags();
            chkAllowDns.CheckedChanged += (s, e) => UpdateSelectedNetworkFlags();

            pnlZeroTier.Controls.AddRange(new Control[] { txtNetworkId, btnJoinNet, btnLeaveNet, btnRefreshNet, cmbNetworks, chkAllowDefault, chkAllowDns });
            Controls.Add(pnlZeroTier);

            // 3. Section 2: Global Kernel Hardening Bar
            pnlHardening = new Panel { Location = new Point(16, 198), Size = new Size(712, 42), BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(255, 250, 235) };
            chkBootTimeGuard = new CheckBox
            {
                Text = "Boot-Time WFP Leak Guard (blocks apps before Windows boots)",
                Location = new Point(10, 10),
                Size = new Size(375, 22),
                Checked = true,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
            };
            chkStrictDnsLock = new CheckBox
            {
                Text = "Strict ZeroTier DNS Lock (blocks Port 53 outside ZT)",
                Location = new Point(392, 10),
                Size = new Size(312, 22),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.DarkRed
            };
            chkStrictDnsLock.CheckedChanged += StrictDnsLock_CheckedChanged;

            pnlHardening.Controls.AddRange(new Control[] { chkBootTimeGuard, chkStrictDnsLock });
            Controls.Add(pnlHardening);

            // 4. Section 3: Queue Applications to Lock
            Controls.Add(new Label
            {
                Text = "2. Applications to Lock to Selected ZeroTier Network:",
                Location = new Point(16, 250),
                Size = new Size(712, 22),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                UseMnemonic = false
            });

            lstQueue = new ListBox { Location = new Point(16, 275), Size = new Size(560, 132), HorizontalScrollbar = true };

            Button btnBrowse = new Button { Text = "Browse .EXE...", Location = new Point(586, 275), Size = new Size(142, 30) };
            Button btnFolder = new Button { Text = "Lock App Folder...", Location = new Point(586, 309), Size = new Size(142, 30) };
            Button btnRunning = new Button { Text = "Running Apps...", Location = new Point(586, 343), Size = new Size(142, 30) };
            Button btnRemoveQ = new Button { Text = "Remove Item", Location = new Point(586, 377), Size = new Size(142, 30) };

            btnBrowse.Click += BrowseExe_Click;
            btnFolder.Click += BrowseFolder_Click;
            btnRunning.Click += RunningApps_Click;
            btnRemoveQ.Click += (s, e) => { if (lstQueue.SelectedIndex >= 0) lstQueue.Items.RemoveAt(lstQueue.SelectedIndex); };

            Controls.AddRange(new Control[] { lstQueue, btnBrowse, btnFolder, btnRunning, btnRemoveQ });

            Button btnApply = new Button
            {
                Text = "Apply Native WFP Kernel Kill-Switch & Sever Non-ZT Sockets",
                Location = new Point(16, 416),
                Size = new Size(712, 38),
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };
            btnApply.Click += ApplyWfpLocks_Click;
            Controls.Add(btnApply);

            // 5. Section 4: Active WFP Kernel Locks & Live Socket Auditor
            Controls.Add(new Label
            {
                Text = "3. Active WFP Kernel Locks, Per-App Network Bindings & Live Socket Auditor:",
                Location = new Point(16, 466),
                Size = new Size(712, 22),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                UseMnemonic = false
            });

            lstActive = new ListBox { Location = new Point(16, 491), Size = new Size(560, 246), HorizontalScrollbar = true };

            Button btnAuditSockets = new Button
            {
                Text = "Audit Live Sockets",
                Location = new Point(586, 491),
                Size = new Size(142, 34),
                BackColor = Color.FromArgb(16, 124, 16),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
            };
            Button btnSeverSockets = new Button { Text = "Sever ISP Sockets", Location = new Point(586, 531), Size = new Size(142, 30) };
            Button btnReconcile = new Button { Text = "Reconcile All", Location = new Point(586, 565), Size = new Size(142, 30) };
            Button btnUnlockSel = new Button { Text = "Unlock Selected", Location = new Point(586, 599), Size = new Size(142, 30) };
            Button btnUnlockAll = new Button { Text = "Purge All Locks", Location = new Point(586, 633), Size = new Size(142, 30) };
            Button btnExport = new Button { Text = "Export Policy...", Location = new Point(586, 673), Size = new Size(142, 30) };
            Button btnImport = new Button { Text = "Import Policy...", Location = new Point(586, 707), Size = new Size(142, 30) };

            btnAuditSockets.Click += AuditSockets_Click;
            btnSeverSockets.Click += SeverSockets_Click;
            btnReconcile.Click += (s, e) => { GuardService.ReconcilePolicyWithWfp(false); RefreshAll(true); lblStatus.Text = "Reconciled all WFP kernel filters with active ZeroTier interfaces."; };
            btnUnlockSel.Click += UnlockSelected_Click;
            btnUnlockAll.Click += UnlockAll_Click;
            btnExport.Click += ExportPolicy_Click;
            btnImport.Click += ImportPolicy_Click;

            Controls.AddRange(new Control[] { lstActive, btnAuditSockets, btnSeverSockets, btnReconcile, btnUnlockSel, btnUnlockAll, btnExport, btnImport });

            // Bottom Status & Tray Toggle
            lblStatus = new Label { Text = "Native WFP kernel enforcement ready.", Location = new Point(16, 752), Size = new Size(535, 22), ForeColor = Color.DimGray, UseMnemonic = false };
            chkMinimizeToTray = new CheckBox
            {
                Text = "Minimize to System Tray",
                Location = new Point(558, 750),
                Size = new Size(170, 24),
                Checked = true,
                Font = new Font("Segoe UI", 8.5f)
            };
            chkMinimizeToTray.CheckedChanged += (s, e) =>
            {
                _trayIcon.Visible = chkMinimizeToTray.Checked || WindowState == FormWindowState.Minimized;
            };
            Controls.AddRange(new Control[] { lblStatus, chkMinimizeToTray });

            Resize += (s, e) =>
            {
                if (WindowState == FormWindowState.Minimized && chkMinimizeToTray.Checked)
                {
                    _trayIcon.Visible = true;
                    Hide();
                }
            };

            FormClosing += (s, e) =>
            {
                if (!_allowRealClose && chkMinimizeToTray.Checked && e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    WindowState = FormWindowState.Minimized;
                    _trayIcon.Visible = true;
                    Hide();
                }
            };

            NetworkChange.NetworkAvailabilityChanged += (s, e) =>
            {
                if (!IsDisposed && IsHandleCreated)
                    BeginInvoke((Action)(() => { GuardService.ReconcilePolicyWithWfp(false); RefreshAll(true); }));
            };

            _refreshTimer = new System.Windows.Forms.Timer { Interval = 2500 };
            _refreshTimer.Tick += (s, e) => RefreshAll(false);
            _refreshTimer.Start();

            FormClosed += (s, e) =>
            {
                _refreshTimer.Stop();
                if (_trayIcon != null) { _trayIcon.Visible = false; _trayIcon.Dispose(); }
            };

            RefreshAll(true);
        }

        private void JoinNetwork_Click(object sender, EventArgs e)
        {
            string nwid = txtNetworkId.Text.Trim();
            if (nwid.Length != 16)
            {
                MessageBox.Show("Enter a valid 16-character ZeroTier Network ID.", "Invalid Network ID", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                ZeroTierApi.JoinOrConfigureNetwork(nwid, null, true, false, null);
                txtNetworkId.Clear();
                lblStatus.Text = "Joined ZeroTier network " + nwid + ". Authorizing / assigning IP...";
                RefreshAll(true);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to join network: " + ex.Message, "ZeroTier API Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void LeaveNetwork_Click(object sender, EventArgs e)
        {
            ZtNetworkInfo net = cmbNetworks.SelectedItem as ZtNetworkInfo;
            if (net == null) return;

            if (MessageBox.Show(string.Format("Leave ZeroTier network {0} ({1})?", net.Id, net.Name),
                "Confirm Leave Network", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                if (ZeroTierApi.LeaveNetwork(net.Id))
                {
                    lblStatus.Text = "Left ZeroTier network " + net.Id;
                    RefreshAll(true);
                }
            }
        }

        private void SyncNetworkCheckboxesFromSelection()
        {
            ZtNetworkInfo net = cmbNetworks.SelectedItem as ZtNetworkInfo;
            _suppressUiEvents = true;
            try
            {
                chkAllowDefault.Enabled = (net != null);
                chkAllowDns.Enabled = (net != null);
                chkAllowDefault.Checked = (net != null && net.AllowDefault);
                chkAllowDns.Checked = (net != null && net.AllowDNS);
            }
            finally
            {
                _suppressUiEvents = false;
            }
        }

        private void UpdateSelectedNetworkFlags()
        {
            if (_suppressUiEvents) return;
            ZtNetworkInfo net = cmbNetworks.SelectedItem as ZtNetworkInfo;
            if (net == null) return;

            try
            {
                ZeroTierApi.JoinOrConfigureNetwork(net.Id, chkAllowDefault.Checked, null, null, chkAllowDns.Checked);
                lblStatus.Text = string.Format("Updated [{0}]: allowDefault={1}, allowDNS={2}",
                    net.Id, chkAllowDefault.Checked, chkAllowDns.Checked);
                RefreshAll(true);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to update network flags: " + ex.Message, "ZeroTier API Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StrictDnsLock_CheckedChanged(object sender, EventArgs e)
        {
            if (_suppressUiEvents) return;
            ZtNetworkInfo net = cmbNetworks.SelectedItem as ZtNetworkInfo;

            if (chkStrictDnsLock.Checked)
            {
                if (net == null)
                {
                    _suppressUiEvents = true;
                    chkStrictDnsLock.Checked = false;
                    _suppressUiEvents = false;
                    MessageBox.Show("Select an active ZeroTier network first before enabling Strict DNS Lock.", "No ZeroTier Network", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string guid = ZeroTierApi.ResolveAdapterGuidForNetwork(net);
                if (string.IsNullOrWhiteSpace(guid))
                {
                    _suppressUiEvents = true;
                    chkStrictDnsLock.Checked = false;
                    _suppressUiEvents = false;
                    MessageBox.Show("ZeroTier virtual adapter is not online yet. Wait for IP assignment first.", "Adapter Offline", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                try
                {
                    WfpEngine.SetStrictDnsLock(true, guid);
                    PolicyStore.SetStrictDns(true, net.Id);
                    lblStatus.Text = "Strict ZeroTier DNS Lock ENABLED (Port 53 blocked outside " + net.Id + ").";
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Failed to apply Strict DNS Lock: " + ex.Message, "WFP Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                WfpEngine.SetStrictDnsLock(false, null);
                PolicyStore.SetStrictDns(false, null);
                lblStatus.Text = "Strict ZeroTier DNS Lock disabled.";
            }
        }

        private void ApplyWfpLocks_Click(object sender, EventArgs e)
        {
            ZtNetworkInfo net = cmbNetworks.SelectedItem as ZtNetworkInfo;
            if (net == null || lstQueue.Items.Count == 0)
            {
                MessageBox.Show("Select an active ZeroTier network in Section 1 and add at least one application in Section 2.", "Missing Input", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string adapterGuid = ZeroTierApi.ResolveAdapterGuidForNetwork(net);
            if (string.IsNullOrWhiteSpace(adapterGuid))
            {
                MessageBox.Show("Could not resolve a virtual network adapter for ZeroTier network " + net.Id + ". Verify the network status is OK.", "Adapter Not Ready", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            int lockedCount = 0;
            int severedTotal = 0;
            bool bootGuard = chkBootTimeGuard.Checked;

            foreach (object item in lstQueue.Items)
            {
                string exePath = item.ToString();
                if (!File.Exists(exePath)) continue;

                try
                {
                    WfpEngine.ApplyAppLock(exePath, adapterGuid, bootGuard);
                    PolicyStore.UpsertAppLock(exePath, net.Id, bootGuard);
                    severedTotal += SocketManager.SeverNonCompliantSockets(exePath, adapterGuid);
                    lockedCount++;
                }
                catch (Exception ex)
                {
                    MessageBox.Show("WFP lock failed for " + Path.GetFileName(exePath) + ":\n" + ex.Message, "WFP Kernel Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            lstQueue.Items.Clear();
            RefreshAll(true);
            lblStatus.Text = string.Format("Locked {0} app(s) in WFP kernel to [{1}] (severed {2} existing non-ZT socket(s)).",
                lockedCount, net.Id, severedTotal);
        }

        private void UnlockSelected_Click(object sender, EventArgs e)
        {
            ActiveLockDisplayItem item = lstActive.SelectedItem as ActiveLockDisplayItem;
            if (item == null) return;

            WfpEngine.RemoveAppLock(item.Policy.ExePath);
            PolicyStore.RemoveAppLock(item.Policy.ExePath);
            RefreshAll(true);
            lblStatus.Text = "Removed WFP kernel filters for " + Path.GetFileName(item.Policy.ExePath);
        }

        private void UnlockAll_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("Purge ALL ZT-AppLocker WFP kernel filters and restore unrestricted network access?",
                "Confirm Purge All", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                WfpEngine.PurgeAllWfpFilters();
                PolicyStore.ClearAllApps();
                RefreshAll(true);
                lblStatus.Text = "Purged all WFP kernel filters cleanly.";
            }
        }

        private void SeverSockets_Click(object sender, EventArgs e)
        {
            AppLockerPolicy pol = PolicyStore.Load();
            List<ZtNetworkInfo> nets = ZeroTierApi.GetNetworks();
            int totalSevered = 0;

            foreach (var entry in pol.LockedApps)
            {
                ZtNetworkInfo net = nets.FirstOrDefault(n => string.Equals(n.Id, entry.NetworkId, StringComparison.OrdinalIgnoreCase)) ?? nets.FirstOrDefault();
                string guid = ZeroTierApi.ResolveAdapterGuidForNetwork(net);
                totalSevered += SocketManager.SeverNonCompliantSockets(entry.ExePath, guid);
            }

            RefreshAll(true);
            lblStatus.Text = string.Format("Severed {0} established non-ZeroTier TCP socket(s) across locked applications.", totalSevered);
        }

        private void AuditSockets_Click(object sender, EventArgs e)
        {
            AppLockerPolicy pol = PolicyStore.Load();
            if (pol.LockedApps.Count == 0)
            {
                MessageBox.Show("No locked applications in policy to audit.", "Live Socket Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            List<ZtNetworkInfo> nets = ZeroTierApi.GetNetworks();
            ZtTelemetrySummary telem = ZeroTierApi.GetTelemetrySummary();

            StringBuilder sb = new StringBuilder();
            sb.AppendLine(string.Format("ZeroTier Node: {0}  |  Path: {1}", telem.NodeId, telem.PeerSummary));
            sb.AppendLine(string.Format("Strict DNS Lock: {0}", pol.StrictDnsLock ? "ENABLED (Port 53 Locked)" : "Disabled"));
            sb.AppendLine(new string('-', 64));

            int leakCount = 0;
            foreach (var entry in pol.LockedApps)
            {
                string leaf = Path.GetFileName(entry.ExePath);
                ZtNetworkInfo net = nets.FirstOrDefault(n => string.Equals(n.Id, entry.NetworkId, StringComparison.OrdinalIgnoreCase));
                string guid = ZeroTierApi.ResolveAdapterGuidForNetwork(net);

                var sockets = SocketManager.InspectProcessSockets(entry.ExePath, guid);
                if (sockets.Count == 0)
                {
                    sb.AppendLine(string.Format("[IDLE] {0} -> No active TCP sockets.", leaf));
                    continue;
                }

                foreach (var s in sockets)
                {
                    if (!s.IsCompliant) leakCount++;
                    string badge = s.IsCompliant ? "[SAFE-ZT]" : "[LEAK-ISP!]";
                    sb.AppendLine(string.Format("{0} {1} (PID {2}) {3}:{4} -> {5}:{6} ({7})",
                        badge, leaf, s.Pid, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort, s.State));
                }
            }

            sb.AppendLine(new string('-', 64));
            sb.AppendLine(leakCount == 0
                ? "RESULT: 0 non-compliant sockets detected. Zero ISP leak verified."
                : string.Format("WARNING: {0} non-compliant socket(s) found! Click 'Sever ISP Sockets' to terminate them.", leakCount));

            MessageBox.Show(sb.ToString(), "Live TCP Socket & Leak Audit", MessageBoxButtons.OK,
                leakCount == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void RefreshAll(bool force)
        {
            ZtTelemetrySummary telem = ZeroTierApi.GetTelemetrySummary();
            List<ZtNetworkInfo> networks = ZeroTierApi.GetNetworks();
            string svcStatus = ServiceManager.GetServiceStatus();
            AppLockerPolicy pol = PolicyStore.Load();

            // Update System Tray
            try
            {
                ZtNetworkInfo primaryNet = networks.FirstOrDefault(n => n.Status == "OK") ?? networks.FirstOrDefault();
                string trayHover = telem.DaemonOnline && primaryNet != null
                    ? string.Format("ZT: {0} | {1} | Locks: {2}", primaryNet.PrimaryIpv4, telem.PeerSummary, pol.LockedApps.Count)
                    : string.Format("ZT: OFFLINE | WFP Locks: {0} (Fail-Closed)", pol.LockedApps.Count);
                if (trayHover.Length > 63) trayHover = trayHover.Substring(0, 63);
                _trayIcon.Text = trayHover;

                _trayNodeHeader.Text = string.Format("Node {0}: {1}", telem.NodeId, telem.PeerSummary);
                _trayNetDetail.Text = primaryNet != null
                    ? string.Format("Net {0}: {1}  |  Locked Apps: {2}", primaryNet.Id, primaryNet.PrimaryIpv4, pol.LockedApps.Count)
                    : string.Format("No Active Network  |  Locked Apps: {0}", pol.LockedApps.Count);
            }
            catch { }

            string sig = string.Join("|", new[]
            {
                telem.NodeId,
                telem.DaemonOnline.ToString(),
                telem.PeerSummary,
                svcStatus,
                pol.StrictDnsLock.ToString(),
                string.Join(";", networks.Select(n => n.Id + ":" + n.Status + ":" + n.PrimaryIpv4 + ":" + n.AllowDefault + ":" + n.AllowDNS)),
                string.Join(";", pol.LockedApps.Select(a => a.ExePath + ":" + a.NetworkId + ":" + a.BootTimeGuard))
            });

            if (!force && sig == _lastStateHash)
                return;
            _lastStateHash = sig;

            // Update Top Status Panel
            if (!telem.DaemonOnline)
            {
                pnlTopStatus.BackColor = Color.FromArgb(253, 231, 233);
                lblNodeStatus.ForeColor = Color.DarkRed;
                lblNodeStatus.Text = "ZEROTIER CORE OFFLINE (All Locked Apps Fail-Closed)";
                lblDaemonDetail.Text = "Start ZeroTier Core service or verify ZeroTier One installation.";
                btnStartZtDaemon.Visible = true;
                btnInstallSvc.Location = new Point(500, 12);
                btnInstallSvc.Size = new Size(92, 30);
                btnUninstallSvc.Visible = false;
            }
            else
            {
                pnlTopStatus.BackColor = Color.FromArgb(223, 246, 221);
                lblNodeStatus.ForeColor = Color.DarkGreen;
                lblNodeStatus.Text = string.Format("NODE {0} ONLINE  [{1}]", telem.NodeId, telem.PeerSummary);
                lblDaemonDetail.Text = string.Format("ZT Core v{0}  |  Guard Service: {1}  |  WFP Sublayer Active", telem.Version, svcStatus);
                btnStartZtDaemon.Visible = false;
                btnInstallSvc.Location = new Point(402, 12);
                btnInstallSvc.Size = new Size(100, 30);
                btnUninstallSvc.Visible = true;
            }

            btnInstallSvc.Text = svcStatus == "NotInstalled" ? "Install Guard" : "Repair Guard";
            btnUninstallSvc.Enabled = (svcStatus != "NotInstalled");

            // Sync Hardening Checkboxes
            _suppressUiEvents = true;
            chkStrictDnsLock.Checked = pol.StrictDnsLock;
            _suppressUiEvents = false;

            // Update Networks ComboBox
            ZtNetworkInfo prevNet = cmbNetworks.SelectedItem as ZtNetworkInfo;
            string prevNetId = prevNet != null ? prevNet.Id : null;

            cmbNetworks.Items.Clear();
            int selIdx = -1;
            for (int i = 0; i < networks.Count; i++)
            {
                cmbNetworks.Items.Add(networks[i]);
                if (prevNetId != null && string.Equals(networks[i].Id, prevNetId, StringComparison.OrdinalIgnoreCase))
                    selIdx = i;
            }
            if (cmbNetworks.Items.Count > 0)
                cmbNetworks.SelectedIndex = selIdx >= 0 ? selIdx : 0;
            SyncNetworkCheckboxesFromSelection();

            // Update Active Locks ListBox
            lstActive.BeginUpdate();
            lstActive.Items.Clear();
            foreach (var entry in pol.LockedApps)
            {
                ZtNetworkInfo net = networks.FirstOrDefault(n => string.Equals(n.Id, entry.NetworkId, StringComparison.OrdinalIgnoreCase));
                string label = net != null
                    ? (string.IsNullOrWhiteSpace(net.Name) ? net.Id : string.Format("{0} ({1})", net.Name, net.PrimaryIpv4))
                    : entry.NetworkId;

                string tag = "[WFP-LOCKED]";
                if (!File.Exists(entry.ExePath))
                    tag = "[EXE MISSING]";
                else if (net == null || net.Status != "OK")
                    tag = "[TUNNEL OFFLINE - BLOCKING]";

                lstActive.Items.Add(new ActiveLockDisplayItem
                {
                    Policy = entry,
                    NetworkLabel = label,
                    StatusTag = tag
                });
            }
            lstActive.EndUpdate();
        }

        private void BrowseExe_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog { Filter = "Executables (*.exe)|*.exe", Multiselect = true })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    foreach (string f in ofd.FileNames)
                    {
                        if (ProtectedBinaries.Contains(Path.GetFileName(f)) || f.IndexOf(@"\ZeroTier\One\", StringComparison.OrdinalIgnoreCase) >= 0)
                            continue;
                        if (!lstQueue.Items.Contains(f)) lstQueue.Items.Add(f);
                    }
                }
            }
        }

        private void BrowseFolder_Click(object sender, EventArgs e)
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog { Description = "Select an application folder to lock all executables inside:" })
            {
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    int added = 0;
                    foreach (string f in Directory.GetFiles(fbd.SelectedPath, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ProtectedBinaries.Contains(Path.GetFileName(f)) || f.IndexOf(@"\ZeroTier\One\", StringComparison.OrdinalIgnoreCase) >= 0)
                            continue;
                        if (!lstQueue.Items.Contains(f)) { lstQueue.Items.Add(f); added++; }
                    }
                    lblStatus.Text = string.Format("Queued {0} executable(s) from {1}.", added, fbd.SelectedPath);
                }
            }
        }

        private void RunningApps_Click(object sender, EventArgs e)
        {
            Form dlg = new Form
            {
                Text = "Select Running Applications",
                Size = new Size(640, 470),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                Font = new Font("Segoe UI", 9.5f)
            };

            Label lblSearch = new Label { Text = "Filter by name or path:", Location = new Point(14, 15), Size = new Size(140, 22) };
            TextBox txtFilter = new TextBox { Location = new Point(156, 12), Size = new Size(375, 25) };
            Button btnClear = new Button { Text = "Clear", Location = new Point(538, 11), Size = new Size(74, 27) };
            CheckedListBox clb = new CheckedListBox { Location = new Point(14, 46), Size = new Size(598, 330), CheckOnClick = true, HorizontalScrollbar = true };
            Button btnCheckAll = new Button { Text = "Check All Visible", Location = new Point(14, 388), Size = new Size(125, 32) };
            Button btnUncheckAll = new Button { Text = "Uncheck All", Location = new Point(146, 388), Size = new Size(105, 32) };
            Button btnAdd = new Button { Text = "Add Checked (0)", Location = new Point(452, 388), Size = new Size(160, 32), BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };

            List<ProcessCandidate> candidates = new List<ProcessCandidate>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Process p in Process.GetProcesses().OrderBy(x => x.ProcessName))
            {
                try
                {
                    string path = p.MainModule.FileName;
                    if (!ProtectedBinaries.Contains(Path.GetFileName(path)) &&
                        path.IndexOf(@"\ZeroTier\One\", StringComparison.OrdinalIgnoreCase) < 0 &&
                        seen.Add(path))
                    {
                        candidates.Add(new ProcessCandidate { ExeName = Path.GetFileName(path), ExePath = path });
                    }
                }
                catch { }
            }

            candidates = candidates.OrderBy(c => c.ExeName).ToList();
            HashSet<string> checkedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool suppress = false;

            Action updateCount = () => { btnAdd.Text = string.Format("Add Checked ({0})", checkedPaths.Count); };
            Action applyFilter = () =>
            {
                string q = txtFilter.Text.Trim();
                suppress = true;
                clb.BeginUpdate();
                clb.Items.Clear();
                foreach (var c in candidates)
                {
                    if (string.IsNullOrEmpty(q) ||
                        c.ExeName.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        c.ExePath.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        int idx = clb.Items.Add(c);
                        if (checkedPaths.Contains(c.ExePath)) clb.SetItemChecked(idx, true);
                    }
                }
                clb.EndUpdate();
                suppress = false;
                updateCount();
            };

            clb.ItemCheck += (s2, e2) =>
            {
                if (suppress) return;
                ProcessCandidate c = clb.Items[e2.Index] as ProcessCandidate;
                if (c == null) return;
                if (e2.NewValue == CheckState.Checked) checkedPaths.Add(c.ExePath);
                else checkedPaths.Remove(c.ExePath);
                BeginInvoke((Action)(() => updateCount()));
            };

            txtFilter.TextChanged += (s2, e2) => applyFilter();
            btnClear.Click += (s2, e2) => { txtFilter.Text = ""; txtFilter.Focus(); };
            btnCheckAll.Click += (s2, e2) =>
            {
                suppress = true;
                for (int i = 0; i < clb.Items.Count; i++)
                {
                    ProcessCandidate c = clb.Items[i] as ProcessCandidate;
                    if (c != null) { checkedPaths.Add(c.ExePath); clb.SetItemChecked(i, true); }
                }
                suppress = false;
                updateCount();
            };
            btnUncheckAll.Click += (s2, e2) =>
            {
                checkedPaths.Clear();
                suppress = true;
                for (int i = 0; i < clb.Items.Count; i++) clb.SetItemChecked(i, false);
                suppress = false;
                updateCount();
            };
            btnAdd.Click += (s2, e2) =>
            {
                foreach (string path in checkedPaths)
                    if (!lstQueue.Items.Contains(path)) lstQueue.Items.Add(path);
                dlg.Close();
            };

            dlg.Controls.AddRange(new Control[] { lblSearch, txtFilter, btnClear, clb, btnCheckAll, btnUncheckAll, btnAdd });
            applyFilter();
            dlg.Shown += (s2, e2) => txtFilter.Focus();
            dlg.ShowDialog();
        }

        private void ExportPolicy_Click(object sender, EventArgs e)
        {
            AppLockerPolicy pol = PolicyStore.Load();
            using (SaveFileDialog sfd = new SaveFileDialog { Filter = "JSON Policy (*.json)|*.json", FileName = "ZT-AppLocker-v3-Policy.json" })
            {
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    using (FileStream fs = File.Create(sfd.FileName))
                    {
                        DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppLockerPolicy));
                        ser.WriteObject(fs, pol);
                    }
                    lblStatus.Text = "Exported policy (" + pol.LockedApps.Count + " app(s)) to " + sfd.FileName;
                }
            }
        }

        private void ImportPolicy_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog { Filter = "JSON Policy (*.json)|*.json" })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    using (FileStream fs = File.OpenRead(ofd.FileName))
                    {
                        DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppLockerPolicy));
                        AppLockerPolicy imported = ser.ReadObject(fs) as AppLockerPolicy;
                        if (imported != null)
                        {
                            PolicyStore.Save(imported);
                            GuardService.ReconcilePolicyWithWfp(false);
                            RefreshAll(true);
                            lblStatus.Text = "Imported policy and reconciled WFP kernel locks.";
                        }
                    }
                }
            }
        }

        private void RestoreFromTray()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
            RefreshAll(true);
        }

        private void ShowLogViewer()
        {
            Form logForm = new Form { Text = "ZTAppLockerGuard v3.0 Service Log", Size = new Size(740, 450), StartPosition = FormStartPosition.CenterParent };
            TextBox tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f) };

            Action loadLog = () =>
            {
                tb.Text = File.Exists(ServiceManager.LogFilePath)
                    ? File.ReadAllText(ServiceManager.LogFilePath)
                    : "No service log entries yet. Install and start the Guard service first.";
                tb.SelectionStart = tb.Text.Length;
                tb.ScrollToCaret();
            };

            Panel topBar = new Panel { Dock = DockStyle.Top, Height = 36 };
            Button btnRef = new Button { Text = "Refresh Log", Location = new Point(8, 5), Size = new Size(95, 26) };
            Button btnClr = new Button { Text = "Clear Log", Location = new Point(110, 5), Size = new Size(85, 26) };
            btnRef.Click += (s, e) => loadLog();
            btnClr.Click += (s, e) =>
            {
                try { if (File.Exists(ServiceManager.LogFilePath)) File.WriteAllText(ServiceManager.LogFilePath, ""); } catch { }
                loadLog();
            };
            topBar.Controls.AddRange(new Control[] { btnRef, btnClr });

            logForm.Controls.Add(tb);
            logForm.Controls.Add(topBar);
            loadLog();
            logForm.ShowDialog();
        }
    }
}
'@

Set-Content -Path "$RepoDir\src\MainForm.cs" -Value $MainFormCode -Encoding ASCII

# ---------------------------------------------------------------------------
# 4. Write Build-ZTAppLocker-v3.ps1 & Clean Up Legacy v2.5.1
# ---------------------------------------------------------------------------
Write-Host "[3/5] Writing Build-ZTAppLocker-v3.ps1..." -ForegroundColor Cyan

$BuildScriptCode = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Compiles ZT-AppLocker v3.0 (ZeroTier Control Plane + Native WFP Kernel Enforcer)
#>

$ErrorActionPreference = "Stop"

$CscPath = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $CscPath)) {
    throw "Built-in .NET C# compiler not found at $CscPath"
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir   = Join-Path $RepoRoot "src"
$DistDir  = Join-Path $RepoRoot "dist"
if (-not (Test-Path $DistDir)) { New-Item -Path $DistDir -ItemType Directory -Force | Out-Null }

$IconPath    = Join-Path $DistDir "ZTAppLocker.ico"
$DistExePath = Join-Path $DistDir "ZT-AppLocker.exe"
$DesktopExe  = "$([Environment]::GetFolderPath('Desktop'))\ZT-AppLocker.exe"

# --- 1. GENERATE SHIELD + PADLOCK .ICO ---
Write-Host "[1/3] Generating Shield + Network Lock icon..." -ForegroundColor Cyan

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(64, 64)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

$shieldPts = @(
    (New-Object System.Drawing.Point(32, 4)),
    (New-Object System.Drawing.Point(56, 13)),
    (New-Object System.Drawing.Point(56, 33)),
    (New-Object System.Drawing.Point(32, 60)),
    (New-Object System.Drawing.Point(8, 33)),
    (New-Object System.Drawing.Point(8, 13))
)
$shieldPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$shieldPath.AddPolygon($shieldPts)

$gradBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Point(8, 4)),
    (New-Object System.Drawing.Point(56, 60)),
    [System.Drawing.Color]::FromArgb(0, 132, 235),
    [System.Drawing.Color]::FromArgb(0, 72, 155)
)
$g.FillPath($gradBrush, $shieldPath)

$borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 2.5)
$g.DrawPath($borderPen, $shieldPath)

$shacklePen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3.5)
$g.DrawArc($shacklePen, 24, 17, 16, 16, 180, 180)
$g.DrawLine($shacklePen, 24, 25, 24, 29)
$g.DrawLine($shacklePen, 40, 25, 40, 29)

$lockBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 200, 45))
$g.FillRectangle($lockBrush, 20, 29, 24, 18)

$keyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 35, 65))
$g.FillEllipse($keyBrush, 30, 34, 4, 4)
$g.FillRectangle($keyBrush, 31, 37, 2, 5)

$pngStream = New-Object System.IO.MemoryStream
$bmp.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngStream.ToArray()

$icoStream = New-Object System.IO.FileStream($IconPath, [System.IO.FileMode]::Create)
$bw = New-Object System.IO.BinaryWriter($icoStream)
$bw.Write([uint16]0)
$bw.Write([uint16]1)
$bw.Write([uint16]1)
$bw.Write([byte]64)
$bw.Write([byte]64)
$bw.Write([byte]0)
$bw.Write([byte]0)
$bw.Write([uint16]1)
$bw.Write([uint16]32)
$bw.Write([uint32]$pngBytes.Length)
$bw.Write([uint32]22)
$bw.Write($pngBytes)
$bw.Close()
$icoStream.Close()
$g.Dispose()
$bmp.Dispose()

# --- 2. COMPILE ALL MODULAR C# SOURCES ---
Write-Host "[2/3] Compiling modular C# v3.0 sources via csc.exe..." -ForegroundColor Cyan

$CsFiles = Get-ChildItem -Path $SrcDir -Filter "*.cs" | Select-Object -ExpandProperty FullName
if ($CsFiles.Count -eq 0) {
    throw "No .cs source files found in $SrcDir"
}

& $CscPath `
    /target:winexe `
    /platform:x64 `
    /optimize+ `
    /nologo `
    /win32icon:"$IconPath" `
    /out:"$DistExePath" `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Drawing.dll `
    /reference:System.Runtime.Serialization.dll `
    /reference:System.ServiceProcess.dll `
    /reference:System.Windows.Forms.dll `
    $CsFiles

if ($LASTEXITCODE -ne 0) {
    throw "C# compilation failed with exit code $LASTEXITCODE"
}

Copy-Item -Path $DistExePath -Destination $DesktopExe -Force
Write-Host "[3/3] SUCCESS! Built ZT-AppLocker v3.0 at:" -ForegroundColor Green
Write-Host "      - $DistExePath" -ForegroundColor Green
Write-Host "      - $DesktopExe" -ForegroundColor Green
'@

Set-Content -Path "$RepoDir\Build-ZTAppLocker-v3.ps1" -Value $BuildScriptCode -Encoding ASCII

if (Test-Path "$RepoDir\Build-ZTAppLocker-v2.5.1.ps1") {
    Remove-Item "$RepoDir\Build-ZTAppLocker-v2.5.1.ps1" -Force
}

# ---------------------------------------------------------------------------
# 5. Execute Full v3.0 Build & Push to GitHub
# ---------------------------------------------------------------------------
Write-Host "[4/5] Executing Build-ZTAppLocker-v3.ps1 to compile full v3.0 binary..." -ForegroundColor Cyan
& "$RepoDir\Build-ZTAppLocker-v3.ps1"

Write-Host "[5/5] Committing and pushing ZT-AppLocker v3.0 to GitHub..." -ForegroundColor Cyan
git add -A
git commit -m "feat(v3.0): complete ZeroTier control plane, native WFP kernel kill-switch, and unified GUI"
git push

Write-Host "`nALL DONE! ZT-AppLocker v3.0 is compiled on your Desktop and pushed to GitHub!" -ForegroundColor Green