using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace EyePatch
{
    public partial class MainWindow : Window
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private readonly DispatcherTimer _refreshTimer = new DispatcherTimer();
        private readonly Dictionary<int, bool> _HookedStates = new Dictionary<int, bool>();
        private readonly Dictionary<string, long> _exportOffsetCache = new Dictionary<string, long>();

        private bool _isRefreshing = false;

        public ObservableCollection<ProcessViewModel> Processes { get; set; }





        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint TH32CS_SNAPMODULE = 0x00000008;
        private const uint TH32CS_SNAPMODULE32 = 0x00000010;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }




        private static bool CanCurrentProcessHookTarget(string targetArch, out string reason)






        {
            bool currentIs64 = Environment.Is64BitProcess;

            if (currentIs64)
            {
                // x64 controller can hook both native x64 and WOW64 x86
                if (targetArch == "x64" || targetArch == "x86")
                {
                    reason = null;
                    return true;
                }
            }
            else
            {
                // x86 controller should only hook x86 targets
                if (targetArch == "x86")
                {
                    reason = null;
                    return true;
                }

                reason =
                    "This EyePatch build is 32-bit and cannot hook a 64-bit process. " +
                    "Build EyePatch as x64 to support x64 targets.";
                return false;
            }

            reason = "Unknown or unsupported target architecture: " + targetArch;
            return false;
        }


        public bool IsHooked { get; set; }

        public string HookStatus
        {
            get { return IsHooked ? "Hooked" : "Not hooked"; }
        }




        public MainWindow()
        {
            InitializeComponent();

            Processes = new ObservableCollection<ProcessViewModel>();
            ProcessGrid.ItemsSource = Processes;

            _refreshTimer.Interval = TimeSpan.FromSeconds(5);
            _refreshTimer.Tick += RefreshTimer_Tick;

            Log("EyePatch started.");


            LoadProcesses(false);
        }

        public void Log(string message)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ConsoleBox.AppendText(
                    "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);

                ConsoleBox.ScrollToEnd();
            }));
        }

        private async void LoadProcesses(bool quiet)
        {
            if (_isRefreshing)
                return;

            _isRefreshing = true;



            try
            {

                if (!quiet)
                    Log("Refreshing process list...");

                List<ProcessViewModel> result = await Task.Run(() =>
                {
                    List<ProcessViewModel> found = new List<ProcessViewModel>();

                    foreach (Process process in Process.GetProcesses().OrderBy(p => p.ProcessName))
                    {
                        try
                        {
                            string arch = GetProcessArchitecture(process);

                            IntPtr AmsiBase = GetModuleBaseFromProcess(process, "Amsi.dll");
                            if (AmsiBase == IntPtr.Zero)
                                continue;


                            bool Hooked = false;

                            if (_HookedStates.ContainsKey(process.Id))
                                Hooked = _HookedStates[process.Id];

                            found.Add(new ProcessViewModel
                            {
                                Id = process.Id,
                                ProcessName = arch == "x86" ? process.ProcessName + " (x86)": process.ProcessName,
                                MemoryUsage = (process.WorkingSet64 / 1024 / 1024) + " MB",
                                IsHooked = Hooked,
                                Architecture = arch,
                                AmsiBaseAddress = AmsiBase == IntPtr.Zero
                                    ? "Not found"
                                    : "0x" + AmsiBase.ToInt64().ToString("X")
                            });
                        }
                        catch
                        {
                        }
                        finally
                        {
                            process.Dispose();
                        }
                    }

                    return found;
                });

                Processes.Clear();

                foreach (ProcessViewModel item in result)
                    Processes.Add(item);

                if (!quiet)
                    Log("Refresh completed. Found " + result.Count + " process(es) with Amsi.dll.");
            }
            finally
            {
                _isRefreshing = false;
            }
        }

        private static IntPtr GetModuleBaseFromProcess(Process process, string moduleName)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                (uint)process.Id);

            if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE)
                return IntPtr.Zero;

            try
            {
                MODULEENTRY32 module = new MODULEENTRY32();
                module.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (!Module32First(snapshot, ref module))
                    return IntPtr.Zero;

                do
                {
                    if (module.szModule.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        return module.modBaseAddr;
                }
                while (Module32Next(snapshot, ref module));
            }
            catch
            {
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return IntPtr.Zero;
        }
        private static IntPtr GetRemoteModuleBase(int pid, string moduleName)
        {
            try
            {
                using (Process process = Process.GetProcessById(pid))
                {
                    return GetModuleBaseFromProcess(process, moduleName);
                }
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private long GetExportOffset(string modulePath, string exportName)
        {
            string cacheKey = modulePath.ToLowerInvariant() + "!" + exportName;

            if (_exportOffsetCache.ContainsKey(cacheKey))
                return _exportOffsetCache[cacheKey];

            IntPtr localModule = LoadLibrary(modulePath);

            if (localModule == IntPtr.Zero)
                return 0;

            IntPtr localExport = GetProcAddress(localModule, exportName);

            if (localExport == IntPtr.Zero)
                return 0;

            long offset = localExport.ToInt64() - localModule.ToInt64();

            _exportOffsetCache[cacheKey] = offset;
            return offset;
        }

        private IntPtr GetRemoteExportAddress(int pid, string moduleName, string exportName)
        {
            IntPtr remoteBase = GetRemoteModuleBase(pid, moduleName);

            if (remoteBase == IntPtr.Zero)
                return IntPtr.Zero;

            long offset = GetExportOffset(moduleName, exportName);

            if (offset == 0)
                return IntPtr.Zero;

            return new IntPtr(remoteBase.ToInt64() + offset);
        }

        private static string GetProcessArchitecture(Process process)
        {
            try
            {
                if (!Environment.Is64BitOperatingSystem)
                    return "x86";

                bool isWow64;

                if (!IsWow64Process(process.Handle, out isWow64))
                    return "Unknown";

                return isWow64 ? "x86" : "x64";
            }
            catch
            {
                return "Unknown";
            }
        }

        private static string GetProcessArchitecture(int pid)
        {
            try
            {
                using (Process process = Process.GetProcessById(pid))
                {
                    return GetProcessArchitecture(process);
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private ProcessViewModel GetSelectedProcess()
        {
            return ProcessGrid.SelectedItem as ProcessViewModel;
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            LoadProcesses(false);
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            LoadProcesses(true);
        }

        private void LiveRefresh_Checked(object sender, RoutedEventArgs e)
        {
            _refreshTimer.Start();
            Log("Live refresh enabled.");
        }

        private void LiveRefresh_Unchecked(object sender, RoutedEventArgs e)
        {
            _refreshTimer.Stop();
            Log("Live refresh disabled.");
        }





        private void ProcessGrid_MouseDoubleClick(
            object sender,
            System.Windows.Input.MouseButtonEventArgs e)
        {
            ProcessViewModel selected = GetSelectedProcess();

            if (selected == null)
                return;

            IntPtr AmsiBase = GetRemoteModuleBase(selected.Id, "Amsi.dll");

            IntPtr AmsiScanBuffer = GetRemoteExportAddress(
                selected.Id,
                "Amsi.dll",
                "AmsiScanBuffer");

            Log("Process: " + selected.ProcessName);
            Log("PID: " + selected.Id);
            Log("Architecture: " + GetProcessArchitecture(selected.Id));
            Log("Amsi.dll Base: 0x" + AmsiBase.ToInt64().ToString("X"));
            Log("AmsiScanBuffer: 0x" + AmsiScanBuffer.ToInt64().ToString("X"));

            MessageBox.Show(
                "Process: " + selected.ProcessName +
                "\nPID: " + selected.Id +
                "\nMemory: " + selected.MemoryUsage +
                "\nArchitecture: " + selected.Architecture +
                "\nHooked: " + selected.IsHooked +
                "\nAmsi.dll Base: 0x" + AmsiBase.ToInt64().ToString("X") +
                "\nAmsiScanBuffer: 0x" + AmsiScanBuffer.ToInt64().ToString("X"),
                "Process Selected");
        }


        private void TitleBar_MouseLeftButtonDown(
    object sender,
    System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                Maximize_Click(sender, e);
                return;
            }

            DragMove();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void Unhook_Click(object sender, RoutedEventArgs e)
        {
            ProcessViewModel selected = GetSelectedProcess();

            if (selected == null)
            {
                Log("Unpatch failed: no process selected.");
                MessageBox.Show("Please select a process first.");
                return;
            }


            int pid = selected.Id;

            bool success = await Task.Run(() =>
            {
                var patcher = new Hooker(Log);
                return patcher.Unhook(pid);
            });

            if (!success)
            {
                Log("Patch failed for PID " + pid);
                return;
            }
            selected.IsHooked = false;
            _HookedStates[selected.Id] = false;

            ProcessGrid.Items.Refresh();

            Log("Marked unHooked: " + selected.ProcessName + " PID " + selected.Id);
        }

        private async void Hook_Click(object sender, RoutedEventArgs e)
        {
            ProcessViewModel selected = GetSelectedProcess();

            if (selected == null)
            {
                Log("Patch failed: no process selected.");
                MessageBox.Show("Please select a process first.");
                return;
            }

            string reason;
            if (!CanCurrentProcessHookTarget(selected.Architecture, out reason))
            {
                Log("Patch blocked: " + reason);
                MessageBox.Show(reason, "Unsupported architecture");
                return;
            }

            int pid = selected.Id;

            Log(
                "Hook requested. Current process architecture=" +
                (Environment.Is64BitProcess ? "x64" : "x86") +
                ", target architecture=" + selected.Architecture +
                ", PID=" + pid);

            bool success = await Task.Run(() =>
            {
                var patcher = new Hooker(Log);
                return patcher.Hook(pid);
            });

            if (!success)
            {
                Log("Patch failed for PID " + pid);
                return;
            }

            selected.IsHooked = true;
            _HookedStates[pid] = true;
            ProcessGrid.Items.Refresh();

            Log("Marked Hooked: " + selected.ProcessName + " PID " + pid);
        }

    }

    public class ProcessViewModel
    {
        public int Id { get; set; }

        public string ProcessName { get; set; }

        public string MemoryUsage { get; set; }

        public bool IsHooked { get; set; }

        public string HookStatus
        {
            get
            {
                return IsHooked ? "Hooked" : "Not hooked";
            }
        }

        public string Architecture { get; set; }

        public string AmsiBaseAddress { get; set; }
    }
}