using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace EyePatch.Patch
{
    internal static class Native
    {
        public const string Kernel32 = "kernel32.dll";

        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const uint DBG_CONTINUE = 0x00010002;

        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint STATUS_WX86_SINGLE_STEP = 0x4000001E;

        public const uint WAIT_TIMEOUT = 121;
        public const uint INFINITE = 0xFFFFFFFF;

        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;

        public const uint CONTEXT_i386 = 0x00010000;
        public const uint CONTEXT_CONTROL = CONTEXT_i386 | 0x00000001;
        public const uint CONTEXT_INTEGER = CONTEXT_i386 | 0x00000002;
        public const uint CONTEXT_SEGMENTS = CONTEXT_i386 | 0x00000004;
        public const uint CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x00000008;
        public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x00000010;

        public const uint CONTEXT32_ALL_NEEDED =
            CONTEXT_CONTROL |
            CONTEXT_INTEGER |
            CONTEXT_SEGMENTS |
            CONTEXT_FLOATING_POINT |
            CONTEXT_DEBUG_REGISTERS;

        [DllImport(Kernel32, SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport(Kernel32, SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool DebugActiveProcess(uint dwProcessId);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool WaitForDebugEvent(
            out DEBUG_EVENT lpDebugEvent,
            uint dwMilliseconds);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool ContinueDebugEvent(
            uint dwProcessId,
            uint dwThreadId,
            uint dwContinueStatus);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern IntPtr OpenThread(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwThreadId);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool IsWow64Process(
            IntPtr hProcess,
            out bool wow64Process);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool GetThreadContext(
            IntPtr hThread,
            ref CONTEXT64 lpContext);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool SetThreadContext(
            IntPtr hThread,
            ref CONTEXT64 lpContext);

        [DllImport(Kernel32, SetLastError = true, EntryPoint = "GetThreadContext")]
        public static extern bool GetThreadContext32(
            IntPtr hThread,
            ref CONTEXT32 lpContext);

        [DllImport(Kernel32, SetLastError = true, EntryPoint = "SetThreadContext")]
        public static extern bool SetThreadContext32(
            IntPtr hThread,
            ref CONTEXT32 lpContext);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool Wow64GetThreadContext(
            IntPtr hThread,
            ref CONTEXT32 lpContext);

        [DllImport(Kernel32, SetLastError = true)]
        public static extern bool Wow64SetThreadContext(
            IntPtr hThread,
            ref CONTEXT32 lpContext);

        public static CONTEXT64 CreateContext64()
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

        public static CONTEXT32 CreateContext32()
        {
            return new CONTEXT32
            {
                ContextFlags = CONTEXT32_ALL_NEEDED,
                FloatSave = new FLOATING_SAVE_AREA
                {
                    RegisterArea = new byte[80]
                },
                ExtendedRegisters = new byte[512]
            };
        }

        public enum DebugEventCode : uint
        {
            EXCEPTION_DEBUG_EVENT = 1,
            CREATE_THREAD_DEBUG_EVENT = 2,
            CREATE_PROCESS_DEBUG_EVENT = 3,
            EXIT_THREAD_DEBUG_EVENT = 4,
            EXIT_PROCESS_DEBUG_EVENT = 5,
            LOAD_DLL_DEBUG_EVENT = 6,
            UNLOAD_DLL_DEBUG_EVENT = 7,
            OUTPUT_DEBUG_STRING_EVENT = 8,
            RIP_EVENT = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DEBUG_EVENT
        {
            public uint dwDebugEventCode;
            public uint dwProcessId;
            public uint dwThreadId;
            public DEBUG_EVENT_UNION u;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct DEBUG_EVENT_UNION
        {
            [FieldOffset(0)]
            public EXCEPTION_DEBUG_INFO Exception;

            [FieldOffset(0)]
            public EXIT_PROCESS_DEBUG_INFO ExitProcess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXIT_PROCESS_DEBUG_INFO
        {
            public uint dwExitCode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }

        [Flags]
        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_AMD64 = 0x00100000,
            CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001,
            CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010,

            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER,
            CONTEXT_ALL_NEEDED = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct M128A
        {
            public ulong Low;
            public long High;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
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
        public struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;

            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

            public ulong Rax, Rcx, Rdx, Rbx;
            public ulong Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;

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

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;

            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct CONTEXT32
        {
            public uint ContextFlags;

            public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

            public FLOATING_SAVE_AREA FloatSave;

            public uint SegGs, SegFs, SegEs, SegDs;

            public uint Edi, Esi, Ebx, Edx, Ecx, Eax;

            public uint Ebp, Eip, SegCs, EFlags, Esp, SegSs;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }
    }
}
