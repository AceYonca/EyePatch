using EyePatch.Patch;
using System;
using System.Collections.Generic;

internal class Hooker //  https://github.com/AceYonca
{
    private readonly Action<string> _log;
    private readonly HashSet<int> _hookedPids = new HashSet<int>();

    public Hooker(Action<string> log)
    {
        _log = log ?? (_ => { });
    }

    public bool Hook(int pid)
    {
        try
        {
            if (_hookedPids.Contains(pid))
                return true;

            HardwareBreakpoint.Invoke(pid, _log);
            _hookedPids.Add(pid);

            return true;
        }
        catch (Exception ex)
        {
            _log("Patch error: " + ex.Message);
            return false;
        }
    }

    public bool Unhook(int pid)
    {
        try
        {
            if (!_hookedPids.Contains(pid))
                return true;

            HardwareBreakpoint.Stop();
            _hookedPids.Remove(pid);

            return true;
        }
        catch (Exception ex)
        {
            _log("Unpatch error: " + ex.Message);
            return false;
        }
    }
}