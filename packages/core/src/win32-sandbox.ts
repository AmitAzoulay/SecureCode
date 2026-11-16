// packages/core/src/win32-sandbox.ts
import { spawnSync } from "node:child_process"
import crypto from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const CSHARP_SANDBOX_SOURCE = `
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

public class Program {
    const uint DISABLE_MAX_PRIVILEGE = 0x1;
    const uint LUA_TOKEN = 0x4;
    const uint WRITE_RESTRICTED = 0x8;
    const uint TOKEN_ALL_ACCESS = 0xF01FF;
    const int TokenGroups = 2;
    const int TokenDefaultDacl = 6;
    const uint SE_GROUP_LOGON_ID = 0xC0000000;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_DEFAULT_DACL {
        public IntPtr DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(
        IntPtr ExistingTokenHandle,
        uint Flags,
        uint DisableSidCount,
        IntPtr SidsToDisable,
        uint DeletePrivilegeCount,
        IntPtr PrivilegesToDelete,
        uint RestrictedSidCount,
        [In] SID_AND_ATTRIBUTES[] SidsToRestrict,
        out IntPtr NewTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, ref TOKEN_DEFAULT_DACL TokenInformation, int TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, int cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    static IntPtr GetLogonSid(IntPtr hToken) {
        int len = 0;
        GetTokenInformation(hToken, TokenGroups, IntPtr.Zero, 0, out len);
        IntPtr buf = Marshal.AllocHGlobal(len);
        try {
            if (!GetTokenInformation(hToken, TokenGroups, buf, len, out len))
                return IntPtr.Zero;
            int count = Marshal.ReadInt32(buf);
            IntPtr itemPtr = IntPtr.Add(buf, IntPtr.Size);
            for (int i = 0; i < count; i++) {
                SID_AND_ATTRIBUTES sa = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(itemPtr, typeof(SID_AND_ATTRIBUTES));
                if ((sa.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
                    SecurityIdentifier sid = new SecurityIdentifier(sa.Sid);
                    IntPtr outSid;
                    ConvertStringSidToSid(sid.Value, out outSid);
                    return outSid;
                }
                itemPtr = IntPtr.Add(itemPtr, Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
            }
        } finally {
            Marshal.FreeHGlobal(buf);
        }
        return IntPtr.Zero;
    }

    static void ConfigureWorkspaceAcl(string dirPath, string sidString, bool grant) {
        DirectoryInfo dInfo = new DirectoryInfo(dirPath);
        DirectorySecurity dSec = dInfo.GetAccessControl();
        SecurityIdentifier sid = new SecurityIdentifier(sidString);
        FileSystemAccessRule rule = new FileSystemAccessRule(
            sid,
            FileSystemRights.Modify | FileSystemRights.Synchronize | FileSystemRights.DeleteSubdirectoriesAndFiles,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);
        if (grant) dSec.AddAccessRule(rule);
        else dSec.RemoveAccessRuleSpecific(rule);
        dInfo.SetAccessControl(dSec);
    }

    static IntPtr BuildWriteRestrictedToken(string sidStr) {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out hToken))
            throw new Exception("OpenProcessToken failed: " + Marshal.GetLastWin32Error());

        IntPtr pSynthSid, pEveryoneSid;
        ConvertStringSidToSid(sidStr, out pSynthSid);
        ConvertStringSidToSid("S-1-1-0", out pEveryoneSid);
        IntPtr pLogonSid = GetLogonSid(hToken);

        SID_AND_ATTRIBUTES[] restrictList = pLogonSid != IntPtr.Zero
            ? new SID_AND_ATTRIBUTES[] {
                new SID_AND_ATTRIBUTES { Sid = pSynthSid, Attributes = 0 },
                new SID_AND_ATTRIBUTES { Sid = pLogonSid, Attributes = 0 },
                new SID_AND_ATTRIBUTES { Sid = pEveryoneSid, Attributes = 0 }
            }
            : new SID_AND_ATTRIBUTES[] {
                new SID_AND_ATTRIBUTES { Sid = pSynthSid, Attributes = 0 },
                new SID_AND_ATTRIBUTES { Sid = pEveryoneSid, Attributes = 0 }
            };

        IntPtr hRestricted;
        uint flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED;
        if (!CreateRestrictedToken(hToken, flags, 0, IntPtr.Zero, 0, IntPtr.Zero, (uint)restrictList.Length, restrictList, out hRestricted))
            throw new Exception("CreateRestrictedToken failed: " + Marshal.GetLastWin32Error());

        RawAcl rawAcl = new RawAcl(2, 4);
        SecurityIdentifier userSid = WindowsIdentity.GetCurrent().User;
        SecurityIdentifier synthSidObj = new SecurityIdentifier(sidStr);
        SecurityIdentifier everyoneSidObj = new SecurityIdentifier("S-1-1-0");
        rawAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1F01FF, userSid, false, null));
        rawAcl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1F01FF, synthSidObj, false, null));
        rawAcl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1F01FF, everyoneSidObj, false, null));
        if (pLogonSid != IntPtr.Zero) {
            rawAcl.InsertAce(3, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1F01FF, new SecurityIdentifier(pLogonSid), false, null));
        }
        byte[] aclBytes = new byte[rawAcl.BinaryLength];
        rawAcl.GetBinaryForm(aclBytes, 0);
        IntPtr pAcl = Marshal.AllocHGlobal(aclBytes.Length);
        Marshal.Copy(aclBytes, 0, pAcl, aclBytes.Length);
        TOKEN_DEFAULT_DACL tdd = new TOKEN_DEFAULT_DACL { DefaultDacl = pAcl };
        SetTokenInformation(hRestricted, TokenDefaultDacl, ref tdd, Marshal.SizeOf(tdd));
        return hRestricted;
    }

    static int SpawnUnderToken(IntPtr hRestricted, string workDir, string commandLine) {
        IntPtr hJob = CreateJobObjectW(IntPtr.Zero, null);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, 9, ref jeli, Marshal.SizeOf(jeli));

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(-10);
        si.hStdOutput = GetStdHandle(-11);
        si.hStdError = GetStdHandle(-12);

        PROCESS_INFORMATION pi;
        StringBuilder cmdMut = new StringBuilder(commandLine);
        if (!CreateProcessAsUserW(hRestricted, null, cmdMut, IntPtr.Zero, IntPtr.Zero, true, CREATE_SUSPENDED, IntPtr.Zero, workDir, ref si, out pi)) {
            int err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine("OS Confinement CreateProcessAsUserW failed (Win32 Error " + err + ")");
            return 1;
        }

        AssignProcessToJobObject(hJob, pi.hProcess);
        ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        uint exitCode = 1;
        GetExitCodeProcess(pi.hProcess, out exitCode);
        return (int)exitCode;
    }

    static string QuoteArg(string arg) {
        char dq = (char)34;
        char bs = (char)92;
        char tab = (char)9;
        if (string.IsNullOrEmpty(arg)) return new string(dq, 2);
        if (arg.IndexOf(' ') < 0 && arg.IndexOf(tab) < 0 && arg.IndexOf(dq) < 0) return arg;
        StringBuilder sb = new StringBuilder();
        sb.Append(dq);
        int backslashes = 0;
        foreach (char c in arg) {
            if (c == bs) backslashes++;
            else if (c == dq) {
                sb.Append(bs, backslashes * 2 + 1);
                sb.Append(dq);
                backslashes = 0;
            } else {
                if (backslashes > 0) { sb.Append(bs, backslashes); backslashes = 0; }
                sb.Append(c);
            }
        }
        if (backslashes > 0) sb.Append(bs, backslashes * 2);
        sb.Append(dq);
        return sb.ToString();
    }

    public static int Main(string[] args) {
        try {
            if (args.Length < 3) return 2;
            string mode = args[0];
            string sidStr = args[1];
            string targetDir = args[2];

            if (mode == "--grant") {
                ConfigureWorkspaceAcl(targetDir, sidStr, true);
                return 0;
            }
            if (mode == "--revoke") {
                ConfigureWorkspaceAcl(targetDir, sidStr, false);
                return 0;
            }
            if (mode == "--write-file-worker") {
                // Executed inside the OS-restricted child process to perform file writes!
                string destFile = args[3];
                string srcTempFile = args[4];
                string parent = Path.GetDirectoryName(destFile);
                if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent)) {
                    Directory.CreateDirectory(parent);
                }
                byte[] data = File.ReadAllBytes(srcTempFile);
                File.WriteAllBytes(destFile, data);
                return 0;
            }
            if (mode == "--write-file") {
                string destFile = args[3];
                string srcTempFile = args[4];
                IntPtr hRestricted = BuildWriteRestrictedToken(sidStr);
                string selfExe = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string cmd = QuoteArg(selfExe) + " --write-file-worker " + QuoteArg(sidStr) + " " + QuoteArg(targetDir) + " " + QuoteArg(destFile) + " " + QuoteArg(srcTempFile);
                return SpawnUnderToken(hRestricted, targetDir, cmd);
            }
            if (mode == "--exec") {
                // args[3] = real shell executable, args[4..] = shell arguments
                StringBuilder cmdBuilder = new StringBuilder();
                for (int i = 3; i < args.Length; i++) {
                    if (i > 3) cmdBuilder.Append(" ");
                    cmdBuilder.Append(QuoteArg(args[i]));
                }
                IntPtr hRestricted = BuildWriteRestrictedToken(sidStr);
                return SpawnUnderToken(hRestricted, targetDir, cmdBuilder.ToString());
            }
            return 1;
        } catch (Exception ex) {
            Console.Error.WriteLine("[OS Confinement Error] " + ex.Message);
            return 5; // ERROR_ACCESS_DENIED
        }
    }
}
`

export namespace Win32Sandbox {
  const activeGrants = new Map<string, string>()
  let compiledExe: string | undefined

  export function deriveSid(sessionDir: string): string {
    const norm = fs.realpathSync(path.resolve(sessionDir)).toLowerCase()
    const hash = crypto.createHash("sha256").update(norm).digest()
    return `S-1-5-99-${hash.readUInt32LE(0)}-${hash.readUInt32LE(4)}-${hash.readUInt32LE(8)}`
  }

  export function getRunnerExe(): string {
    if (compiledExe && fs.existsSync(compiledExe)) return compiledExe
    const binDir = path.join(os.homedir(), ".opencode", "bin")
    fs.mkdirSync(binDir, { recursive: true })
    const exePath = path.join(binDir, "opencode-win32-sandbox-v2.exe")
    const csPath = path.join(binDir, "opencode-win32-sandbox-v2.cs")

    if (!fs.existsSync(exePath)) {
      fs.writeFileSync(csPath, CSHARP_SANDBOX_SOURCE, "utf8")
      const csc = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
      const res = spawnSync(csc, ["/nologo", "/optimize+", `/out:${exePath}`, csPath], {
        windowsHide: true,
      })
      if (res.status !== 0) {
        throw new Error(`Failed to compile Win32 sandbox runner: ${res.stderr?.toString() || res.stdout?.toString()}`)
      }
    }
    compiledExe = exePath
    return exePath
  }

  export function ensureGrant(sessionDir: string): { sid: string; tmpDir: string; realSessionDir: string } {
    const realSessionDir = fs.realpathSync(path.resolve(sessionDir))
    const sid = deriveSid(realSessionDir)
    const tmpDir = path.join(realSessionDir, ".opencode", "tmp")
    fs.mkdirSync(tmpDir, { recursive: true })

    if (process.platform === "win32" && !activeGrants.has(realSessionDir)) {
      const exe = getRunnerExe()
      const res = spawnSync(exe, ["--grant", sid, realSessionDir], { windowsHide: true })
      if (res.status !== 0) {
        throw new Error(`Failed to apply NTFS DACL on ${realSessionDir}: ${res.stderr?.toString()}`)
      }
      activeGrants.set(realSessionDir, sid)
    }
    return { sid, tmpDir, realSessionDir }
  }

  export function wrapShellSpawn(
    sessionDir: string,
    cwd: string,
    shellExe: string,
    shellArgs: string[],
    env: Record<string, string | undefined>,
  ): { executable: string; args: string[]; cwd: string; env: Record<string, string | undefined> } {
    if (process.platform !== "win32") {
      return { executable: shellExe, args: shellArgs, cwd, env }
    }
    const { sid, tmpDir, realSessionDir } = ensureGrant(sessionDir)
    const exe = getRunnerExe()

    // Convert Windows backslashes to forward slashes for MSYS2/Git Bash TMPDIR compatibility
    const posixTmp = tmpDir.replaceAll("\\", "/")

    const confinedEnv: Record<string, string | undefined> = {
      ...env,
      TEMP: tmpDir,
      TMP: tmpDir,
      TMPDIR: posixTmp,
      HOME: realSessionDir,
      USERPROFILE: realSessionDir,
      NPM_CONFIG_CACHE: path.join(tmpDir, "npm-cache"),
      BUN_INSTALL_CACHE_DIR: path.join(tmpDir, "bun-cache"),
    }

    return {
      executable: exe,
      args: ["--exec", sid, cwd, shellExe, ...shellArgs],
      cwd,
      env: confinedEnv,
    }
  }

  export function writeFileRestrictedSync(sessionDir: string, targetFile: string, data: Uint8Array): void {
    const { sid, tmpDir, realSessionDir } = ensureGrant(sessionDir)
    const exe = getRunnerExe()
    const stagingFile = path.join(tmpDir, `stage-${ process.pid }-${ Date.now() }-${ Math.random().toString(36).slice(2) }.tmp`)
    fs.writeFileSync(stagingFile, data)
    try {
      const res = spawnSync(exe, ["--write-file", sid, realSessionDir, targetFile, stagingFile], {
        windowsHide: true,
      })
      if (res.status !== 0) {
        const stderr = res.stderr?.toString().trim() || "STATUS_ACCESS_DENIED (0xC0000022)"
        throw new Error(`OS Kernel Restricted Token blocked write to ${targetFile}: ${stderr}`)
      }
    } finally {
      try {
        fs.unlinkSync(stagingFile)
      } catch {}
    }
  }
}