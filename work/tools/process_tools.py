#!/usr/bin/env python3
"""Small process/ADB runner. Results describe operations, never game acceptance.

Helper path options and the preflight script resolve against the caller's current
directory, not --cwd. Command argv is passed unchanged; child programs interpret
their relative paths in --cwd. Each invocation creates a unique evidence directory
under --output-dir; existing logs are never replaced.

Before the first device command, use adb-start-server to establish the shared
daemon outside the ordinary descendant-cleanup lifecycle. It never runs
kill-server; start-server timeout means daemon state is unknown. Keep using the
same pinned ADB binary: ADB's own version-mismatch restart behavior is outside
this helper's process-ownership guarantee.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Callable, Mapping, Sequence


@dataclass
class ProcessResult:
    outcome: str
    exit_code: int | None
    timed_out: bool
    duration_s: float
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_log: str
    stderr_log: str
    cleanup_scope: str
    diagnostic: str | None = None


class _WindowsJob:
    """Best-effort ownership of descendants; no process-name or global killing."""

    def __init__(self, process: subprocess.Popen):
        from ctypes import wintypes

        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("min_ws", ctypes.c_size_t),
                        ("max_ws", ctypes.c_size_t), ("active", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                        ("scheduling", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                        ("peak_job", ctypes.c_size_t)]

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self.api = api
        self.handle = api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = Extended()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not api.AssignProcessToJobObject(self.handle, int(process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def _positive(value: float, name: str) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and greater than zero")


def _summary(path: Path, limit: int) -> tuple[str, int]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        if size <= limit:
            data = stream.read(limit)
        else:
            head = limit // 2
            data = stream.read(head)
            stream.seek(-max(1, limit - head), os.SEEK_END)
            data += b"\n[output truncated; see full log]\n" + stream.read(limit - head)
    return data.decode("utf-8", errors="replace"), size


def run_process(argv: Sequence[str], *, cwd: str | Path, output_dir: str | Path,
                timeout_s: float = 60, summary_bytes: int = 4096,
                env: Mapping[str, str] | None = None,
                cleanup_descendants: bool = True) -> ProcessResult:
    """Run exactly argv, with no shell or retries; preserve full raw output logs.

    env supplies overrides, not a replacement environment. Arguments/environment
    are intentionally not persisted because they may contain signing secrets.
    A timeout means the operation's completion is unknown (not a game failure).
    Owned descendants are cleaned up even after success by default. The explicit
    cleanup_descendants=False lifecycle retains descendants on every outcome;
    timeout still kills/reaps this exact client process and leaves daemon state
    unknown. Its cleanup_scope is process_only_preserve_descendants. Use the
    narrow start_adb_server helper for ADB startup, before normal device calls.
    An existing ADB server is not owned by this operation. Retained descendants
    may keep writing inherited logs; summaries describe the client completion.
    Windows Job assignment happens immediately after Popen, not atomically with
    creation; early/breakaway descendants cannot be guaranteed to belong to it.
    """
    if isinstance(argv, (str, bytes)) or not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
        raise ValueError("argv must be a nonempty sequence of strings without NUL")
    if not argv[0]:
        raise ValueError("argv[0] must name an executable")
    if os.name == "nt" and Path(argv[0]).suffix.lower() in (".cmd", ".bat"):
        raise ValueError("Invoke a real executable; batch files require an explicit shell adapter")
    _positive(timeout_s, "timeout_s")
    if not isinstance(cleanup_descendants, bool):
        raise ValueError("cleanup_descendants must be a boolean")
    if not isinstance(summary_bytes, int) or summary_bytes < 32:
        raise ValueError("summary_bytes must be at least 32")
    child_cwd = Path(cwd).resolve(strict=True)
    if not child_cwd.is_dir():
        raise ValueError("cwd must be a directory")
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="operation-", dir=root))
    out_path, err_path = run_dir / "stdout.log", run_dir / "stderr.log"
    child_env = os.environ.copy()
    child_env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    if env:
        child_env.update(env)
    process = None
    job = None
    outcome, diagnostic, exit_code = "launch_error", None, None
    scope = "not_started"
    started = time.monotonic()
    with out_path.open("wb") as stdout, err_path.open("wb") as stderr:
        try:
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
            process = subprocess.Popen(list(argv), cwd=child_cwd, env=child_env,
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       shell=False, **options)
            if cleanup_descendants:
                scope = "process_only" if os.name == "nt" else "process_group"
            else:
                scope = "process_only_preserve_descendants"
                diagnostic = "Descendants intentionally retained; daemon state is not independently verified."
            if os.name == "nt" and cleanup_descendants:
                try:
                    job = _WindowsJob(process)
                    scope = "windows_job"
                except OSError as exc:
                    diagnostic = f"Job assignment unavailable; only owned process cleanup guaranteed: {exc}"
            try:
                exit_code = process.wait(timeout=timeout_s)
                outcome = "succeeded" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                outcome = "timed_out"
        except OSError as exc:
            diagnostic = f"Process launch failed: {exc}"
        finally:
            # Logs use files, so descendants cannot keep a communicate() pipe open.
            if job:
                job.close()
            elif process is not None and os.name != "nt" and cleanup_descendants:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process is not None and process.poll() is None:
                process.kill()  # Popen owns the exact Windows process handle.
            if process is not None:
                process.wait()
    out, out_size = _summary(out_path, summary_bytes)
    err, err_size = _summary(err_path, summary_bytes)
    result = ProcessResult(outcome, exit_code, outcome == "timed_out", round(time.monotonic() - started, 3),
                           out, err, out_size, err_size, str(out_path), str(err_path), scope, diagnostic)
    (run_dir / "result.json").write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def start_adb_server(adb: Path | str, *, cwd: str | Path,
                     output_dir: str | Path, timeout_s: float = 15,
                     summary_bytes: int = 4096,
                     runner: Callable = run_process) -> ProcessResult:
    """Start/reuse the shared ADB daemon without owning or cleaning it up.

    This host-level preflight has no device serial and performs exactly one
    `adb start-server` call. Windows launch is hidden through run_process. No
    server shutdown, broad process kill, or automatic timeout retry is issued.
    Success proves client exit zero; timeout/launch failure must not be treated
    as proof that no server exists. Use the same resolved ADB for later calls;
    changing ADB versions can trigger ADB's own server replacement behavior.
    """
    return runner([str(adb), "start-server"], cwd=cwd, output_dir=output_dir,
                  timeout_s=timeout_s, summary_bytes=summary_bytes,
                  cleanup_descendants=False)


def resolve_adb(explicit: str | Path | None = None, *, sdk_root: str | Path | None = None,
                environ: Mapping[str, str] | None = None) -> Path:
    """Resolve explicit path > ADB_EXE > explicit SDK > SDK env > default SDK > PATH.

    An invalid explicit choice is an error, never a silent switch to another ADB.
    This only checks filesystem availability; it does not start the ADB server.
    """
    values = os.environ if environ is None else environ
    executable = "adb.exe" if os.name == "nt" else "adb"

    def checked(value: str | Path) -> Path:
        path = Path(value).expanduser().resolve()
        if not path.is_file() or (os.name != "nt" and not os.access(path, os.X_OK)):
            raise FileNotFoundError(f"ADB executable is not usable: {path}")
        if os.name == "nt" and path.suffix.lower() != ".exe":
            raise ValueError("ADB must be an .exe on Windows")
        return path

    if explicit is not None or values.get("ADB_EXE"):
        return checked(explicit if explicit is not None else values["ADB_EXE"])
    if sdk_root is not None:
        return checked(Path(sdk_root) / "platform-tools" / executable)
    candidates = [Path(values[k]) / "platform-tools" / executable
                  for k in ("ANDROID_SDK_ROOT", "ANDROID_HOME") if values.get(k)]
    if values.get("LOCALAPPDATA"):
        candidates.append(Path(values["LOCALAPPDATA"]) / "Android" / "Sdk" / "platform-tools" / executable)
    candidates.append(Path.home() / "Android" / "Sdk" / "platform-tools" / executable)
    for path in candidates:
        if path.is_file():
            return checked(path)
    found = shutil.which(executable, path=values.get("PATH", ""))
    if found:
        return checked(found)
    raise FileNotFoundError("ADB not found; pass --adb-exe or --sdk-root, or set ADB_EXE")


def _adb_argv(adb: Path | str, serial: str, args: Sequence[str]) -> list[str]:
    if not serial or serial.startswith("-") or any(ch.isspace() for ch in serial):
        raise ValueError("A single explicit ADB serial is required")
    return [str(adb), "-s", serial, *args]


def adb_shell_argv(adb: Path | str, serial: str, args: Sequence[str]) -> list[str]:
    """Preserve argv through adb's second, remote POSIX-shell parsing layer.

    Accept command tokens, not shell fragments: pipes/redirections are literal
    arguments. Use an explicitly reviewed remote script for compound operations.
    """
    if isinstance(args, (str, bytes)) or not args or any(
            not isinstance(arg, str) or "\0" in arg for arg in args):
        raise ValueError("Remote command must be nonempty argv without NUL")
    if not args[0]:
        raise ValueError("Remote executable must not be empty")
    return _adb_argv(adb, serial, ["shell", shlex.join(args)])


def device_capabilities(adb: Path | str, serial: str, *, cwd: str | Path,
                        output_dir: str | Path, timeout_s: float = 10,
                        runner: Callable = run_process) -> dict:
    probes = {}

    def probe(name: str, args: list[str]) -> ProcessResult:
        result = runner(_adb_argv(adb, serial, args), cwd=cwd, output_dir=output_dir, timeout_s=timeout_s)
        probes[name] = asdict(result)
        return result

    ps = probe("ps_all", ["shell", "ps", "-A"])
    ps_args = ["shell", "ps", "-A"] if ps.outcome == "succeeded" else None
    if ps_args is None:
        basic = probe("ps_basic", ["shell", "ps"])
        if basic.outcome == "succeeded":
            ps_args = ["shell", "ps"]
    hash_probe = probe("sha256sum", ["shell", "command", "-v", "sha256sum"])
    hash_args = ["shell", "sha256sum"] if hash_probe.outcome == "succeeded" and hash_probe.stdout.strip() else None
    if hash_args is None:
        toybox = probe("toybox_sha256sum", ["shell", "toybox", "sha256sum", "--help"])
        if toybox.outcome == "succeeded":
            hash_args = ["shell", "toybox", "sha256sum"]
    page = probe("runtime_page_size", ["shell", "getconf", "PAGESIZE"])
    text = page.stdout.strip()
    size = int(text) if page.outcome == "succeeded" and text.isascii() and text.isdigit() else None
    if size is not None and (size < 1024 or size & (size - 1)):
        size = None
    return {"serial": serial, "ps_argv": ps_args, "sha256_argv": hash_args,
            "runtime_page_size": size, "complete": ps_args is not None and hash_args is not None and size is not None,
            "probes": probes}


def query_pid(adb: Path | str, serial: str, package: str, *, cwd: str | Path,
              output_dir: str | Path, timeout_s: float = 10,
              runner: Callable = run_process) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
        raise ValueError("package must be an Android package name")
    result = runner(_adb_argv(adb, serial, ["shell", "pidof", package]),
                    cwd=cwd, output_dir=output_dir, timeout_s=timeout_s)
    tokens = result.stdout.split()
    pids = [int(token) for token in tokens if token.isascii() and token.isdigit() and int(token) > 0]
    if result.outcome == "succeeded" and tokens and len(pids) == len(tokens):
        state = "running"
    elif result.outcome in ("succeeded", "failed") and result.exit_code in (0, 1) and not tokens and not result.stderr.strip():
        state = "absent"
    else:
        state, pids = "unknown", []
    return {"state": state, "pids": pids, "operation": asdict(result)}


def preflight_python(script: str | Path, *, cwd: str | Path, output_dir: str | Path,
                     timeout_s: float = 10) -> ProcessResult:
    """Compile syntax only; never execute/import the target or create pycache."""
    path = Path(script).resolve(strict=True)
    code = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(),str(p),'exec'); print('syntax_ok')"
    return run_process([sys.executable, "-X", "utf8", "-B", "-c", code, str(path)],
                       cwd=cwd, output_dir=output_dir, timeout_s=timeout_s)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("run", "adb", "adb-shell", "adb-start-server", "preflight-python", "adb-capabilities", "adb-pid"):
        sub = commands.add_parser(name, help={"run": "Run executable argv without a shell", "adb": "Run one explicit-device ADB operation, without retries", "adb-shell": "Quote literal command tokens for the remote Android shell", "adb-start-server": "Start/reuse ADB daemon without descendant cleanup or a device serial", "preflight-python": "Compile syntax without running the script", "adb-capabilities": "Probe ps, sha256 and runtime getconf", "adb-pid": "Query pidof; empty exit 1 means absent"}[name])
        sub.add_argument("--cwd", required=True, help="Existing child working directory")
        sub.add_argument("--output-dir", required=True, help="Evidence root; each operation creates a unique subdirectory")
        sub.add_argument("--timeout", type=float, default=15 if name == "adb-start-server" else 60, help="Seconds per operation/probe; timeout is unknown completion")
        if name.startswith("adb"):
            sub.add_argument("--adb-exe")
            sub.add_argument("--sdk-root")
            if name != "adb-start-server":
                sub.add_argument("--serial", required=True)
        if name in ("run", "adb", "adb-shell", "adb-start-server"):
            sub.add_argument("--summary-bytes", type=int, default=4096, help="Head+tail bytes per stream, plus truncation marker")
        if name in ("run", "adb", "adb-shell"):
            sub.add_argument("command", nargs=argparse.REMAINDER, help="Use -- before literal executable/ADB argument list")
        if name == "preflight-python":
            sub.add_argument("script", help="Path relative to caller cwd, not --cwd")
        if name == "adb-pid":
            sub.add_argument("package")
    args = parser.parse_args(argv)
    try:
        common = {"cwd": args.cwd, "output_dir": args.output_dir, "timeout_s": args.timeout}
        adb = resolve_adb(args.adb_exe, sdk_root=args.sdk_root) if args.action.startswith("adb") else None
        if args.action in ("run", "adb", "adb-shell"):
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                raise ValueError("Provide arguments after --")
            actual = (adb_shell_argv(adb, args.serial, command) if args.action == "adb-shell"
                      else _adb_argv(adb, args.serial, command) if adb else command)
            result = run_process(actual,
                                 summary_bytes=args.summary_bytes, **common)
            payload = asdict(result)
            status = {"succeeded": 0, "failed": 1, "timed_out": 124, "launch_error": 125}[result.outcome]
        elif args.action == "adb-start-server":
            result = start_adb_server(adb, summary_bytes=args.summary_bytes, **common)
            payload = asdict(result)
            status = {"succeeded": 0, "failed": 1, "timed_out": 124, "launch_error": 125}[result.outcome]
        elif args.action == "preflight-python":
            result = preflight_python(args.script, **common)
            payload = asdict(result)
            status = 0 if result.outcome == "succeeded" else 124 if result.timed_out else 1
        elif args.action == "adb-capabilities":
            payload = device_capabilities(adb, args.serial, **common)
            status = 0 if payload["complete"] else 2
        else:
            payload = query_pid(adb, args.serial, args.package, **common)
            status = 0 if payload["state"] != "unknown" else 2
    except (ValueError, OSError) as exc:
        payload, status = {"outcome": "configuration_error", "diagnostic": str(exc)}, 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
