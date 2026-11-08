#!/usr/bin/env python3
"""Attribute saved logcat observations and provide a small progress watchdog.

CLI:
    python route_signals.py analyze LOG --start EPOCH --package com.example.game \
        --pid 1234 --guard-token r4=0x00000000

Input is `adb logcat -v epoch` without extra modifiers: epoch, PID, TID,
priority, tag: message. Threadtime, UID modifiers, raw tombstones and multiline
messages without logcat prefixes are unsupported and retained as ambiguous.
Native writer attribution accepts explicit pid/package identity on the current
line or recent preceding lines of the same writer (2 seconds / 50 input lines).
A new tombstone header clears that context. Unknown attribution needs review.
Run start excludes stale entries, including old records with reused PIDs; PID
reuse *during* the run cannot be resolved without separate process evidence.

Guard tokens are opt-in, literal and bounded by non-word characters. A register
value is not a universal crash signature. Summaries are derived observations,
not route acceptance or durable state. Evidence lists/snippets are bounded;
counts include omitted evidence. No files or devices are modified.

Exit codes: 0 no failure observed with current target evidence; 1 target failure;
2 needs review, invalid arguments, or unreadable input. Zero is not a route PASS.
"""
import argparse
from collections import Counter
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import sys
import time


EPOCH_LINE = re.compile(
    r"^\s*(?P<timestamp>\d+(?:\.\d+)?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<priority>[VDIWEFAS])\s+(?P<tag>[^:]+):\s?(?P<message>.*)$")
PID_REFERENCE = re.compile(r"(?<![\w])pid\s*[:=]?\s*(\d+)(?![\w])", re.IGNORECASE)
PACKAGE_IDENTITY = re.compile(
    r"(?:\bProcess:\s*|>>>\s*)([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+(?:[:][A-Za-z0-9_.-]+)?)(?=\s|,|$|<<<)")
# AndroidRuntime and libc normally write from the affected application PID;
# DEBUG/crash_dump can write tombstones on behalf of another process.
SYSTEM_WRITERS = {"debug", "debuggerd", "crash_dump32", "crash_dump64", "tombstoned"}
FATAL_PATTERNS = (
    ("android_runtime", re.compile(r"\bFATAL EXCEPTION\b")),
    ("native_signal", re.compile(r"\bFatal signal\s+\d+\b", re.IGNORECASE)),
    ("native_signal_summary", re.compile(r"\bsignal\s+\d+\s+\(SIG[A-Z0-9]+\)")),
    ("native_abort", re.compile(r"\b(?:Abort message:|JNI DETECTED ERROR IN APPLICATION\b|FORTIFY:)")),
    ("guest_abort", re.compile(r"\bGuest called abort\(\)")),
    ("guest_guard", re.compile(r"(?<!\w)(?:GUEST_GUARD_FAILED|guest guard failed)(?!\w)", re.IGNORECASE)),
)


@dataclass(frozen=True)
class LogEntry:
    line: int
    timestamp: float
    pid: int
    tid: int
    priority: str
    tag: str
    message: str


def exact_token_pattern(token):
    if not token or "\n" in token or "\r" in token:
        raise ValueError("markers must be nonempty single-line literal tokens")
    return re.compile(r"(?<!\w)" + re.escape(token) + r"(?!\w)")


def parse_epoch(line, index):
    match = EPOCH_LINE.fullmatch(line.rstrip("\r\n"))
    if not match:
        return None
    stamp = float(match["timestamp"])
    if not math.isfinite(stamp):
        return None
    return LogEntry(index, stamp, int(match["pid"]), int(match["tid"]),
                    match["priority"], match["tag"].strip(), match["message"])


def identity(entry):
    return ({int(value) for value in PID_REFERENCE.findall(entry.message)},
            set(PACKAGE_IDENTITY.findall(entry.message)))


def attribute(entry, target_pids, package, reference):
    pids, packages = reference
    matching_package = any(value == package or value.startswith(package + ":") for value in packages)
    other_package = bool(packages) and not matching_package
    matching_pid = bool(pids & target_pids)
    if other_package and (matching_pid or entry.pid in target_pids):
        return "ambiguous", "PID and explicit package identity conflict"
    if matching_package or matching_pid:
        return "target", "explicit target PID/package identity"
    if pids and entry.pid in target_pids:
        return "ambiguous", "selected writer references another PID"
    if other_package or pids:
        return "unrelated", "explicit identity names another process"
    if entry.pid in target_pids:
        return "target", "selected writer PID during this run"
    if entry.tag.lower() in SYSTEM_WRITERS:
        return "ambiguous", "system/runtime writer without attributable target identity"
    return "unrelated", "writer PID is outside the selected target PIDs"


def failure_kinds(entry, guard_patterns):
    found = [name for name, pattern in FATAL_PATTERNS if pattern.search(entry.message)]
    # Tombstone metadata/backtrace lines also use F. Attribute the actual
    # signal/abort instead of treating a pre-identity fingerprint as a crash.
    if entry.priority == "F" and entry.tag.lower() not in SYSTEM_WRITERS:
        found.append("fatal_priority")
    for token, pattern in guard_patterns:
        if pattern.search(entry.message):
            found.append("guard_token:" + token)
    return found


def analyze(lines, *, target_pids, package, start_timestamp, guard_tokens=(),
            max_evidence=50, snippet_limit=300, source="saved logcat -v epoch"):
    """Stream saved log lines and return bounded JSON-compatible observations."""
    target_pids = set(target_pids)
    if any(not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 for pid in target_pids):
        raise ValueError("target PIDs must be positive integers")
    if not package or not math.isfinite(start_timestamp) or start_timestamp < 0:
        raise ValueError("package and a finite nonnegative run start timestamp are required")
    if max_evidence < 1 or snippet_limit < 1:
        raise ValueError("evidence and snippet limits must be positive")
    guard_patterns = [(token, exact_token_pattern(token)) for token in guard_tokens]
    buckets = {"target_failures": [], "unrelated": [], "ambiguous": []}
    counts = Counter({key: 0 for key in buckets})
    contexts = {}
    lines_seen = parsed = current_target_records = 0

    def add(bucket, index, snippet, reason, entry=None, kinds=()):
        counts[bucket] += 1
        if len(buckets[bucket]) >= max_evidence:
            return
        record = {"line": index, "snippet": snippet[:snippet_limit],
                  "snippet_truncated": len(snippet) > snippet_limit,
                  "reason": reason, "kinds": list(kinds)}
        if entry is not None:
            record.update(timestamp=entry.timestamp, writer_pid=entry.pid, writer_tid=entry.tid, tag=entry.tag)
        buckets[bucket].append(record)

    for index, raw in enumerate(lines, 1):
        lines_seen = index
        if not raw.strip() or raw.lstrip().startswith("--------- beginning of "):
            continue
        entry = parse_epoch(raw, index)
        if entry is None:
            add("ambiguous", index, raw.rstrip("\r\n"), "unsupported or malformed logcat line")
            continue
        parsed += 1
        kinds = failure_kinds(entry, guard_patterns)
        if entry.timestamp < start_timestamp:
            if kinds:
                add("unrelated", index, entry.message, "before this run start (stale evidence)", entry, kinds)
            continue

        key = (entry.pid, entry.tid, entry.tag.lower())
        if entry.message.startswith("*** ***"):
            contexts.pop(key, None)
        direct = identity(entry)
        reference = direct
        if any(direct):
            contexts[key] = (entry.timestamp, index, direct)
        elif key in contexts:
            stamp, context_line, previous = contexts[key]
            if 0 <= entry.timestamp - stamp <= 2 and index - context_line <= 50:
                reference = previous
            else:
                contexts.pop(key, None)
        attribution, reason = attribute(entry, target_pids, package, reference)
        if attribution == "target":
            current_target_records += 1
        if kinds:
            bucket = "target_failures" if attribution == "target" else attribution
            add(bucket, index, entry.message, reason, entry, kinds)

    warnings = []
    if not target_pids:
        warnings.append("no selected target PIDs: absence of a failure cannot establish target execution")
    if not current_target_records:
        warnings.append("no current attributable target records")
    status = ("target_failure" if counts["target_failures"] else
              "needs_review" if counts["ambiguous"] or warnings else "no_failure_observed")
    return {"schema_version": 1, "source": source, "format": "logcat -v epoch",
            "status": status, "exit_code": {"no_failure_observed": 0, "target_failure": 1, "needs_review": 2}[status],
            "package": package, "target_pids": sorted(target_pids), "start_timestamp": start_timestamp,
            "lines_seen": lines_seen, "parsed_lines": parsed, "current_target_records": current_target_records,
            "counts": dict(counts), "warnings": warnings, **buckets,
            "evidence_truncated": {key: counts[key] > len(buckets[key]) for key in buckets}}


class ProgressWatchdog:
    """Caller-driven monotonic deadline; only new explicit route markers advance it.

    No thread or timer is created. The runner calls check() while waiting and
    fail() on a classifier/runner failure. The first failure is immutable from
    the caller's perspective, and its callback fires at most once. Repeated
    copies of the same marker do not count as new progress.
    """
    def __init__(self, timeout_seconds, progress_markers, *, clock=time.monotonic, on_first_failure=None):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout_seconds = timeout_seconds
        self._patterns = {marker: exact_token_pattern(marker) for marker in progress_markers}
        self._clock = clock
        self._on_first_failure = on_first_failure
        self._last_progress = clock()
        self._seen = set()
        self._first_failure = None

    @property
    def first_failure(self):
        return dict(self._first_failure) if self._first_failure is not None else None

    def fail(self, reason, detail=""):
        if self._first_failure is None:
            self._first_failure = {"reason": reason, "detail": detail, "monotonic_timestamp": self._clock()}
            if self._on_first_failure is not None:
                self._on_first_failure(self.first_failure)
        return self.first_failure

    def check(self):
        if self._first_failure is None and self._clock() - self._last_progress >= self.timeout_seconds:
            self.fail("no_progress", f"no new explicit progress marker for {self.timeout_seconds} seconds")
        return self.first_failure

    def mark_progress(self, marker):
        if self.check() is not None or marker not in self._patterns or marker in self._seen:
            return False
        self._seen.add(marker)
        self._last_progress = self._clock()
        return True

    def observe(self, message):
        """Offer a log message; ordinary log traffic cannot extend the deadline."""
        if self.check() is not None:
            return False
        advanced = False
        for marker, pattern in self._patterns.items():
            if pattern.search(message):
                advanced = self.mark_progress(marker) or advanced
        return advanced


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("analyze", help="analyze a saved epoch log; emit only JSON")
    command.add_argument("log", type=Path)
    command.add_argument("--start", type=float, required=True, help="run start as Unix epoch seconds")
    command.add_argument("--package", required=True)
    command.add_argument("--pid", type=int, action="append", default=[])
    command.add_argument("--guard-token", action="append", default=[])
    command.add_argument("--max-evidence", type=int, default=50)
    command.add_argument("--snippet-limit", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        with args.log.open(encoding="utf-8", errors="strict") as stream:
            result = analyze(stream, target_pids=args.pid, package=args.package, start_timestamp=args.start,
                             guard_tokens=args.guard_token, max_evidence=args.max_evidence,
                             snippet_limit=args.snippet_limit, source=str(args.log.resolve()))
    except (OSError, UnicodeError, ValueError) as error:
        result = {"schema_version": 1, "status": "needs_review", "exit_code": 2, "error": str(error)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
