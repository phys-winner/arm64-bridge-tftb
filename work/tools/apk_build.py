#!/usr/bin/env python3
"""Incremental APK packaging, not native compilation or runtime acceptance.

Paths are relative to the caller's cwd. Sources: GAME/app and
GAME/splits/NAME. Outputs: GAME/out/base.apk and out/splits/NAME.apk.
Only tools under --tool-root are used, except the explicitly selected Java and
the mandatory portable signer. Cache/evidence lives in out/build-cache.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Callable
import uuid
import xml.etree.ElementTree as ET
import zipfile

from process_tools import run_process


EXPECTED_CERT = "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"
SCHEMA = 1
ANDROID = "{http://schemas.android.com/apk/res/android}"


class BuildError(RuntimeError):
    def __init__(self, message: str, *, outcome: str = "validation_failed", evidence: str | None = None):
        super().__init__(message)
        self.outcome, self.evidence = outcome, evidence


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def tree_hash(path: Path, *, exclude: set[str] = frozenset()) -> str:
    """Content-based hash, with root-only exclusions; mtimes are not trusted."""
    digest = hashlib.sha256()
    if _link(path):
        raise BuildError(f"Source/framework tree must not be a symlink or junction: {path}")
    for directory, dirs, files in os.walk(path):
        current = Path(directory)
        if current == path:
            dirs[:] = [name for name in dirs if name not in exclude]
            files = [name for name in files if name not in exclude]
        dirs.sort()
        for name in dirs:
            if _link(current / name):
                raise BuildError(f"Source/framework link is not a stable input: {current / name}")
        for name in sorted(files):
            source = current / name
            if _link(source) or not source.is_file():
                raise BuildError(f"Source/framework input must be a regular file: {source}")
            relative = source.relative_to(path).as_posix()
            digest.update(json.dumps([relative, file_hash(source)], ensure_ascii=False).encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def parse_badging(text: str) -> dict:
    package_lines = re.findall(r"^package:\s*(.*)$", text, re.MULTILINE)
    if len(package_lines) != 1:
        raise BuildError("Expected exactly one package line from aapt2 badging")
    attrs = dict(re.findall(r"([A-Za-z][A-Za-z0-9_-]*)='([^']*)'", package_lines[0]))
    if not attrs.get("name") or not attrs.get("versionCode", "").isdigit():
        raise BuildError("Badging is missing package name or numeric versionCode")
    if not attrs.get("versionCodeMajor", "0").isdigit():
        raise BuildError("Badging has an invalid versionCodeMajor")
    native_lines = re.findall(r"^native-code:\s*(.*)$", text, re.MULTILINE)
    if len(native_lines) > 1:
        raise BuildError("Ambiguous native-code lines in badging")
    return {"package": attrs["name"], "version_code": attrs["versionCode"],
            "version_code_major": attrs.get("versionCodeMajor", "0"),
            "version_name": attrs.get("versionName", ""), "split": attrs.get("split", ""),
            "abis": re.findall(r"'([^']+)'", native_lines[0]) if native_lines else []}


def parse_certificate(text: str) -> str:
    digests = re.findall(r"^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F:]+)\s*$", text, re.MULTILINE)
    normalized = [value.replace(":", "").lower() for value in digests]
    if normalized != [EXPECTED_CERT]:
        raise BuildError(f"Signing certificate mismatch: expected one mandatory test signer, got {normalized}")
    return normalized[0]


@contextmanager
def _project_lock(cache_root: Path):
    lock = cache_root / "packaging.lock"
    token = f"{os.getpid()}:{uuid.uuid4()}"
    try:
        with lock.open("x", encoding="utf-8") as stream:
            stream.write(token)
    except FileExistsError as exc:
        raise BuildError(f"Packaging lock exists: {lock}; inspect its owner before removing a stale lock") from exc
    try:
        yield
    finally:
        if lock.is_file() and lock.read_text(encoding="utf-8") == token:
            lock.unlink()


class ApkBuilder:
    def __init__(self, project_root: str | Path, tool_root: str | Path, java: str | Path,
                 *, build_tools: str = "37.0.0", arm64_bridge: bool = False,
                 framework_path: str | Path | None = None,
                 timeout_s: float = 600, runner: Callable = run_process):
        self.project = Path(project_root).resolve(strict=True)
        self.tools = Path(tool_root).resolve(strict=True)
        self.java = Path(java).resolve(strict=True)
        if not self.project.is_dir() or not self.tools.is_dir() or not self.java.is_file():
            raise BuildError("project-root/tool-root must be directories and java a file")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", build_tools) or ".." in build_tools:
            raise BuildError("build-tools must be a version directory name")
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise BuildError("timeout must be finite and positive")
        self.app = self.project / "app"
        self.out = self.project / "out"
        self.cache_root = self.out / "build-cache"
        self.arm64_bridge, self.timeout_s, self.runner = arm64_bridge, timeout_s, runner
        self.apktool = self.tools / "apktool.jar"
        directory = self.tools / "sdk" / "build-tools" / build_tools
        self.aapt = directory / "aapt2.exe"
        self.zipalign = directory / "zipalign.exe"
        self.framework = Path(framework_path).resolve() if framework_path is not None else self.project / "work/tool-cache/apktool-framework"
        if self.framework.is_relative_to(self.app.resolve()):
            raise BuildError("framework-path must be outside canonical app sources")
        sign_root = os.environ.get("APK_SIGNER_ROOT")
        if not sign_root:
            raise BuildError("APK_SIGNER_ROOT must select the portable signer directory")
        sign_root = Path(sign_root).resolve(strict=True)
        self.signer = sign_root / "apksigner.jar"
        self.key = sign_root / "testkey.pk8"
        self.cert = sign_root / "testkey.x509.pem"
        self.tool_files = [self.java, self.apktool, self.aapt, self.zipalign, self.signer, self.key, self.cert]
        for path in self.tool_files:
            if not path.is_file():
                raise BuildError(f"Required tool/signing input missing: {path}")
        for path in (self.apktool, self.aapt, self.zipalign):
            if not path.resolve().is_relative_to(self.tools):
                raise BuildError(f"APK tool resolves outside tool-root: {path}")

    def _tool_identity(self) -> dict:
        return {"schema": SCHEMA, "files": {str(path): file_hash(path) for path in self.tool_files},
                "framework_path": str(self.framework), "framework": tree_hash(self.framework),
                "arm64_bridge": self.arm64_bridge, "zipalign": ["-P", "16", "4"],
                "certificate": EXPECTED_CERT, "apktool": ["b", "-f", "--aapt", "--frame-path"]}

    def _prepare_framework(self):
        """Stabilize apktool's bundled default before fingerprinting, without Java.

        Existing 1.apk and extra framework files are retained and fingerprinted.
        This creates only a missing 1.apk from the chosen apktool's own resource;
        external/OEM frameworks must be prepared by decode with the same -p path.
        """
        self.framework.mkdir(parents=True, exist_ok=True)
        if (self.framework / "1.apk").is_file():
            return
        with zipfile.ZipFile(self.apktool) as archive:
            defaults = [name for name in ("prebuilt/android-framework.jar", "brut/androlib/android-framework.jar") if name in archive.namelist()]
            if len(defaults) != 1:
                raise BuildError(f"No unambiguous bundled default framework in {self.apktool}; prepare {self.framework} during decode")
            # Exclusive creation refuses to overwrite a concurrently prepared input.
            with archive.open(defaults[0]) as source, (self.framework / "1.apk").open("xb") as destination:
                shutil.copyfileobj(source, destination, 1024 * 1024)

    def _check_output_path(self, path: Path):
        if not path.resolve().is_relative_to(self.project):
            raise BuildError(f"Output resolves outside project-root: {path}")
        for component in [path, *path.parents]:
            if component == self.project:
                break
            if _link(component):
                raise BuildError(f"Output path must not use symlinks or junctions: {component}")

    def _source(self, name: str) -> Path:
        source = self.app if name == "base" else self.project / "splits" / name
        if not source.is_dir() or not source.resolve().is_relative_to(self.project):
            raise BuildError(f"Missing or external canonical source tree: {source}")
        for required in ("apktool.yml", "AndroidManifest.xml"):
            if not (source / required).is_file():
                raise BuildError(f"Incomplete source target {name}: missing {source / required}")
        return source

    def _selected(self, target: str) -> list[str]:
        if target not in ("base", "splits", "all"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", target) or ".." in target:
                raise BuildError("Target must be base, splits, all, or a split directory name")
            return [target]
        if target == "base":
            return ["base"]
        split_root = self.project / "splits"
        if _link(split_root):
            raise BuildError(f"Split source directory must not be a link: {split_root}")
        names = sorted(path.name for path in split_root.iterdir() if path.is_dir()) if split_root.is_dir() else []
        for name in names:
            if name in ("base", "splits", "all") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or ".." in name:
                raise BuildError(f"Invalid/reserved split directory name: {name}")
        if target == "splits" and not names:
            raise BuildError("No split source trees under splits")
        return (["base"] if target == "all" else []) + names

    def _source_hash(self, name: str) -> str:
        exclusions = {"build", "dist"}
        if name == "base":
            exclusions.add("splits")
        return tree_hash(self._source(name), exclude=exclusions)

    def _fingerprint(self, name: str, source_hash: str, tools: dict) -> str:
        payload = {"target": name, "source": source_hash, "tools": tools}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def _command(self, argv: list[str], evidence: Path) -> str:
        result = self.runner(argv, cwd=self.project, output_dir=evidence, timeout_s=self.timeout_s)
        if result.outcome != "succeeded":
            raise BuildError(f"Packaging operation {result.outcome}; inspect full logs", outcome=result.outcome, evidence=result.stderr_log)
        # Parsers consume the full log; the runner's summary may be truncated.
        return Path(result.stdout_log).read_text(encoding="utf-8", errors="replace")

    def _validate_identity(self, name: str, info: dict):
        fields = ("package", "version_code", "version_code_major", "version_name", "split")
        if not isinstance(info, dict) or any(not isinstance(info.get(field), str) for field in fields) or not isinstance(info.get("abis"), list):
            raise BuildError(f"Incomplete badging identity for target {name}")
        expected_split = "" if name == "base" else name
        if info["split"] != expected_split:
            raise BuildError(f"Target {name} has split identity {info['split']!r}, expected {expected_split!r}")
        if self.arm64_bridge:
            allowed = [["arm64-v8a"]] if name == "base" else [[], ["arm64-v8a"]]
            if info["abis"] not in allowed:
                raise BuildError(f"Target {name} has invalid bridge ABIs: {info['abis']}")

    def _zip_gate(self, name: str, apk: Path) -> list[str]:
        with zipfile.ZipFile(apk) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise BuildError(f"Duplicate ZIP entries in target {name}")
            guest_prefixes = ("assets/guest_libs/", "assets/guestlib/armeabi-v7a/")
            guests = [info for info in archive.infolist() if info.filename.startswith(guest_prefixes) and info.filename.endswith(".so")]
            if self.arm64_bridge:
                if name == "base" and not guests:
                    raise BuildError("Bridge base has no STORED guest libraries")
                expected = {path.relative_to(self._source(name)).as_posix()
                            for prefix in guest_prefixes
                            for path in (self._source(name) / prefix).rglob("*.so") if path.is_file()}
                if {info.filename for info in guests} != expected:
                    raise BuildError(f"Packaged guest library set differs from canonical sources in target {name}")
                if any(info.compress_type != zipfile.ZIP_STORED for info in guests):
                    raise BuildError(f"Guest libraries must be STORED in target {name}")
                native = [path for path in names if path.startswith("lib/") and not path.endswith("/")]
                if any(not path.startswith("lib/arm64-v8a/") or not path.endswith(".so") for path in native):
                    raise BuildError(f"Unexpected native library/artifact path in target {name}")
            return [info.filename for info in guests]

    def _cached(self, name: str, fingerprint: str, final: Path, metadata: Path) -> dict | None:
        try:
            cached = json.loads(metadata.read_text(encoding="utf-8"))
            if cached["schema"] != SCHEMA or cached["fingerprint"] != fingerprint or cached["artifact_sha256"] != file_hash(final):
                return None
            if cached["certificate"] != EXPECTED_CERT:
                return None
            self._validate_identity(name, cached["identity"])
            self._zip_gate(name, final)
            return {**cached, "cached": True, "artifact": str(final)}
        except (OSError, ValueError, KeyError, TypeError, BuildError, zipfile.BadZipFile):
            return None

    def _package(self, name: str, fingerprint: str, target_cache: Path) -> dict:
        attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=target_cache))
        unsigned, aligned, signed = (attempt / filename for filename in ("unsigned.apk", "aligned.apk", "signed.apk"))
        evidence = attempt / "logs"
        self._command([str(self.java), "-jar", str(self.apktool), "b", str(self._source(name)),
                       "-f", "--aapt", str(self.aapt), "--frame-path", str(self.framework), "-o", str(unsigned)], evidence)
        self._command([str(self.zipalign), "-f", "-P", "16", "4", str(unsigned), str(aligned)], evidence)
        self._command([str(self.java), "-jar", str(self.signer), "sign", "--key", str(self.key),
                       "--cert", str(self.cert), "--out", str(signed), str(aligned)], evidence)
        certificate = parse_certificate(self._command([str(self.java), "-jar", str(self.signer), "verify", "--verbose", "--print-certs", str(signed)], evidence))
        self._command([str(self.zipalign), "-c", "-P", "16", "4", str(signed)], evidence)
        identity = parse_badging(self._command([str(self.aapt), "dump", "badging", str(signed)], evidence))
        self._validate_identity(name, identity)
        guests = self._zip_gate(name, signed)
        return {"schema": SCHEMA, "fingerprint": fingerprint, "artifact_sha256": file_hash(signed),
                "identity": identity, "certificate": certificate, "guest_libraries": guests,
                "cached": False, "artifact": str(signed), "evidence": str(evidence)}

    def _set_identity(self, results: dict[str, dict]):
        baseline = results["base"]
        key = lambda item: (item["identity"]["package"], item["identity"]["version_code"], item["identity"]["version_code_major"], item["identity"]["version_name"], item["certificate"])
        for name, item in results.items():
            if key(item) != key(baseline):
                raise BuildError(f"Split set package/version/certificate mismatch: {name}")

    def build(self, target: str = "all") -> dict:
        names = self._selected(target)
        for name in names:
            self._source(name)
        if target == "all":
            for name in names:
                manifest = ET.parse(self._source(name) / "AndroidManifest.xml").getroot()
                needed = [element.attrib.get(ANDROID + "name") for element in manifest.findall("uses-split")]
                if any(split not in names or split == "base" for split in needed):
                    raise BuildError(f"Incomplete split set: {name} requires {needed}")
        self._check_output_path(self.cache_root)
        self.cache_root.mkdir(parents=True, exist_ok=True)
        with _project_lock(self.cache_root):
            self._prepare_framework()
            tools = self._tool_identity()
            hashes = {name: self._source_hash(name) for name in names}
            results, destinations, metadata_paths = {}, {}, {}
            for name in names:
                target_cache = self.cache_root / name
                self._check_output_path(target_cache)
                target_cache.mkdir(parents=True, exist_ok=True)
                final = self.out / "base.apk" if name == "base" else self.out / "splits" / f"{name}.apk"
                self._check_output_path(final)
                metadata = target_cache / "cache.json"
                fingerprint = self._fingerprint(name, hashes[name], tools)
                results[name] = self._cached(name, fingerprint, final, metadata) or self._package(name, fingerprint, target_cache)
                destinations[name], metadata_paths[name] = final, metadata
            # Refuse to publish if inputs changed while the operation was running.
            if hashes != {name: self._source_hash(name) for name in names} or tools != self._tool_identity():
                raise BuildError("Source/tool/signing inputs changed during packaging; no candidate was published")
            if target == "all":
                self._set_identity(results)
            for name, item in results.items():
                if item["cached"]:
                    continue
                destination = destinations[name]
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(item["artifact"], destination)
                item["artifact"] = str(destination)
                temporary = metadata_paths[name].with_suffix(".json.tmp")
                temporary.write_text(json.dumps(item, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                os.replace(temporary, metadata_paths[name])
            return {"outcome": "packaging_validated", "runtime_acceptance": False, "target": target,
                    "split_set_checked": target == "all", "framework_path": str(self.framework),
                    "framework_sha256": tools["framework"], "targets": results}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--tool-root", required=True)
    parser.add_argument("--java", required=True, help="Explicit Java executable; no PATH lookup")
    parser.add_argument("--build-tools", default="37.0.0")
    parser.add_argument("--framework-path", help="Persistent apktool -p directory, shared with decode; default GAME/work/tool-cache/apktool-framework")
    parser.add_argument("--target", default="all", help="base | splits | all | SPLIT_NAME")
    parser.add_argument("--arm64-bridge", action="store_true", help="Static arm64 ABI and STORED guest gates; not runtime acceptance")
    parser.add_argument("--timeout", type=float, default=600, help="Seconds per tool operation; timeout is unknown completion")
    args = parser.parse_args(argv)
    try:
        response = ApkBuilder(args.project_root, args.tool_root, args.java, build_tools=args.build_tools,
                              arm64_bridge=args.arm64_bridge, framework_path=args.framework_path,
                              timeout_s=args.timeout).build(args.target)
        code = 0
    except (BuildError, OSError, ValueError, ET.ParseError, zipfile.BadZipFile) as exc:
        response = {"outcome": getattr(exc, "outcome", "configuration_error"), "diagnostic": str(exc),
                    "evidence": getattr(exc, "evidence", None), "runtime_acceptance": False}
        code = 124 if response["outcome"] == "timed_out" else 1
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
