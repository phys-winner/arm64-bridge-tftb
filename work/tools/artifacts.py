#!/usr/bin/env python3
"""Guarded artifact operations; STATE.md remains the only workflow state.

All paths are absolute or relative to the explicitly supplied --root. JSON on
stdout is derived artifact evidence, never a workflow-state database. No archive
extraction, tool discovery, APK build, signing, or device operation is performed.

Use a quiescent tree with one writer. Portable Python does not provide a
cross-platform directory rename-no-replace or protection against hostile races
between a path check and an OS operation. Symlinks, Windows reparse points,
special files, path traversal, and writes into original/decoded_original are
rejected. Copy publication and file replacement use the destination filesystem.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


CHUNK_SIZE = 1024 * 1024
PROTECTED_COMPONENTS = {"original", "decoded_original"}


class ArtifactError(ValueError):
    """A safety check or artifact precondition failed."""


def _reject_link(path, info):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ArtifactError(f"Symlink/reparse point is not allowed: {path}")


def checked_root(root):
    """Return an existing explicit root without following linked ancestors."""
    raw = Path(root)
    if ".." in raw.parts:
        raise ArtifactError("Root must not contain '..'")
    absolute = Path(os.path.abspath(raw))
    for part in reversed((absolute, *absolute.parents)):
        info = part.lstat()
        _reject_link(part, info)
        if not stat.S_ISDIR(info.st_mode):
            raise ArtifactError(f"Root ancestor is not a directory: {part}")
    return absolute


def checked_path(root, path, *, must_exist=True):
    """Validate every component, including links which would escape root."""
    root = checked_root(root)
    raw = Path(path)
    if ".." in raw.parts:
        raise ArtifactError("Artifact paths must not contain '..'")
    absolute = raw if raw.is_absolute() else root / raw
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ArtifactError(f"Path is outside explicit root: {absolute}") from error
    cursor = root
    for index, component in enumerate(relative.parts):
        if ":" in component or component.endswith((".", " ")):
            raise ArtifactError(f"Ambiguous artifact path component: {component!r}")
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if not must_exist and index == len(relative.parts) - 1:
                return absolute
            raise ArtifactError(f"Path or parent does not exist: {cursor}") from None
        _reject_link(cursor, info)
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ArtifactError(f"Parent is not a directory: {cursor}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ArtifactError(f"Special file is not allowed: {cursor}")
    return absolute


def _writable_target(path):
    if any(part.casefold() in PROTECTED_COMPONENTS for part in path.parts):
        raise ArtifactError(f"Immutable input tree cannot be a write target: {path}")


def _under(path, parent):
    return path == parent or parent in path.parents


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_digest(artifact_type, entries):
    payload = {"version": 1, "artifact_type": artifact_type, "entries": entries}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def manifest(root, path):
    """Hash a file or full directory, including empty directories, deterministically.

    Paths inside the report are relative to the artifact, so a decoded tree and
    its independently named copy have identical manifests. Timestamps and modes
    are intentionally excluded: this is content evidence, not a backup format.
    """
    root = checked_root(root)
    target = checked_path(root, path)
    entries = []

    def visit(current):
        checked_path(root, current)
        info = current.lstat()
        relative = current.relative_to(target).as_posix()
        if stat.S_ISDIR(info.st_mode):
            entries.append({"path": relative, "type": "directory"})
            for child in sorted(current.iterdir(), key=lambda item: item.name):
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            digest = _sha256_file(current)
            after = current.lstat()
            _reject_link(current, after)
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ArtifactError(f"File changed while hashing: {current}")
            entries.append({"path": relative, "type": "file",
                            "size": info.st_size, "sha256": digest})
        else:
            raise ArtifactError(f"Special file is not allowed: {current}")

    visit(target)
    entries.sort(key=lambda entry: entry["path"])
    artifact_type = "directory" if target.is_dir() else "file"
    return {"version": 1, "artifact_type": artifact_type, "entries": entries,
            "manifest_sha256": _manifest_digest(artifact_type, entries)}


def compare_manifests(left, right):
    """Compare reports produced by manifest(), without reading report paths."""
    for report in (left, right):
        if report.get("version") != 1 or report.get("artifact_type") not in (
                "file", "directory"):
            raise ArtifactError("Unsupported artifact manifest")
        if report.get("manifest_sha256") != _manifest_digest(
                report["artifact_type"], report["entries"]):
            raise ArtifactError("Artifact manifest digest does not match its entries")
    left_map = {entry["path"]: entry for entry in left["entries"]}
    right_map = {entry["path"]: entry for entry in right["entries"]}
    added = sorted(right_map.keys() - left_map.keys())
    removed = sorted(left_map.keys() - right_map.keys())
    changed = sorted(path for path in left_map.keys() & right_map.keys()
                     if left_map[path] != right_map[path])
    return {"equal": left == right, "added": added, "removed": removed,
            "changed": changed,
            "left_manifest_sha256": left["manifest_sha256"],
            "right_manifest_sha256": right["manifest_sha256"]}


def _cleanup_owned_temp(root, path):
    """Delete only a freshly allocated helper-owned temporary path under root."""
    checked_path(root, path)
    if not path.name.startswith(".artifacts-"):
        raise ArtifactError(f"Refusing to clean a non-helper path: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def copy_decoded(root, source, destination, *, expected_manifest_sha256=None):
    """Copy an immutable decode to a new independent tree; never decode twice.

    Both trees must be inside root, without overlap, and destination's parent
    must already exist. No hardlinks are created and files in the working copy
    are made owner-writable. Source content is checked again before publication.
    """
    root = checked_root(root)
    source = checked_path(root, source)
    destination = checked_path(root, destination, must_exist=False)
    _writable_target(destination)
    if not source.is_dir():
        raise ArtifactError("Decoded baseline must be a directory")
    if destination.exists():
        raise ArtifactError(f"Destination already exists: {destination}")
    if _under(destination, source) or _under(source, destination):
        raise ArtifactError("Source and destination must not overlap")
    before = manifest(root, source)
    if expected_manifest_sha256 is not None and before["manifest_sha256"] != (
            expected_manifest_sha256.lower()):
        raise ArtifactError("Decoded baseline manifest hash does not match")
    temporary = Path(tempfile.mkdtemp(prefix=".artifacts-copy-",
                                      dir=destination.parent))
    try:
        for entry in before["entries"]:
            if entry["path"] == ".":
                continue
            src = checked_path(root, source / entry["path"])
            dst = temporary / entry["path"]
            if entry["type"] == "directory":
                dst.mkdir()
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
                checked_path(root, dst)
                dst.chmod(dst.stat().st_mode | stat.S_IWUSR)
                if os.path.samefile(src, dst):
                    raise ArtifactError(f"Working file aliases its baseline: {src}")
        copied = manifest(root, temporary)
        after = manifest(root, source)
        if not compare_manifests(before, copied)["equal"] or not (
                compare_manifests(before, after)["equal"]):
            raise ArtifactError("Copied tree or baseline changed during copy")
        checked_path(root, destination, must_exist=False)
        if destination.exists():
            raise ArtifactError(f"Destination appeared during copy: {destination}")
        os.rename(temporary, destination)
        return {"source": str(source), "destination": str(destination),
                "manifest_sha256": copied["manifest_sha256"],
                "file_count": sum(entry["type"] == "file"
                                  for entry in copied["entries"])}
    finally:
        if temporary.exists():
            _cleanup_owned_temp(root, temporary)


def parse_patch(value):
    """Parse OFFSET:BEFORE_HEX:AFTER_HEX; OFFSET may be 0x-prefixed or decimal."""
    try:
        offset, before, after = value.split(":")
        result = (int(offset, 0), bytes.fromhex(before), bytes.fromhex(after))
    except (ValueError, TypeError) as error:
        raise ArtifactError("Patch must be OFFSET:BEFORE_HEX:AFTER_HEX") from error
    return result


def _patched_stream(stream, patches, output=None):
    """Hash (and optionally write) an equal-length patched stream."""
    digest = hashlib.sha256()

    def emit(data):
        digest.update(data)
        if output is not None:
            output.write(data)

    stream.seek(0)
    for offset, before, after in patches:
        remaining = offset - stream.tell()
        while remaining:
            data = stream.read(min(CHUNK_SIZE, remaining))
            if not data:
                raise ArtifactError("Source shortened while preparing patch")
            emit(data)
            remaining -= len(data)
        if stream.read(len(before)) != before:
            raise ArtifactError(f"Preimage changed at offset {offset:#x}")
        emit(after)
    for data in iter(lambda: stream.read(CHUNK_SIZE), b""):
        emit(data)
    return digest.hexdigest()


def patch_binary(root, path, expected_sha256, patches, *, verify_only=False):
    """Verify all guards before any write, then atomically replace one file.

    Only equal-length, non-overlapping patches are supported. A full input hash
    and each exact preimage are mandatory. Already-patched inputs fail instead
    of silently treating a potentially different artifact as accepted.
    """
    root = checked_root(root)
    target = checked_path(root, path)
    if not verify_only:
        _writable_target(target)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ArtifactError("Binary patch target must be a regular file")
    if not verify_only and info.st_nlink != 1:
        raise ArtifactError("Binary patch target must not have hardlink aliases")
    expected_sha256 = expected_sha256.lower()
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef"
                                         for c in expected_sha256):
        raise ArtifactError("Expected SHA-256 must contain exactly 64 hex digits")
    patches = sorted(patches, key=lambda item: item[0])
    if not patches:
        raise ArtifactError("At least one patch is required")
    previous_end = 0
    for offset, before, after in patches:
        if (not isinstance(offset, int) or offset < 0 or not before or
                len(before) != len(after)):
            raise ArtifactError("Patches need a nonnegative offset and equal nonzero lengths")
        if offset < previous_end:
            raise ArtifactError("Patches must not overlap")
        if offset + len(before) > info.st_size:
            raise ArtifactError(f"Patch extends beyond file at offset {offset:#x}")
        previous_end = offset + len(before)
    if _sha256_file(target) != expected_sha256:
        raise ArtifactError("Binary input SHA-256 does not match")
    # Validate every preimage and predict output before allocating a temp file.
    with target.open("rb") as source:
        predicted = _patched_stream(source, patches)
    result = {"path": str(target), "input_sha256": expected_sha256,
              "output_sha256": predicted, "verify_only": verify_only,
              "patches": [{"offset": hex(offset), "before": before.hex(),
                           "after": after.hex()} for offset, before, after in patches]}
    if verify_only:
        return result
    descriptor, name = tempfile.mkstemp(prefix=".artifacts-patch-", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output, target.open("rb") as source:
            actual = _patched_stream(source, patches, output)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(stat.S_IMODE(info.st_mode))
        checked_path(root, target)
        current = target.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                current.st_nlink) != (info.st_dev, info.st_ino, info.st_size,
                                     info.st_mtime_ns, info.st_nlink):
            raise ArtifactError("Binary target changed before replacement")
        if actual != predicted or _sha256_file(target) != expected_sha256:
            raise ArtifactError("Binary content changed before replacement")
        os.replace(temporary, target)
        return result
    finally:
        if temporary.exists():
            # A source read-only mode can have been copied before a failed check.
            temporary.chmod(temporary.stat().st_mode | stat.S_IWUSR)
            _cleanup_owned_temp(root, temporary)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
            ("manifest", "Print derived SHA-256 content evidence for a file/tree"),
            ("compare", "Compare file/tree contents (exit 1 for differences)"),
            ("copy-decoded", "Make one independent, verified working copy"),
            ("patch", "Verify/apply equal-length guarded binary patches")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--root", required=True, help="Explicit existing project root")
        if name == "manifest":
            command.add_argument("--path", required=True)
        elif name == "compare":
            command.add_argument("--left", required=True)
            command.add_argument("--right", required=True)
        elif name == "copy-decoded":
            command.add_argument("--source", required=True)
            command.add_argument("--destination", required=True)
            command.add_argument("--expect-manifest-sha256")
        else:
            command.add_argument("--path", required=True)
            command.add_argument("--expect-sha256", required=True)
            command.add_argument("--patch", action="append", required=True,
                                 metavar="OFFSET:BEFORE_HEX:AFTER_HEX")
            command.add_argument("--verify-only", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "manifest":
            result = manifest(args.root, args.path)
        elif args.command == "compare":
            result = compare_manifests(manifest(args.root, args.left),
                                       manifest(args.root, args.right))
        elif args.command == "copy-decoded":
            result = copy_decoded(args.root, args.source, args.destination,
                                 expected_manifest_sha256=args.expect_manifest_sha256)
        else:
            result = patch_binary(args.root, args.path, args.expect_sha256,
                                  [parse_patch(value) for value in args.patch],
                                  verify_only=args.verify_only)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
        return 1 if args.command == "compare" and not result["equal"] else 0
    except (ArtifactError, OSError) as error:
        print(f"artifacts: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
