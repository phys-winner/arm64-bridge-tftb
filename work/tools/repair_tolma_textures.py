"""Repair the three pinned Tolma105 textures; never alter the input ZIP.

Two repairs change section lengths only. CatchARide also corrects its tiny mip
length and derives one tiny texel plus the missing B/A of one main texel.
These two derived texels are documented, not claimed as recovered source data.
Only Python's standard library and the two adjacent retained readers are used.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import zipfile
import zlib

from ttarchive_reader import BytesRange, TTArchive
from texture_meta import parse_texture


ZIP_BYTES = 3282471877
ZIP_SHA = "4169aaa8530fe00c190d2cfa676e122ba7923560047045dd9f8592aa90aecb54"
MEMBER = "data/com.telltalegames.borderlands100/files/Net/Tolma4_Team_TFTB105.ttarch2"
ARCHIVE_BYTES = 9779264
ARCHIVE_SHA = "0f0a74a879d3a31d9bdcb3872b0262df9e6418d046b38df6aa5d2a822ce94848"
PREIMAGES = {
    "obj_signPleaseRemainCalm.d3dtx": {
        "sha256": "aa39954b6f062788fcaaf7c06587d27d3e34761da43b98a631f432a9ca0e13c2",
        "crc64": "457799869da8c7b5", "offset": 17373681, "size": 2097431,
        "flags": 0, "old_default": 327, "new_default": 187, "payload_offset": 279},
    "obj_hyperionPosterE.d3dtx": {
        "sha256": "6911e53422e0493abf88ea0b1c2b9ebf0847b4f684bfa1adf9b33b11fef86986",
        "crc64": "595efbd7ec28570b", "offset": 22060132, "size": 2097426,
        "flags": 0, "old_default": 322, "new_default": 182, "payload_offset": 274},
    "obj_signCatchARideA.d3dtx": {
        "sha256": "28458dea2e851c603267ea147621578f7c8587ce2472473da1ba3c5a748c7669",
        "crc64": "b78a1367f474a21e", "offset": 48086195, "size": 699504,
        "flags": 0, "old_default": 302, "new_default": 362, "payload_offset": 454},
}
CATCH = "obj_signCatchARideA.d3dtx"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(data_zip):
    path = Path(data_zip).resolve(strict=True)
    require(path.stat().st_size == ZIP_BYTES and hash_file(path) == ZIP_SHA,
            "Immutable data.zip preimage mismatch")
    with zipfile.ZipFile(path) as source:
        matches = [e for e in source.infolist() if e.filename == MEMBER]
        require(len(matches) == 1, "Expected exactly one Tolma105 ZIP member")
        member = matches[0]
        require(member.compress_type == zipfile.ZIP_STORED and member.file_size == ARCHIVE_BYTES,
                "Tolma105 ZIP member geometry mismatch")
        raw = source.read(member)
    require(sha(raw) == ARCHIVE_SHA, "Tolma105 archive preimage mismatch")
    archive = TTArchive(BytesRange(raw))
    require(archive.magic == b"ZCTT" and archive.version == 2 and len(archive.entries) == 43,
            "Pinned Tolma105 container geometry mismatch")
    return path, raw, archive


def _srgb_box(pixels):
    def linear(v):
        s = v / 255.0
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4
    def encoded(v):
        s = 12.92 * v if v <= 0.0031308 else 1.055 * v ** (1.0 / 2.4) - 0.055
        return max(0, min(255, math.floor(s * 255.0 + 0.5)))
    rgb = [encoded(sum(linear(p[k]) for p in pixels) / len(pixels)) for k in range(3)]
    alpha = math.floor(sum(p[3] for p in pixels) / len(pixels) + 0.5)
    return bytes(rgb + [alpha])


def _edits(before, after):
    edits, start = [], None
    for index in range(max(len(before), len(after))):
        changed = before[index:index + 1] != after[index:index + 1]
        if changed and start is None:
            start = index
        if start is not None and (not changed or index == max(len(before), len(after)) - 1):
            end = index + 1 if changed else index
            edits.append({"offset": start, "before_hex": before[start:end].hex(),
                          "after_hex": after[start:end].hex()})
            start = None
    return edits


def _repair_entries(archive):
    replacements, reports = {}, []
    for name, pin in PREIMAGES.items():
        entry = archive.by_name[name]
        require(all(entry[k] == pin[k] for k in ("crc64", "offset", "size", "flags")),
                f"Archive row preimage mismatch: {name}")
        original = archive.read_entry(name)
        require(sha(original) == pin["sha256"], f"Texture preimage mismatch: {name}")
        require(struct.unpack_from("<I", original, 4)[0] == pin["old_default"],
                f"Default section preimage mismatch: {name}")
        fixed = bytearray(original)
        struct.pack_into("<I", fixed, 4, pin["new_default"])
        derived = None
        if name == CATCH:
            require(struct.unpack_from("<I", original, 266)[0] == 2,
                    "Tiny mip length preimage mismatch")
            require(original[454:458] == bytes.fromhex("44ff47ff"), "Tiny mip preimage mismatch")
            require(original[458:466] == bytes.fromhex("6b4e44ff6b4e4aff"),
                    "Complete 2x1 parent mip preimage mismatch")
            struct.pack_into("<I", fixed, 266, 4)
            tiny = _srgb_box([original[458:462], original[462:466]])
            require(tiny == bytes.fromhex("6b4e47ff"), "sRGB box filter result mismatch")
            fixed[454:458] = tiny
            top = 175218
            source_offset = top + (254 * 512 + 511) * 4
            corroborating_offset = top + (255 * 512 + 509) * 4
            source_pixel = original[source_offset:source_offset + 4]
            corroborating_pixel = original[corroborating_offset:corroborating_offset + 4]
            require(len(original) == top + 512 * 256 * 4 - 2,
                    "Main mip missing-byte location mismatch")
            require(original[-2:] == b"\x00\x04" and
                    source_pixel == corroborating_pixel == bytes.fromhex("000408ff"),
                    "Matching-RG edge source preimage mismatch")
            require(all(a == 255 for a in original[top + 3::4]),
                    "Complete main-mip alpha is not uniformly opaque")
            fixed.extend(source_pixel[2:])
            derived = {
                "not_lossless_reconstruction": True,
                "tiny_mip": {"mip": 9, "size": [1, 1], "offset": 454,
                             "original_rgba_hex": original[454:458].hex(),
                             "derived_rgba_hex": tiny.hex(), "parent_mip": 8,
                             "parent_size": [2, 1], "parent_offset": 458,
                             "parent_rgba_hex": original[458:466].hex(),
                             "filter": "IEC sRGB transfer; equal box mean in linear RGB; linear alpha; nearest integer, half up"},
                "main_corner": {"mip": 0, "size": [512, 256], "xy": [511, 255],
                                "original_known_rg_hex": original[-2:].hex(),
                                "derived_ba_hex": source_pixel[2:].hex(),
                                "append_offset": len(original), "source_xy": [511, 254],
                                "source_offset": source_offset, "source_rgba_hex": source_pixel.hex(),
                                "corroborating_xy": [509, 255],
                                "corroborating_offset": corroborating_offset,
                                "corroborating_rgba_hex": corroborating_pixel.hex(),
                                "existing_main_bytes_preserved": 524286,
                                "complete_main_pixels_preserved": 131071},
                "authorization": "ROOT explicitly authorized the matching-RG top-edge B/A derivation and sRGB tiny-mip box filter on 2026-10-11"}
        fixed = bytes(fixed)
        metadata = parse_texture(fixed, len(fixed))
        require(metadata["warnings"] == [], f"Repaired texture geometry warnings: {name}")
        require(metadata["format"] == 0 and metadata["payload_offset"] == pin["payload_offset"],
                f"Unexpected repaired texture format/boundary: {name}")
        if name != CATCH:
            require(original[pin["payload_offset"]:] == fixed[pin["payload_offset"]:],
                    f"Header-only repair altered payload: {name}")
        else:
            require(original[458:] == fixed[458:-2], "Existing complete higher mips/main bytes changed")
            require(metadata["width"] == 512 and metadata["height"] == 256 and metadata["mips"] == 10,
                    "CatchARide native RGBA8 geometry mismatch")
        regions = []
        for region in metadata["regions"]:
            offset, size = region["offset"], region["size"]
            payload = fixed[offset:offset + size]
            regions.append(dict(region, sha256=sha(payload), width=max(1, metadata["width"] >> region["mip"]),
                                height=max(1, metadata["height"] >> region["mip"]),
                                alpha_ff_pixels=sum(a == 255 for a in payload[3::4])))
        reports.append({"name": name, "preimage": dict(pin), "original_entry_sha256": sha(original),
                        "repaired_entry_sha256": sha(fixed), "original_bytes": len(original),
                        "repaired_bytes": len(fixed), "byte_edits_exhaustive": _edits(original, fixed),
                        "metadata": metadata, "regions": regions, "derived_pixels": derived})
        replacements[name] = fixed
    return replacements, reports


def _pack(original, archive, replacements):
    body = archive.read_at(0, archive.size)
    changed = bytearray(body[:archive.data_offset])
    cursor, data_parts = archive.data_offset, []
    index_changes = []
    for index, entry in enumerate(archive.entries):
        old_start = archive.data_offset + entry["offset"]
        require(old_start == cursor, "Pinned entries are no longer contiguous in index order")
        payload = replacements.get(entry["name"], body[old_start:old_start + entry["size"]])
        new_offset = sum(len(part) for part in data_parts)
        row_offset = 16 + index * 28
        old_row = bytes(changed[row_offset:row_offset + 28])
        struct.pack_into("<QI", changed, row_offset + 8, new_offset, len(payload))
        if old_row != changed[row_offset:row_offset + 28]:
            index_changes.append({"name": entry["name"], "row": index,
                                  "old_offset": entry["offset"], "new_offset": new_offset,
                                  "old_size": entry["size"], "new_size": len(payload)})
        data_parts.append(payload)
        cursor = old_start + entry["size"]
    trailer = body[cursor:]
    changed.extend(b"".join(data_parts) + trailer)
    blocks, reused = [], 0
    for index, start in enumerate(range(0, len(changed), archive.chunk_size)):
        data = bytes(changed[start:start + archive.chunk_size])
        if index < len(archive.offsets) - 1 and data == archive._chunk(index):
            a, b = archive.offsets[index:index + 2]
            blocks.append(original[a:b])
            reused += 1
        else:
            compressor = zlib.compressobj(level=9, wbits=-15)
            blocks.append(compressor.compress(data) + compressor.flush())
    offsets = [12 + (len(blocks) + 1) * 8]
    for block in blocks:
        offsets.append(offsets[-1] + len(block))
    packed = b"ZCTT" + struct.pack("<II", archive.chunk_size, len(blocks))
    packed += struct.pack(f"<{len(offsets)}Q", *offsets) + b"".join(blocks)
    container = {"original_inner_bytes": len(body), "repaired_inner_bytes": len(changed),
                 "original_chunks": len(archive.offsets) - 1, "repaired_chunks": len(blocks),
                 "compressed_chunks_reused_byte_identical": reused,
                 "chunks_encoded": len(blocks) - reused, "index_row_changes": index_changes,
                 "opaque_trailer_bytes": len(trailer), "opaque_trailer_sha256": sha(trailer)}
    return packed, container


def _validate(archive, repaired, replacements):
    require(repaired.version == archive.version and len(repaired.entries) == len(archive.entries),
            "Repacked index version/count changed")
    rows, changed_names = [], []
    for old, new in zip(archive.entries, repaired.entries):
        require(all(old[k] == new[k] for k in ("name", "crc64", "flags")),
                "Repacked entry name/CRC/flags changed")
        before, after = archive.read_entry(old), repaired.read_entry(new)
        expected = replacements.get(old["name"], before)
        require(after == expected, f"Independent entry readback mismatch: {old['name']}")
        if before != after:
            changed_names.append(old["name"])
            require(parse_texture(after, len(after))["warnings"] == [],
                    "Independent texture re-read failed native geometry")
        rows.append({"name": old["name"], "crc64": old["crc64"], "flags": old["flags"],
                     "original_offset": old["offset"], "repaired_offset": new["offset"],
                     "original_size": old["size"], "repaired_size": new["size"],
                     "original_sha256": sha(before), "repaired_sha256": sha(after),
                     "changed_content": before != after})
    require(set(changed_names) == set(PREIMAGES), "Changed entry allowlist mismatch")
    old_end = archive.data_offset + max(e["offset"] + e["size"] for e in archive.entries)
    new_end = repaired.data_offset + max(e["offset"] + e["size"] for e in repaired.entries)
    require(archive.read_at(old_end, archive.size - old_end) ==
            repaired.read_at(new_end, repaired.size - new_end), "Opaque trailer changed")
    return rows


def repair_archive(data_zip, output_archive, report_path):
    """Produce an exclusive output archive plus full JSON proof; return that proof."""
    output, report = Path(output_archive).resolve(), Path(report_path).resolve()
    source = Path(data_zip).resolve(strict=True)
    require(len({source, output, report}) == 3, "Input/output/report paths must differ")
    require(not output.exists() and not report.exists(), "Output archive/report must not already exist")
    source, raw, archive = _load(source)
    replacements, textures = _repair_entries(archive)
    packed, container = _pack(raw, archive, replacements)
    _validate(archive, TTArchive(BytesRange(packed)), replacements)
    output.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(packed)
    rows = _validate(archive, TTArchive(output), replacements)
    require(source.stat().st_size == ZIP_BYTES and hash_file(source) == ZIP_SHA,
            "Immutable input changed during repair")
    result = {"status": "HOST_REPAIRED_INDEPENDENT_READBACK_PASS", "runtime_gpu_acceptance": "NOT_RUN",
              "input": {"path": str(source), "bytes": ZIP_BYTES, "sha256": ZIP_SHA},
              "member": {"name": MEMBER, "bytes": len(raw), "sha256": sha(raw)},
              "output": {"path": str(output), "bytes": len(packed), "sha256": hash_file(output)},
              "container": container, "textures": textures, "all_entries": rows,
              "changed_entry_names": list(PREIMAGES), "unchanged_entry_count": len(rows) - len(PREIMAGES),
              "claims": ["All 43 entries independently read back; exactly three content changes",
                         "Names, CRC64, flags, entry order and all 135 opaque trailer bytes retained",
                         "Two header-only repairs preserve their entire source payloads",
                         "CatchARide preserves every source byte after its tiny texel; only two main-corner channels are appended",
                         "Derived tiny RGB and main-corner B/A are not exact recovery of missing/corrupt original data"],
              "tools": {name: {"path": str(Path(__file__).with_name(name)),
                               "sha256": hash_file(Path(__file__).with_name(name))}
                        for name in ("repair_tolma_textures.py", "ttarchive_reader.py", "texture_meta.py")}}
    with report.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return result


def self_check(data_zip):
    _, raw, archive = _load(data_zip)
    replacements, textures = _repair_entries(archive)
    packed, _ = _pack(raw, archive, replacements)
    _validate(archive, TTArchive(BytesRange(packed)), replacements)
    malformed = bytearray(replacements[CATCH])
    struct.pack_into("<I", malformed, 266, 2)
    require(bool(parse_texture(malformed, len(malformed))["warnings"]),
            "Negative malformed-tiny-mip geometry check failed")
    try:
        TTArchive(BytesRange(packed[:-1]))
    except ValueError:
        pass
    else:
        raise ValueError("Negative truncated-container check failed")
    require(_srgb_box([bytes.fromhex("6b4e44ff"), bytes.fromhex("6b4e4aff")]) ==
            bytes.fromhex("6b4e47ff"), "sRGB reference self-check failed")
    return {"status": "PASS", "cases": ["three pinned repairs", "43-entry independent container roundtrip",
            "malformed tiny mip rejected", "truncated container rejected", "sRGB tiny reference"],
            "changed_entries": [t["name"] for t in textures], "in_memory_output_sha256": sha(packed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_zip")
    parser.add_argument("output_archive", nargs="?")
    parser.add_argument("report_path", nargs="?")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        require(args.output_archive is None and args.report_path is None, "Self-check does not write outputs")
        result = self_check(args.data_zip)
    else:
        require(args.output_archive is not None and args.report_path is not None,
                "Output archive and report path are required")
        result = repair_archive(args.data_zip, args.output_archive, args.report_path)
    print(json.dumps({k: result[k] for k in ("status",) if k in result} |
                     {"output": result.get("output"), "self_check": result if args.self_check else None}, indent=2))


if __name__ == "__main__":
    main()
