"""TFTB MSV5 texture v5 parser, adapted from retained TWAU audit_textures.py.

Native description fields in TFTB add import specular power, layout, surface
gamma, resource usage, specular gloss and leading face indices.
Only metadata is decoded; the texture payload is never materialized here.
"""
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_texture(data, size):
    require(data[:4] == b"5VSM", "unsupported texture meta magic")
    default_size, debug_size, async_size, types = struct.unpack_from("<4I", data, 4)
    start = 20 + types * 12
    end = start + default_size
    declared_size = end + debug_size + async_size
    require(declared_size <= size, "MSV5 sections exceed entry bounds")
    require(end <= len(data), "bounded metadata prefix too small")
    pos = start

    def unpack(fmt):
        nonlocal pos
        count = struct.calcsize("<" + fmt)
        require(pos + count <= end, "metadata value exceeds default section")
        value = struct.unpack_from("<" + fmt, data, pos)
        pos += count
        return value[0] if len(value) == 1 else value

    def block():
        nonlocal pos
        length = unpack("I")
        require(4 <= length and pos + length - 4 <= end, "metadata block bounds")
        value = data[pos:pos + length - 4]
        pos += length - 4
        return value

    def string():
        raw = block()
        length = struct.unpack_from("<I", raw)[0]
        require(length == len(raw) - 4, "string block length")
        return raw[4:].decode("utf-8")

    version = unpack("I")
    require(version == 5, "unsupported texture version")
    sampler = struct.unpack("<I", block())[0]
    platform = struct.unpack("<I", block())[0]
    name, import_name = string(), string()
    import_scale, import_specular_power = unpack("ff")
    require(unpack("B") == 0x30, "nonempty ToolProps not implemented")
    format_offset = pos + 12
    mips, width, height, fmt, layout, gamma, usage, kind, normal = unpack("9I")
    specular_gloss, hdr_scale, toon_cutoff = unpack("3f")
    alpha, color = unpack("ii")
    uv = unpack("4f")
    toon_regions = block()
    stream_header_offset = pos
    regions, auxiliary, total = unpack("III")
    require(auxiliary == 0, "auxiliary texture blocks not implemented")
    require(width > 0 and height > 0 and 0 < mips <= 32, "texture dimensions/mips")
    mip_regions, warnings = [], []
    payload_offset = end + debug_size
    offset = payload_offset
    for _ in range(regions):
        record_offset = pos
        face, mip, count, byte_size, pitch = unpack("5I")
        require(offset + byte_size <= declared_size, "mip payload exceeds async section")
        require(0 <= mip < mips and count == 1, "region mip/count outside single-mip layout")
        mip_regions.append({"mip": mip, "count": count, "size": byte_size,
                            "pitch": pitch, "face": face, "offset": offset,
                            "record_offset": record_offset})
        offset += byte_size
    require(pos == end, "metadata end mismatch")
    if total != async_size or total != sum(r["size"] for r in mip_regions):
        warnings.append("region byte sizes differ from section total")
    faces = sorted({r["face"] for r in mip_regions})
    for face in faces:
        if sorted(r["mip"] for r in mip_regions if r["face"] == face) != list(range(mips)):
            warnings.append("region list is not a complete distinct mip chain")
    if declared_size != size:
        warnings.append("trailing bytes outside declared MSV5 sections")
    for r in mip_regions:
        w, h = max(1, width >> r["mip"]), max(1, height >> r["mip"])
        if fmt in (64, 65, 66, 96, 97, 98, 112):
            expected = ((w + 3) // 4) * ((h + 3) // 4) * (8 if fmt in (64, 96, 112) else 16)
        elif fmt in (0, 2, 3, 4, 16, 17, 18):
            bpp = {0: 4, 2: 2, 3: 2, 4: 2, 16: 1, 17: 1, 18: 2}[fmt]
            expected = r["pitch"] * h
            if r["pitch"] < w * bpp:
                warnings.append("uncompressed pitch smaller than width")
        else:
            expected = r["size"]
            warnings.append("format geometry not implemented")
        if r["size"] != expected:
            warnings.append("region byte size differs from native format geometry")
    return {"version": version, "metadata_start": start, "metadata_end": end,
            "format_offset": format_offset, "stream_header_offset": stream_header_offset,
            "payload_offset": payload_offset, "payload_size": async_size,
            "trailing_bytes": size - declared_size, "faces": faces,
            "sampler": sampler, "platform": platform, "name": name,
            "import_name": import_name, "import_scale": import_scale,
            "import_specular_power": import_specular_power, "mips": mips,
            "width": width, "height": height, "format": fmt, "layout": layout,
            "surface_gamma": gamma, "usage": usage, "type": kind,
            "normal_map_format": normal, "specular_gloss": specular_gloss,
            "hdr_lightmap_scale": hdr_scale, "toon_cutoff": toon_cutoff,
            "alpha_mode": alpha, "color_mode": color, "uv": uv,
            "toon_regions_hex": toon_regions.hex(), "regions": mip_regions,
            "warnings": sorted(set(warnings))}


if __name__ == "__main__":
    # A deliberately truncated metadata block must fail closed.
    try:
        parse_texture(b"5VSM" + struct.pack("<4I", 1000, 0, 0, 0), 20)
    except ValueError:
        pass
    else:
        raise AssertionError("Out-of-bounds texture metadata accepted")
    print("TFTB texture metadata bounds self-check OK")
