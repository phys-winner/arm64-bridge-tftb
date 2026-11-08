"""Read-only, bounded NCTT/ZCTT TTA3 indexes and entry ranges; never extracts cache."""
import functools
import struct
import zlib
from pathlib import Path


class FileRange:
    def __init__(self, path, offset=0, size=None):
        self.path = Path(path)
        self.offset = offset
        self.size = self.path.stat().st_size - offset if size is None else size
        if not 0 <= offset <= self.path.stat().st_size:
            raise ValueError("File offset outside bounds")
        if not 0 <= self.size <= self.path.stat().st_size - offset:
            raise ValueError("File size outside bounds")

    def read_at(self, offset, size):
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError(f"File range outside bounds: {offset}+{size}/{self.size}")
        with self.path.open("rb") as handle:
            handle.seek(self.offset + offset)
            data = handle.read(size)
        if len(data) != size:
            raise ValueError("Truncated file range")
        return data


class BytesRange:
    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, size):
        if min(offset, size) < 0 or offset + size > self.size:
            raise ValueError("Read outside byte buffer")
        return self.data[offset:offset + size]


class EntryRange:
    def __init__(self, reader, offset, size):
        self.reader, self.offset, self.size = reader, offset, size
        if min(offset, size) < 0 or offset + size > reader.size:
            raise ValueError("Entry range outside bounds")

    def read_at(self, offset, size):
        if min(offset, size) < 0 or offset + size > self.size:
            raise ValueError("Read outside entry bounds")
        return self.reader.read_at(self.offset + offset, size)


class TTArchive:
    def __init__(self, source):
        self.source = FileRange(source) if isinstance(source, (str, Path)) else source
        self.magic = self.source.read_at(0, 4)
        if self.magic == b"NCTT":
            self.size = struct.unpack("<Q", self.source.read_at(4, 8))[0]
            if self.size != self.source.size - 12:
                raise ValueError("NCTT advertised size mismatch")
        elif self.magic == b"ZCTT":
            self.chunk_size, count = struct.unpack("<II", self.source.read_at(4, 8))
            if not 0 < self.chunk_size <= 0x100000 or not 0 < count <= 1000000:
                raise ValueError("Invalid ZCTT chunk geometry")
            self.offsets = struct.unpack(f"<{count + 1}Q", self.source.read_at(12, (count + 1) * 8))
            if self.offsets[0] != 12 + (count + 1) * 8 or self.offsets[-1] != self.source.size:
                raise ValueError("ZCTT chunk table bounds mismatch")
            if any(a >= b for a, b in zip(self.offsets, self.offsets[1:])):
                raise ValueError("Nonmonotonic ZCTT chunk offsets")
            self.size = (count - 1) * self.chunk_size + len(self._chunk(count - 1))
        else:
            raise ValueError(f"Unsupported archive magic {self.magic!r}")
        inner_magic, self.version, names_size, count = struct.unpack("<4sIII", self.read_at(0, 16))
        if inner_magic != b"3ATT" or self.version not in (2, 8) or names_size % 65536:
            raise ValueError(f"Unsupported inner index {inner_magic!r}/{self.version}/{names_size}")
        if count > 1000000:
            raise ValueError("Implausible archive entry count")
        table = self.read_at(16, count * 28)
        names = self.read_at(16 + count * 28, names_size)
        self.data_offset = 16 + count * 28 + names_size
        self.entries = []
        for index in range(count):
            crc, offset, size, flags, page, name_offset = struct.unpack_from("<QQIIHH", table, index * 28)
            pointer = page * 65536 + name_offset
            end = names.find(b"\0", pointer)
            if pointer >= len(names) or end < pointer:
                raise ValueError("Invalid archive name pointer")
            name = names[pointer:end].decode("utf-8")
            if not name or offset + size > self.size - self.data_offset:
                raise ValueError(f"Invalid entry range: {name}/{offset}/{size}")
            self.entries.append({"name": name, "crc64": f"{crc:016x}", "offset": offset, "size": size, "flags": flags})
        if len({entry["name"] for entry in self.entries}) != count:
            raise ValueError("Duplicate archive entry names")
        self.by_name = {entry["name"]: entry for entry in self.entries}

    @functools.lru_cache(maxsize=4)
    def _chunk(self, index):
        start, end = self.offsets[index:index + 2]
        decompressor = zlib.decompressobj(-15)
        data = decompressor.decompress(self.source.read_at(start, end - start), self.chunk_size + 1)
        if not decompressor.eof or decompressor.unused_data or len(data) > self.chunk_size:
            raise ValueError("Invalid or oversized ZCTT deflate chunk")
        if index < len(self.offsets) - 2 and len(data) != self.chunk_size:
            raise ValueError("Short intermediate ZCTT chunk")
        return data

    def read_at(self, offset, size):
        if min(offset, size) < 0 or offset + size > self.size:
            raise ValueError("Read outside archive bounds")
        if self.magic == b"NCTT":
            return self.source.read_at(12 + offset, size)
        data = bytearray()
        while size:
            index, local = divmod(offset, self.chunk_size)
            chunk = self._chunk(index)
            count = min(size, len(chunk) - local)
            if count <= 0:
                raise ValueError("Read beyond final ZCTT chunk")
            data.extend(chunk[local:local + count])
            offset, size = offset + count, size - count
        return bytes(data)

    def entry_range(self, entry):
        entry = self.by_name[entry] if isinstance(entry, str) else entry
        return EntryRange(self, self.data_offset + entry["offset"], entry["size"])

    def read_entry(self, entry, limit=None):
        reader = self.entry_range(entry)
        return reader.read_at(0, reader.size if limit is None else min(limit, reader.size))


def self_check():
    names = b"sample.lua\0".ljust(65536, b"\0")
    body = struct.pack("<4sIII", b"3ATT", 8, len(names), 1)
    body += struct.pack("<QQIIHH", 1, 0, 4, 101, 0, 0) + names + b"test"
    class MemoryRange:
        def __init__(self, data):
            self.data, self.size = data, len(data)
        def read_at(self, offset, size):
            assert 0 <= offset <= offset + size <= self.size
            return self.data[offset:offset + size]
    uncompressed = TTArchive(MemoryRange(b"NCTT" + struct.pack("<Q", len(body)) + body))
    assert uncompressed.read_entry("sample.lua") == b"test"
    blocks = []
    for start in range(0, len(body), 65536):
        compressor = zlib.compressobj(wbits=-15)
        blocks.append(compressor.compress(body[start:start + 65536]) + compressor.flush())
    offsets = [12 + (len(blocks) + 1) * 8]
    for block in blocks:
        offsets.append(offsets[-1] + len(block))
    packed = b"ZCTT" + struct.pack("<II", 65536, len(blocks))
    packed += struct.pack(f"<{len(offsets)}Q", *offsets) + b"".join(blocks)
    compressed = TTArchive(MemoryRange(packed))
    assert compressed.entries == uncompressed.entries
    assert compressed.read_entry("sample.lua") == b"test"
    try:
        compressed.read_at(compressed.size, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("Out-of-bounds read accepted")
    print("TTArchive self-check OK (NCTT, ZCTT, entry content, bounds)")


if __name__ == "__main__":
    self_check()
