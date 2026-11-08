"""Validate the complete managed cache ZIP carriers, or genuinely cacheless ones."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

import os
from apk_build import ApkBuilder, file_hash
from artifacts import checked_path
from verify_cache_sources import ROOT, PROJECT, DESCRIPTOR, ROLES, PREFIXES, members

DEX_SHA = '07a8c5c799f0e80d32089ada2294bb73d3db358b6e4d92649b9147086219a966'

def directory_frame(stream, archive):
    # shortcut: current signed artifacts have empty ZIP comments; add authored-comment support only for a verified new input.
    assert not archive.comment
    stream.seek(-22, 2)
    end = stream.tell()
    signature, disk, cd_disk, count_disk, count, size, offset, comment = struct.unpack('<IHHHHIIH', stream.read(22))
    infos = archive.infolist()
    assert signature == 0x06054b50 and disk == cd_disk == comment == 0
    assert count_disk == count == len(infos) < 0xffff
    assert size < 0xffffffff and offset == archive.start_dir < 0xffffffff and offset + size == end
    stream.seek(offset)
    for info in infos:
        raw = stream.read(46)
        assert len(raw) == 46 and raw[:4] == b'PK\x01\x02'
        needed, flags, method = struct.unpack_from('<HHH', raw, 6)
        crc, packed, logical = struct.unpack_from('<III', raw, 16)
        names, extra, comments, volume = struct.unpack_from('<HHHH', raw, 28)
        local = struct.unpack_from('<I', raw, 42)[0]
        assert (needed, flags, method, crc, packed, logical, volume, local) == (info.extract_version, info.flag_bits, info.compress_type, info.CRC, info.compress_size, info.file_size, 0, info.header_offset)
        assert all(v < 0xffffffff for v in (packed, logical, local))
        name = stream.read(names)
        assert name.decode('utf-8' if flags & 0x800 else 'cp437') == info.filename
        assert len(stream.read(extra + comments)) == extra + comments
    assert stream.tell() == end

def local_range(stream, archive, info, *, stored=True):
    stream.seek(info.header_offset)
    raw = stream.read(30)
    assert len(raw) == 30
    signature, version, flags, method, clock, date, crc, packed, size, names, extra = struct.unpack('<IHHHHHIIIHH', raw)
    assert signature == 0x04034b50 and flags == info.flag_bits
    assert version == info.extract_version and not info.reserved and version in (10, 20)
    assert method == info.compress_type and method in (0, 8)
    assert method != 8 or version == 20
    assert not flags & ~(0x0808 | (6 if method == 8 else 0))
    assert not info.volume and all(0 <= v < 0xffffffff for v in (packed, size, info.compress_size, info.file_size, info.header_offset))
    assert method != 0 or info.compress_size == info.file_size
    assert not stored or method == zipfile.ZIP_STORED
    for actual, expected in ((crc, info.CRC), (packed, info.compress_size), (size, info.file_size)):
        assert actual == expected or flags & 8 and actual == 0
    encoded = stream.read(names)
    assert encoded.decode('utf-8' if flags & 0x800 else 'cp437') == info.filename
    start = info.header_offset + 30 + names + extra
    limit = min([row.header_offset for row in archive.infolist() if row.header_offset > info.header_offset] + [archive.start_dir])
    end = start + info.compress_size
    if flags & 8:
        stream.seek(end)
        descriptor = stream.read(12)
        assert len(descriptor) == 12
        values = struct.unpack('<III', descriptor)
        end += 12
        if values != (info.CRC, info.compress_size, info.file_size):
            assert values[0] == 0x08074b50
            tail = stream.read(4)
            assert len(tail) == 4
            assert (*values[1:], struct.unpack('<I', tail)[0]) == (info.CRC, info.compress_size, info.file_size)
            end += 4
    assert 0 <= info.header_offset < start <= end <= limit <= archive.start_dir
    return start, info.file_size

def payload(archive, info):
    digest, crc = hashlib.sha256(), 0
    with archive.open(info) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            crc = zlib.crc32(block, crc)
    assert crc == info.CRC
    return digest.hexdigest()

def verify(stage, mode):
    tool_sha = file_hash(Path(__file__))
    stage = checked_path(ROOT, stage)
    assert stage.is_dir() and (stage == ROOT or stage.is_relative_to(ROOT / 'out'))
    rows = members(checked_path(ROOT, DESCRIPTOR).read_text())
    source = ApkBuilder(PROJECT, os.environ['APK_TOOL_ROOT'], os.environ['JAVA_EXE'], arm64_bridge=True)
    result = {}
    for role in [*ROLES, 'split_widescreen']:
        apk = checked_path(ROOT, stage / 'out' / ('base.apk' if role == 'base' else 'splits/' + role + '.apk'))
        before = apk.stat()
        expected = {r['asset']: r for r in rows if ROLES[r['owner']] == role} if mode == 'packaged' else {}
        critical = []
        with zipfile.ZipFile(apk) as archive, apk.open('rb') as raw:
            infos = archive.infolist()
            assert len(infos) == len({i.filename for i in infos})
            assert len(infos) == len({i.filename.rstrip('/').casefold() for i in infos})
            assert len(infos) == len({i.header_offset for i in infos})
            directory_frame(raw, archive)
            for info in infos:
                assert not any(x in info.filename for x in ('\\', ':', '\x00')) and not info.filename.startswith('/')
                assert all(x not in ('', '.', '..') for x in info.filename.rstrip('/').split('/'))
                assert not info.filename.casefold().startswith(PREFIXES) or info.filename.startswith(PREFIXES)
                local_range(raw, archive, info, stored=False)
            actual = {i.filename for i in infos if i.filename.startswith(PREFIXES)}
            assert actual == set(expected), (role, actual ^ set(expected))
            for name, row in expected.items():
                info = archive.getinfo(name)
                assert (info.file_size, info.CRC) == (row['size'], row['crc32'])
                start, size = local_range(raw, archive, info)
                assert payload(archive, info) == row['sha256']
                critical.append({'name': name, 'start': start, 'bytes': size, 'sha256': row['sha256'], 'crc32': info.CRC})
            expected_source = source._source(role)
            guest_prefix = 'assets/guestlib/armeabi-v7a/'
            guests = {p.relative_to(expected_source).as_posix() for p in (expected_source / guest_prefix).glob('*.so')}
            natives = {p.relative_to(expected_source).as_posix() for p in (expected_source / 'lib/arm64-v8a').glob('*.so')}
            assert {i.filename for i in infos if i.filename.startswith(guest_prefix) and not i.is_dir()} == guests
            assert {i.filename for i in infos if i.filename.startswith('lib/') and not i.is_dir()} == natives
            assert (len(guests), len(natives)) == ((5, 1) if role == 'base' else (0, 0))
            for name in sorted(guests | natives):
                info = archive.getinfo(name)
                start, size = local_range(raw, archive, info)
                canonical = checked_path(ROOT, expected_source / name)
                assert size == canonical.stat().st_size
                digest = file_hash(canonical)
                assert payload(archive, info) == digest
                critical.append({'name': name, 'start': start, 'bytes': size, 'sha256': digest, 'crc32': info.CRC})
            if role == 'base':
                assert payload(archive, archive.getinfo('classes.dex')) == DEX_SHA
            marker = 'assets/telltale/widescreen.enable'
            marker_names = {i.filename for i in infos if i.filename == marker}
            assert marker_names == ({marker} if role == 'split_widescreen' else set())
            if marker_names:
                assert archive.read(marker) == b''
            assert archive.testzip() is None
        digest = file_hash(apk)
        after = apk.stat()
        assert all(getattr(before, k) == getattr(after, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        result[role] = {'artifact': str(apk), 'bytes': before.st_size, 'sha256': digest,
                        'managed_members': len(expected), 'framed_entries': len(infos), 'critical_stored_ranges': critical}
    assert file_hash(Path(__file__)) == tool_sha
    return {'status': 'FULL137_PACKAGED_ZIP_PASS' if mode == 'packaged' else 'ZERO_MANAGED_CACHELESS_ZIP_PASS',
            'validation_tool_sha256': tool_sha,
            'mode': mode, 'descriptor_sha256': file_hash(DESCRIPTOR), 'DEX_sha256': DEX_SHA,
            'managed_members': sum(r['managed_members'] for r in result.values()), 'artifacts': result,
            'scope': 'Host empty-comment EOCD disk/count/CD framing; every-entry supported local/central version-method-flags/descriptor physical bounds and full CRC. Full managed SHA/STORED and original guest/native/DEX bytes. Runtime admission/consumption and certificate/badging are separate gates.'}

def self_check():
    # One critical local header fixture; reject a descriptor flag and overlapping payload.
    import io
    fixture = io.BytesIO()
    with zipfile.ZipFile(fixture, 'w') as writer:
        writer.writestr('x', b'test')
    good = fixture.getvalue()
    with zipfile.ZipFile(io.BytesIO(good)) as reader:
        directory_frame(io.BytesIO(good), reader)
        for position, value in ((-18, 1), (-12, 0)):
            bad = bytearray(good)
            struct.pack_into('<H', bad, len(bad) + position, value)
            try:
                directory_frame(io.BytesIO(bad), reader)
            except AssertionError:
                continue
            raise AssertionError('Invalid EOCD disk/count accepted')
    info = zipfile.ZipInfo('assets/telltale/files/x')
    info.header_offset = 0
    info.extract_version = 20
    info.file_size = info.compress_size = 4
    info.CRC = zlib.crc32(b'test')
    class Archive:
        start_dir = 30 + len(info.filename) + 4
        def infolist(self):
            return [info]
    archive = Archive()
    def header(flags=0, size=4, version=20):
        return struct.pack('<IHHHHHIIIHH', 0x04034b50, version, flags, 0, 0, 0, info.CRC, size, size, len(info.filename), 0) + info.filename.encode() + b'test'
    assert local_range(io.BytesIO(header()), archive, info) == (30 + len(info.filename), 4)
    for raw, flags, version in ((header(8), 8, 20), (header(size=5), 0, 20),
                                (header()[4:], 0, 20), (header(0x2000), 0x2000, 20),
                                (header(0x10), 0x10, 20), (header(version=30), 0, 30)):
        info.flag_bits, info.extract_version = flags, version
        try:
            local_range(io.BytesIO(raw), archive, info)
        except (AssertionError, struct.error):
            continue
        raise AssertionError('Invalid critical ZIP member accepted')
    info.flag_bits, info.extract_version = 8, 20
    for descriptor in (struct.pack('<III', info.CRC, 4, 4), struct.pack('<IIII', 0x08074b50, info.CRC, 4, 4)):
        archive.start_dir = 30 + len(info.filename) + 4 + len(descriptor)
        assert local_range(io.BytesIO(header(8) + descriptor), archive, info) == (30 + len(info.filename), 4)
    bad = header(8) + struct.pack('<III', info.CRC ^ 1, 4, 4)
    try:
        local_range(io.BytesIO(bad), archive, info)
    except AssertionError:
        pass
    else:
        raise AssertionError('Malformed descriptor accepted')
    info.flag_bits = 0
    archive.start_dir = 30 + len(info.filename) + 4
    archive.start_dir -= 1
    try:
        local_range(io.BytesIO(header()), archive, info)
    except AssertionError:
        return
    raise AssertionError('Overlapping payload accepted')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', type=Path)
    parser.add_argument('mode', choices=('packaged', 'cacheless'))
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    self_check()
    data = verify(args.stage, args.mode)
    destination = checked_path(ROOT, args.receipt, must_exist=False)
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': data['status'], 'managed_members': data['managed_members'], 'receipt': str(destination), 'sha256': file_hash(destination)}))
