"""Verify all current cache source bytes/owners, without APK builds or ADB."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import sys
import zipfile
import zlib

import os
from apk_build import ApkBuilder, file_hash
from artifacts import checked_path

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / 'native/src/tftb_cache_manifest.h'
PROJECT = ROOT
ROLES = ['base', 'split_episode_02', 'split_episode_03', 'split_episode_04',
         'split_episode_05', 'split_hide_border', 'split_russian']
PREFIXES = ('assets/telltale/files/', 'assets/telltale/obb/')


def members(text):
    body = text.split('static constexpr CacheMember kTftbCacheMembers[] = {', 1)[1].split('};', 1)[0]
    result = []
    for line in body.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*\{"([^"]+)", (\d+)ull, 0x([0-9a-f]{8})u, "([0-9a-f]{64})", ([0-6])u\},', line)
        if not match:
            raise ValueError('Malformed cache descriptor row')
        asset, size, crc, digest, owner = match.groups()
        if not asset.startswith(PREFIXES) or any(p in ('', '.', '..') for p in asset.split('/')) or ':' in asset or '\\' in asset:
            raise ValueError('Noncanonical cache asset path')
        result.append(dict(asset=asset, size=int(size), crc32=int(crc, 16), sha256=digest, owner=int(owner)))
    if len(result) != 137 or len({r['asset'] for r in result}) != 137 or {r['owner'] for r in result} != set(range(7)):
        raise ValueError('Incomplete/duplicate cache descriptor or owner set')
    return result


def stored_extensions(text):
    keys = list(re.finditer(r'''^(?:doNotCompress|["']doNotCompress["'])[ \t]*:[^\n]*(?:\n|$)''', text, re.MULTILINE))
    if len(keys) != 1 or keys[0].group() != 'doNotCompress:\n':
        raise ValueError('Missing/duplicate or unsupported doNotCompress block')
    body = re.split(r'^[A-Za-z_][A-Za-z0-9_]*:', text[keys[0].end():], maxsplit=1, flags=re.MULTILINE)[0]
    lines = [line for line in body.splitlines() if line.strip()]
    if not lines or any(not re.fullmatch('- [a-z0-9]+', line) for line in lines):
        raise ValueError('Unsupported doNotCompress sequence')
    return {line[2:] for line in lines}


def self_check(text):
    rows = members(text)
    first = next(line for line in text.splitlines() if '{"assets/' in line)
    last = next(line for line in reversed(text.splitlines()) if '{"assets/' in line)
    for bad in (text.replace(first, '', 1), text.replace(last, first, 1),
                text.replace(rows[0]['asset'], 'assets/telltale/files/../escape', 1),
                text.replace(rows[0]['sha256'], 'invalid', 1)):
        try:
            members(bad)
        except (ValueError, IndexError):
            continue
        raise AssertionError('Invalid descriptor accepted')
    assert stored_extensions('other:\n- lua\ndoNotCompress:\n- obb\n') == {'obb'}
    for bad in ('other:\n- obb\n', 'doNotCompress:\n- obb\ndoNotCompress:\n- lua\n',
                'doNotCompress:\n- obb\ndoNotCompress: []\n', 'doNotCompress:\n- obb\ndoNotCompress:\n'):
        try:
            stored_extensions(bad)
        except ValueError:
            continue
        raise AssertionError('Missing/duplicate storage key accepted')


def verify():
    text = checked_path(ROOT, DESCRIPTOR).read_text(encoding='utf-8')
    self_check(text)
    rows = members(text)
    builder = ApkBuilder(PROJECT, os.environ['APK_TOOL_ROOT'],
                         os.environ['JAVA_EXE'], arm64_bridge=True)
    assert set(builder._selected('all')) == set(ROLES + ['split_widescreen'])
    source_hashes = {role: builder._source_hash(role) for role in builder._selected('all')}
    stored = {role: stored_extensions(builder._source(role).joinpath('apktool.yml').read_text()) for role in source_hashes}
    actual = {(role, p.relative_to(builder._source(role)).as_posix())
              for role in source_hashes for p in (builder._source(role)/'assets/telltale').rglob('*')
              if p.is_file() and p.relative_to(builder._source(role)).as_posix().startswith(PREFIXES)}
    assert actual == {(ROLES[r['owner']], r['asset']) for r in rows}, 'Cache carriers differ from complete owner sets'
    external_path = checked_path(ROOT, 'bridge/external_cache_fixture_20261007.json')
    external = json.loads(external_path.read_text())
    expected_files = {r['asset'][len(PREFIXES[0]):]: dict(size=r['size'], sha256=r['sha256'])
                      for r in rows if r['asset'].startswith(PREFIXES[0]) and r['owner'] < 5}
    assert len(external) == len(expected_files) == 111
    assert {r['relative']: dict(size=r['size'], sha256=r['sha256']) for r in external} == expected_files
    totals = {role: dict(members=0, bytes=0) for role in ROLES}
    for row in rows:
        role = ROLES[row['owner']]
        path = checked_path(ROOT, builder._source(role)/row['asset'])
        before = path.stat()
        digest, crc = hashlib.sha256(), 0
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024), b''):
                digest.update(block)
                crc = zlib.crc32(block, crc)
        after = path.stat()
        assert all(getattr(after, key) == getattr(before, key) for key in
                   ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), str(path)
        assert (before.st_size, crc, digest.hexdigest()) == (row['size'], row['crc32'], row['sha256']), str(path)
        assert PurePosixPath(row['asset']).suffix[1:] in stored[role]
        totals[role]['members'] += 1
        totals[role]['bytes'] += row['size']
    original = checked_path(ROOT, 'obb.zip')
    original_sha = file_hash(original)
    assert original_sha == 'c857bc5cb8d70985a37aee48deeddf344ee58ef701bfc0896c578a061e4660b9'
    with zipfile.ZipFile(original) as archive:
        entries = [i for i in archive.infolist() if not i.is_dir()]
        originals = {i.filename: i for i in entries}
        assert len(originals) == len(entries)
        obbs = [r for r in rows if r['asset'].startswith(PREFIXES[1])]
        names = {'obb/com.telltalegames.borderlands100/' + PurePosixPath(r['asset']).name for r in obbs}
        assert set(originals) == names and len(obbs) == 2
        for row in obbs:
            info = originals['obb/com.telltalegames.borderlands100/' + PurePosixPath(row['asset']).name]
            assert (info.file_size, info.CRC) == (row['size'], row['crc32'])
            with archive.open(info) as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256']
    return dict(status='FULL137_CANONICAL_SOURCE_SHA_CRC_OWNER_PASS', members=137,
                bytes=sum(r['size'] for r in rows), owners=totals,
                descriptor_sha256=file_hash(DESCRIPTOR), external_fixture_sha256=file_hash(external_path),
                original_obb_zip_sha256=original_sha, original_obb_full_payload_sha_checked=True,
                source_hashes=source_hashes, malformed_descriptor_checks=4, storage_key_checks=5,
                scope='Host canonical sources only; installed payload/runtime P/E/B/negative/no-extraction acceptance remains open.')


if __name__ == '__main__':
    assert len(sys.argv) in (1, 2)
    result = verify()
    if len(sys.argv) == 2:
        output = checked_path(ROOT, sys.argv[1], must_exist=False)
        with output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    else:
        assert len(sys.argv) == 1
    print(json.dumps(result, indent=2))
