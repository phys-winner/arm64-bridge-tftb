"""Apply the selected menu/boot edits to pinned archives; keep whole OBB inputs intact."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib

from lua52_inspect import Chunk, walk, self_check as lua_self_check
from ttarchive_reader import TTArchive, BytesRange

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'work/menu_ui'
FILES = ROOT / 'app/assets/telltale/files'
NET = FILES / 'Net'
DESCRIPTOR = ROOT / 'native/src/tftb_cache_manifest.h'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def semantic(node):
    return {k: [semantic(n) for n in v] if k == 'children' else v
            for k, v in node.items() if k != 'code_offset'}


def jump(pc, target):
    return 23 | ((target - pc - 1 + 131071) << 14)


def patch_chunk(raw, edits, rename=None):
    tree = Chunk(raw).root
    nodes = dict(walk(tree))
    expected = copy.deepcopy(tree)
    after_nodes = dict(walk(expected))
    result = bytearray(raw)
    for name, pc, before, after in edits:
        node = nodes[name]
        if node['code'][pc] != before:
            raise ValueError(f'Unexpected Lua instruction {name}/{pc}')
        struct.pack_into('<I', result, node['code_offset'] + pc * 4, after)
        after_nodes[name]['code'][pc] = after
    if rename:
        name, before, after = rename
        node = nodes[name]
        start = node['code_offset'] + len(node['code']) * 4 + 4
        needle = b'\x04' + struct.pack('<I', len(before) + 1) + before.encode() + b'\0'
        assert raw[start:].count(needle) == 1
        offset = raw.index(needle, start)
        replacement = b'\x04' + struct.pack('<I', len(after) + 1) + after.encode() + b'\0'
        result[offset:offset + len(needle)] = replacement
        index = node['constants'].index(before)
        after_nodes[name]['constants'][index] = after
    assert semantic(Chunk(bytes(result)).root) == semantic(expected)
    return bytes(result)


def repack(raw, replacements):
    archive = TTArchive(BytesRange(raw))
    assert set(replacements) <= set(archive.by_name)
    body = archive.read_at(0, archive.size)
    changed = bytearray(body[:archive.data_offset])
    payload = bytearray()
    cursor = archive.data_offset
    for index, entry in sorted(enumerate(archive.entries), key=lambda item: item[1]['offset']):
        start = archive.data_offset + entry['offset']
        assert start >= cursor, 'Overlapping archive entries'
        payload.extend(body[cursor:start])
        data = replacements.get(entry['name'], archive.read_entry(entry))
        struct.pack_into('<QI', changed, 16 + index * 28 + 8, len(payload), len(data))
        payload.extend(data)
        cursor = start + entry['size']
    changed.extend(payload + body[cursor:])
    if archive.magic == b'NCTT':
        result = b'NCTT' + struct.pack('<Q', len(changed)) + changed
    else:
        blocks = []
        for index, start in enumerate(range(0, len(changed), archive.chunk_size)):
            data = bytes(changed[start:start + archive.chunk_size])
            if index < len(archive.offsets) - 1 and data == archive._chunk(index):
                blocks.append(raw[archive.offsets[index]:archive.offsets[index + 1]])
            else:
                compressor = zlib.compressobj(level=9, wbits=-15)
                blocks.append(compressor.compress(data) + compressor.flush())
        offsets = [12 + (len(blocks) + 1) * 8]
        for block in blocks:
            offsets.append(offsets[-1] + len(block))
        result = b'ZCTT' + struct.pack('<II', archive.chunk_size, len(blocks))
        result += struct.pack(f'<{len(offsets)}Q', *offsets) + b''.join(blocks)
    check = TTArchive(BytesRange(result))
    for old, new in zip(archive.entries, check.entries):
        assert all(old[k] == new[k] for k in ('name', 'crc64', 'flags'))
        assert check.read_entry(new) == replacements.get(old['name'], archive.read_entry(old))
    assert len(check.entries) == len(archive.entries)
    return result


def write_changed(path, data):
    if path.read_bytes() != data:
        temporary = path.with_name(path.name + '.tmp')
        temporary.write_bytes(data)
        os.replace(temporary, path)


def self_check():
    lua_self_check()
    # A wrong opcode must fail before any patch can be published.
    raw = TTArchive(SOURCE / 'preimages/Port_QA_Menu.ttarch2').read_entry('Port_Menu_Main_original.lua')
    try:
        patch_chunk(raw, [('root/5', 0, 0, 0x0080001f)])
    except ValueError:
        pass
    else:
        raise AssertionError('Wrong Lua preimage accepted')
    mutated = patch_chunk(raw, [('root/5', 0, 0x00400006, 0x0080001f)])
    rebuilt = repack((SOURCE / 'preimages/Port_QA_Menu.ttarch2').read_bytes(),
                     {'Port_Menu_Main_original.lua': mutated})
    assert TTArchive(BytesRange(rebuilt)).read_entry('Port_Menu_Main_original.lua') == mutated


def main():
    self_check()
    expected = json.loads((SOURCE / 'preimages/sha256.json').read_text())
    archives = {}
    for name, digest in expected.items():
        raw = (SOURCE / 'preimages' / name).read_bytes()
        assert sha(raw) == digest, name
        archives[name] = raw
    replacements = {name: {} for name in archives}
    pause = (SOURCE / 'Menu_Pause.lua').read_bytes()
    cheats = (SOURCE / 'Port_Cheats.lua').read_bytes()
    for name, raw in archives.items():
        a = TTArchive(BytesRange(raw))
        if 'Menu_Pause.lua' in a.by_name:
            replacements[name]['Menu_Pause.lua'] = pause
        if 'Port_Cheats.lua' in a.by_name:
            replacements[name]['Port_Cheats.lua'] = cheats
    qa = TTArchive(BytesRange(archives['Port_QA_Menu.ttarch2']))
    replacements['Port_QA_Menu.ttarch2'].update({
        'Menu_Main.lua': (SOURCE / 'Menu_Main.lua').read_bytes(),
        'Menu_Extras.lua': (SOURCE / 'Menu_Extras.lua').read_bytes(),
        'Port_Menu_Main_original.lua': patch_chunk(qa.read_entry('Port_Menu_Main_original.lua'), [
            ('root/5', 0, 0x00400006, 0x0080001f),
            ('root/6/0', 138, 0x00480046, jump(138, 181)),
            ('root/6/0', 292, 0x00400046, jump(292, 296)),
            ('root/6/0', 330, 0x00490046, 0x0080001f),
            ('root/7', 109, 0x004000c6, jump(109, 183)),
        ]),
        'Port_Menu_Extras_original.lua': patch_chunk(qa.read_entry('Port_Menu_Extras_original.lua'), [
            ('root/0', 0, 0x00400006, 0x0080001f),
            ('root/1/0', 19, 0x00418086, jump(19, 25)),
            ('root/1/0', 51, 0x0043c0c6, jump(51, 74)),
        ]),
    })
    replacements['Port_TouchOptions.ttarch2']['Menu_Options.lua'] = (SOURCE / 'Menu_Options.lua').read_bytes()
    name = 'Borderlands_android_Android_105_Boot_compressed.ttarch2'
    boot = TTArchive(BytesRange(archives[name]))
    replacements[name]['bootTitle.lua'] = patch_chunk(boot.read_entry('bootTitle.lua'), [
        ('root/18', 0, 0x00400006, jump(0, 21)),
        ('root/18', 153, 0x004240c6, jump(153, 253)),
        ('root/18', 257, 0x004100c6, jump(257, 263)),
        ('root/19', 160, 0x004a0106, jump(160, 223)),
        ('root/19', 224, 0x00100141, 0x02000100),
        ('root/19', 225, 0x0100411d, 0x0080411d),
    ], ('root/19', 'InputMapperActivate', 'PressStart'))
    outputs = {name: repack(raw, replacements[name]) for name, raw in archives.items()}
    # Check every target before beginning writes, including repeated/idempotent runs.
    for name, data in outputs.items():
        assert (NET / name).read_bytes() in (archives[name], data), name
    changed = {}
    for name, data in outputs.items():
        write_changed(NET / name, data)
        changed['Net/' + name] = data
    for path in FILES.glob('*.mft'):
        data = json.loads(path.read_text())
        edited = False
        for row in data.get('files', []):
            key = 'Net/' + row['filename']
            if key in changed:
                raw = changed[key]
                row['hash'], row['size'] = hashlib.md5(raw).hexdigest(), len(raw)
                edited = True
        if edited:
            raw = (json.dumps(data, indent=2) + '\n').encode()
            write_changed(path, raw)
            changed[path.name] = raw
    text = DESCRIPTOR.read_text()
    for relative, raw in changed.items():
        asset = 'assets/telltale/files/' + relative
        pattern = r'    \{"' + re.escape(asset) + r'", \d+ull, 0x[0-9a-f]{8}u, "[0-9a-f]{64}", 0u\},'
        replacement = f'    {{"{asset}", {len(raw)}ull, 0x{zlib.crc32(raw):08x}u, "{sha(raw)}", 0u}},'
        text, count = re.subn(pattern, lambda _: replacement, text)
        assert count == 1, asset
    write_changed(DESCRIPTOR, text.encode())
    fixture = ROOT / 'bridge/external_cache_fixture_20261007.json'
    rows = json.loads(fixture.read_text())
    assert len(rows) == 111
    for row in rows:
        if row['relative'] in changed:
            raw = changed[row['relative']]
            row['size'], row['sha256'] = len(raw), sha(raw)
    write_changed(fixture, (json.dumps(rows, indent=2) + '\n').encode())
    report = dict(status='PINNED_MENU_BOOT_ARCHIVES_PATCHED_STATIC_VERIFIED',
                  inputs=expected, outputs={n: sha(d) for n, d in outputs.items()},
                  changed_members=list(changed), runtime_acceptance=False)
    report_path = ROOT / 'work/evidence/menu_startup_20261015/ui_patch.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
