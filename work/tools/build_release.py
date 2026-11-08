"""Reproduce the complete signed ARM64 release, including the optional Russian split."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import zipfile
import zlib

from apk_build import ApkBuilder, file_hash
from process_tools import run_process
from repair_tolma_textures import repair_archive
import verify_cache_apks
import verify_cache_sources

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT
NATIVE = ROOT / 'native'
PUB = ROOT / 'pub'


def write_changed(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_bytes() != data:
        temporary = path.with_name(path.name + '.tmp')
        temporary.write_bytes(data)
        os.replace(temporary, path)


def prepare_russian(work):
    split = PROJECT / 'splits/split_russian'
    files = split / 'assets/telltale/files'
    repaired, report = work / 'Tolma105.ttarch2', work / 'texture_repairs.json'
    repair_archive(ROOT / 'data.zip', repaired, report)
    with zipfile.ZipFile(ROOT / 'data.zip') as archive:
        prefix = 'data/com.telltalegames.borderlands100/files/'
        items = [i for i in archive.infolist() if i.filename.startswith(prefix + 'Net/')
                 and 'Tolma4_Team_' in i.filename and not i.is_dir()]
        assert len(items) == 20 and len({i.filename for i in items}) == 20
        for item in items:
            name = item.filename[len(prefix):]
            assert re.fullmatch(r'Net/[A-Za-z0-9_.-]+', name)
            data = repaired.read_bytes() if name.endswith('Tolma4_Team_TFTB105.ttarch2') else archive.read(item)
            write_changed(files / name, data)
        mft = json.loads(archive.read(prefix + 'Tolma4_Team_Patch.mft'))
    names = sorted(item.filename[len(prefix + 'Net/'):] for item in items)
    mft['files'] = [{'filename': name, 'size': (files / 'Net' / name).stat().st_size,
                     'hash': hashlib.md5((files / 'Net' / name).read_bytes()).hexdigest()} for name in names]
    mft['numfiles'] = len(names)
    write_changed(files / 'Tolma4_Team_Patch.mft', (json.dumps(mft, ensure_ascii=False, indent=2) + '\n').encode())
    source = PROJECT / 'splits/split_hide_border'
    for name in ('AndroidManifest.xml', 'apktool.yml'):
        write_changed(split / name, (source / name).read_bytes().replace(b'split_hide_border', b'split_russian'))
    rows = []
    for path in sorted(files.rglob('*')):
        if path.is_file():
            data = path.read_bytes()
            rows.append('    {"' + path.relative_to(split).as_posix() + '", ' + str(len(data))
                        + 'ull, 0x' + format(zlib.crc32(data), '08x') + 'u, "'
                        + hashlib.sha256(data).hexdigest() + '", 6u},')
    assert len(rows) == 21
    descriptor = NATIVE / 'src/tftb_cache_manifest.h'
    text = descriptor.read_text()
    text = '\n'.join(line for line in text.splitlines() if not re.search(r', 6u\},$', line)) + '\n'
    assert text.count('\n};') == 1
    text = text.replace('\n};', '\n' + '\n'.join(rows) + '\n};', 1)
    text = re.sub(r'(static_assert\(sizeof\(kTftbCacheMembers\) / sizeof\(kTftbCacheMembers\[0\]\) == )\d+', r'\g<1>137', text)
    write_changed(descriptor, text.encode())
    return report


def main():
    staging = ROOT / 'out/release-staging'
    staging.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=staging) as directory:
        work = Path(directory)
        repair_report = prepare_russian(work)
        print('Russian split: all five episodes, 20 Net files and complete MFT.', flush=True)
        result = run_process([os.environ.get('PWSH_EXE', 'pwsh'), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                              str(ROOT / 'build_arm64.ps1')], cwd=ROOT,
                             output_dir=staging / 'native-logs', timeout_s=1200, summary_bytes=1200)
        if result.outcome != 'succeeded':
            raise RuntimeError('Native build failed: ' + result.stderr_log + '\n' + result.stderr)
        shutil.copyfile(ROOT / 'out/native-candidate/libmain.so', PROJECT / 'app/lib/arm64-v8a/libmain.so')
        source_proof = verify_cache_sources.verify()
        print('Canonical cache: 137 complete members verified.', flush=True)
        built = ApkBuilder(PROJECT, os.environ['APK_TOOL_ROOT'],
                           os.environ['JAVA_EXE'], arm64_bridge=True).build('all')
        verify_cache_apks.self_check()
        proof = verify_cache_apks.verify(PROJECT, 'packaged')
        assert set(built['targets']) == set(proof['artifacts']) and len(built['targets']) == 8
        PUB.mkdir(exist_ok=True)
        published = {}
        for role, row in proof['artifacts'].items():
            source = Path(row['artifact'])
            target = PUB / ('base.apk' if role == 'base' else role + '.apk')
            temporary = target.with_suffix('.apk.tmp')
            shutil.copyfile(source, temporary)
            assert file_hash(temporary) == row['sha256']
            os.replace(temporary, target)
            published[role] = dict(file=target.name, bytes=row['bytes'], sha256=row['sha256'])
        repair = json.loads(repair_report.read_text())
        repaired_source = PROJECT / 'splits/split_russian/assets/telltale/files/Net/Tolma4_Team_TFTB105.ttarch2'
        assert file_hash(repaired_source) == repair['output']['sha256']
        repair['output']['path'] = str(repaired_source)
        repair['output']['validation'] = 'Generated copy independently validated; canonical copy has the same SHA-256'
        write_changed(PUB / 'texture_repairs.json', (json.dumps(repair, indent=2, ensure_ascii=False) + '\n').encode())
        manifest = dict(package='com.telltalegames.borderlands100', version_code=10179, version_name='1.79',
                        sdk=dict(min=24, target=37), abi='arm64-v8a', artifacts=published,
                        certificate=built['targets']['base']['certificate'],
                        native_sha256=file_hash(PROJECT / 'app/lib/arm64-v8a/libmain.so'),
                        descriptor_sha256=source_proof['descriptor_sha256'],
                        canonical_source_tree_hashes=source_proof['source_hashes'],
                        build_entry_sha256=file_hash(Path(__file__)),
                        texture_repairs_sha256=file_hash(PUB / 'texture_repairs.json'),
                        managed_members=proof['managed_members'], runtime_acceptance=False,
                        russian_text='Tolma4 Team; original English language slot; selected by split installation',
                        russian_voice=False, page_16kb_acceptance='USER_EXCLUDED', fmod='HOST_VERIFIED_RUNTIME_PENDING')
        write_changed(PUB / 'release_manifest.json', (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode())
        print(json.dumps(dict(status='ALL8_RELEASE_APKS_PUBLISHED_HOST_VERIFIED', pub=str(PUB),
                              files=list(published), bytes=sum(r['bytes'] for r in published.values())), indent=2))


if __name__ == '__main__':
    main()
