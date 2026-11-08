#!/usr/bin/env python3
"""Build the relocatable ARM-state guest qsort image."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

TARGET = "armv7a-linux-androideabi26"
ENTRY = "guest_qsort_entry"
SECTION_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+\S+\s+([A-Za-z]+)"
)
SYMBOL_RE = re.compile(
    r"^\s*\d+:\s+([0-9A-Fa-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)(?:\s+(\S+))?"
)


class BuildError(RuntimeError):
    pass


def run(command: list[Path | str], capture: bool = False) -> str:
    print("+", " ".join(map(str, command)))
    result = subprocess.run(
        [str(arg) for arg in command], check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    return result.stdout if capture else ""


def select_ndk(value: Path | None) -> Path:
    if value:
        return value
    for variable in ("CMAKE_ANDROID_NDK", "ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"):
        if os.environ.get(variable):
            return Path(os.environ[variable])
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(variable):
            return Path(os.environ[variable]) / "ndk/27.2.12479018"
    return Path.home() / "AppData/Local/Android/Sdk/ndk/27.2.12479018"


def get_tools(ndk: Path) -> dict[str, Path]:
    props = ndk / "source.properties"
    if not props.is_file():
        raise BuildError(f"NDK source.properties not found: {props}")
    revision = re.search(r"Pkg\.Revision\s*=\s*([0-9]+)\.([0-9]+)", props.read_text())
    if not revision or revision.groups() != ("27", "2"):
        raise BuildError(f"NDK 27.2 required: {ndk}")
    bindir = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
    result = {n: bindir / n for n in ("clang.exe", "ld.lld.exe", "llvm-readelf.exe", "llvm-objcopy.exe")}
    missing = [str(path) for path in result.values() if not path.is_file()]
    if missing:
        raise BuildError("missing NDK tools: " + ", ".join(missing))
    return result


def check_elf(tc: dict[str, Path], elf: Path, base: int, raw: Path) -> tuple[bytes, int]:
    section_text = run([tc["llvm-readelf.exe"], "-SW", elf], True)
    allocated, text_flags = [], ""
    for line in section_text.splitlines():
        match = SECTION_RE.match(line)
        if not match:
            continue
        name, flags = match.groups()
        if ".got" in name or ".plt" in name:
            raise BuildError(f"GOT/PLT section present: {name}")
        if name == ".text":
            text_flags = flags
        if "A" in flags:
            allocated.append(name)
    if allocated != [".text"] or "X" not in text_flags:
        raise BuildError(f"unexpected allocated sections: {allocated}")

    if "Relocation section" in run([tc["llvm-readelf.exe"], "-r", elf], True):
        raise BuildError("runtime relocations remain in linked image")
    entry = None
    for line in run([tc["llvm-readelf.exe"], "-sW", elf], True).splitlines():
        match = SYMBOL_RE.match(line)
        if not match:
            continue
        value, index, name = match.groups()
        if index == "UND" and name:
            raise BuildError(f"undefined symbol remains: {name}")
        if name == "_GLOBAL_OFFSET_TABLE_":
            raise BuildError("GOT symbol remains in linked image")
        if name == ENTRY:
            entry = int(value, 16)
    if entry is None or entry < base:
        raise BuildError(f"missing {ENTRY} symbol")

    run([tc["llvm-objcopy.exe"], "-O", "binary", "--only-section=.text", elf, raw])
    image = raw.read_bytes()
    offset = entry - base
    if not image or offset < 0 or offset >= len(image):
        raise BuildError("entry point is outside extracted .text")
    return image, offset


def make_link_script(path: Path, base: int) -> None:
    path.write_text(
        f"""OUTPUT_FORMAT(elf32-littlearm)
OUTPUT_ARCH(arm)
ENTRY({ENTRY})
SECTIONS
{{
  . = 0x{base:x};
  .text : {{ KEEP(*(.text.guest_qsort_entry)) *(.text*) }}
  .rodata : {{ *(.rodata*) }}
  .data : {{ *(.data*) }}
  .bss (NOLOAD) : {{ *(.bss*) *(COMMON) }}
  /DISCARD/ : {{ *(.ARM.exidx*) *(.ARM.extab*) *(.eh_frame*) *(.comment) *(.note*) }}
}}
""",
        encoding="ascii",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--source", type=Path, default=root / "src/guest_qsort.c")
    parser.add_argument("--output", type=Path, default=root / "guest_qsort_image.h")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    work, output = (args.work_dir or args.output.parent / "guest_qsort_build").resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        tc = get_tools(select_ndk(args.ndk).resolve())
        obj = work / "guest_qsort.o"
        run([tc["clang.exe"], f"--target={TARGET}", "-march=armv7-a", "-marm", "-mfloat-abi=softfp",
             "-std=c11", "-O2", "-ffreestanding", "-fno-builtin", "-fPIC", "-fno-plt",
             "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
             "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-c",
             args.source.resolve(), "-o", obj])
        images, offsets = [], []
        for base in (0, 0x10000):
            script, elf, raw = (work / f"guest_qsort_{base:x}.{suffix}" for suffix in ("ld", "elf", "bin"))
            make_link_script(script, base)
            run([tc["ld.lld.exe"], "-flavor", "gnu", "-m", "armelf_linux_eabi", "--gc-sections",
                 "--no-undefined", "-T", script, "-o", elf, obj])
            image, offset = check_elf(tc, elf, base, raw)
            images.append(image)
            offsets.append(offset)
        if images[0] != images[1] or offsets[0] != offsets[1]:
            raise BuildError("images or entry offsets differ at link bases 0 and 0x10000")
        lines = ["#pragma once", "", "#include <cstdint>", "", "inline constexpr unsigned char kGuestQsortCode[] = {"]
        lines += ["    " + ", ".join(f"0x{byte:02x}" for byte in images[0][i:i + 12]) + "," for i in range(0, len(images[0]), 12)]
        lines += ["};", "", f"inline constexpr uint32_t kGuestQsortEntryOffset = 0x{offsets[0]:x}u;", ""]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    except (OSError, subprocess.CalledProcessError, BuildError) as error:
        parser.error(str(error))
    print(f"guest qsort image: {len(images[0])} bytes, entry offset 0x{offsets[0]:x}")
    print(f"header: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
