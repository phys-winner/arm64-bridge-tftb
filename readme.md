# ARM64 bridge for Tales from the Borderlands

An unofficial ARM32-to-ARM64 compatibility bridge for the Android version of **Tales from the Borderlands**, with tools for validating and packaging a locally prepared game installation.

The bridge runs the original ARMv7 native modules through Dynarmic on ARM64 Android and forwards their Android, JNI, graphics, audio and C library calls to the host. It targets game version **1.79 (version code 10179)** and package `com.telltalegames.borderlands100`.

This is a source repository. It contains no game executables, APKs, OBBs, decoded game code, assets, saves, signing keys, device logs or bundled third-party dependency sources. You must supply your own legally obtained game files. It is not a standalone replacement for the game or an automatic original-APK-to-port converter.

## Features

- ARMv7 ELF loading and ARM64 JIT execution using a pinned, locally patched Dynarmic checkout.
- JNI and native API bridging for the original SDL2, FMOD and game engine modules.
- OpenGL ES, EGL and OpenSL ES forwarding, including audio callback and lifecycle handling.
- Direct reading of whole cache containers from stored APK entries, with size, checksum, hash and owner-cohort validation; optional external cache support.
- Game-specific widescreen and presentation pacing support.
- Android API 24 target for the native bridge and 16 KiB ELF segment alignment.
- Python tools for archive inspection, guarded Lua edits, texture repair, cache verification and split APK packaging.

## Repository layout

| Path | Purpose |
| --- | --- |
| `native/src/` | Bridge implementation and game-specific cache metadata |
| `native/patches/dynarmic/` | Patch applied to a disposable dependency copy during configuration |
| `native/tests/` | Bridge regression fixtures and original-engine fingerprint check |
| `bridge/game_port_config.h` | TFTB module list and bridge feature selection |
| `build_arm64.ps1` | Native build entry point |
| `work/tools/` | Game data processing, verification and packaging scripts |

## External dependencies

Prepare dependencies outside this repository. The build does not download them automatically.

| Dependency | Tested version / revision | Source |
| --- | --- | --- |
| Dynarmic | `e77b1ba0b7da7cbe93021b01a663acfe7c4dd516` | [azahar-emu/dynarmic](https://github.com/azahar-emu/dynarmic) |
| Boost headers | 1.83.0 | [Boost releases](https://www.boost.org/releases/) |
| Android NDK | 27.2.12479018 | Android SDK Manager |
| CMake and Ninja | SDK CMake 3.22.1 | Android SDK Manager |
| Python | 3.13 used for validation; standard library only | [Python](https://www.python.org/) |
| PowerShell | 7 | [PowerShell](https://github.com/PowerShell/PowerShell) |
| Git | With submodule support | [Git](https://git-scm.com/) |

Dynarmic must be a clean checkout at the exact revision above, with its submodules initialized. Its own external libraries remain in that external checkout. The repository stores only the bridge's Dynarmic patch. Boost's selected directory must contain `boost/version.hpp`.

For an initial dependency checkout, run these commands from a separate dependency directory:

```powershell
git clone --no-checkout https://github.com/azahar-emu/dynarmic.git dynarmic
git -C dynarmic checkout --detach e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
git -C dynarmic submodule update --init --recursive
```

Set `ANDROID_SDK_ROOT`, `DYNARMIC_SOURCE_DIR` and `BOOST_ROOT` in your local environment. They select the Android SDK, external Dynarmic checkout and external Boost headers. Do not put machine paths or credentials in tracked files.

## Build the native bridge

The build validates the original ARMv7 game engine before compiling. Supply it locally at `app/assets/guestlib/armeabi-v7a/libGameEngine.so`. This ignored input must be exactly **17,373,252 bytes** with SHA-256:

```text
2e54f21cef4c906b670d5386ac33cc4fea7450c4a8fe178713bcd2607a4c51bc
```

From the repository root, with the dependency environment variables set:

```powershell
pwsh -NoProfile -File ./build_arm64.ps1
```

The output is `out/native-candidate/libmain.so`; intermediate files stay in `out/native-build/`. The wrapper verifies the output's AArch64 ELF identity and at least 16 KiB load-segment alignment. For explicit dependency paths, use the wrapper's `-SdkRoot`, `-DynarmicSourceDir` and `-BoostRoot` parameters. Internal logging is off unless `-EnableLogging` is passed.

The guest modules remain ARMv7. The resulting bridge is an ARM64 Android library and requires the corresponding game-side Java/JNI integration and original guest libraries in a locally prepared APK.

## Game processing and packaging

These tools operate on an existing, privately prepared restoration workspace. A fresh source checkout does not contain that workspace. In particular, full packaging needs the canonical apktool `app/` and `splits/` trees, original data archives, the private menu Lua sources and pinned archive preimages under `work/menu_ui/`, and the external-cache verification fixture under `bridge/`. These inputs are deliberately excluded from Git.

For packaging, additionally set:

- `APK_TOOL_ROOT`: directory containing `apktool.jar` and `sdk/build-tools/37.0.0/` with `aapt2.exe` and `zipalign.exe`.
- `JAVA_EXE`: Java executable; the existing workflow used JDK 24.
- `APK_SIGNER_ROOT`: private portable signer directory containing `apksigner.jar`, `testkey.pk8` and `testkey.x509.pem`.
- `PWSH_EXE`: optional PowerShell executable override; defaults to `pwsh`.

The signer certificate must match the existing restoration's pinned SHA-256 certificate fingerprint. The scripts fail on a mismatch. Do not commit signing material or silently substitute another certificate.

Useful entry points, after supplying their private inputs:

```powershell
python -B work/tools/verify_cache_sources.py
python -B work/tools/verify_cache_apks.py --help
python -B work/tools/apk_build.py --help
python -B work/tools/repair_tolma_textures.py --help
python -B work/tools/route_signals.py --help
```

`work/tools/build_release.py` rebuilds the native library, prepares the optional Russian split, packages eight APKs, verifies them and replaces matching files and release metadata in the local `pub/` directory. Run it only when you intend to rebuild those local outputs. It does not upload anything or repeat device acceptance.

`patch_menu_startup.py` requires the private, pinned preimages and menu inputs; it checks expected Lua instructions before changing archives. The texture repair tool likewise checks known inputs. Neither tool is a general-purpose patcher for arbitrary game versions.

## Checks and compatibility limits

```powershell
python -B native/tests/fps_image_pin_check.py
python -B work/tools/lua52_inspect.py
python -B work/tools/ttarchive_reader.py
```

The native CMake project also provides the optional `guest_qsort_test` and `elf_loader_test` Android targets. They are not built by default and need separate device execution.

The restoration has prior bounded device validation, including startup, selected gameplay, menus, lifecycle and audio callback fixtures. This source publication does not establish full-campaign compatibility, every QTE, all-device support or acceptance on an ARM64-only device running with 16 KiB memory pages. Static ELF alignment alone does not prove runtime compatibility. Game-specific fingerprints intentionally reject other engine versions.

## License

The original bridge and tooling in this repository are licensed under **GNU GPL version 3 or, at your option, any later version** (`GPL-3.0-or-later`). See [LICENSE](LICENSE). When distributing covered binaries or modified versions, follow the GPL's corresponding-source and license requirements.

External dependencies retain their own licenses and notices. The Dynarmic patch modifies ISC-licensed upstream code; preserve upstream notices when distributing the patched dependency. No license to the game, its assets, FMOD binaries, translations or other proprietary material is granted here. This project is not affiliated with or endorsed by the game's rights holders.
