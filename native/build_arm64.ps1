[CmdletBinding()]
param(
    [string]$SdkRoot,
    [string]$NdkVersion = '27.2.12479018',
    [string]$CmakeVersion = '3.22.1',
    [string]$AndroidPlatform = 'android-26',
    [string]$TargetName = 'main',
    [Parameter(Mandatory = $true)][string]$GameConfigDir,
    [string]$DynarmicSourceDir,
    [string]$BoostRoot = $env:BOOST_ROOT,
    [switch]$EnableJitPerfMap,
    [switch]$EnableDynarmicValidation,
    [switch]$EnableLogging,
    [string]$JitPerfMapDirectory = '/data/local/tmp',
    [string]$BuildDirectory,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$Project = $PSScriptRoot
if ($TargetName -notmatch '\A[A-Za-z_][A-Za-z0-9_]*\z') {
    throw "invalid bridge target name: $TargetName"
}
if (-not $SdkRoot) {
    $SdkRoot = if ($env:ANDROID_SDK_ROOT) {
        $env:ANDROID_SDK_ROOT
    }
    else {
        Join-Path $env:LOCALAPPDATA 'Android\Sdk'
    }
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Project 'dist'
}
if (-not $DynarmicSourceDir) {
    $DynarmicSourceDir = $env:DYNARMIC_SOURCE_DIR
}
if (-not $DynarmicSourceDir) {
    throw 'DynarmicSourceDir (or DYNARMIC_SOURCE_DIR) must select an external pinned checkout'
}
if (-not $BoostRoot -or -not (Test-Path -LiteralPath (Join-Path $BoostRoot 'boost/version.hpp') -PathType Leaf)) {
    throw 'BoostRoot (or BOOST_ROOT) must select an external Boost 1.83 header root'
}
$BoostRoot = (Resolve-Path -LiteralPath $BoostRoot).Path
$DynarmicSourceDir = (Resolve-Path -LiteralPath $DynarmicSourceDir).Path

$Ndk = Join-Path $SdkRoot "ndk\$NdkVersion"
$CmakeRoot = Join-Path $SdkRoot "cmake\$CmakeVersion"
$Cmake = Join-Path $CmakeRoot 'bin\cmake.exe'
$Ninja = Join-Path $CmakeRoot 'bin\ninja.exe'
$Toolchain = Join-Path $Ndk 'build\cmake\android.toolchain.cmake'
$LlvmBin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$Strip = Join-Path $LlvmBin 'llvm-strip.exe'
$Readelf = Join-Path $LlvmBin 'llvm-readelf.exe'
if (-not $BuildDirectory) {
    $BuildDirectory = Join-Path $Project "build_arm64_$TargetName"
}
$Build = [IO.Path]::GetFullPath($BuildDirectory)
$BuildPrefix = $Build.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar
if ($DynarmicSourceDir.Equals($Build, [StringComparison]::OrdinalIgnoreCase) -or
    $DynarmicSourceDir.StartsWith($BuildPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'DynarmicSourceDir must be outside BuildDirectory so a clean rebuild cannot delete its own input'
}
$BuiltLibrary = Join-Path $Build "lib$TargetName.so"
$OutputLibrary = Join-Path $OutputDirectory "lib$TargetName.so"

if (-not (Test-Path -LiteralPath (Join-Path $GameConfigDir 'game_port_config.h') -PathType Leaf)) {
    throw "missing game_port_config.h in: $GameConfigDir"
}
foreach ($Required in @($Cmake, $Ninja, $Toolchain, $Strip, $Readelf)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "missing build dependency: $Required"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $DynarmicSourceDir 'CMakeLists.txt') -PathType Leaf)) {
    throw "invalid Dynarmic checkout: $DynarmicSourceDir"
}

New-Item -ItemType Directory -Path $Build -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$JitPerfMapEnabled = if ($EnableJitPerfMap) { 'ON' } else { 'OFF' }
$DynarmicValidationEnabled = if ($EnableDynarmicValidation) { 'ON' } else { 'OFF' }
$LoggingEnabled = if ($EnableLogging) { 'ON' } else { 'OFF' }

& $Cmake -S $Project -B $Build -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$Ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
    '-DANDROID_ABI=arm64-v8a' `
    "-DANDROID_PLATFORM=$AndroidPlatform" `
    '-DANDROID_STL=c++_static' `
    "-DBRIDGE_TARGET=$TargetName" `
    "-DGAME_CONFIG_DIR=$GameConfigDir" `
    "-DBOOST_ROOT=$BoostRoot" `
    "-DFETCHCONTENT_SOURCE_DIR_DYNARMIC=$DynarmicSourceDir" `
    '-DFETCHCONTENT_FULLY_DISCONNECTED=ON' `
    '-DFETCHCONTENT_UPDATES_DISCONNECTED=ON' `
    "-DARM32_BRIDGE_ENABLE_JIT_PERF_MAP=$JitPerfMapEnabled" `
    "-DARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION=$DynarmicValidationEnabled" `
    "-DARM32_BRIDGE_ENABLE_LOGGING=$LoggingEnabled" `
    "-DARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY=$JitPerfMapDirectory" `
    '-DCMAKE_BUILD_TYPE=Release'
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed: $LASTEXITCODE"
}

& $Cmake --build $Build --config Release --parallel
if ($LASTEXITCODE -ne 0) {
    throw "ARM64 bridge build failed: $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $BuiltLibrary -PathType Leaf)) {
    throw "bridge output is missing: $BuiltLibrary"
}

Copy-Item -LiteralPath $BuiltLibrary -Destination $OutputLibrary -Force
& $Strip --strip-unneeded $OutputLibrary
if ($LASTEXITCODE -ne 0) {
    throw "llvm-strip failed: $LASTEXITCODE"
}

$Header = (& $Readelf -h $OutputLibrary) -join "`n"
if ($Header -notmatch 'Class:\s+ELF64' -or $Header -notmatch 'Machine:\s+AArch64') {
    throw 'bridge is not ELF64 AArch64'
}
$Loads = & $Readelf -lW $OutputLibrary | Select-String '^\s*LOAD\s'
if (-not $Loads) {
    throw 'bridge has no PT_LOAD segments'
}
foreach ($Load in $Loads) {
    if ($Load.Line -notmatch '\s(0x[0-9a-fA-F]+)\s*$') {
        throw "unable to parse PT_LOAD alignment: $($Load.Line)"
    }
    $Alignment = [Convert]::ToUInt64($Matches[1].Substring(2), 16)
    if ($Alignment -lt 0x4000) {
        throw "PT_LOAD alignment below 16 KiB: $($Load.Line)"
    }
}

Get-Item -LiteralPath $OutputLibrary | Select-Object FullName, Length, LastWriteTime
Get-FileHash -Algorithm SHA256 -LiteralPath $OutputLibrary
