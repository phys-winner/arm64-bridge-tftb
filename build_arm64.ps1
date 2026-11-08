[CmdletBinding()]
param(
    [string]$SdkRoot = $env:ANDROID_SDK_ROOT,
    [string]$DynarmicSourceDir = $env:DYNARMIC_SOURCE_DIR,
    [string]$BoostRoot = $env:BOOST_ROOT,
    [switch]$EnableLogging
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'native/build_arm64.ps1') `
    -GameConfigDir (Join-Path $PSScriptRoot 'bridge') `
    -BuildDirectory (Join-Path $PSScriptRoot 'out/native-build') `
    -OutputDirectory (Join-Path $PSScriptRoot 'out/native-candidate') `
    -DynarmicSourceDir $DynarmicSourceDir -BoostRoot $BoostRoot -SdkRoot $SdkRoot `
    -TargetName main -AndroidPlatform android-24 -EnableLogging:$EnableLogging
