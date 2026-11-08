#pragma once

#include <array>

// TFTB 1.79: retain its five original softfp modules and native interfaces.
#define ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION 1
#define ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_INDEX 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_CURRENT_DIRECTORY_FIX 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_DIAGNOSTIC_PROBES 0
#define ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG 0
#define ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_AUDIO_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_GL_SHADER_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE 0
#define ARM32_BRIDGE_ENABLE_GOT_WIDESCREEN_OVERRIDE 0
#define ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE 1
#define ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE 0
#define ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE 0
#define ARM32_BRIDGE_ENABLE_MCSM_RESOURCE_HOOKS 0
#define ARM32_BRIDGE_REDIRECT_EXTERNAL_STORAGE_TO_APP_FILES 1

namespace portcfg {
inline constexpr char kSdlActivityClass[] = "org/libsdl/app/SDLActivity";
inline constexpr char kSdlInputClass[] = "org/libsdl/app/SDLInputConnection";
inline constexpr char kFmodMediaCodecClass[] = "org/fmod/MediaCodec";
inline constexpr char kTelltaleActivityClass[] = "com/telltalegames/telltale/TelltaleActivity";
inline constexpr char kGuestAssetPrefix[] = "assets/guestlib/armeabi-v7a/";
inline constexpr std::array kGuestModules = {
    "libfmod.so", "libfmodstudio.so", "libSDL2.so", "libGameEngine.so", "libmain.so",
};
}
