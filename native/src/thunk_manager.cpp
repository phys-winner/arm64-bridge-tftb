#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_types.h"
#include <android/log.h>
#include <algorithm>

#define LOG_TAG "Arm32Bridge_Thunks"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

uint32_t ThunkManager::s_screenWidth = 1213;
uint32_t ThunkManager::s_screenHeight = 540;
uint32_t ThunkManager::s_virtualWidth = 0;
uint32_t ThunkManager::s_virtualHeight = 0;
uint32_t ThunkManager::s_forced_dpi = 0;
uint32_t ThunkManager::s_ui_inset = 0;

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {}

ThunkManager::~ThunkManager() = default;

#include "thunks_opensles.h"
#include "thunks_android.h"

// These are bridge provider scopes, not host dlsym search paths. Unknown libraries
// or versions must not silently inherit a similarly named provider.
static constexpr const char* kBridgeSystemLibraries[] = {
    "libc.so", "libm.so", "libdl.so", "libstdc++.so", "liblog.so", "libandroid.so",
    "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libOpenSLES.so"
};
static constexpr const char* kBridgeVersionPairs[] = {
    "libc.so:LIBC", "libm.so:LIBC", "libdl.so:LIBC"
};

bool ThunkManager::SupportsLibrary(const std::string& library) {
    for (const char* name : kBridgeSystemLibraries) if (library == name) return true;
    return false;
}

bool ThunkManager::SupportsVersion(const std::string& library, const std::string& version) {
    if (version.empty()) return library.empty() || SupportsLibrary(library);
    for (const char* pair : kBridgeVersionPairs) if (library + ":" + version == pair) return true;
    return false;
}

void ThunkManager::RegisterAllThunks() {
    // Core providers plus the 241 FakeJniEnv slots currently fit with headroom.
    // Registration finishes before guest execution, so dispatch sees a stable array.
    m_id_to_handler.reserve(1024);
    m_registration_libraries = {"libGLESv1_CM.so", "libGLESv2.so", "libEGL.so"};
    RegisterGLThunks();
    m_registration_libraries = {"libOpenSLES.so"};
    RegisterOpenSLESThunks(*this, m_host);
    m_registration_libraries = {"libandroid.so", "liblog.so", "libEGL.so"};
    RegisterAndroidThunks(*this, m_host);
    m_registration_libraries = {"libc.so", "libm.so", "libdl.so", "libstdc++.so"};
    RegisterLibcThunks();
    m_registration_libraries.clear();
    // The guest-visible JNIEnv/JavaVM tables live in FakeJniEnv; jni_bridge.cpp
    // calls FakeJniEnv::Instance().Init(host) once the host JavaVM is known.
}

#include <jni.h>
#include <sys/system_properties.h>
#include <cmath>
#include <cctype>
#include <cstring>

JavaVM* GetHostJavaVM();

std::string QueryDeviceLanguage() {
    std::string lang = "en";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getLang = env->GetMethodID(locCls, "getLanguage", "()Ljava/lang/String;");
                        if (getLang) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getLang);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    lang = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (lang.empty() || lang == "en") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.locale", prop) > 0 ||
            __system_property_get("ro.product.locale", prop) > 0 ||
            __system_property_get("persist.sys.language", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash) *dash = '\0';
            char* under = strchr(prop, '_');
            if (under) *under = '\0';
            if (strlen(prop) > 0) lang = prop;
        }
    }
    for (char& c : lang) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lang;
}

std::string QueryDeviceCountryCode() {
    std::string country = "US";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getCountry = env->GetMethodID(locCls, "getCountry", "()Ljava/lang/String;");
                        if (getCountry) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getCountry);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    country = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (country.empty() || country == "US") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.country", prop) > 0 ||
            __system_property_get("ro.product.locale.region", prop) > 0) {
            if (strlen(prop) > 0) country = prop;
        } else if (__system_property_get("persist.sys.locale", prop) > 0 ||
                   __system_property_get("ro.product.locale", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash && strlen(dash + 1) >= 2) {
                country = std::string(dash + 1, 2);
            } else {
                char* under = strchr(prop, '_');
                if (under && strlen(under + 1) >= 2) {
                    country = std::string(under + 1, 2);
                }
            }
        }
    }
    for (char& c : country) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return country;
}

uint32_t QueryDeviceDensity() {
    if (ThunkManager::s_forced_dpi > 0) {
        return ThunkManager::s_forced_dpi;
    }
    uint32_t density = 0;
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getDM = env->GetMethodID(resCls, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;");
                        if (getDM) {
                            jobject dmObj = env->CallObjectMethod(resObj, getDM);
                            if (dmObj) {
                                jclass dmCls = env->FindClass("android/util/DisplayMetrics");
                                jfieldID fid = env->GetFieldID(dmCls, "densityDpi", "I");
                                if (fid) {
                                    density = static_cast<uint32_t>(env->GetIntField(dmObj, fid));
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (density == 0) {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.sf.lcd_density", prop) > 0 ||
            __system_property_get("qemu.sf.lcd_density", prop) > 0) {
            density = static_cast<uint32_t>(atoi(prop));
        }
    }
    if (density == 0) {
        density = 320;
    }
    return density;
}

uint32_t QueryDeviceIsPad() {
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            // Configuration.screenLayout is the platform answer; the diagonal
            // fallback below covers devices that report it wrong.
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getCfg = env->GetMethodID(resCls, "getConfiguration", "()Landroid/content/res/Configuration;");
                        if (getCfg) {
                            jobject cfgObj = env->CallObjectMethod(resObj, getCfg);
                            if (cfgObj) {
                                jclass cfgCls = env->FindClass("android/content/res/Configuration");
                                jfieldID slFid = env->GetFieldID(cfgCls, "screenLayout", "I");
                                if (slFid) {
                                    jint screenLayout = env->GetIntField(cfgObj, slFid);
                                    if ((screenLayout & 0x0F) >= 3) { // SCREENLAYOUT_SIZE_LARGE or XLARGE
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (attached) jvm->DetachCurrentThread();
                                        return 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }

    uint32_t w = ThunkManager::s_screenWidth;
    uint32_t h = ThunkManager::s_screenHeight;
    uint32_t dpi = QueryDeviceDensity();
    if (w > 0 && h > 0 && dpi > 0) {
        double w_in = static_cast<double>(w) / static_cast<double>(dpi);
        double h_in = static_cast<double>(h) / static_cast<double>(dpi);
        double diag = sqrt(w_in * w_in + h_in * h_in);
        if (diag >= 6.5) return 1;
    }
    return 0;
}


uint32_t ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    auto existing = m_symbol_to_address.find(name);
    if (existing != m_symbol_to_address.end()) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[THUNK] duplicate registration rejected: %s", name.c_str());
        return existing->second;
    }

    uint32_t thunk_id = static_cast<uint32_t>(m_id_to_handler.size() + 1);
    uint32_t thunk_addr = m_next_thunk_addr;
    m_next_thunk_addr += 8; // 2 instructions per trampoline

    // Write ARM32 trampoline instructions into guest memory:
    // 0: SVC #thunk_id (0xEF000000 | thunk_id)
    // 4: BX LR (0xE12FFF1E)
    uint32_t svc_instr = 0xEF000000 | (thunk_id & 0x00FFFFFF);
    uint32_t bx_lr_instr = 0xE12FFF1E;

    m_host.MemoryWrite32(thunk_addr, svc_instr);
    m_host.MemoryWrite32(thunk_addr + 4, bx_lr_instr);
    // Trampolines are also created at runtime (dlsym, OpenSL ES vtables), so the JIT may
    // already hold a translation of this address range.
    m_host.InvalidateGuestCode(thunk_addr, 8);

    m_symbol_to_address[name] = thunk_addr;
    m_symbol_kinds[name] = ProviderKind::Function;
    m_symbol_libraries[name] = m_registration_libraries;
    m_id_to_handler.push_back(std::move(handler));
    m_id_to_name[thunk_id] = name;
    return thunk_addr;
}

void ThunkManager::RegisterSymbol(const std::string& name, uint32_t address) {
    RegisterDataSymbol(name, address);
}

void ThunkManager::RegisterDataSymbol(const std::string& name, uint32_t address,
                                      const std::vector<std::string>& libraries) {
    auto [it, inserted] = m_symbol_to_address.emplace(name, address);
    if (!inserted) {
        if (it->second != address || m_symbol_kinds[name] != ProviderKind::Object) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[THUNK] duplicate data symbol registration rejected: %s", name.c_str());
        }
        return;
    }
    m_symbol_kinds[name] = ProviderKind::Object;
    m_symbol_libraries[name] = libraries.empty() ? m_registration_libraries : libraries;
}

uint32_t ThunkManager::FindProvider(const std::string& name, ProviderKind kind,
                                    const std::string& version, const std::string& library) const {
    auto address = m_symbol_to_address.find(name);
    auto provider = m_symbol_kinds.find(name);
    if (address == m_symbol_to_address.end() || provider == m_symbol_kinds.end() || provider->second != kind ||
        !SupportsVersion(library, version)) return 0;
    if (!library.empty()) {
        auto scope = m_symbol_libraries.find(name);
        if (scope == m_symbol_libraries.end() ||
            std::find(scope->second.begin(), scope->second.end(), library) == scope->second.end()) return 0;
    }
    return address->second;
}

uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    auto it = m_symbol_to_address.find(name);
    if (it != m_symbol_to_address.end()) return it->second;
    // Missing dlsym/vtable entries are failures, never synthetic success handlers.
    LOGE("[THUNK] Missing provider: %s (no default thunk created)", name.c_str());
    return 0;
}

void ThunkManager::DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit) {
    if (thunk_id != 0) {
        const size_t handler_index = static_cast<size_t>(thunk_id - 1);
        if (handler_index < m_id_to_handler.size()) {
            m_id_to_handler[handler_index](jit, m_host);
            return;
        }
    }

    auto name_it = m_id_to_name.find(thunk_id);
    const char* name = (name_it != m_id_to_name.end()) ? name_it->second.c_str() : "unknown";
    __android_log_assert(nullptr, LOG_TAG, "[THUNK] Unknown thunk ID: %u (%s) at PC: 0x%08X", thunk_id, name, jit.Regs()[15]);
}
