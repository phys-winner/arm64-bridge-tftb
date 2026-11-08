#include "thunks_android.h"
#include "cache_read_diag.h"
#include "cache_sources.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"
#include "presentation_pacer.h"

#include <EGL/egl.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <android/log.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <climits>
#include <memory>
#include <unistd.h>
#include <mutex>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_Android"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace {
template <typename T>
class HandleTable {
public:
    uint32_t Add(T value) {
        if (!value) return 0;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [handle, existing] : values_) if (existing == value) return handle;
        const uint32_t handle = next_++;
        values_[handle] = value;
        return handle;
    }
    T Get(uint32_t handle) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = values_.find(handle);
        return it == values_.end() ? T{} : it->second;
    }
    void Remove(uint32_t handle) {
        typename decltype(values_)::node_type removed;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            removed = values_.extract(handle);
        } // Destroy the removed resource after releasing the registry lock.
    }
private:
    mutable std::mutex mutex_;
    uint32_t next_ = 0x60000000;
    std::unordered_map<uint32_t, T> values_;
};

HandleTable<EGLDisplay> displays;
HandleTable<EGLConfig> configs;
HandleTable<EGLContext> contexts;
HandleTable<EGLSurface> surfaces;
HandleTable<ANativeWindow*> windows;
HandleTable<AAssetManager*> asset_managers;
struct BridgeAsset {
    AAsset* native = nullptr;
    CacheAssetRegion region;
    off_t position = 0;
    std::mutex mutex;
    ~BridgeAsset() {
        if (native) AAsset_close(native);
        if (region.fd >= 0) ::close(region.fd);
    }
    int Read(void* buffer, size_t count) {
        if (native) return AAsset_read(native, buffer, count);
        const size_t wanted = std::min<size_t>({count, static_cast<size_t>(region.length - position), INT_MAX});
        if (!wanted) return 0;
        ssize_t result;
        do { result = ::pread(region.fd, buffer, wanted, region.offset + position); }
        while (result < 0 && errno == EINTR);
        if (!result && wanted) { errno = EIO; return -1; }
        if (result > 0) position += result;
        return static_cast<int>(result);
    }
    off_t Seek(int32_t offset, int whence) {
        if (native) return AAsset_seek(native, offset, whence);
        const int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? position : whence == SEEK_END ? region.length : -1;
        const int64_t target = base + offset;
        if (base < 0 || target < 0 || target > region.length) { errno = EINVAL; return -1; }
        return position = static_cast<off_t>(target);
    }
    off_t Length() const { return native ? AAsset_getLength(native) : region.length; }
    int OpenFd(off_t& start, off_t& length) const {
        if (native) return AAsset_openFileDescriptor(native, &start, &length);
        const int fd = ::dup(region.fd);
        if (fd >= 0) { start = region.offset; length = region.length; }
        return fd;
    }
};

struct BridgeAssetDir {
    AAssetDir* native = nullptr;
    std::vector<std::string> names;
    size_t position = 0;
    std::mutex mutex;
    ~BridgeAssetDir() { if (native) AAssetDir_close(native); }
};

// Shared ownership keeps an in-flight call alive when another caller closes its handle.
HandleTable<std::shared_ptr<BridgeAsset>> assets;
HandleTable<std::shared_ptr<BridgeAssetDir>> asset_dirs;

bool ValidAssetManager(uint32_t handle, AAssetManager* native) {
#if defined(BRIDGE_OPENSL_TEST)
    // Shell checks have no JVM. This token can only open selected cache, never NDK assets.
    if (handle == UINT32_MAX) return true;
#endif
    return native != nullptr;
}

void AssetError(DynarmicHost& host, int error) {
    errno = error;
    const uint32_t address = host.CurrentGuestErrnoAddress();
    host.MemoryWrite32(address ? address : 0x300, static_cast<uint32_t>(error));
}

const char* GuestString(DynarmicHost& host, uint32_t address) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return nullptr;
    const char* value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
    return memchr(value, 0, host.GetGuestMemorySize() - address) ? value : nullptr;
}

const EGLint* GuestEglInts(DynarmicHost& host, uint32_t address) {
    if (!address || address % alignof(EGLint)) return nullptr;
    const size_t size = host.GetGuestMemorySize();
    for (uint64_t cursor = address; cursor + sizeof(EGLint) <= size; cursor += 2 * sizeof(EGLint)) {
        if (host.MemoryRead32(static_cast<uint32_t>(cursor)) == EGL_NONE)
            return reinterpret_cast<const EGLint*>(host.GetGuestMemoryBase() + address);
        if (cursor + 2 * sizeof(EGLint) > size) break;
    }
    LOGE("EGL rejected unterminated guest attributes at 0x%08X", address);
    return nullptr;
}

uint32_t CopyHostString(DynarmicHost& host, const char* value) {
    if (!value) return 0;
    const size_t size = strlen(value) + 1;
    const uint32_t guest = host.GuestAlloc(size, 4);
    if (guest) memcpy(host.GetGuestMemoryBase() + guest, value, size);
    return guest;
}
}

void RegisterAndroidThunks(ThunkManager& manager, DynarmicHost& host) {
    manager.RegisterThunk("ANativeWindow_fromSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject surface = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && surface) ? windows.Add(ANativeWindow_fromSurface(env, surface)) : 0;
    });
    manager.RegisterThunk("ANativeWindow_release", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        ANativeWindow* window = windows.Get(jit.Regs()[0]);
        if (window) ANativeWindow_release(window);
        windows.Remove(jit.Regs()[0]);
    });

    manager.RegisterThunk("AAssetManager_fromJava", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject object = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && object) ? asset_managers.Add(AAssetManager_fromJava(env, object)) : 0;
    });
    manager.RegisterThunk("AAssetManager_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        std::shared_ptr<BridgeAsset> asset;
        if (ValidAssetManager(jit.Regs()[0], manager_ptr) && name && jit.Regs()[2] <= AASSET_MODE_BUFFER) {
            auto opened = std::make_shared<BridgeAsset>();
            const int selected = OpenCacheAssetRegion(name, opened->region);
            if (!selected && manager_ptr) opened->native = AAssetManager_open(manager_ptr, name, jit.Regs()[2]);
            if (selected == 1 || opened->native) asset = std::move(opened);
            else AssetError(host, selected < 0 ? errno : ENOENT);
        } else AssetError(host, name ? EINVAL : EFAULT);
        jit.Regs()[0] = assets.Add(asset);
        CACHE_DIAG(cache_diag::RememberAsset(jit.Regs()[0], name,
            asset && asset->region.external ? "EXTERNAL_CACHE_ASSET" : "APK_ASSET",
            asset && asset->region.fd >= 0 ? asset->region.owner : nullptr,
            asset && asset->region.fd >= 0 ? asset->region.offset : -1, asset && asset->region.fd >= 0 ? asset->region.length : -1));
        LOGI("AAssetManager_open '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAssetManager_openDir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        std::shared_ptr<BridgeAssetDir> dir;
        if (ValidAssetManager(jit.Regs()[0], manager_ptr) && name) {
            auto opened = std::make_shared<BridgeAssetDir>();
            const bool selected = CacheAssetDirectory(name, opened->names);
            if (!selected && manager_ptr) opened->native = AAssetManager_openDir(manager_ptr, name);
            if (selected || opened->native) dir = std::move(opened);
            else AssetError(host, ENOENT);
        } else AssetError(host, name ? EINVAL : EFAULT);
        jit.Regs()[0] = asset_dirs.Add(dir);
        LOGI("AAssetManager_openDir '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAsset_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        auto asset = assets.Get(handle);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        const auto origin = cache_diag::Asset(handle);
#endif
        void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]);
        int result = -1;
        if (asset && buffer) {
            std::lock_guard<std::mutex> lock(asset->mutex);
            result = asset->Read(buffer, jit.Regs()[2]);
            if (result < 0) AssetError(host, asset->native ? EIO : errno);
        } else AssetError(host, asset ? EFAULT : EBADF);
        CACHE_DIAG(cache_diag::AssetDelivered(handle, origin, result));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AAsset_seek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto asset = assets.Get(jit.Regs()[0]);
        off_t result = -1;
        if (asset) {
            std::lock_guard<std::mutex> lock(asset->mutex);
            result = asset->Seek(static_cast<int32_t>(jit.Regs()[1]), jit.Regs()[2]);
            if (result < 0) AssetError(host, EINVAL);
        } else AssetError(host, EBADF);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AAsset_close", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        CACHE_DIAG(cache_diag::ForgetAsset(jit.Regs()[0]));
        assets.Remove(jit.Regs()[0]);
    });
    manager.RegisterThunk("AAsset_getLength", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        auto asset = assets.Get(jit.Regs()[0]);
        off_t result = 0;
        if (asset) {
            std::lock_guard<std::mutex> lock(asset->mutex);
            result = asset->Length();
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AAsset_openFileDescriptor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        auto asset = assets.Get(handle);
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], sizeof(uint32_t)) ||
            !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2], sizeof(uint32_t))) {
            AssetError(host, EFAULT);
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }
        off_t start = 0, length = 0;
        int fd = -1;
        if (asset) {
            std::lock_guard<std::mutex> lock(asset->mutex);
            fd = asset->OpenFd(start, length);
            if (fd < 0) AssetError(host, asset->native ? EIO : errno);
        } else AssetError(host, EBADF);
        CACHE_DIAG(cache_diag::RememberFd(fd, asset && asset->region.external ? "EXTERNAL_CACHE_FD" : "APK_ASSET_FD",
            cache_diag::Asset(handle).name.c_str(), asset && asset->region.fd >= 0 ? asset->region.owner : nullptr, start, length));
        if (fd >= 0) {
            host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(start));
            host.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(length));
        }
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });
    manager.RegisterThunk("AAssetDir_getNextFileName", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto dir = asset_dirs.Get(jit.Regs()[0]);
        uint32_t result = 0;
        if (dir) {
            std::lock_guard<std::mutex> lock(dir->mutex);
            const char* name = dir->native ? AAssetDir_getNextFileName(dir->native)
                : dir->position < dir->names.size() ? dir->names[dir->position++].c_str() : nullptr;
            result = CopyHostString(host, name);
        }
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("AAssetDir_rewind", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        auto dir = asset_dirs.Get(jit.Regs()[0]);
        if (dir) {
            std::lock_guard<std::mutex> lock(dir->mutex);
            if (dir->native) AAssetDir_rewind(dir->native);
            else dir->position = 0;
        }
    });
    manager.RegisterThunk("AAssetDir_close", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        asset_dirs.Remove(jit.Regs()[0]);
    });

    manager.RegisterThunk("eglBindAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglBindAPI(jit.Regs()[0]); });
    manager.RegisterThunk("eglQueryAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglQueryAPI(); });
    manager.RegisterThunk("eglGetDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = displays.Add(eglGetDisplay(EGL_DEFAULT_DISPLAY));
    });
    manager.RegisterThunk("eglInitialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        EGLint* major = jit.Regs()[1] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], sizeof(EGLint))) : nullptr;
        EGLint* minor = jit.Regs()[2] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[2], sizeof(EGLint))) : nullptr;
        if ((jit.Regs()[1] && !major) || (jit.Regs()[2] && !minor)) { jit.Regs()[0] = EGL_FALSE; return; }
        jit.Regs()[0] = eglInitialize(display, major, minor);
    });
    manager.RegisterThunk("eglChooseConfig", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[1]);
        const uint32_t out = jit.Regs()[2];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[3]);
        const uint32_t count_out = host.MemoryRead32(jit.Regs()[13]);
        if ((jit.Regs()[1] && !attributes) || capacity < 0 ||
            !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglChooseConfig(display, attributes, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglChooseConfig(display, attributes, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[2]);
        const uint32_t count_out = jit.Regs()[3];
        if (capacity < 0 || !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglGetConfigs(display, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglGetConfigs(display, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], sizeof(EGLint))) { jit.Regs()[0] = EGL_FALSE; return; }
        EGLint value = 0;
        const EGLBoolean ok = eglGetConfigAttrib(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]), jit.Regs()[2], &value);
        if (ok) host.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglCreateWindowSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        EGLSurface surface = eglCreateWindowSurface(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            windows.Get(jit.Regs()[2]), attributes);
        jit.Regs()[0] = surfaces.Add(surface);
    });
    manager.RegisterThunk("eglCreateContext", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        EGLContext context = eglCreateContext(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            contexts.Get(jit.Regs()[2]), attributes);
        jit.Regs()[0] = contexts.Add(context);
    });
    manager.RegisterThunk("eglMakeCurrent", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglMakeCurrent(displays.Get(jit.Regs()[0]), surfaces.Get(jit.Regs()[1]),
                                      surfaces.Get(jit.Regs()[2]), contexts.Get(jit.Regs()[3]));
    });
    manager.RegisterThunk("eglSwapBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
#if ARM32_BRIDGE_ENABLE_LOGGING
        static std::atomic<uint32_t> swaps{0};
#endif
        const uint32_t display = jit.Regs()[0], surface = jit.Regs()[1];
        if (displays.Get(display) && surfaces.Get(surface))
            presentation_pacer::WaitBeforeSwap(display, surface);
        // Resolve again after waiting: lifecycle may have retired either handle.
        const EGLBoolean result = eglSwapBuffers(displays.Get(display), surfaces.Get(surface));
#if ARM32_BRIDGE_ENABLE_LOGGING
        const uint32_t count = ++swaps;
        if (count <= 10 || count % 300 == 0) LOGI("eglSwapBuffers #%u result=%u", count, result);
#endif
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("eglSwapInterval", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglSwapInterval(displays.Get(jit.Regs()[0]), static_cast<EGLint>(jit.Regs()[1]));
    });
    manager.RegisterThunk("eglDestroySurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLBoolean ok = eglDestroySurface(displays.Get(jit.Regs()[0]), surfaces.Get(jit.Regs()[1]));
        if (ok) surfaces.Remove(jit.Regs()[1]);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglDestroyContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLBoolean ok = eglDestroyContext(displays.Get(jit.Regs()[0]), contexts.Get(jit.Regs()[1]));
        if (ok) contexts.Remove(jit.Regs()[1]);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglTerminate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglTerminate(displays.Get(jit.Regs()[0]));
    });
    manager.RegisterThunk("eglWaitNative", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitNative(jit.Regs()[0]); });
    manager.RegisterThunk("eglWaitGL", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitGL(); });
    manager.RegisterThunk("eglReleaseThread", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglReleaseThread(); });
    manager.RegisterThunk("eglGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglGetError(); });
    manager.RegisterThunk("eglQueryString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = CopyHostString(host, eglQueryString(displays.Get(jit.Regs()[0]), jit.Regs()[1]));
    });
    manager.RegisterThunk("eglGetCurrentDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = displays.Add(eglGetCurrentDisplay()); });
    manager.RegisterThunk("eglGetCurrentContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = contexts.Add(eglGetCurrentContext()); });
    manager.RegisterThunk("eglGetCurrentSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = surfaces.Add(eglGetCurrentSurface(jit.Regs()[0])); });
    manager.RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestString(host, jit.Regs()[0]);
        jit.Regs()[0] = name ? host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function) : 0;
    });

    LOGI("Registered Android asset/window/EGL thunks");
}
