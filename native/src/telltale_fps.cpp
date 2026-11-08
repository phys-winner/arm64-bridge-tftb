#include "telltale_fps.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "lua_fps_arg.h"
#include "presentation_pacer.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "game_port_config.h"
#include <android/log.h>
#include <android/looper.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <sys/eventfd.h>
#include <unistd.h>

JavaVM* GetHostJavaVM();
namespace {
constexpr char kSetter[] = "Port_SetFpsLimit";
std::atomic<int> ui_fd{-1};
jclass ui_class = nullptr;
std::atomic<ALooper*> ui_looper{nullptr};
jmethodID ui_apply = nullptr;
struct ErrnoRestore { int value = errno; ~ErrnoRestore() { errno = value; } };

void NotifyUi() {
    const int fd = ui_fd.load(std::memory_order_acquire);
    if (fd < 0) return; // InitUi returns the latest mode when the UI attaches.
    const uint64_t one = 1;
    ssize_t written;
    do { written = write(fd, &one, sizeof(one)); } while (written < 0 && errno == EINTR);
    if (written != static_cast<ssize_t>(sizeof(one)) && !(written < 0 && errno == EAGAIN))
        __android_log_print(ANDROID_LOG_ERROR, "Arm32Bridge_FPS", "UI signal failed: errno=%d", errno);
}

int ApplyUi(int fd, int events, void*) {
    ErrnoRestore preserve;
    uint64_t count = 0;
    ssize_t consumed = -1;
    if (!(events & (ALOOPER_EVENT_ERROR | ALOOPER_EVENT_HANGUP | ALOOPER_EVENT_INVALID))) {
        do { consumed = read(fd, &count, sizeof(count)); } while (consumed < 0 && errno == EINTR);
        if (consumed < 0 && errno == EAGAIN) return 1;
    }
    if (consumed != static_cast<ssize_t>(sizeof(count))) {
        ui_fd.store(-1, std::memory_order_release);
        // Keep this fd open: a publisher can already hold its old number.
        __android_log_print(ANDROID_LOG_ERROR, "Arm32Bridge_FPS", "UI signal registration lost");
        return 0;
    }
    JNIEnv* env = nullptr;
    JavaVM* vm = GetHostJavaVM();
    if (!vm || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
        !env || env->ExceptionCheck()) return 1;
    const int mode = presentation_pacer::GetMode(); // Unlock before Java can report refresh back.
    env->CallStaticVoidMethod(ui_class, ui_apply, static_cast<jint>(mode));
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear(); // This callback created the exception; no foreign exception is cleared.
        __android_log_print(ANDROID_LOG_ERROR, "Arm32Bridge_FPS", "applyMode failed");
    }
    ApplyPendingSdlWindowLifecycle(env);
    return 1;
}

bool ModuleSpan(const ElfLoader& module, uint32_t address, uint32_t size, uint32_t flags) {
    if (!size || address < module.GetBaseAddress()) return false;
    const uint64_t start = uint64_t(address) - module.GetBaseAddress(), end = start + size;
    for (const auto& segment : module.GetSegments())
        if (start >= segment.vaddr && end <= uint64_t(segment.vaddr) + segment.memsz &&
            (segment.flags & flags) == flags) return true;
    return false;
}
} // namespace

bool VerifyTelltaleFpsImage(JNIEnv* env, const uint8_t* image, size_t size) {
    static constexpr std::array<unsigned char, 32> expected = {
        0x2e,0x54,0xf2,0x1c,0xef,0x4c,0x90,0x6b,0x67,0x0d,0x53,0x86,0xac,0x33,0xcc,0x4f,
        0xea,0x74,0x50,0xc4,0xa8,0xfe,0x17,0x87,0x13,0xbc,0xd2,0x60,0x7a,0x4c,0x51,0xbc};
    if (!env || env->ExceptionCheck() || !image || size != 17373252 || env->PushLocalFrame(8) < 0)
        return false;
    struct Frame { JNIEnv* env; ~Frame() { env->PopLocalFrame(nullptr); } } frame{env};
    jclass cls = env->FindClass("java/security/MessageDigest");
    if (!cls || env->ExceptionCheck()) return false;
    jmethodID factory = env->GetStaticMethodID(cls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!factory || env->ExceptionCheck()) return false;
    jmethodID update = env->GetMethodID(cls, "update", "(Ljava/nio/ByteBuffer;)V");
    if (!update || env->ExceptionCheck()) return false;
    jmethodID digest = env->GetMethodID(cls, "digest", "()[B");
    if (!digest || env->ExceptionCheck()) return false;
    jstring algorithm = env->NewStringUTF("SHA-256");
    if (!algorithm || env->ExceptionCheck()) return false;
    jobject context = env->CallStaticObjectMethod(cls, factory, algorithm);
    if (!context || env->ExceptionCheck()) return false;
    jobject bytes = env->NewDirectByteBuffer(const_cast<uint8_t*>(image), static_cast<jlong>(size));
    if (!bytes || env->ExceptionCheck()) return false;
    env->CallVoidMethod(context, update, bytes);
    if (env->ExceptionCheck()) return false;
    auto result = static_cast<jbyteArray>(env->CallObjectMethod(context, digest));
    if (!result || env->ExceptionCheck() || env->GetArrayLength(result) != 32) return false;
    std::array<jbyte, 32> actual{};
    env->GetByteArrayRegion(result, 0, 32, actual.data());
    return !env->ExceptionCheck() && !std::memcmp(actual.data(), expected.data(), expected.size());
}

uint32_t RegisterTelltaleFpsSetter(DynarmicHost& host) {
    // Written once before initializers; avoid looking into mutable thunk maps from a callback.
    auto callback = std::make_shared<uint32_t>(0);
    *callback = host.GetThunkManager().RegisterThunk(kSetter, [callback](Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
        ErrnoRestore preserve;
        const int mode = DecodeTelltaleFpsArg(runtime.GetGuestMemoryBase(), runtime.GetGuestMemorySize(),
                                            jit.Regs()[0], *callback);
        presentation_pacer::SetMode(mode);
        NotifyUi();
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_FPS", "Lua mode=%d", mode);
#endif
        jit.Regs()[0] = 0; // Lua C callback returns zero results without touching its stack.
    });
    return *callback;
}

TelltaleFpsBinding PrepareTelltaleFpsBinding(DynarmicHost& host) {
    const uint32_t node = host.GuestAlloc(12 + sizeof(kSetter), 4);
    if (!node) return {};
    const uint32_t callback = RegisterTelltaleFpsSetter(host);
    if (!callback) return {};
    std::memcpy(host.GetGuestMemoryBase() + node + 12, kSetter, sizeof(kSetter));
    host.MemoryWrite32(node, node + 12);
    host.MemoryWrite32(node + 4, callback);
    host.MemoryWrite32(node + 8, 0);
    return {node, callback};
}

bool InstallTelltaleFpsBinding(DynarmicHost& host, TelltaleFpsBinding binding) {
    const ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* collection = engine ? engine->GetExportedSymbol("gLuaCollectionLuaEngine") : nullptr;
    if (!binding.node || !binding.callback || !engine || !collection || collection->type != STT_OBJECT ||
        collection->size != 12 || uint64_t(engine->GetBaseAddress()) + 0x10c6cb0 != collection->value ||
        !ModuleSpan(*engine, collection->value, 12, PF_R | PF_W) ||
        (binding.node & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), binding.node, 12 + sizeof(kSetter))) return false;
    const uint64_t constructor = uint64_t(engine->GetBaseAddress()) + 0xb9ce98;
    const uint64_t main_state = uint64_t(engine->GetBaseAddress()) + 0x10c5af4;
    if (constructor > UINT32_MAX || main_state > UINT32_MAX ||
        !ModuleSpan(*engine, static_cast<uint32_t>(constructor), 24, PF_R | PF_X) ||
        !ModuleSpan(*engine, static_cast<uint32_t>(main_state), 4, PF_R | PF_W)) return false;
    static constexpr uint32_t code[] = {0xe52de004,0xe591e004,0xe5803000,0xe9804004,0xe5810004,0xe49df004};
    for (size_t i = 0; i < std::size(code); ++i)
        if (host.MemoryRead32(static_cast<uint32_t>(constructor) + static_cast<uint32_t>(4 * i)) != code[i])
            return false;
    const uint32_t head = host.MemoryRead32(collection->value + 4);
    if (host.MemoryRead32(collection->value) || host.MemoryRead32(static_cast<uint32_t>(main_state)) ||
        !head || (head & 3u) || !ModuleSpan(*engine, head, 12, PF_R | PF_W) ||
        host.MemoryRead32(binding.node) != binding.node + 12 ||
        host.MemoryRead32(binding.node + 4) != binding.callback ||
        std::memcmp(host.GetGuestMemoryBase() + binding.node + 12, kSetter, sizeof(kSetter))) return false;
    host.MemoryWrite32(binding.node + 8, head);
    host.MemoryWrite32(collection->value + 4, binding.node); // Publish last, before ScriptManager creates Lua.
    return true;
}

void NotifyTelltaleUiLifecycle() {
    ErrnoRestore preserve;
    NotifyUi();
}

bool TelltaleUiLifecycleOwner() {
    return ui_fd.load(std::memory_order_acquire) >= 0 &&
        ALooper_forThread() == ui_looper.load(std::memory_order_acquire);
}

jint InitTelltaleFpsUi(JNIEnv* env, jclass cls) {
    ErrnoRestore preserve;
    if (!env || env->ExceptionCheck() || !ALooper_forThread()) return -1;
    if (ui_fd.load(std::memory_order_acquire) >= 0) {
        if (!TelltaleUiLifecycleOwner()) return -1;
        ApplyPendingSdlWindowLifecycle(env);
        return presentation_pacer::GetMode();
    }
    jmethodID apply = env->GetStaticMethodID(cls, "applyMode", "(I)V");
    if (!apply || env->ExceptionCheck()) return -1;
    jclass global = static_cast<jclass>(env->NewGlobalRef(cls));
    if (!global || env->ExceptionCheck()) return -1;
    const int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0 || ALooper_addFd(ALooper_forThread(), fd, 0, ALOOPER_EVENT_INPUT, ApplyUi, nullptr) != 1) {
        if (fd >= 0) close(fd);
        env->DeleteGlobalRef(global);
        return -1;
    }
    if (ui_class) env->DeleteGlobalRef(ui_class);
    ui_class = global;
    ui_apply = apply;
    ui_looper.store(ALooper_forThread(), std::memory_order_release);
    // shortcut: UI looper/class/fd live for this process; add teardown if the host unloads its library.
    ui_fd.store(fd, std::memory_order_release);
    ApplyPendingSdlWindowLifecycle(env);
    return presentation_pacer::GetMode();
}

void RefreshTelltaleFpsDisplay(JNIEnv*, jclass, jfloat actual_hz) {
    ErrnoRestore preserve;
    presentation_pacer::SetRefreshHz(actual_hz);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_FPS", "observed refresh=%.6f", actual_hz);
#endif
}
