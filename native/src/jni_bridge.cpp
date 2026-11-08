#include <jni.h>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <zlib.h>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "jni_fake_env.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "game_port_config.h"
#include "cache_read_diag.h"
#include "cache_bootstrap.h"
#include "tftb_cache_manifest.h"
#if defined(BRIDGE_OPENSL_TEST)
#include <cassert>
#include <cstdio>
#include <cstdlib>
#endif
#include "thunks_opensles.h"
#include "telltale_addcallback_fastpath.h"
#include "telltale_propertyset_fastpath.h"
#include "presentation_pacer.h"
#include "telltale_fps.h"

#define LOG_TAG "Arm32Bridge_JNI"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

std::unique_ptr<DynarmicHost> g_host;
JavaVM* g_jvm = nullptr;
JavaVM* GetHostJavaVM() { return g_jvm; }
static std::mutex& g_load_mutex = cache_bootstrap::LoadMutex();
static std::atomic<bool> g_ready{false};
static thread_local bool g_loading_here = false;
static bool g_load_started = false; // One attempt; guest threads/FakeJNI may retain a failed host.
static std::string g_files_dir;
static std::mutex g_presentation_mutex;
// SDL starts unpaused; ready and Surface still gate the initial render loop.
static bool g_presentation_foreground = true, g_presentation_surface = false;

static void UpdatePresentationActiveLocked() {
    presentation_pacer::SetActive(g_ready.load(std::memory_order_acquire) &&
                                 g_presentation_foreground && g_presentation_surface);
}
static void SetPresentationForeground(bool foreground) {
    std::lock_guard<std::mutex> lock(g_presentation_mutex);
    g_presentation_foreground = foreground;
    UpdatePresentationActiveLocked();
    presentation_pacer::Reset();
}
static void SetPresentationSurface(bool present) {
    std::lock_guard<std::mutex> lock(g_presentation_mutex);
    g_presentation_surface = present;
    UpdatePresentationActiveLocked();
    presentation_pacer::Reset();
}

extern "C" int TelltaleWidescreenOverrideEnabled();

// The source image lives in a STORED APK asset. ELF segments are copied by
// LoadModulesFromMemory; this mapping can be released before guest execution.
struct GuestAssetImage {
    void* mapping = MAP_FAILED;
    size_t span = 0, bias = 0, size = 0;
    std::string asset;

    const uint8_t* data() const { return static_cast<const uint8_t*>(mapping) + bias; }
    bool Unmap() {
        if (mapping == MAP_FAILED) return true;
        const int result = munmap(mapping, span);
        __android_log_print(result ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG,
                            "guest munmap: asset=%s span=%zu result=%d", asset.c_str(), span, result);
        mapping = MAP_FAILED;
        return result == 0;
    }
    ~GuestAssetImage() { Unmap(); }
};

static bool MapGuestAsset(AAssetManager* manager, const std::string& entry, GuestAssetImage& image) {
    if (!manager || !entry.starts_with("assets/")) return false;
    AAsset* asset = AAssetManager_open(manager, entry.c_str() + 7, AASSET_MODE_RANDOM);
    if (!asset) { LOGE("Guest asset missing: %s", entry.c_str()); return false; }
    off64_t start = 0, length = 0;
    const off64_t asset_length = AAsset_getLength64(asset);
    const int source_fd = AAsset_openFileDescriptor64(asset, &start, &length);
    const int fd = source_fd >= 0 ? dup(source_fd) : -1;
    if (source_fd >= 0) close(source_fd);
    AAsset_close(asset);
    const long page = sysconf(_SC_PAGESIZE);
    struct stat status{};
    if (fd < 0 || start < 0 || start % alignof(Elf32_Ehdr) || length <= 0 ||
        length != asset_length || page <= 0 || fstat(fd, &status) || !S_ISREG(status.st_mode) ||
        start > status.st_size || length > status.st_size - start ||
        static_cast<uint64_t>(length) > SIZE_MAX - static_cast<uint64_t>(page)) {
        if (fd >= 0) close(fd);
        LOGE("Guest asset is not a valid directly readable STORED file: %s", entry.c_str());
        return false;
    }
    image.asset = entry;
    image.bias = static_cast<size_t>(start % page);
    image.size = static_cast<size_t>(length);
    image.span = image.bias + image.size;
    image.mapping = mmap(nullptr, image.span, PROT_READ, MAP_PRIVATE, fd, start - image.bias);
    __android_log_print(image.mapping == MAP_FAILED ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG,
                        "guest mmap: asset=%s fd=%d offset=%lld size=%zu apk_size=%lld page=%ld -> %p",
                        entry.c_str(), fd, static_cast<long long>(start), image.size,
                        static_cast<long long>(status.st_size), page,
                        image.mapping == MAP_FAILED ? nullptr : image.data());
    close(fd);
    return image.mapping != MAP_FAILED;
}

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION
static bool InstallTelltaleZlibAcceleration(DynarmicHost& host) {
    static constexpr char kSymbol[] = "_ZN11Compression14ZlibDecompressEPvPjPKvj";
    static constexpr std::array<uint32_t, 13> kFingerprint = {
        0xE92D4010, 0xE24DD008, 0xE1A04001, 0xE3A0C004, 0xE5911000,
        0xE58DC000, 0xEBFFFF4B, 0xE5943000, 0xE0630000, 0xE16F0F10,
        0xE1A002A0, 0xE28DD008, 0xE8BD8010,
    };

    ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* symbol = engine ? engine->GetExportedSymbol(kSymbol) : nullptr;
    if (!symbol || symbol->type != STT_FUNC || symbol->size != sizeof(kFingerprint) ||
        !symbol->value || (symbol->value & 1u)) {
        LOGE("Native raw-DEFLATE acceleration unavailable: unexpected symbol metadata");
        return false;
    }

    const uint32_t target = symbol->value;
    for (size_t i = 0; i < kFingerprint.size(); ++i) {
        if (host.MemoryRead32(target + static_cast<uint32_t>(i * sizeof(uint32_t))) != kFingerprint[i]) {
            LOGE("Native raw-DEFLATE acceleration refused: fingerprint mismatch at 0x%08X",
                 target + static_cast<uint32_t>(i * sizeof(uint32_t)));
            return false;
        }
    }

    const uint32_t thunk = host.GetThunkManager().RegisterThunk(
        "__telltale_native_raw_deflate_decompress",
        [](Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
            const uint32_t destination = jit.Regs()[0];
            const uint32_t expected_size_ptr = jit.Regs()[1];
            const uint32_t source = jit.Regs()[2];
            const uint32_t source_size = jit.Regs()[3];
            uint32_t produced = UINT32_MAX;

            if (destination && expected_size_ptr && source &&
                GuestRangeValid(runtime.GetGuestMemorySize(), expected_size_ptr, sizeof(uint32_t))) {
                const uint32_t capacity = runtime.MemoryRead32(expected_size_ptr);
                auto* output = static_cast<Bytef*>(GuestSpan(runtime.GetGuestMemoryBase(),
                                                             runtime.GetGuestMemorySize(),
                                                             destination, capacity));
                auto* input = static_cast<Bytef*>(GuestSpan(runtime.GetGuestMemoryBase(),
                                                            runtime.GetGuestMemorySize(),
                                                            source, source_size));
                if (output && input) {
                    Bytef empty_output = 0;
                    z_stream stream{};
                    stream.next_in = input;
                    stream.avail_in = source_size;
                    stream.next_out = capacity ? output : &empty_output;
                    stream.avail_out = capacity;

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS
                    const auto start = std::chrono::steady_clock::now();
#endif
                    const int init_result = inflateInit2(&stream, -MAX_WBITS);
                    int inflate_result = init_result;
                    if (init_result == Z_OK) {
                        inflate_result = inflate(&stream, Z_FINISH);
                        if (inflate_result == Z_STREAM_END && stream.total_out <= UINT32_MAX) {
                            produced = static_cast<uint32_t>(stream.total_out);
                        }
                        inflateEnd(&stream);
                    }

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS
                    static std::atomic<uint32_t> calls{0};
                    static std::atomic<uint64_t> total_output{0};
                    static std::atomic<uint64_t> total_microseconds{0};
                    const uint64_t elapsed_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start).count());
                    const uint32_t call = calls.fetch_add(1, std::memory_order_relaxed) + 1;
                    const uint64_t bytes = produced == UINT32_MAX ? 0 : produced;
                    const uint64_t aggregate_bytes =
                        total_output.fetch_add(bytes, std::memory_order_relaxed) + bytes;
                    const uint64_t aggregate_us =
                        total_microseconds.fetch_add(elapsed_us, std::memory_order_relaxed) + elapsed_us;
                    if ((call & (call - 1)) == 0) {
                        LOGI("Native raw-DEFLATE calls=%u last=%u->%u status=%d total=%" PRIu64
                             " bytes time=%" PRIu64 " us",
                             call, source_size, produced, inflate_result,
                             aggregate_bytes, aggregate_us);
                    }
#endif
                }
            }

            // The ARM32 wrapper reads the expected size again and never writes it.
            jit.Regs()[0] = produced == runtime.MemoryRead32(expected_size_ptr) ? 1u : 0u;
        });
    if (!thunk) {
        LOGE("Native raw-DEFLATE acceleration unavailable: thunk registration failed");
        return false;
    }

    // Tail-jump through the bridge trampoline. Writing the destination first keeps
    // the entry fail-closed if a debugger observes the pair between stores.
    host.MemoryWrite32(target + 4, thunk);
    host.MemoryWrite32(target, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.InvalidateGuestCode(target, 8);
    LOGI("Installed native raw-DEFLATE acceleration at 0x%08X -> 0x%08X", target, thunk);
    return true;
}
#endif

static std::string JString(JNIEnv* env, jstring value) {
    if (!value) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return result;
}


// Diagnostic metadata only; never creates dirs, reads payloads or changes cache ownership.
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
struct PrivateMetaIdentity {
    std::string package, ce, de, native_library;
    uid_t uid = static_cast<uid_t>(-1);
};
static PrivateMetaIdentity g_private_identity; // Single writer under the existing job load mutex.
static std::atomic<bool> g_private_identity_ready{false}; // Immutable after release publication.
static std::atomic<bool> g_private_prepare_taken{false}, g_private_before_taken{false};
static std::atomic<bool> g_private_mid_taken{false}, g_private_route_taken{false};
static std::atomic<bool> g_private_after_taken{false}, g_private_exit_taken{false};

struct PrivateMetaErrno {
    int saved = errno;
    ~PrivateMetaErrno() { errno = saved; }
};
struct PrivateMetaFd {
    int value;
    explicit PrivateMetaFd(int fd = -1) : value(fd) {}
    PrivateMetaFd(const PrivateMetaFd&) = delete;
    ~PrivateMetaFd() { if (value >= 0) close(value); }
    int Close() { const int fd = value; value = -1; return fd >= 0 ? close(fd) : 0; }
};
static std::string PrivateMetaHex(const std::string& value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char byte : value) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 15]); }
    return result;
}
static bool PrivateMetaPath(const std::string& path) {
    if (path.size() < 2 || path.size() > 512 || path.front() != '/' || path.back() == '/') return false;
    for (size_t offset = 1; offset < path.size();) {
        const size_t end = path.find('/', offset);
        const std::string part = path.substr(offset, end == std::string::npos ? end : end - offset);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string::npos) break;
        offset = end + 1;
    }
    return true;
}

// Caller already owns LoadMutex. A diagnostic failure must never poison the cache job.
static bool CapturePrivateIdentity(JNIEnv* env, jobject context, const char* expected_package) {
    if (!env || !context || !expected_package || env->ExceptionCheck()) return false;
    if (g_private_identity_ready.load(std::memory_order_acquire))
        return g_private_identity.package == expected_package;
    struct Frame {
        JNIEnv* env;
        bool pushed;
        ~Frame() { if (env->ExceptionCheck()) env->ExceptionClear(); if (pushed) env->PopLocalFrame(nullptr); }
    } frame{env, env->PushLocalFrame(24) == JNI_OK};
    if (!frame.pushed) return false;
    auto text = [&](jstring value, std::string& out) {
        if (!value || env->ExceptionCheck()) return false;
        const jsize length = env->GetStringUTFLength(value);
        if (env->ExceptionCheck() || length <= 0 || length > 512) return false;
        const char* chars = env->GetStringUTFChars(value, nullptr);
        struct Utf {
            JNIEnv* env; jstring value; const char* chars;
            ~Utf() { if (chars) env->ReleaseStringUTFChars(value, chars); }
        } utf{env, value, chars};
        if (!chars || env->ExceptionCheck()) return false;
        out.assign(chars, static_cast<size_t>(length));
        return !out.empty();
    };
    jclass klass = env->GetObjectClass(context);
    if (!klass || env->ExceptionCheck()) return false;
    jmethodID package_name = env->GetMethodID(klass, "getPackageName", "()Ljava/lang/String;");
    if (!package_name || env->ExceptionCheck()) return false;
    jmethodID application = env->GetMethodID(klass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (!application || env->ExceptionCheck()) return false;
    jmethodID data_dir = env->GetMethodID(klass, "getDataDir", "()Ljava/io/File;");
    if (!data_dir || env->ExceptionCheck()) return false;
    jmethodID is_de = env->GetMethodID(klass, "isDeviceProtectedStorage", "()Z");
    if (!is_de || env->ExceptionCheck()) return false;
    PrivateMetaIdentity candidate;
    std::string actual_package;
    if (!text(static_cast<jstring>(env->CallObjectMethod(context, package_name)), actual_package) ||
        actual_package != expected_package) return false;
    jobject info = env->CallObjectMethod(context, application);
    if (!info || env->ExceptionCheck()) return false;
    jclass info_class = env->GetObjectClass(info);
    if (!info_class || env->ExceptionCheck()) return false;
    auto field = [&](const char* name, std::string& out) {
        jfieldID id = env->GetFieldID(info_class, name, "Ljava/lang/String;");
        if (!id || env->ExceptionCheck()) return false;
        auto value = static_cast<jstring>(env->GetObjectField(info, id));
        const bool ok = text(value, out);
        if (value) env->DeleteLocalRef(value);
        return ok;
    };
    if (!field("packageName", candidate.package) || candidate.package != expected_package ||
        !field("dataDir", candidate.ce) || !field("deviceProtectedDataDir", candidate.de) ||
        !field("nativeLibraryDir", candidate.native_library)) return false;
    jfieldID uid = env->GetFieldID(info_class, "uid", "I");
    if (!uid || env->ExceptionCheck()) return false;
    const jint app_uid = env->GetIntField(info, uid);
    if (env->ExceptionCheck() || app_uid < 0 || static_cast<uid_t>(app_uid) != getuid() || getuid() != geteuid()) return false;
    candidate.uid = static_cast<uid_t>(app_uid);
    const jboolean protected_storage = env->CallBooleanMethod(context, is_de);
    if (env->ExceptionCheck() || protected_storage) return false;
    jobject directory = env->CallObjectMethod(context, data_dir);
    if (!directory || env->ExceptionCheck()) return false;
    jclass file_class = env->GetObjectClass(directory);
    if (!file_class || env->ExceptionCheck()) return false;
    jmethodID absolute = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
    if (!absolute || env->ExceptionCheck()) return false;
    std::string actual_root;
    if (!text(static_cast<jstring>(env->CallObjectMethod(directory, absolute)), actual_root) ||
        actual_root != candidate.ce || candidate.ce == candidate.de ||
        !PrivateMetaPath(candidate.ce) || !PrivateMetaPath(candidate.de) || !PrivateMetaPath(candidate.native_library)) return false;
    for (const std::string* root : {&candidate.ce, &candidate.de})
        if (root->substr(root->find_last_of('/') + 1) != candidate.package) return false;
    g_private_identity = std::move(candidate);
    g_private_identity_ready.store(true, std::memory_order_release);
    return true;
}

struct PrivateMetaState {
    const char* phase;
    size_t entries = 0;
    const char* status = "COMPLETE";
    int error = 0;
    bool stopped = false;
    const char* root_tag = "CE";
    const PrivateMetaIdentity* identity = nullptr;
    struct stat root_identity{};
    bool root_present = false;
    size_t legacy_pending_links = 0, inert_legacy_links = 0;
};
static void PrivateMetaFail(PrivateMetaState& state, const char* reason, int error = 0, bool stop = true) {
    if (!strcmp(state.status, "COMPLETE") || (stop && !state.stopped)) { state.status = reason; state.error = error; }
    state.stopped = state.stopped || stop;
}
static bool PrivateMetaSame(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_size == b.st_size && a.st_nlink == b.st_nlink &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
static bool PrivateMetaSameDirectory(const struct stat& a, const struct stat& b) {
    return S_ISDIR(a.st_mode) && S_ISDIR(b.st_mode) && PrivateMetaSame(a, b);
}
enum class PrivateMetaLibKind { Ordinary, Native, LegacyPending };
static void PrivateMetaRow(PrivateMetaState& state, const std::string& relative,
                           const struct stat& value, PrivateMetaLibKind lib_kind = PrivateMetaLibKind::Ordinary) {
    // shortcut: six finite phases, each root at most512 entries/depth16/path512; increase after an observed cap.
    if (state.entries >= 512 || relative.size() > 512) { PrivateMetaFail(state, "LIMIT"); return; }
    ++state.entries;
    const char type = S_ISREG(value.st_mode) ? 'F' : S_ISDIR(value.st_mode) ? 'D' : S_ISLNK(value.st_mode) ? 'L' : 'O';
    const std::string name = PrivateMetaHex(relative);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META ROW phase=%s root=%s n=%zu path_hex=%s type=%c mode=%o uid=%u gid=%u "
        "size=%lld dev=%llu ino=%llu nlink=%llu mtime=%lld:%ld ctime=%lld:%ld trusted_native_link=%d lib_metadata_class=%s",
        state.phase, state.root_tag, state.entries, name.c_str(), type, static_cast<unsigned>(value.st_mode),
        static_cast<unsigned>(value.st_uid), static_cast<unsigned>(value.st_gid), static_cast<long long>(value.st_size),
        static_cast<unsigned long long>(value.st_dev), static_cast<unsigned long long>(value.st_ino),
        static_cast<unsigned long long>(value.st_nlink), static_cast<long long>(value.st_mtim.tv_sec), value.st_mtim.tv_nsec,
        static_cast<long long>(value.st_ctim.tv_sec), value.st_ctim.tv_nsec, lib_kind == PrivateMetaLibKind::Native,
        lib_kind == PrivateMetaLibKind::Native ? "NATIVE_TARGET" : lib_kind == PrivateMetaLibKind::LegacyPending ? "LEGACY_PENDING" : "ORDINARY");
    // A pending inert-link proof grants no native trust and must close before root completeness.
    if (S_ISLNK(value.st_mode)) {
        if (lib_kind == PrivateMetaLibKind::LegacyPending) ++state.legacy_pending_links;
        else if (lib_kind != PrivateMetaLibKind::Native) PrivateMetaFail(state, "LINK_PRESENT", 0, false);
    }
    else if (value.st_uid != state.identity->uid) PrivateMetaFail(state, "FOREIGN_UID", 0, false);
    else if (type == 'O') PrivateMetaFail(state, "SPECIAL_ENTRY", 0, false);
}
#if defined(BRIDGE_OPENSL_TEST)
static void (*g_private_link_test_hook)(int) = nullptr; // Own synthetic fixture only; absent from libmain.
static void (*g_private_absence_test_hook)(int) = nullptr;
static void (*g_private_parent_alias_test_hook)(const char*) = nullptr;
static const char* g_private_legacy_parent_test_path = nullptr;
static void (*g_private_legacy_test_hook)(int, int) = nullptr;
#endif
static bool PrivateMetaTrustedLib(int parent, const struct stat& expected, PrivateMetaState& state) {
    std::array<char, 513> target{}, repeated{};
    const ssize_t length = readlinkat(parent, "lib", target.data(), target.size());
    // Older fscrypt reports ciphertext st_size; validate bounded plaintext bytes and repeat link metadata.
    if (length <= 0 || length > 512) {
        PrivateMetaFail(state, "LINK_READ_ERROR", length < 0 ? errno : 0, false); return false;
    }
    const std::string observed(target.data(), static_cast<size_t>(length));
    const std::string expected_hex = PrivateMetaHex(state.identity->native_library), observed_hex = PrivateMetaHex(observed);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META LINK phase=%s root=%s path_hex=6c6962 target_hex=%s expected_hex=%s payload_reads=0",
        state.phase, state.root_tag, observed_hex.c_str(), expected_hex.c_str());
    if (observed != state.identity->native_library) { PrivateMetaFail(state, "LINK_TARGET_MISMATCH", 0, false); return false; }
    struct stat target_before{}, held{}, target_after{}, link_after{};
    if (lstat(observed.c_str(), &target_before)) {
        PrivateMetaFail(state, "NATIVE_DIRECTORY_UNAVAILABLE", errno, false); return false;
    }
    if (!S_ISDIR(target_before.st_mode)) { PrivateMetaFail(state, "NATIVE_TARGET_NOT_DIRECTORY", 0, false); return false; }
    const int fd = open(observed.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { PrivateMetaFail(state, "NATIVE_DIRECTORY_OPEN_ERROR", errno, false); return false; }
    PrivateMetaFd owned(fd);
    bool same = fstat(fd, &held) == 0 && PrivateMetaSameDirectory(target_before, held);
    if (same) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META NATIVE_TARGET phase=%s root=%s dev=%llu ino=%llu mode=%o uid=%u payload_reads=0",
        state.phase, state.root_tag, static_cast<unsigned long long>(held.st_dev),
        static_cast<unsigned long long>(held.st_ino), static_cast<unsigned>(held.st_mode), held.st_uid);
#if defined(BRIDGE_OPENSL_TEST)
    if (same && g_private_link_test_hook) g_private_link_test_hook(parent);
#endif
    const ssize_t second = readlinkat(parent, "lib", repeated.data(), repeated.size());
    same = same && second == length && !memcmp(target.data(), repeated.data(), static_cast<size_t>(length)) &&
        fstatat(parent, "lib", &link_after, AT_SYMLINK_NOFOLLOW) == 0 && PrivateMetaSame(expected, link_after) &&
        lstat(observed.c_str(), &target_after) == 0 && PrivateMetaSameDirectory(held, target_after);
    if (owned.Close()) same = false;
    if (!same) PrivateMetaFail(state, "LINK_OR_NATIVE_DIRECTORY_CHANGED", 0, false);
    return same; // Never enumerate/read the installed native-library directory.
}
static std::string PrivateMetaLegacyLeaf(const std::string& target, const PrivateMetaIdentity& identity) {
    // shortcut: flat legacy /data/app/package-id/lib/arm only; expand after a new observed layout and negative contracts.
    const std::string prefix = "/data/app/" + identity.package + "-", suffix = "/lib/arm";
    if (target.size() <= prefix.size() + suffix.size() || target.size() > 512 ||
        target.compare(0, prefix.size(), prefix) || target.compare(target.size() - suffix.size(), suffix.size(), suffix)) return {};
    const std::string leaf = target.substr(10, target.size() - 10 - suffix.size());
    if (leaf.size() > 255 || identity.package.empty()) return {};
    for (unsigned char c : identity.package)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_')) return {};
    for (size_t i = identity.package.size() + 1; i < leaf.size(); ++i) {
        const unsigned char c = leaf[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '+' || c == '=' || c == '-')) return {};
    }
    return leaf;
}
static void PrivateMetaLegacyStat(const PrivateMetaState& state, const char* stage, const struct stat& value) {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META LEGACY_STAT phase=%s root=%s stage=%s mode=%o uid=%u gid=%u size=%lld dev=%llu ino=%llu "
        "nlink=%llu mtime=%lld:%ld ctime=%lld:%ld pid=%d observer_uid=%u",
        state.phase, state.root_tag, stage, static_cast<unsigned>(value.st_mode), value.st_uid, value.st_gid,
        static_cast<long long>(value.st_size), static_cast<unsigned long long>(value.st_dev), static_cast<unsigned long long>(value.st_ino),
        static_cast<unsigned long long>(value.st_nlink), static_cast<long long>(value.st_mtim.tv_sec), value.st_mtim.tv_nsec,
        static_cast<long long>(value.st_ctim.tv_sec), value.st_ctim.tv_nsec, getpid(), getuid());
}
struct PrivateMetaLegacyProof {
    PrivateMetaFd app;
    const char* parent = "/data/app";
    std::string leaf, target;
    struct stat parent_begin{}, link_begin{};
    int first_rc = -2, first_error = 0;
    bool attempted = false, pending = false;
    size_t row = 0;
    bool Begin(int root, const struct stat& link, const std::string& observed, const std::string& parsed, PrivateMetaState& state) {
        if (attempted) { PrivateMetaFail(state, "LEGACY_DUPLICATE_CANDIDATE", 0, false); return false; }
        attempted = true; leaf = parsed; target = observed; link_begin = link; row = state.entries + 1;
#if defined(BRIDGE_OPENSL_TEST)
        if (g_private_legacy_parent_test_path) parent = g_private_legacy_parent_test_path;
#endif
        std::unique_ptr<char, decltype(&::free)> resolved(::realpath(parent, nullptr), &::free);
        if (!resolved || strcmp(resolved.get(), parent)) { PrivateMetaFail(state, "LEGACY_PARENT_RESOLUTION", resolved ? 0 : errno, false); return false; }
        struct stat path{};
        const int path_rc = lstat(parent, &path), path_error = path_rc ? errno : 0;
        if (path_rc || !S_ISDIR(path.st_mode)) { PrivateMetaFail(state, "LEGACY_PARENT_LSTAT", path_error, false); return false; }
        app.value = open(parent, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (app.value < 0) { PrivateMetaFail(state, "LEGACY_PARENT_OPEN", errno, false); return false; }
        const int held_rc = fstat(app.value, &parent_begin), held_error = held_rc ? errno : 0;
        if (held_rc || !PrivateMetaSameDirectory(path, parent_begin)) {
            PrivateMetaFail(state, "LEGACY_PARENT_IDENTITY", held_error, false); return false;
        }
        PrivateMetaLegacyStat(state, "APP_BEGIN", parent_begin);
        PrivateMetaLegacyStat(state, "LIB_BEGIN", link_begin);
        struct stat value{};
        first_rc = fstatat(app.value, leaf.c_str(), &value, AT_SYMLINK_NOFOLLOW);
        first_error = first_rc == -1 ? errno : 0;
        if (!first_rc) PrivateMetaLegacyStat(state, "LEAF_FIRST_PRESENT", value);
        pending = first_rc == -1 && first_error == ENOENT;
        if (!pending) PrivateMetaFail(state, !first_rc ? "LEGACY_NAMESPACE_PRESENT" : "LEGACY_NAMESPACE_QUERY_ERROR", first_error, false);
#if defined(BRIDGE_OPENSL_TEST)
        if (pending && g_private_legacy_test_hook) g_private_legacy_test_hook(app.value, root);
#endif
        return pending;
    }
    void End(int root, const struct stat& root_begin, PrivateMetaState& state) {
        if (!attempted) return;
        bool same = pending;
        int second_rc = -2, second_error = 0;
        if (app.value >= 0) {
            struct stat value{}, held{}, path{}, link{}, root_end{};
            second_rc = fstatat(app.value, leaf.c_str(), &value, AT_SYMLINK_NOFOLLOW);
            second_error = second_rc == -1 ? errno : 0;
            if (!second_rc) PrivateMetaLegacyStat(state, "LEAF_SECOND_PRESENT", value);
            if (second_rc != -1 || second_error != ENOENT) {
                same = false; PrivateMetaFail(state, !second_rc ? "LEGACY_NAMESPACE_PRESENT" : "LEGACY_NAMESPACE_QUERY_ERROR", second_error, false);
            }
            const int held_rc = fstat(app.value, &held), held_error = held_rc ? errno : 0;
            if (!held_rc) PrivateMetaLegacyStat(state, "APP_FD_END", held);
            const int path_rc = lstat(parent, &path), path_error = path_rc ? errno : 0;
            if (!path_rc) PrivateMetaLegacyStat(state, "APP_PATH_END", path);
            std::unique_ptr<char, decltype(&::free)> resolved(::realpath(parent, nullptr), &::free);
            const int resolution_error = resolved ? 0 : errno;
            if (held_rc || path_rc || !resolved || strcmp(resolved.get(), parent) ||
                !PrivateMetaSameDirectory(parent_begin, held) || !PrivateMetaSameDirectory(parent_begin, path)) {
                same = false; PrivateMetaFail(state, "LEGACY_PARENT_CHANGED", held_rc ? held_error : path_rc ? path_error : resolution_error, false);
            }
            std::array<char, 513> bytes{};
            const ssize_t length = readlinkat(root, "lib", bytes.data(), bytes.size());
            const int read_error = length < 0 ? errno : 0;
            const int link_rc = fstatat(root, "lib", &link, AT_SYMLINK_NOFOLLOW), link_error = link_rc ? errno : 0;
            if (!link_rc) PrivateMetaLegacyStat(state, "LIB_END", link);
            const std::string repeated = length > 0 && length <= 512 ? std::string(bytes.data(), static_cast<size_t>(length)) : "";
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "VFS_PRIVATE_META LEGACY_LINK_END phase=%s root=%s row=%zu length=%zd errno=%d target_hex=%s",
                state.phase, state.root_tag, row, length, read_error, PrivateMetaHex(repeated).c_str());
            if (length <= 0 || length > 512 || repeated != target || link_rc || !PrivateMetaSame(link_begin, link)) {
                same = false; PrivateMetaFail(state, "LEGACY_LINK_CHANGED", link_rc ? link_error : read_error, false);
            }
            const int root_rc = fstat(root, &root_end), root_error = root_rc ? errno : 0;
            PrivateMetaLegacyStat(state, "ROOT_BEGIN", root_begin);
            if (!root_rc) PrivateMetaLegacyStat(state, "ROOT_END", root_end);
            if (root_rc || !PrivateMetaSameDirectory(root_begin, root_end)) {
                same = false; PrivateMetaFail(state, "LEGACY_ROOT_CHANGED", root_error, false);
            }
        } else same = false;
        const int closed = app.Close(), close_error = closed ? errno : 0;
        if (closed) { same = false; PrivateMetaFail(state, "LEGACY_PARENT_CLOSE_ERROR", close_error, false); }
        if (state.legacy_pending_links) {
            --state.legacy_pending_links;
            if (same) ++state.inert_legacy_links;
        }
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "VFS_PRIVATE_META LEGACY_PROOF phase=%s root=%s row=%zu path_hex=6c6962 target_hex=%s leaf_hex=%s "
            "first_rc=%d first_errno=%d second_rc=%d second_errno=%d close_rc=%d close_errno=%d result=%s "
            "trusted_native_link=0 scope=PHYSICAL_METADATA_NO_LINK_TRAVERSAL pid=%d uid=%u",
            state.phase, state.root_tag, row, PrivateMetaHex(target).c_str(), PrivateMetaHex(leaf).c_str(),
            first_rc, first_error, second_rc, second_error, closed, close_error,
            same ? "INERT_LEGACY_NAMESPACE_ABSENT" : "INCOMPLETE", getpid(), getuid());
    }
};
static PrivateMetaLibKind PrivateMetaClassifyLib(int root, const struct stat& link, PrivateMetaState& state,
                                                bool legacy_scope, PrivateMetaLegacyProof& legacy) {
    std::array<char, 513> bytes{};
    const ssize_t length = readlinkat(root, "lib", bytes.data(), bytes.size());
    if (length <= 0 || length > 512) { PrivateMetaFail(state, "LINK_READ_ERROR", length < 0 ? errno : 0, false); return PrivateMetaLibKind::Ordinary; }
    const std::string target(bytes.data(), static_cast<size_t>(length));
    if (target != state.identity->native_library && legacy_scope) {
        const std::string leaf = PrivateMetaLegacyLeaf(target, *state.identity);
        if (!leaf.empty()) return legacy.Begin(root, link, target, leaf, state) ? PrivateMetaLibKind::LegacyPending : PrivateMetaLibKind::Ordinary;
    }
    return PrivateMetaTrustedLib(root, link, state) ? PrivateMetaLibKind::Native : PrivateMetaLibKind::Ordinary;
}
// Takes ownership of fd. Descendant traversal stays tied to held directories.
static void PrivateMetaWalk(int fd, const std::string& relative, unsigned depth,
                            const struct stat& expected, PrivateMetaState& state) {
    PrivateMetaFd owned(fd);
    struct stat begin{};
    if (fstat(fd, &begin)) { PrivateMetaFail(state, "FSTAT_ERROR", errno); return; }
    if (!PrivateMetaSameDirectory(expected, begin)) { PrivateMetaFail(state, "DIRECTORY_CHANGED"); return; }
    if (relative.empty() && depth == 0) { state.root_identity = begin; state.root_present = true; }
    std::unique_ptr<DIR, decltype(&::closedir)> stream(fdopendir(fd), &::closedir);
    if (!stream) { PrivateMetaFail(state, "FDOPENDIR_ERROR", errno); return; }
    owned.value = -1; // fdopendir transfers descriptor ownership to the stream.
    DIR* directory = stream.get();
    PrivateMetaLegacyProof legacy;
    while (!state.stopped) {
        errno = 0;
        struct dirent* entry = readdir(directory);
        if (!entry) { if (errno) PrivateMetaFail(state, "READDIR_ERROR", errno); break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (state.entries >= 512) { PrivateMetaFail(state, "LIMIT"); break; }
        const std::string child = relative.empty() ? std::string(entry->d_name) : relative + "/" + entry->d_name;
        if (child.size() > 512) { PrivateMetaFail(state, "LIMIT"); break; }
        struct stat value{};
        if (fstatat(dirfd(directory), entry->d_name, &value, AT_SYMLINK_NOFOLLOW)) { PrivateMetaFail(state, "LSTAT_ERROR", errno); break; }
        const auto lib_kind = child == "lib" && S_ISLNK(value.st_mode) ? PrivateMetaClassifyLib(dirfd(directory), value, state,
            relative.empty() && depth == 0 && !strcmp(state.root_tag, "CE"), legacy) : PrivateMetaLibKind::Ordinary;
        PrivateMetaRow(state, child, value, lib_kind);
        if (state.stopped) break;
        if (S_ISDIR(value.st_mode) && value.st_uid == state.identity->uid) {
            if (depth >= 16) { PrivateMetaFail(state, "LIMIT"); break; }
            const int child_fd = openat(dirfd(directory), entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child_fd < 0) { PrivateMetaFail(state, "OPEN_DIRECTORY_ERROR", errno); break; }
            PrivateMetaWalk(child_fd, child, depth + 1, value, state);
        }
    }
    struct stat end{};
    if (fstat(dirfd(directory), &end)) PrivateMetaFail(state, "FSTAT_ERROR", errno);
    else if (!PrivateMetaSameDirectory(begin, end)) PrivateMetaFail(state, "DIRECTORY_CHANGED");
    legacy.End(dirfd(directory), begin, state);
    if (closedir(stream.release())) PrivateMetaFail(state, "CLOSEDIR_ERROR", errno);
}
static PrivateMetaState PrivateMetadataRoot(const char* phase, const char* tag, const std::string& root,
                                            const PrivateMetaIdentity& identity) {
    PrivateMetaErrno preserve;
    PrivateMetaState state{phase}; state.root_tag = tag; state.identity = &identity;
    const std::string root_hex = PrivateMetaHex(root), package_hex = PrivateMetaHex(identity.package);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META BEGIN phase=%s root=%s scope=APPLICATIONINFO_CE_DE root_hex=%s package_hex=%s "
        "pid=%d uid=%u cap=512 depth=16 path_bytes=512 payload_reads=0", phase, tag, root_hex.c_str(), package_hex.c_str(), getpid(), getuid());
    const size_t slash = root.find_last_of('/');
    const std::string parent = root.substr(0, slash), leaf = root.substr(slash + 1);
    // realpath resolves trusted platform parent aliases; the resolved endpoint is opened nofollow and held.
    std::unique_ptr<char, decltype(&::free)> resolved(::realpath(parent.c_str(), nullptr), &::free);
    PrivateMetaFd parent_owned;
    int& parent_fd = parent_owned.value;
    struct stat parent_before{}, parent_after{}, alias_before{}, alias_after{}, value{}, root_after{};
    if (!resolved || strlen(resolved.get()) > 512) PrivateMetaFail(state, "PARENT_RESOLUTION_ERROR", errno);
    else {
        parent_fd = open(resolved.get(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent_fd < 0 || fstat(parent_fd, &parent_before)) PrivateMetaFail(state, "PARENT_OPEN_ERROR", errno);
        else if (stat(parent.c_str(), &alias_before) || !PrivateMetaSameDirectory(parent_before, alias_before))
            PrivateMetaFail(state, "PARENT_ALIAS_CHANGED", errno);
        else {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "VFS_PRIVATE_META PARENT phase=%s root=%s resolved_hex=%s dev=%llu ino=%llu uid=%u",
                phase, tag, PrivateMetaHex(resolved.get()).c_str(), static_cast<unsigned long long>(parent_before.st_dev),
                static_cast<unsigned long long>(parent_before.st_ino), parent_before.st_uid);
#if defined(BRIDGE_OPENSL_TEST)
            if (g_private_parent_alias_test_hook) g_private_parent_alias_test_hook(parent.c_str());
#endif
            if (fstatat(parent_fd, leaf.c_str(), &value, AT_SYMLINK_NOFOLLOW)) {
                const int error = errno;
                if (!strcmp(tag, "DE") && error == ENOENT) {
#if defined(BRIDGE_OPENSL_TEST)
                    if (g_private_absence_test_hook) g_private_absence_test_hook(parent_fd);
#endif
                    if (fstatat(parent_fd, leaf.c_str(), &root_after, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT)
                        state.status = "ABSENT";
                    else PrivateMetaFail(state, "ABSENCE_CHANGED");
                } else PrivateMetaFail(state, "ROOT_LSTAT_ERROR", error);
            } else {
                PrivateMetaRow(state, "", value);
                if (!S_ISDIR(value.st_mode)) PrivateMetaFail(state, "ROOT_NOT_DIRECTORY");
                else if (value.st_uid == identity.uid) {
                    const int fd = openat(parent_fd, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    if (fd < 0) PrivateMetaFail(state, "ROOT_OPEN_ERROR", errno);
                    else PrivateMetaWalk(fd, "", 0, value, state);
                }
                if (fstatat(parent_fd, leaf.c_str(), &root_after, AT_SYMLINK_NOFOLLOW) || !PrivateMetaSame(value, root_after))
                    PrivateMetaFail(state, "ROOT_CHANGED", errno);
            }
            if (fstat(parent_fd, &parent_after) || !PrivateMetaSameDirectory(parent_before, parent_after))
                PrivateMetaFail(state, "PARENT_CHANGED", errno);
            if (stat(parent.c_str(), &alias_after) || !PrivateMetaSameDirectory(parent_before, alias_after))
                PrivateMetaFail(state, "PARENT_ALIAS_CHANGED", errno);
        }
    }
    if (parent_owned.Close()) PrivateMetaFail(state, "PARENT_CLOSE_ERROR", errno);
    if (state.legacy_pending_links) PrivateMetaFail(state, "LEGACY_PROOF_NOT_CLOSED");
    const bool complete = !strcmp(state.status, "COMPLETE") || !strcmp(state.status, "ABSENT");
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META END phase=%s root=%s status=%s reason=%s entries=%zu errno=%d pid=%d uid=%u "
        "inert_legacy_links=%zu legacy_pending_links=%zu scope=PHYSICAL_METADATA_NO_LINK_TRAVERSAL",
        phase, tag, complete ? state.status : "INCOMPLETE", state.status, state.entries, state.error, getpid(), getuid(),
        state.inert_legacy_links, state.legacy_pending_links);
    return state;
}
static PrivateMetaState PrivateMetadataSnapshot(const char* phase, std::atomic<bool>& taken) noexcept {
    PrivateMetaErrno preserve;
    try {
    if (!g_private_identity_ready.load(std::memory_order_acquire) || g_private_identity.uid != getuid() || getuid() != geteuid()) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "VFS_PRIVATE_META END phase=%s root=BOTH status=INCOMPLETE reason=IDENTITY_NOT_READY entries=0 pid=%d uid=%u", phase, getpid(), getuid());
        return {phase, 0, "IDENTITY_NOT_READY", 0, true}; // Invalid identity does not occupy the phase slot.
    }
    // One valid-identity attempt per finite phase, including incomplete traversal; ALREADY is never completeness.
    if (taken.exchange(true, std::memory_order_relaxed)) return {phase, 0, "ALREADY_OBSERVED"};
    const PrivateMetaIdentity& identity = g_private_identity;
    PrivateMetaState ce = PrivateMetadataRoot(phase, "CE", identity.ce, identity);
    PrivateMetaState de = PrivateMetadataRoot(phase, "DE", identity.de, identity);
    if (ce.root_present && de.root_present && ce.root_identity.st_dev == de.root_identity.st_dev &&
        ce.root_identity.st_ino == de.root_identity.st_ino) PrivateMetaFail(de, "CE_DE_ALIAS");
    PrivateMetaState result{phase, ce.entries + de.entries};
    result.inert_legacy_links = ce.inert_legacy_links + de.inert_legacy_links;
    if (strcmp(ce.status, "COMPLETE")) PrivateMetaFail(result, ce.status, ce.error);
    if (strcmp(de.status, "COMPLETE") && strcmp(de.status, "ABSENT")) PrivateMetaFail(result, de.status, de.error);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "VFS_PRIVATE_META SUMMARY phase=%s status=%s ce=%s de=%s entries=%zu pid=%d uid=%u inert_legacy_links=%zu "
        "scope=PHYSICAL_METADATA_NO_LINK_TRAVERSAL",
        phase, result.status, ce.status, de.status, result.entries, getpid(), getuid(), result.inert_legacy_links);
    return result;
    } catch (...) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "VFS_PRIVATE_META END phase=%s root=BOTH status=INCOMPLETE reason=OBSERVER_EXCEPTION", phase);
        return {phase, 0, "OBSERVER_EXCEPTION", 0, true};
    }
}
static void PrivateMetadataBeforeProcessExit() {
    try { PrivateMetadataSnapshot("BEFORE_PROCESS_EXIT", g_private_exit_taken); }
    catch (...) { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "VFS_PRIVATE_META END phase=BEFORE_PROCESS_EXIT status=INCOMPLETE reason=OBSERVER_EXCEPTION"); }
}

#if defined(BRIDGE_OPENSL_TEST)
extern "C" bool PrivateMetadataContractCheck() {
    assert(::setvbuf(stdout, nullptr, _IONBF, 0) == 0);
    char temporary[] = "/data/local/tmp/tftb-private-meta-XXXXXX";
    const char* fixture = ::mkdtemp(temporary); assert(fixture);
    const std::string base(fixture), ce = base + "/ce", de = base + "/de", nested = ce + "/nested";
    const std::string native = base + "/native", wrong = base + "/wrong", link = ce + "/lib";
    for (const std::string* directory : {&ce, &de, &nested, &native, &wrong}) assert(::mkdir(directory->c_str(), 0700) == 0);
    const std::string payload = nested + "/payload.bin", sibling = ce + "/sibling.bin", de_file = de + "/sdk.bin";
    const std::string outside = native + "/MUST_NOT_BE_ENUMERATED";
    for (const std::string* file : {&payload, &sibling, &de_file, &outside}) {
        const int fd = ::open(file->c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); assert(fd >= 0 && ::close(fd) == 0);
    }
    assert(::symlink(native.c_str(), link.c_str()) == 0);
    const PrivateMetaIdentity saved = g_private_identity;
    const bool saved_ready = g_private_identity_ready.load();
    g_private_identity_ready.store(false);
    std::atomic<bool> once{false}; errno = E2BIG;
    assert(!strcmp(PrivateMetadataSnapshot("TEST_CAPTURE_RETRY", once).status, "IDENTITY_NOT_READY") && !once.load());
    g_private_identity = {"host_contract_fixture", ce, de, native, getuid()}; g_private_identity_ready.store(true, std::memory_order_release);
    const PrivateMetaState first = PrivateMetadataSnapshot("TEST_CE_DE_NATIVE_LINK", once);
    assert(errno == E2BIG && first.entries == 7 && !strcmp(first.status, "COMPLETE"));
    assert(!strcmp(PrivateMetadataSnapshot("TEST_CE_DE_NATIVE_LINK", once).status, "ALREADY_OBSERVED"));
    const std::string app = base + "/app", app_old = app + ".old", app_alias = base + "/app_alias";
    const std::string old_leaf = "host_contract_fixture-old", legacy = "/data/app/" + old_leaf + "/lib/arm";
    assert(::mkdir(app.c_str(), 0700) == 0);
    assert(!g_private_legacy_parent_test_path && !g_private_legacy_test_hook);
    g_private_legacy_parent_test_path = app.c_str();
    auto fd_count = [] {
        PrivateMetaErrno preserve;
        DIR* directory = ::opendir("/proc/self/fd"); assert(directory);
        size_t count = 0;
        while (struct dirent* entry = ::readdir(directory))
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
        assert(::closedir(directory) == 0); return count;
    };
    const size_t initial_fds = fd_count();
    auto observe = [&](const char* phase) {
        printf("PRIVATE_METADATA_CASE phase=%s uid=%u\n", phase, getuid());
        std::atomic<bool> phase_once{false}; errno = E2BIG;
        const auto result = PrivateMetadataSnapshot(phase, phase_once);
        assert(errno == E2BIG && phase_once.load() && fd_count() == initial_fds && !result.legacy_pending_links);
        printf("PRIVATE_METADATA_RESULT phase=%s status=%s entries=%zu inert=%zu errno=%d\n",
               phase, result.status, result.entries, result.inert_legacy_links, result.error);
        return result;
    };
    auto set_link = [&](const std::string& target) {
        assert(::unlink(link.c_str()) == 0 && ::symlink(target.c_str(), link.c_str()) == 0);
    };
    assert(PrivateMetaLegacyLeaf(legacy, g_private_identity) == old_leaf);
    assert(PrivateMetaLegacyLeaf("/data/app/host_contract_fixture-A_+=-9/lib/arm", g_private_identity) == "host_contract_fixture-A_+=-9");
    for (const std::string& target : std::array<std::string, 10>{"/data/app/other-old/lib/arm",
         "/data/app/host_contract_fixture-/lib/arm", "/data/app/host_contract_fixture-../lib/arm",
         "/data/app/host_contract_fixture-old/child/lib/arm", "/data/app/host_contract_fixture-old/lib/arm64",
         "/data/app/host_contract_fixture-old/lib/arm/", "/data/app/host_contract_fixture-old/lib/arm/..",
         "/data/app/host_contract_fixture-" + std::string("o\0ld", 4) + "/lib/arm", std::string(513, 'x'),
         "/data/app/host_contract_fixture-" + std::string(255, 'x') + "/lib/arm"})
        assert(PrivateMetaLegacyLeaf(target, g_private_identity).empty());
    set_link(legacy);
    {
        PrivateMetaErrno preserve;
        const int fd = ::open(ce.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
        struct stat link_value{}, root_value{};
        assert(::fstat(fd, &root_value) == 0 && ::fstatat(fd, "lib", &link_value, AT_SYMLINK_NOFOLLOW) == 0);
        PrivateMetaState duplicate{"TEST_LEGACY_DUPLICATE"}; duplicate.identity = &g_private_identity;
        PrivateMetaLegacyProof proof;
        const auto kind = PrivateMetaClassifyLib(fd, link_value, duplicate, true, proof);
        assert(kind == PrivateMetaLibKind::LegacyPending); PrivateMetaRow(duplicate, "lib", link_value, kind);
        const int held = proof.app.value;
        assert(fd_count() == initial_fds + 2 && duplicate.legacy_pending_links == 1);
        const auto second_kind = PrivateMetaClassifyLib(fd, link_value, duplicate, true, proof);
        assert(second_kind == PrivateMetaLibKind::Ordinary && proof.app.value == held && proof.row == 1 && proof.leaf == old_leaf);
        PrivateMetaRow(duplicate, "lib", link_value, second_kind);
        assert(!strcmp(duplicate.status, "LEGACY_DUPLICATE_CANDIDATE") && duplicate.legacy_pending_links == 1 && fd_count() == initial_fds + 2);
        proof.End(fd, root_value, duplicate);
        assert(!strcmp(duplicate.status, "LEGACY_DUPLICATE_CANDIDATE") && !duplicate.legacy_pending_links && duplicate.inert_legacy_links == 1);
        assert(fd_count() == initial_fds + 1 && ::close(fd) == 0 && fd_count() == initial_fds);
        puts("PRIVATE_METADATA_DUPLICATE_CHECK_PASS: first proof/FD retained, duplicate incomplete, one close, pending0");
    }
    const auto legacy_absent = observe("TEST_LEGACY_ABSENT_A");
    assert(!strcmp(legacy_absent.status, "COMPLETE") && legacy_absent.entries == 7 && legacy_absent.inert_legacy_links == 1);
    const std::string other = ce + "/other_link";
    assert(::symlink(native.c_str(), other.c_str()) == 0);
    const auto bad_sibling = observe("TEST_LEGACY_UNKNOWN_SIBLING");
    assert(!strcmp(bad_sibling.status, "LINK_PRESENT") && bad_sibling.entries == 8 && bad_sibling.inert_legacy_links == 1);
    assert(::unlink(other.c_str()) == 0);
    assert(::symlink("MUST_NOT_BE_FOLLOWED", (app + "/" + old_leaf).c_str()) == 0);
    const auto legacy_present = observe("TEST_LEGACY_PRESENT_B");
    assert(!strcmp(legacy_present.status, "LEGACY_NAMESPACE_PRESENT") && legacy_present.entries == 7 && !legacy_present.inert_legacy_links);
    assert(::unlink((app + "/" + old_leaf).c_str()) == 0);
    g_private_legacy_test_hook = [](int parent, int) {
        assert(::symlinkat("MUST_NOT_BE_FOLLOWED", parent, "host_contract_fixture-old") == 0);
    };
    const auto legacy_appeared = observe("TEST_LEGACY_APPEARED");
    g_private_legacy_test_hook = nullptr;
    assert(!strcmp(legacy_appeared.status, "LEGACY_NAMESPACE_PRESENT") && legacy_appeared.entries == 7 && !legacy_appeared.inert_legacy_links);
    assert(::unlink((app + "/" + old_leaf).c_str()) == 0);
    g_private_legacy_test_hook = [](int, int root) {
        assert(::unlinkat(root, "lib", 0) == 0 && ::symlinkat("../wrong", root, "lib") == 0);
    };
    const auto legacy_retargeted = observe("TEST_LEGACY_RETARGET");
    g_private_legacy_test_hook = nullptr;
    assert(strcmp(legacy_retargeted.status, "COMPLETE") && legacy_retargeted.entries == 7 && !legacy_retargeted.inert_legacy_links);
    set_link(legacy);
    g_private_legacy_test_hook = [](int, int) {
        const std::string path = g_private_legacy_parent_test_path;
        assert(::rename(path.c_str(), (path + ".old").c_str()) == 0 && ::mkdir(path.c_str(), 0700) == 0);
    };
    const auto parent_replaced = observe("TEST_LEGACY_PARENT_REPLACED");
    g_private_legacy_test_hook = nullptr;
    assert(strcmp(parent_replaced.status, "COMPLETE") && !parent_replaced.inert_legacy_links);
    assert(::rmdir(app.c_str()) == 0 && ::rename(app_old.c_str(), app.c_str()) == 0);
    assert(getuid() != 0 && ::chmod(app.c_str(), 0000) == 0);
    const auto legacy_denied = observe("TEST_LEGACY_DENIED");
    assert(::chmod(app.c_str(), 0700) == 0);
    assert(!strcmp(legacy_denied.status, "LEGACY_NAMESPACE_QUERY_ERROR") && legacy_denied.error == EACCES && !legacy_denied.inert_legacy_links);
    assert(::symlink("app", app_alias.c_str()) == 0);
    g_private_legacy_parent_test_path = app_alias.c_str();
    const auto legacy_alias = observe("TEST_LEGACY_PARENT_ALIAS");
    g_private_legacy_parent_test_path = app.c_str();
    assert(!strcmp(legacy_alias.status, "LEGACY_PARENT_RESOLUTION") && !legacy_alias.inert_legacy_links && ::unlink(app_alias.c_str()) == 0);
    set_link("/data/app/other-old/lib/arm");
    const auto other_package = observe("TEST_LEGACY_OTHER_PACKAGE");
    assert(!strcmp(other_package.status, "LINK_TARGET_MISMATCH") && !other_package.inert_legacy_links);
    set_link("/data/app/host_contract_fixture-../lib/arm");
    const auto malformed_legacy = observe("TEST_LEGACY_MALFORMED");
    assert(!strcmp(malformed_legacy.status, "LINK_TARGET_MISMATCH") && !malformed_legacy.inert_legacy_links);
    set_link(native);
    for (const std::string& misplaced : {de + "/lib", nested + "/lib", ce + "/another_lib"}) {
        assert(::symlink(legacy.c_str(), misplaced.c_str()) == 0);
        const auto misplaced_result = observe(misplaced == de + "/lib" ? "TEST_LEGACY_DE_SCOPE" :
                                             misplaced == nested + "/lib" ? "TEST_LEGACY_NESTED_SCOPE" : "TEST_LEGACY_NAME_SCOPE");
        assert(strcmp(misplaced_result.status, "COMPLETE") && misplaced_result.entries == 8 && !misplaced_result.inert_legacy_links);
        assert(::unlink(misplaced.c_str()) == 0);
    }
    g_private_legacy_parent_test_path = nullptr;
    assert(::rmdir(app.c_str()) == 0 && fd_count() == initial_fds);
    const auto native_again = observe("TEST_NATIVE_AFTER_LEGACY");
    assert(!strcmp(native_again.status, "COMPLETE") && native_again.entries == 7 && !native_again.inert_legacy_links);
    const std::string alias = base + "/parent_alias"; assert(::symlink("ce", alias.c_str()) == 0);
    g_private_parent_alias_test_hook = [](const char* path) { assert(::unlink(path) == 0 && ::symlink("de", path) == 0); };
    const auto alias_changed = PrivateMetadataRoot("TEST_PARENT_ALIAS_RACE", "CE", alias + "/nested", g_private_identity);
    g_private_parent_alias_test_hook = nullptr;
    assert(!strcmp(alias_changed.status, "PARENT_ALIAS_CHANGED") && ::unlink(alias.c_str()) == 0);
    g_private_identity_ready.store(false); g_private_identity.de = ce; g_private_identity_ready.store(true, std::memory_order_release);
    std::atomic<bool> alias_once{false};
    assert(!strcmp(PrivateMetadataSnapshot("TEST_CE_DE_ALIAS", alias_once).status, "CE_DE_ALIAS"));
    g_private_identity_ready.store(false); g_private_identity.de = de; g_private_identity_ready.store(true, std::memory_order_release);
    struct stat link_stat{}, root_stat{};
    const int root_fd = ::open(ce.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); assert(root_fd >= 0);
    assert(::fstatat(root_fd, "lib", &link_stat, AT_SYMLINK_NOFOLLOW) == 0);
    PrivateMetaState leaf{"TEST_LEAF_RACE"}; leaf.identity = &g_private_identity;
    g_private_link_test_hook = [](int parent) {
        assert(::unlinkat(parent, "lib", 0) == 0 && ::symlinkat("../wrong", parent, "lib") == 0);
    };
    assert(!PrivateMetaTrustedLib(root_fd, link_stat, leaf) && !strcmp(leaf.status, "LINK_OR_NATIVE_DIRECTORY_CHANGED"));
    g_private_link_test_hook = nullptr;
    assert(::close(root_fd) == 0);
    std::atomic<bool> mismatch_once{false};
    const auto mismatch = PrivateMetadataSnapshot("TEST_MISMATCH_SIBLINGS", mismatch_once);
    assert(mismatch.entries == 7 && !strcmp(mismatch.status, "LINK_TARGET_MISMATCH"));
    assert(::unlink(link.c_str()) == 0 && ::symlink(native.c_str(), link.c_str()) == 0);
    const std::string unknown = ce + "/other_link"; assert(::symlink(native.c_str(), unknown.c_str()) == 0);
    std::atomic<bool> unknown_once{false};
    const auto unknown_result = PrivateMetadataSnapshot("TEST_UNKNOWN_LINK", unknown_once);
    assert(unknown_result.entries == 8 && !strcmp(unknown_result.status, "LINK_PRESENT"));
    assert(::unlink(unknown.c_str()) == 0);
    PrivateMetaState foreign_link{"TEST_INSTALLER_UID"}; foreign_link.identity = &g_private_identity;
    link_stat.st_uid = 0; PrivateMetaRow(foreign_link, "lib", link_stat, PrivateMetaLibKind::Native);
    assert(!strcmp(foreign_link.status, "COMPLETE"));
    assert(::lstat(ce.c_str(), &root_stat) == 0);
    PrivateMetaState capped{"TEST_CAP", 511}; capped.identity = &g_private_identity;
    {
        PrivateMetaErrno preserve;
        const int fd = ::open(ce.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
        PrivateMetaWalk(fd, "", 0, root_stat, capped);
    }
    assert(capped.entries == 512 && capped.stopped && !strcmp(capped.status, "LIMIT") && errno == E2BIG);
    for (const auto& limit : {std::pair<std::string, unsigned>{"", 16}, {std::string(513, 'x'), 0}}) {
        PrivateMetaState limited{"TEST_DEPTH_PATH"}; limited.identity = &g_private_identity;
        PrivateMetaErrno preserve;
        const int fd = ::open(ce.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
        PrivateMetaWalk(fd, limit.first, limit.second, root_stat, limited);
        assert(limited.stopped && !strcmp(limited.status, "LIMIT"));
    }
    assert(!PrivateMetaPath("/bad//path") && !PrivateMetaPath("/bad/../path") && !PrivateMetaPath("/bad/./path") &&
           !PrivateMetaPath("relative") && !PrivateMetaPath("/trailing/") && !PrivateMetaPath("/" + std::string(512, 'x')));
    const auto absent = PrivateMetadataRoot("TEST_MISSING_DE", "DE", base + "/missing", g_private_identity);
    assert(!strcmp(absent.status, "ABSENT") && absent.entries == 0);
    g_private_absence_test_hook = [](int parent) { assert(::mkdirat(parent, "missing", 0700) == 0); };
    const auto appeared = PrivateMetadataRoot("TEST_ABSENCE_RACE", "DE", base + "/missing", g_private_identity);
    g_private_absence_test_hook = nullptr;
    assert(!strcmp(appeared.status, "ABSENCE_CHANGED") && ::rmdir((base + "/missing").c_str()) == 0);
    const auto missing_parent = PrivateMetadataRoot("TEST_UNKNOWN_PARENT", "DE", base + "/missing_parent/de", g_private_identity);
    assert(!strcmp(missing_parent.status, "PARENT_RESOLUTION_ERROR"));
    g_private_identity_ready.store(false); g_private_identity = saved; g_private_identity_ready.store(saved_ready, std::memory_order_release);
    for (const std::string* file : {&payload, &sibling, &de_file, &outside, &link}) assert(::unlink(file->c_str()) == 0);
    for (const std::string* directory : {&nested, &ce, &de, &native, &wrong, &base}) assert(::rmdir(directory->c_str()) == 0);
    puts("PRIVATE_METADATA_CHECK_PASS: CE+DE, native link, fresh absent/present legacy phases, appearance/retarget/parent/denial/scope negatives, siblings, once/caps/errno/FD closure, no link traversal");
    return true;
}
#endif
#endif

void cache_bootstrap::ObservePrivateMetadataPreparation(JNIEnv* env, jobject context, const char* package, jlong token) noexcept {
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    PrivateMetaErrno preserve;
    try {
        if (!CapturePrivateIdentity(env, context, package)) {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "VFS_PRIVATE_META CAPTURE token=%lld status=INCOMPLETE reason=IDENTITY_UNAVAILABLE", static_cast<long long>(token));
            return;
        }
        cache_diag::before_process_exit.store(&PrivateMetadataBeforeProcessExit, std::memory_order_release);
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "VFS_PRIVATE_META PREPARE token=%lld admission=PREPARE_ATTEMPT pid=%d uid=%u", static_cast<long long>(token), getpid(), getuid());
        PrivateMetadataSnapshot("BEFORE_CACHE_PREPARE", g_private_prepare_taken);
    } catch (...) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "VFS_PRIVATE_META END phase=BEFORE_CACHE_PREPARE status=INCOMPLETE reason=OBSERVER_EXCEPTION");
    }
#endif
}

static jint Native_nativePrivateMetadataPhase(JNIEnv* env, jclass, jint phase) {
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    PrivateMetaErrno preserve;
    if (env->ExceptionCheck()) return -3; // Preserve an entry exception; never Ensure or join.
    if (phase != 1 && phase != 2) return -4;
    if (!cache_bootstrap::Admitted() || !g_ready.load(std::memory_order_acquire)) return 3;
    try {
        const auto result = phase == 1 ? PrivateMetadataSnapshot("MID_ACTUAL_ROUTE", g_private_mid_taken) :
                                        PrivateMetadataSnapshot("AFTER_ROUTE_BEFORE_EXIT", g_private_route_taken);
        return !strcmp(result.status, "COMPLETE") ? 0 : !strcmp(result.status, "ALREADY_OBSERVED") ? 2 : 1;
    } catch (...) { return 1; }
#else
    return -1;
#endif
}


static bool DiscoverApplicationPaths(JNIEnv* env, jobject& java_assets) {
    cache_bootstrap::Snapshot snapshot;
    if (!cache_bootstrap::CopyActiveSnapshot(snapshot) || !cache_bootstrap::ValidateSnapshot(env, snapshot)) return false;
    g_files_dir = snapshot.files;
    jclass context_class = env->GetObjectClass(snapshot.context);
    if (!context_class || env->ExceptionCheck()) return false;
    jmethodID get_assets = env->GetMethodID(context_class, "getAssets", "()Landroid/content/res/AssetManager;");
    if (!get_assets || env->ExceptionCheck()) return false;
    java_assets = env->CallObjectMethod(snapshot.context, get_assets);
    return java_assets && !env->ExceptionCheck();
}

static uint32_t Sym(const char* module_name, const char* symbol) {
    ElfLoader* module = g_host ? g_host->FindModule(module_name) : nullptr;
    const uint32_t address = module ? module->GetSymbolAddress(symbol) : 0;
    if (!address) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Missing guest symbol %s in %s", symbol, module_name);
    return address;
}

struct GuestSymbols {
    uint32_t nativeInit = 0;
    uint32_t nativeAddJoystick = 0, nativeFlipBuffers = 0, nativeLowMemory = 0;
    uint32_t nativePause = 0, nativeQuit = 0, nativeRemoveJoystick = 0, nativeResume = 0;
    uint32_t onNativeAccel = 0, onNativeHat = 0, onNativeJoy = 0;
    uint32_t onNativeKeyDown = 0, onNativeKeyUp = 0, onNativeKeyboardFocusLost = 0;
    uint32_t onNativePadDown = 0, onNativePadUp = 0, onNativeResize = 0;
    uint32_t onNativeSurfaceChanged = 0, onNativeSurfaceDestroyed = 0, onNativeTouch = 0;
    uint32_t nativeCommitText = 0, nativeSetComposingText = 0;
    uint32_t fmodGetSize = 0, fmodReadAt = 0, nativeOnPurchaseComplete = 0;
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
    uint32_t nativeOnPermissionComplete = 0;
#endif
} g_symbols;

#if defined(ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE
static bool GuestRangeHasFlags(const ElfLoader& module, uint32_t address, uint32_t size,
                               uint32_t required_flags) {
    if (!size || address < module.GetBaseAddress()) return false;
    const uint64_t start = static_cast<uint64_t>(address - module.GetBaseAddress());
    const uint64_t end = start + size;
    if (end > UINT32_MAX) return false;
    for (const ElfSegment& segment : module.GetSegments()) {
        const uint64_t segment_start = segment.vaddr;
        const uint64_t segment_end = segment_start + segment.memsz;
        if (start >= segment_start && end <= segment_end &&
            (segment.flags & required_flags) == required_flags) return true;
    }
    return false;
}

static std::atomic<bool> g_mcsm_gameplay_started{false};

struct MCSMEntryHook {
    uint32_t target = 0;
    uint32_t veneer = 0;
    uint32_t svc = 0;
    uint32_t first = 0;
    uint32_t second = 0;
};

static bool PrepareMCSMEntryHook(DynarmicHost& runtime, const ElfLoader& engine,
                                const char* symbol_name, uint32_t expected_size,
                                uint32_t first, uint32_t second, const char* thunk_name,
                                ThunkHandler handler, MCSMEntryHook& out) {
    const ElfSymbol* symbol = engine.GetExportedSymbol(symbol_name);
    if (!symbol || symbol->type != STT_FUNC || symbol->size != expected_size ||
        (symbol->value & 3u) || !GuestRangeHasFlags(engine, symbol->value, symbol->size, PF_X) ||
        runtime.MemoryRead32(symbol->value) != first || runtime.MemoryRead32(symbol->value + 4) != second) {
        LOGE("MCSM aspect hook refused: function fingerprint mismatch for %s.", symbol_name);
        return false;
    }
    const uint32_t thunk = runtime.GetThunkManager().RegisterThunk(thunk_name, std::move(handler));
    const uint32_t svc = thunk ? runtime.MemoryRead32(thunk) : 0;
    if (!thunk || (svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("MCSM aspect hook refused: cannot create thunk %s.", thunk_name);
        return false;
    }
    const uint32_t veneer = runtime.GuestAlloc(32, 4);
    if (!veneer) {
        LOGE("MCSM aspect hook refused: cannot allocate veneer for %s.", symbol_name);
        return false;
    }
    runtime.MemoryWrite32(veneer + 0, svc);
    runtime.MemoryWrite32(veneer + 4, first);
    runtime.MemoryWrite32(veneer + 8, second);
    runtime.MemoryWrite32(veneer + 12, 0xE51FF004u); // ldr pc, [pc, #-4]
    runtime.MemoryWrite32(veneer + 16, symbol->value + 8);
    runtime.InvalidateGuestCode(veneer, 20);
    runtime.AddExecutableRange(veneer, 20);
    out = {symbol->value, veneer, svc, first, second};
    return true;
}

static void CommitMCSMEntryHook(DynarmicHost& runtime, const MCSMEntryHook& hook) {
    runtime.MemoryWrite32(hook.target + 0, 0xE51FF004u); // ldr pc, [pc, #-4]
    runtime.MemoryWrite32(hook.target + 4, hook.veneer);
    runtime.InvalidateGuestCode(hook.target, 8);
}

// MCSM 1.37 Mali: _project.lua forces 16:9 globally. Only the optional
// widescreen split may override that behavior. Without it, leave the guest
// setters and aspect state untouched so every gameplay entry path keeps the
// authored ratio. Every patched target is validated for this exact build.
static bool InstallMCSMGameplayAspectHooks(DynarmicHost& runtime) {
    ElfLoader* engine = runtime.FindModule("libGameEngine.so");
    if (!engine) {
        LOGE("MCSM gameplay aspect hooks refused: libGameEngine.so is not loaded.");
        return false;
    }
    constexpr char kSetForceName[] = "_ZN12RenderDevice30SetForceGameContentAspectRatioEb";
    constexpr char kSetAspectName[] = "_ZN12RenderDevice25SetGameContentAspectRatioEf";
    constexpr char kForceFlagName[] = "_ZN12RenderDevice18sbForceAspectRatioE";
    constexpr char kAspectValueName[] = "_ZN12RenderDevice24sfGameContentAspectRatioE";
    constexpr char kReinitializeName[] = "_ZN12RenderDevice20mbReInitializeDeviceE";
    constexpr char kNewGameName[] = "_Z12luaResetGameP9lua_State";
    constexpr char kLoadGameName[] = "_Z11luaLoadGameP9lua_State";
    const ElfSymbol* set_force = engine->GetExportedSymbol(kSetForceName);
    const ElfSymbol* set_aspect = engine->GetExportedSymbol(kSetAspectName);
    const ElfSymbol* force_flag = engine->GetExportedSymbol(kForceFlagName);
    const ElfSymbol* aspect_value = engine->GetExportedSymbol(kAspectValueName);
    const ElfSymbol* reinitialize = engine->GetExportedSymbol(kReinitializeName);
    const ElfSymbol* new_game = engine->GetExportedSymbol(kNewGameName);
    const ElfSymbol* load_game = engine->GetExportedSymbol(kLoadGameName);
    constexpr uint32_t kSetForceSize = 52;
    constexpr uint32_t kSetAspectSize = 68;
    constexpr uint32_t kNewGameSize = 688;
    constexpr uint32_t kLoadGameSize = 176;
    constexpr uint32_t kSetForceStoreOffset = 0x1C;
    constexpr uint32_t kSetForceStore = 0xE5C30000u; // strb r0, [r3]
    constexpr std::array<uint32_t, 4> kSetForcePrologue = {
        0xE59F3024u, 0xE79F3003u, 0xE5D32000u, 0xE1520000u,
    };
    constexpr std::array<uint32_t, 4> kSetAspectPrologue = {
        0xE59F2030u, 0xEE070A90u, 0xE59F302Cu, 0xE79F2002u,
    };
    constexpr uint32_t kSetAspectForceStoreOffset = 0x30;
    constexpr uint32_t kSetAspectForceStore = 0x15C32000u; // strbne r2, [r3]
    constexpr uint32_t kNewGameFirst = 0xE92D4FF0u;
    constexpr uint32_t kNewGameSecond = 0xE1A04000u;
    constexpr uint32_t kLoadGameFirst = 0xE92D40F0u;
    constexpr uint32_t kLoadGameSecond = 0xE24DD00Cu;
    if (!set_force || set_force->type != STT_FUNC || set_force->size != kSetForceSize ||
        (set_force->value & 3u) || !GuestRangeHasFlags(*engine, set_force->value, set_force->size, PF_X) ||
        !set_aspect || set_aspect->type != STT_FUNC || set_aspect->size != kSetAspectSize ||
        (set_aspect->value & 3u) || !GuestRangeHasFlags(*engine, set_aspect->value, set_aspect->size, PF_X) ||
        !force_flag || force_flag->type != STT_OBJECT || force_flag->size != 1 ||
        !GuestRangeHasFlags(*engine, force_flag->value, force_flag->size, PF_W) ||
        !aspect_value || aspect_value->type != STT_OBJECT || aspect_value->size != 4 ||
        !GuestRangeHasFlags(*engine, aspect_value->value, aspect_value->size, PF_W) ||
        !reinitialize || reinitialize->type != STT_OBJECT || reinitialize->size != 1 ||
        !GuestRangeHasFlags(*engine, reinitialize->value, reinitialize->size, PF_W) ||
        !new_game || new_game->type != STT_FUNC || new_game->size != kNewGameSize ||
        !GuestRangeHasFlags(*engine, new_game->value, new_game->size, PF_X) ||
        !load_game || load_game->type != STT_FUNC || load_game->size != kLoadGameSize ||
        !GuestRangeHasFlags(*engine, load_game->value, load_game->size, PF_X)) {
        LOGE("MCSM gameplay aspect hooks refused: required export type/size/segment checks failed.");
        return false;
    }
    for (size_t i = 0; i < kSetForcePrologue.size(); ++i) {
        if (runtime.MemoryRead32(set_force->value + static_cast<uint32_t>(i * 4)) !=
            kSetForcePrologue[i]) {
            LOGE("MCSM gameplay aspect hooks refused: SetForce prologue mismatch at +0x%zX.", i * 4);
            return false;
        }
        if (runtime.MemoryRead32(set_aspect->value + static_cast<uint32_t>(i * 4)) !=
            kSetAspectPrologue[i]) {
            LOGE("MCSM gameplay aspect hooks refused: SetAspect prologue mismatch at +0x%zX.", i * 4);
            return false;
        }
    }
    const uint32_t set_force_store = runtime.MemoryRead32(set_force->value + kSetForceStoreOffset);
    const uint32_t set_aspect_store = runtime.MemoryRead32(set_aspect->value + kSetAspectForceStoreOffset);
    const uint32_t new_game_first = runtime.MemoryRead32(new_game->value);
    const uint32_t new_game_second = runtime.MemoryRead32(new_game->value + 4);
    const uint32_t load_game_first = runtime.MemoryRead32(load_game->value);
    const uint32_t load_game_second = runtime.MemoryRead32(load_game->value + 4);
    if (set_force_store != kSetForceStore || set_aspect_store != kSetAspectForceStore ||
        new_game_first != kNewGameFirst || new_game_second != kNewGameSecond ||
        load_game_first != kLoadGameFirst || load_game_second != kLoadGameSecond ||
        runtime.MemoryRead8(force_flag->value) > 1) {
        LOGE("MCSM gameplay aspect hooks refused: force-store=0x%08X aspect-store=0x%08X "
             "new-game=0x%08X/0x%08X load-game=0x%08X/0x%08X.",
             set_force_store, set_aspect_store, new_game_first, new_game_second,
             load_game_first, load_game_second);
        return false;
    }

    const bool widescreen_marker = TelltaleWidescreenOverrideEnabled() != 0;
    g_mcsm_gameplay_started.store(false, std::memory_order_relaxed);
    auto gameplay_start = [widescreen_marker, force_address = force_flag->value,
                           aspect_address = aspect_value->value,
                           reinitialize_address = reinitialize->value]
                          (Dynarmic::A32::Jit&, DynarmicHost& host) {
        g_mcsm_gameplay_started.store(true, std::memory_order_relaxed);
        host.MemoryWrite32(aspect_address, 0x3FE38E39u); // 16:9
        host.MemoryWrite8(force_address, widescreen_marker ? 0 : 1);
        host.MemoryWrite8(reinitialize_address, 1);
        LOGI("MCSM gameplay aspect selected: marker=%u force16by9=%u.",
             widescreen_marker ? 1u : 0u, widescreen_marker ? 0u : 1u);
    };
    auto force_gate = [widescreen_marker, force_address = force_flag->value]
                      (Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (jit.Regs()[3] != force_address) return;
        const bool gameplay_started = g_mcsm_gameplay_started.load(std::memory_order_relaxed);
        const uint8_t requested = (!gameplay_started || widescreen_marker)
            ? 0 : static_cast<uint8_t>(jit.Regs()[0] & 1u);
        host.MemoryWrite8(force_address, requested);
    };
    const uint32_t force_gate_thunk = runtime.GetThunkManager().RegisterThunk(
        "mcsm_aspect_force_gate", std::move(force_gate));
    const uint32_t force_gate_svc = force_gate_thunk ? runtime.MemoryRead32(force_gate_thunk) : 0;
    if (!force_gate_thunk || (force_gate_svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("MCSM gameplay aspect hooks refused: cannot create SetForce gate thunk.");
        return false;
    }
    MCSMEntryHook new_game_hook;
    MCSMEntryHook load_game_hook;
    if (!PrepareMCSMEntryHook(runtime, *engine, kNewGameName, kNewGameSize,
            kNewGameFirst, kNewGameSecond, "mcsm_aspect_new_game_start",
            gameplay_start, new_game_hook) ||
        !PrepareMCSMEntryHook(runtime, *engine, kLoadGameName, kLoadGameSize,
            kLoadGameFirst, kLoadGameSecond, "mcsm_aspect_load_game_start",
            gameplay_start, load_game_hook)) {
        return false;
    }

    CommitMCSMEntryHook(runtime, new_game_hook);
    CommitMCSMEntryHook(runtime, load_game_hook);
    runtime.MemoryWrite32(set_force->value + kSetForceStoreOffset, force_gate_svc);
    runtime.MemoryWrite32(set_aspect->value + kSetAspectForceStoreOffset, 0xE1A00000u); // nop
    runtime.MemoryWrite8(force_flag->value, 0);
    runtime.MemoryWrite8(reinitialize->value, 1);
    runtime.InvalidateGuestCode(set_force->value + kSetForceStoreOffset, sizeof(uint32_t));
    runtime.InvalidateGuestCode(set_aspect->value + kSetAspectForceStoreOffset, sizeof(uint32_t));
    LOGI("MCSM gameplay aspect hooks installed: marker=%u force=0x%08X aspect=0x%08X new=0x%08X load=0x%08X.",
         widescreen_marker ? 1u : 0u, set_force->value, set_aspect->value,
         new_game_hook.target, load_game_hook.target);
    return true;
}
#endif

#if defined(ARM32_BRIDGE_ENABLE_GOT_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_GOT_WIDESCREEN_OVERRIDE
static void ApplyWidescreenOverride(DynarmicHost& runtime) {
    const uint32_t set_force = runtime.FindSymbol("_ZN12RenderDevice30SetForceGameContentAspectRatioEb");
    const uint32_t set_aspect = runtime.FindSymbol("_ZN12RenderDevice25SetGameContentAspectRatioEf");
    const uint32_t force_flag = runtime.FindSymbol("_ZN12RenderDevice18sbForceAspectRatioE");
    constexpr uint32_t kArmBxLr = 0xE12FFF1Eu;
    if (set_force) runtime.MemoryWrite32(set_force, kArmBxLr);
    if (set_aspect) runtime.MemoryWrite32(set_aspect, kArmBxLr);
    if (force_flag) runtime.MemoryWrite8(force_flag, 0);
    LOGI("Widescreen override active: neutralized forced game-content aspect (set_force=0x%08X, set_aspect=0x%08X, flag=0x%08X).",
         set_force, set_aspect, force_flag);
}
#endif

#if defined(ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE
bool InstallTFTBWidescreenOverride(DynarmicHost& runtime, bool enabled) {
    if (!enabled) return true;
    const ElfLoader* engine = runtime.FindModule("libGameEngine.so");
    const ElfSymbol* wrapper = engine ? engine->GetExportedSymbol(
        "_Z34luaRenderForce_16_by_9_AspectRatioP9lua_State") : nullptr;
    const ElfSymbol* flag = engine ? engine->GetExportedSymbol(
        "_ZN12RenderDevice18sbForceAspectRatioE") : nullptr;
    // Exact TFTB 1.79 wrapper; retain the real setter and all Lua stack handling.
    constexpr std::array<uint32_t, 17> original = {
        0xE92D4010u, 0xE1A04000u, 0xEB031B18u, 0xE1A00004u,
        0xE3A01001u, 0xEB031F7Au, 0xE1A00004u, 0xE3A01000u,
        0xEB031B19u, 0xE3A00001u, 0xEBFA0ECFu, 0xE3080E39u,
        0xE3430FE3u, 0xEBFA0EBDu, 0xE1A00004u, 0xE8BD4010u,
        0xEA031B0Au,
    };
    auto refuse = []() {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
            "TFTB widescreen refused: exact guest fingerprint mismatch; no writes.");
        return false;
    };
    if (!wrapper || !flag || wrapper->type != STT_FUNC || flag->type != STT_OBJECT ||
        wrapper->size != sizeof(original) || flag->size != 1 ||
        wrapper->value != static_cast<uint64_t>(engine->GetBaseAddress()) + 0x00C19F94u ||
        flag->value != static_cast<uint64_t>(engine->GetBaseAddress()) + 0x01085D75u)
        return refuse();
    auto in_segment = [&](const ElfSymbol& symbol, uint32_t flags) {
        const uint64_t end = static_cast<uint64_t>(symbol.value) + symbol.size;
        if (end > runtime.GetGuestMemorySize()) return false;
        for (const ElfSegment& segment : engine->GetSegments()) {
            const uint64_t start = static_cast<uint64_t>(engine->GetBaseAddress()) + segment.vaddr;
            if (segment.flags == flags && symbol.value >= start && end <= start + segment.filesz)
                return true;
        }
        return false;
    };
    if (!in_segment(*wrapper, PF_R | PF_X) || !in_segment(*flag, PF_R | PF_W)) return refuse();
    for (size_t i = 0; i < original.size(); ++i)
        if (runtime.MemoryRead32(wrapper->value + static_cast<uint32_t>(i * 4)) != original[i])
            return refuse();
    if (runtime.MemoryRead8(flag->value) != 1) return refuse();
    const uint32_t instruction = wrapper->value + 36;
    runtime.MemoryWrite32(instruction, 0xE3A00000u); // mov r0,#0 at the original force setter call
    runtime.MemoryWrite8(flag->value, 0);
    runtime.InvalidateGuestCode(instruction, sizeof(uint32_t));
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "TFTB widescreen applied: instruction=0x%08X flag=0x%08X", instruction, flag->value);
    return true;
}
#endif

#include "tftb_sdl_primary_motion.inc"
#include "tftb_sdl_window_lifecycle.inc"

static bool ResolveGuestSymbols() {
#define RESOLVE(field, module, symbol) do { g_symbols.field = Sym(module, symbol); if (!g_symbols.field) return false; } while (0)
    RESOLVE(nativeInit, "libmain.so", "Java_org_libsdl_app_SDLActivity_nativeInit");
    RESOLVE(nativeAddJoystick, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeAddJoystick");
    RESOLVE(nativeFlipBuffers, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeFlipBuffers");
    RESOLVE(nativeLowMemory, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeLowMemory");
    RESOLVE(nativePause, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativePause");
    RESOLVE(nativeQuit, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeQuit");
    RESOLVE(nativeRemoveJoystick, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeRemoveJoystick");
    RESOLVE(nativeResume, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeResume");
    RESOLVE(onNativeAccel, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeAccel");
    RESOLVE(onNativeHat, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeHat");
    RESOLVE(onNativeJoy, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeJoy");
    RESOLVE(onNativeKeyDown, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyDown");
    RESOLVE(onNativeKeyUp, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyUp");
    RESOLVE(onNativeKeyboardFocusLost, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyboardFocusLost");
    RESOLVE(onNativePadDown, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativePadDown");
    RESOLVE(onNativePadUp, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativePadUp");
    RESOLVE(onNativeResize, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeResize");
    RESOLVE(onNativeSurfaceChanged, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeSurfaceChanged");
    RESOLVE(onNativeSurfaceDestroyed, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeSurfaceDestroyed");
    RESOLVE(onNativeTouch, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeTouch");
    RESOLVE(nativeCommitText, "libSDL2.so", "Java_org_libsdl_app_SDLInputConnection_nativeCommitText");
    RESOLVE(nativeSetComposingText, "libSDL2.so", "Java_org_libsdl_app_SDLInputConnection_nativeSetComposingText");
    RESOLVE(fmodGetSize, "libfmod.so", "Java_org_fmod_MediaCodec_fmodGetSize");
    RESOLVE(fmodReadAt, "libfmod.so", "Java_org_fmod_MediaCodec_fmodReadAt");
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
    RESOLVE(nativeOnPermissionComplete, "libGameEngine.so", "Java_com_telltalegames_telltale_TelltaleActivity_nativeOnPermissionComplete");
#endif
    RESOLVE(nativeOnPurchaseComplete, "libGameEngine.so", "Java_com_telltalegames_telltale_TelltaleActivity_nativeOnPurchaseComplete");
#undef RESOLVE
    return true;
}

static bool EnsureGameLoaded(JNIEnv* env) {
    if (!cache_bootstrap::Admitted() || g_loading_here || env->ExceptionCheck()) return false;
    if (g_ready.load(std::memory_order_acquire)) { FakeJniEnv::Instance().AttachHostEnv(env); return true; }
    std::lock_guard<std::mutex> lock(g_load_mutex);
    if (!cache_bootstrap::Admitted()) return false;
    if (g_ready.load(std::memory_order_acquire)) { FakeJniEnv::Instance().AttachHostEnv(env); return true; }
    if (g_load_started) return false;
    g_load_started = true; // No retry/reset after a guest initializer can create a thread.
    g_loading_here = true;
    struct LoadingThread { ~LoadingThread() { g_loading_here = false; } } loading_thread;
    if (env->PushLocalFrame(64) < 0) return false;
    struct LocalFrame { JNIEnv* env; ~LocalFrame() { env->PopLocalFrame(nullptr); } } frame{env};
    jobject java_assets = nullptr;
    if (!DiscoverApplicationPaths(env, java_assets)) return false;
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    PrivateMetadataSnapshot("BEFORE_GUEST_INITIALIZERS", g_private_before_taken);
#endif
    AAssetManager* assets = AAssetManager_fromJava(env, java_assets);
    if (!assets) return false;

    auto host = std::make_unique<DynarmicHost>();
    if (!host->Initialize()) return false;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.SetJavaVM(g_jvm);
    fake.Init(*host);
    fake.AttachHostEnv(env);
#ifdef ARM32_BRIDGE_REDIRECT_EXTERNAL_STORAGE_TO_APP_FILES
    fake.SetExternalStorageDirectoryOverride(g_files_dir);
    LOGI("Guest external-storage root: '%s'", g_files_dir.c_str());
#endif

    std::array<GuestAssetImage, portcfg::kGuestModules.size()> images;
    std::vector<GuestModuleImage> modules;
    modules.reserve(portcfg::kGuestModules.size());
    bool fps_engine_verified = false;
    bool sdl_image_verified = false;
    for (size_t i = 0; i < portcfg::kGuestModules.size(); ++i) {
        const std::string entry = std::string(portcfg::kGuestAssetPrefix) + portcfg::kGuestModules[i];
        if (!MapGuestAsset(assets, entry, images[i])) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Unable to map guest module: %s", entry.c_str());
            return false;
        }
        if (!std::strcmp(portcfg::kGuestModules[i], "libGameEngine.so")) {
            if (!VerifyTelltaleFpsImage(env, images[i].data(), images[i].size)) {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "FPS engine SHA guard refused guest image");
                return false;
            }
            fps_engine_verified = true;
        }
        if (!std::strcmp(portcfg::kGuestModules[i], "libSDL2.so")) {
            if (!VerifyTftbSdlImage(env, images[i].data(), images[i].size)) {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "TFTB SDL SHA guard refused guest image");
                return false;
            }
            sdl_image_verified = true;
        }
        modules.push_back({portcfg::kGuestModules[i], images[i].data(), images[i].size});
    }
    if (!fps_engine_verified) return false;
    if (!host->LoadModulesFromMemory(modules)) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Guest load-group audit FAILED; no initializers may run.");
        return false;
    }
    if (!InstallTftbPrimaryTouchMotion(*host, sdl_image_verified)) return false;
    if (!InstallTftbSdlWindowLifecycle(*host, sdl_image_verified)) return false;
    for (GuestAssetImage& image : images) if (!image.Unmap()) return false;
    env->DeleteLocalRef(java_assets);
#if defined(ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE
    if (!InstallMCSMHideBorderOverride(*host)) return false;
#endif
#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION
    InstallTelltaleZlibAcceleration(*host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION
    InstallTelltalePropertySetAddCallbackAcceleration(*host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION
    InstallTelltaleGetKeyInfoAcceleration(*host);
#endif
#if !defined(ARM32_BRIDGE_ENABLE_TELLTALE_CURRENT_DIRECTORY_FIX) || ARM32_BRIDGE_ENABLE_TELLTALE_CURRENT_DIRECTORY_FIX
    InstallTelltaleCurrentDirectoryFix(*host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_MCSM_RESOURCE_HOOKS) && ARM32_BRIDGE_ENABLE_MCSM_RESOURCE_HOOKS
    if (!InstallMCSMAppFilesUserLocation(*host)) return false;
    if (!InstallMCSMEpisodeDirectory(*host, g_files_dir)) return false;
#endif
#if ARM32_BRIDGE_ENABLE_TELLTALE_DIAGNOSTIC_PROBES
    InstallTelltaleRenderFrameProbe(*host);
    InstallTelltaleRenderExecuteProbe(*host);
    InstallTelltaleSceneProbes(*host);
    InstallTelltaleDoLoadProbe(*host);
    InstallTelltaleStartupProbes(*host);
    InstallTelltaleTTPCallErrorProbe(*host);
    InstallTelltaleArchiveProbe(*host);
#else
    LOGI("Telltale diagnostic probes disabled for production.");
#endif
    g_host = std::move(host);
    const TelltaleFpsBinding fps_binding = PrepareTelltaleFpsBinding(*g_host);
    if (!fps_binding.node || !fps_binding.callback) return false;
    if (!g_host->RunModuleInitializers()) return false;
    if (!InstallTelltaleFpsBinding(*g_host, fps_binding)) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "FPS early Lua registration guard refused engine state");
        return false;
    }

    for (const char* module_name : {"libSDL2.so", "libfmod.so"}) {
        ElfLoader* module = g_host->FindModule(module_name);
        const uint32_t on_load = module ? module->GetSymbolAddress("JNI_OnLoad") : 0;
        if (on_load) {
            bool completed = false;
            const uint32_t version = g_host->RunFunction(on_load, {fake.VmTableGuestAddr(), 0}, &completed);
            void* version_env = nullptr;
            if (!completed || !g_jvm || g_jvm->GetEnv(&version_env, static_cast<jint>(version)) != JNI_OK) {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Guest %s JNI_OnLoad failed: version=0x%08X completed=%d", module_name, version, completed);
                return false;
            }
            LOGI("Guest %s JNI_OnLoad -> 0x%08X", module_name, version);
        }
    }
    if (!ResolveGuestSymbols()) return false;
    if (const uint32_t suspended = g_host->FindSymbol("_ZN10GameEngine17mbSuspendGameLoopE")) {
        g_host->MemoryWrite8(suspended, 0);
        LOGI("Cleared initial GameEngine suspend flag.");
    }
#if defined(ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE
    if (TelltaleWidescreenOverrideEnabled() && !InstallMCSMGameplayAspectHooks(*g_host))
        LOGE("MCSM widescreen split is installed, but its aspect hooks are unavailable for this guest build.");
#endif
#if defined(ARM32_BRIDGE_ENABLE_GOT_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_GOT_WIDESCREEN_OVERRIDE
    if (TelltaleWidescreenOverrideEnabled()) ApplyWidescreenOverride(*g_host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE
    if (!InstallTFTBWidescreenOverride(*g_host, TelltaleWidescreenOverrideEnabled() != 0)) {
        return false;
    }
#endif
    g_ready.store(true, std::memory_order_release);
    LOGI("Telltale guest runtime ready.");

#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG == 2
    // Bounded generic startup trace: only atomic call boundaries, no game RVAs.
    DynarmicHost* runtime = g_host.get();
    std::thread([runtime]() {
        for (int i = 0; i < 20; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            runtime->LogGuestExecution();
        }
    }).detach();
#elif ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
    static bool watchdog_started = false;
    if (!watchdog_started) {
        watchdog_started = true;
        DynarmicHost* runtime = g_host.get();
        const uint32_t frame_num = runtime->FindSymbol("_ZN7Metrics9mFrameNumE");
        const uint32_t frame_time = runtime->FindSymbol("_ZN7Metrics10mFrameTimeE");
        const uint32_t actual_time = runtime->FindSymbol("_ZN7Metrics16mActualFrameTimeE");
        const uint32_t suspended = runtime->FindSymbol("_ZN10GameEngine17mbSuspendGameLoopE");
        const uint32_t quit = runtime->FindSymbol("_ZN10GameEngine15mbRequestedQuitE");
        const uint32_t window = runtime->FindSymbol("_ZN10GameWindow10smpGameWinE");
        const uint32_t scale = runtime->FindSymbol("_ZN7Metrics6mScaleE");
        const uint32_t next_time = runtime->FindSymbol("_ZN7Metrics14mNextFrameTimeE");
        const uint32_t fixed_time = runtime->FindSymbol("_ZN7Metrics14mFixedTimeStepE");
        const uint32_t tick_value = runtime->FindSymbol("_ZN7Metrics17mTimeGetTimeValueE");
        const uint32_t use_ticks = runtime->FindSymbol("_ZN7Metrics16mbUseTimeGetTimeE");
        const uint32_t get_ticks = runtime->FindSymbol("SDL_GetTicks");
        const uint32_t render_enabled = runtime->FindSymbol("_ZN12RenderDevice17mbEnableRenderingE");
        const uint32_t render_reinit = runtime->FindSymbol("_ZN12RenderDevice20mbReInitializeDeviceE");
        const uint32_t render_delay = runtime->FindSymbol("_ZN12RenderDevice18mRenderDelayFramesE");
        const uint32_t render_in_frame = runtime->FindSymbol("_ZN12RenderDevice9mbInFrameE");
        const uint32_t device_initialized = runtime->FindSymbol("_ZN12RenderDevice20mDeviceIsInitializedE");
        const uint32_t render_caps = runtime->FindSymbol("_ZN12RenderDevice11mRenderCapsE");
        const uint32_t device_width = runtime->FindSymbol("_ZN12RenderDevice12mDeviceWidthE");
        const uint32_t device_height = runtime->FindSymbol("_ZN12RenderDevice13mDeviceHeightE");
        const uint32_t game_width = runtime->FindSymbol("_ZN12RenderDevice10mGameWidthE");
        const uint32_t game_height = runtime->FindSymbol("_ZN12RenderDevice11mGameHeightE");
        const uint32_t current_thread = runtime->FindSymbol("_ZN12RenderDevice16mCurrentThreadIDE");
        const uint32_t render_target_fbo = runtime->FindSymbol("_ZN12RenderDevice16mRenderTargetFBOE");
        const uint32_t blit_target_fbo = runtime->FindSymbol("_ZN12RenderDevice14mBlitTargetFBOE");
        const uint32_t global_obj_cache = runtime->FindSymbol("_ZN11ObjCacheMgr16spGlobalObjCacheE");
        const uint32_t render_thread_enable = runtime->FindSymbol("gMultithreadRenderEnable");
        const uint32_t scene_count = runtime->FindSymbol("_ZN5Scene17msActiveSceneListE");
        const ElfLoader* game_engine = runtime->FindModule("libGameEngine.so");
        const uint32_t render_thread_global = game_engine ? game_engine->GetBaseAddress() + 0x10C0328 : 0;
        const uint32_t render_thread_id_global = game_engine ? game_engine->GetBaseAddress() + 0x10C0338 : 0;
        const uint32_t active_scene_head_global = game_engine ? game_engine->GetBaseAddress() + 0x10E9BAC : 0;
        const uint32_t added_scene_data = game_engine ? game_engine->GetBaseAddress() + 0x10EBD30 : 0;
        const uint32_t added_scene_count = game_engine ? game_engine->GetBaseAddress() + 0x10EBD34 : 0;
        const uint32_t added_scene_capacity = game_engine ? game_engine->GetBaseAddress() + 0x10EBD38 : 0;
        const uint32_t do_open_scene_addr = game_engine ? game_engine->GetBaseAddress() + 0x10EBDC8 : 0;
        const uint32_t do_open_scene_name = game_engine ? game_engine->GetBaseAddress() + 0x10EB388 : 0;
        const uint32_t pending_scene_count = game_engine ? game_engine->GetBaseAddress() + 0x10EBB9C : 0;
        const uint32_t pending_scene_capacity = game_engine ? game_engine->GetBaseAddress() + 0x10EBBA0 : 0;
        const uint32_t pending_scene_data = game_engine ? game_engine->GetBaseAddress() + 0x10EBBA4 : 0;
        const uint32_t game_initialized = game_engine ? game_engine->GetBaseAddress() + 0x10E8B10 : 0;
        const uint32_t render_recursion = game_engine ? game_engine->GetBaseAddress() + 0x10E8B74 : 0;
        const uint32_t script_load_file = runtime->FindSymbol("_ZN13ScriptManager10smLoadFileE");
        const uint32_t script_recent_file = runtime->FindSymbol("_ZN13ScriptManager15sMostRecentFileE");
        const uint32_t script_state = runtime->FindSymbol("_ZN13ScriptManager17smpExecutingStateE");
        const uint32_t script_thread = runtime->FindSymbol("_ZN13ScriptManager18smpExecutingThreadE");
        const uint32_t async_load = runtime->FindSymbol("_ZN16AsyncLoadManager11smSingletonE");
        const uint32_t script_threads = game_engine ? game_engine->GetBaseAddress() + 0x10EB348 : 0;
        std::thread([runtime, frame_num, frame_time, actual_time, suspended, quit, window,
                     scale, next_time, fixed_time, tick_value, use_ticks, get_ticks,
                     render_enabled, render_reinit, render_delay, render_in_frame,
                     device_initialized, render_caps, device_width, device_height,
                     game_width, game_height, current_thread, render_target_fbo,
                     blit_target_fbo, global_obj_cache, render_thread_enable, scene_count,
                     render_thread_global, render_thread_id_global, active_scene_head_global,
                     game_initialized, render_recursion, added_scene_data, added_scene_count,
                     added_scene_capacity, do_open_scene_addr, do_open_scene_name, pending_scene_count,
                     pending_scene_capacity, pending_scene_data, script_load_file, script_recent_file,
                     script_state, script_thread, async_load, script_threads]() {
            for (int i = 0; i < 8; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                runtime->LogGuestExecution();
                auto read_float = [runtime](uint32_t address) {
                    uint32_t bits = address ? runtime->MemoryRead32(address) : 0;
                    float value = 0;
                    memcpy(&value, &bits, sizeof(value));
                    return value;
                };
                auto read_string = [runtime](uint32_t object) {
                    const uint32_t data = object ? runtime->MemoryRead32(object) : 0;
                    const uint32_t length = data ? runtime->MemoryRead32(data - 12) : 0;
                    if (!data || !length || length > 4096) return std::string{};
                    return std::string(reinterpret_cast<const char*>(runtime->GetGuestMemoryBase() + data), length);
                };
                const uint32_t render_thread = render_thread_global ? runtime->MemoryRead32(render_thread_global) : 0;
                const uint32_t render_index = render_thread ? runtime->MemoryRead32(render_thread + 400) : 0;
                const uint32_t render_slot = render_thread && render_index < 4
                    ? runtime->MemoryRead32(render_thread + 336 + render_index * 4) : 0;
                const uint32_t render_frame = render_slot ? runtime->MemoryRead32(render_slot + 68) : 0;
                const uint32_t render_views = render_frame ? runtime->MemoryRead32(render_frame + 28) : 0;
                LOGI("Game loop watch: frame=%u dt=%f actual=%f scale=%f next=%f fixed=%f tickBase=%u ticks=%u useTicks=%u suspended=%u quit=%u window=0x%08X",
                     frame_num ? runtime->MemoryRead32(frame_num) : 0,
                     read_float(frame_time), read_float(actual_time), read_float(scale), read_float(next_time), read_float(fixed_time),
                     tick_value ? runtime->MemoryRead32(tick_value) : 0,
                     get_ticks ? runtime->RunFunction(get_ticks) : 0,
                     use_ticks ? runtime->MemoryRead8(use_ticks) : 0,
                     suspended ? runtime->MemoryRead8(suspended) : 0,
                     quit ? runtime->MemoryRead8(quit) : 0,
                     window ? runtime->MemoryRead32(window) : 0);
                LOGI("Render watch: enabled=%u reinit=%u delay=%d inFrame=%u deviceInit=%u caps=0x%08X device=%ux%u game=%ux%u currentThread=%u targetFbo=%u blitFbo=%u objCache=0x%08X mt=%u renderThread=0x%08X busy=%u recursion=%u worker=%u",
                     render_enabled ? runtime->MemoryRead8(render_enabled) : 0,
                     render_reinit ? runtime->MemoryRead8(render_reinit) : 0,
                     render_delay ? static_cast<int32_t>(runtime->MemoryRead32(render_delay)) : 0,
                     render_in_frame ? runtime->MemoryRead8(render_in_frame) : 0,
                     device_initialized ? runtime->MemoryRead8(device_initialized) : 0,
                     render_caps ? runtime->MemoryRead32(render_caps) : 0,
                     device_width ? runtime->MemoryRead32(device_width) : 0,
                     device_height ? runtime->MemoryRead32(device_height) : 0,
                     game_width ? runtime->MemoryRead32(game_width) : 0,
                     game_height ? runtime->MemoryRead32(game_height) : 0,
                     current_thread ? runtime->MemoryRead32(current_thread) : 0,
                     render_target_fbo ? runtime->MemoryRead32(render_target_fbo) : 0,
                     blit_target_fbo ? runtime->MemoryRead32(blit_target_fbo) : 0,
                     global_obj_cache ? runtime->MemoryRead32(global_obj_cache) : 0,
                     render_thread_enable ? runtime->MemoryRead8(render_thread_enable) : 0,
                     render_thread,
                     render_thread ? runtime->MemoryRead32(render_thread + 432) : 0,
                     render_recursion ? runtime->MemoryRead32(render_recursion) : 0,
                     render_thread_id_global ? runtime->MemoryRead32(render_thread_id_global) : 0);
                const uint32_t added_data_ptr = added_scene_data ? runtime->MemoryRead32(added_scene_data) : 0;
                const uint32_t open_addr_data = do_open_scene_addr ? runtime->MemoryRead32(do_open_scene_addr) : 0;
                LOGI("Render graph: gameInit=%u scenes=%u sceneHead=0x%08X added=%u/%u data=0x%08X pending=%u/%u data=0x%08X doOpen='%s' name='%s' index=%u slot=0x%08X frame=0x%08X views=%u state=%u/%u/%u/%u/%u atomic=%u",
                     game_initialized ? runtime->MemoryRead8(game_initialized) : 0,
                     scene_count ? runtime->MemoryRead32(scene_count) : 0,
                     active_scene_head_global ? runtime->MemoryRead32(active_scene_head_global) : 0,
                     added_scene_count ? runtime->MemoryRead32(added_scene_count) : 0,
                     added_scene_capacity ? runtime->MemoryRead32(added_scene_capacity) : 0,
                     added_data_ptr,
                     pending_scene_count ? runtime->MemoryRead32(pending_scene_count) : 0,
                     pending_scene_capacity ? runtime->MemoryRead32(pending_scene_capacity) : 0,
                     pending_scene_data ? runtime->MemoryRead32(pending_scene_data) : 0,
                     read_string(do_open_scene_addr).c_str(), read_string(do_open_scene_name).c_str(),
                     render_index, render_slot, render_frame, render_views,
                     render_thread ? runtime->MemoryRead32(render_thread + 352) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 364) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 372) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 376) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 384) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 424) : 0);
                const std::string load_file = read_string(script_load_file);
                const std::string recent_file = read_string(script_recent_file);
                const uint32_t async_object = async_load ? runtime->MemoryRead32(async_load) : 0;
                LOGI("Script watch: load='%s' recent='%s' state=0x%08X thread=0x%08X async=0x%08X threadList=0x%08X",
                     load_file.c_str(), recent_file.c_str(),
                     script_state ? runtime->MemoryRead32(script_state) : 0,
                     script_thread ? runtime->MemoryRead32(script_thread) : 0,
                     async_object, script_threads ? runtime->MemoryRead32(script_threads) : 0);
                LOGI("Async graph: stopping=%u main=%08X/%08X async=%08X/%08X/%08X",
                     async_object ? runtime->MemoryRead8(async_object) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 8) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 12) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 16) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 20) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 24) : 0);
            }
        }).detach();
    }
#endif
    return true;
}

static uint32_t ObjectArg(JNIEnv* env, jobject object) {
    if (!g_ready.load(std::memory_order_acquire)) return 0;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    return fake.AddObjectRef(object);
}
static uint32_t FloatArg(jfloat value) { uint32_t bits; memcpy(&bits, &value, sizeof(bits)); return bits; }
static uint32_t Low(jlong value) { return static_cast<uint32_t>(static_cast<uint64_t>(value)); }
static uint32_t High(jlong value) { return static_cast<uint32_t>(static_cast<uint64_t>(value) >> 32); }
static uint32_t Call(JNIEnv* env, jobject object, const uint32_t& symbol, std::vector<uint32_t> args = {},
                     bool* completed = nullptr, bool bootstrap = false) {
    if (completed) *completed = false;
    if (!g_ready.load(std::memory_order_acquire) && !bootstrap) return 0;
    if (!EnsureGameLoaded(env) || !symbol) return 0;
    if (bootstrap) {
        std::lock_guard<std::mutex> lock(g_presentation_mutex);
        UpdatePresentationActiveLocked();
    }
    args.insert(args.begin(), ObjectArg(env, object));
    args.insert(args.begin(), FakeJniEnv::Instance().EnvTableGuestAddr());
    return g_host->RunFunction(symbol, args, completed);
}

static void Native_nativeInit(JNIEnv* env, jclass cls) {
    LOGI("guest nativeInit enter");
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    bool completed = false;
    const uint32_t result = Call(env, cls, g_symbols.nativeInit, {}, &completed, true);
    if (completed) PrivateMetadataSnapshot("AFTER_NATIVE_INIT_RETURN", g_private_after_taken);
    else if (!g_private_after_taken.exchange(true, std::memory_order_relaxed)) {
        PrivateMetaErrno preserve;
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "VFS_PRIVATE_META END phase=AFTER_NATIVE_INIT_RETURN status=NOT_OBSERVED "
            "reason=GUEST_NOT_COMPLETED entries=0 pid=%d uid=%u",
            getpid(), static_cast<unsigned>(getuid()));
    }
#else
    const uint32_t result = Call(env, cls, g_symbols.nativeInit, {}, nullptr, true);
#endif
    LOGI("guest nativeInit returned 0x%08X", result);
    StopSdlWindowLifecycle();
    SetPresentationForeground(false);
    if (g_ready.load(std::memory_order_acquire)) ShutdownOpenSLES(g_host.get());
}
static jint Native_nativeAddJoystick(JNIEnv* env, jclass cls, jint id, jstring name, jstring desc,
                                     jint vendor, jint product, jint buttons, jint axes, jint hats) {
    return static_cast<jint>(Call(env, cls, g_symbols.nativeAddJoystick,
        {static_cast<uint32_t>(id), ObjectArg(env, name), ObjectArg(env, desc), static_cast<uint32_t>(vendor),
         static_cast<uint32_t>(product), static_cast<uint32_t>(buttons), static_cast<uint32_t>(axes), static_cast<uint32_t>(hats)}));
}
static void Native_nativeFlipBuffers(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.nativeFlipBuffers); }
static void Native_nativeLowMemory(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.nativeLowMemory); }
static void Native_nativePause(JNIEnv* env, jclass cls) {
    SetPresentationForeground(false);
    ApplyPendingSdlWindowLifecycle(env);
    if (g_ready.load(std::memory_order_acquire)) PauseAudioPlayback(g_host.get());
}
static void Native_nativeQuit(JNIEnv* env, jclass cls) {
    StopSdlWindowLifecycle();
    SetPresentationForeground(false);
    Call(env, cls, g_symbols.nativeQuit);
}
static jint Native_nativeRemoveJoystick(JNIEnv* env, jclass cls, jint id) { return Call(env, cls, g_symbols.nativeRemoveJoystick, {static_cast<uint32_t>(id)}); }
static void Native_nativeResume(JNIEnv* env, jclass cls) {
    SetPresentationForeground(true);
    if (g_ready.load(std::memory_order_acquire)) ResumeAudioPlayback(g_host.get());
    // The guest transition owns unpause/unmute; pre-clearing its flag skips both.
    ApplyPendingSdlWindowLifecycle(env);
}
static void Native_onNativeAccel(JNIEnv* env, jclass cls, jfloat x, jfloat y, jfloat z) { Call(env, cls, g_symbols.onNativeAccel, {FloatArg(x), FloatArg(y), FloatArg(z)}); }
static void Native_onNativeHat(JNIEnv* env, jclass cls, jint a, jint b, jint c, jint d) { Call(env, cls, g_symbols.onNativeHat, {(uint32_t)a,(uint32_t)b,(uint32_t)c,(uint32_t)d}); }
static void Native_onNativeJoy(JNIEnv* env, jclass cls, jint a, jint b, jfloat c) { Call(env, cls, g_symbols.onNativeJoy, {(uint32_t)a,(uint32_t)b,FloatArg(c)}); }
static void Native_onNativeKeyDown(JNIEnv* env, jclass cls, jint key) { Call(env, cls, g_symbols.onNativeKeyDown, {(uint32_t)key}); }
static void Native_onNativeKeyUp(JNIEnv* env, jclass cls, jint key) { Call(env, cls, g_symbols.onNativeKeyUp, {(uint32_t)key}); }
static void Native_onNativeKeyboardFocusLost(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.onNativeKeyboardFocusLost); }
static jint Native_onNativePadDown(JNIEnv* env, jclass cls, jint a, jint b) { return Call(env, cls, g_symbols.onNativePadDown, {(uint32_t)a,(uint32_t)b}); }
static jint Native_onNativePadUp(JNIEnv* env, jclass cls, jint a, jint b) { return Call(env, cls, g_symbols.onNativePadUp, {(uint32_t)a,(uint32_t)b}); }
static void Native_onNativeResize(JNIEnv* env, jclass cls, jint format, jint width, jint height) {
    Call(env, cls, g_symbols.onNativeResize, {(uint32_t)format,(uint32_t)width,(uint32_t)height}, nullptr, true);
}
static void Native_onNativeSurfaceChanged(JNIEnv* env, jclass cls) {
    SetPresentationSurface(true);
    Call(env, cls, g_symbols.onNativeSurfaceChanged, {}, nullptr, true);
}
static void Native_onNativeSurfaceDestroyed(JNIEnv* env, jclass cls) {
    SetPresentationSurface(false);
    Call(env, cls, g_symbols.onNativeSurfaceDestroyed);
}
static void Native_onNativeTouch(JNIEnv* env, jclass cls, jint a, jint b, jint c, jfloat x, jfloat y, jfloat p) {
#if defined(ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS) && ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS
    LOGI("MCSM touch JNI enter: device=%d pointer=%d action=%d x=%.3f y=%.3f pressure=%.3f",
         a, b, c, x, y, p);
#endif
    Call(env, cls, g_symbols.onNativeTouch, {(uint32_t)a,(uint32_t)b,(uint32_t)c,FloatArg(x),FloatArg(y),FloatArg(p)});
#if defined(ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS) && ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS
    LOGI("MCSM touch JNI exit: device=%d pointer=%d action=%d", a, b, c);
#endif
}
static void Native_nativeCommitText(JNIEnv* env, jobject obj, jstring text, jint cursor) {
    Call(env, obj, g_symbols.nativeCommitText, {ObjectArg(env, text), static_cast<uint32_t>(cursor)});
}
static void Native_nativeSetComposingText(JNIEnv* env, jobject obj, jstring text, jint cursor) {
    Call(env, obj, g_symbols.nativeSetComposingText, {ObjectArg(env, text), static_cast<uint32_t>(cursor)});
}
static uint64_t CallFmod(JNIEnv* env, jclass cls, uint32_t symbol, std::vector<uint32_t> args) {
    if (!g_ready.load(std::memory_order_acquire) || !EnsureGameLoaded(env) || !symbol) return 0;
    args.insert(args.begin(), ObjectArg(env, cls));
    args.insert(args.begin(), FakeJniEnv::Instance().EnvTableGuestAddr());
    bool completed = false;
    const uint64_t result = g_host->RunSynchronousCallback(symbol, args, &completed);
    return completed && g_ready.load(std::memory_order_acquire) ? result : 0;
}
static jlong Native_fmodGetSize(JNIEnv* env, jclass cls, jlong codec) {
    return static_cast<jlong>(CallFmod(env, cls, g_symbols.fmodGetSize, {Low(codec), High(codec)}));
}
static jint Native_fmodReadAt(JNIEnv* env, jclass cls, jlong codec, jlong offset, jbyteArray data, jint size) {
    return static_cast<jint>(CallFmod(env, cls, g_symbols.fmodReadAt,
        {Low(codec), High(codec), Low(offset), High(offset), ObjectArg(env, data), static_cast<uint32_t>(size)}));
}
static void Native_nativeOnPurchaseComplete(JNIEnv* env, jclass cls, jstring sku, jboolean ok, jstring token) {
    Call(env, cls, g_symbols.nativeOnPurchaseComplete, {ObjectArg(env, sku), static_cast<uint32_t>(ok), ObjectArg(env, token)});
}
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
static void Native_nativeOnPermissionComplete(JNIEnv* env, jclass cls, jint permission, jboolean granted) {
    Call(env, cls, g_symbols.nativeOnPermissionComplete,
         {static_cast<uint32_t>(permission), static_cast<uint32_t>(granted)});
}
#endif

extern "C" JNIEXPORT jlong JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheBegin(JNIEnv* env, jclass, jobject context) {
    return cache_bootstrap::Begin(env, context, "com.telltalegames.borderlands100");
}
extern "C" JNIEXPORT jint JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheRun(JNIEnv* env, jclass, jlong token, jboolean hide) {
    return cache_bootstrap::Run(env, token, hide != JNI_FALSE, kTftbCacheMembers, std::size(kTftbCacheMembers));
}
extern "C" JNIEXPORT void JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheCancel(JNIEnv*, jclass, jlong token) { cache_bootstrap::Cancel(token); }
extern "C" JNIEXPORT jboolean JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheActivate(JNIEnv*, jclass, jlong token) { return cache_bootstrap::Activate(token); }
extern "C" JNIEXPORT void JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheRelease(JNIEnv* env, jclass, jlong token) { cache_bootstrap::Release(env, token); }
extern "C" JNIEXPORT jint JNICALL Java_org_libsdl_app_SDLActivity_nativeCacheOwner(JNIEnv*, jclass, jint owner) {
    return owner < 0 ? 0 : cache_bootstrap::OwnerSource(static_cast<unsigned>(owner));
}

#if defined(BRIDGE_CACHE_JOB_TEST)
extern "C" bool BridgeCacheTestNoGuest(JNIEnv* env) {
    if (g_host || g_ready.load(std::memory_order_acquire) || g_load_started) return false;
    if (ObjectArg(env, nullptr) != 0) return false;
    Native_nativeLowMemory(env, nullptr); Native_nativeQuit(env, nullptr);
    Native_nativePause(env, nullptr); Native_nativeResume(env, nullptr);
    Native_onNativeTouch(env, nullptr, 0, 0, 0, 0, 0, 0);
    Native_nativeOnPurchaseComplete(env, nullptr, nullptr, JNI_FALSE, nullptr);
    if (Native_fmodGetSize(env, nullptr, 0) != 0 || Native_fmodReadAt(env, nullptr, 0, 0, nullptr, 0) != 0) return false;
    // Before admission test the gate; after admission test same-thread bootstrap reentry.
    g_loading_here = cache_bootstrap::Admitted();
    Native_nativeInit(env, nullptr); Native_onNativeResize(env, nullptr, 0, 1, 1);
    Native_onNativeSurfaceChanged(env, nullptr);
    g_loading_here = false;
    return !g_host && !g_ready.load(std::memory_order_acquire) && !g_load_started && !env->ExceptionCheck();
}
#endif

#if defined(BRIDGE_TOUCH_PROBE_TEST) && BRIDGE_TOUCH_PROBE_TEST
#include "bridge_touch_probe.inc"
#endif

static const JNINativeMethod kSdlMethods[] = {
#if defined(BRIDGE_TOUCH_PROBE_TEST) && BRIDGE_TOUCH_PROBE_TEST
    {"nativeTouchProbeSnapshot", "()[J", (void*)Native_touchProbeSnapshot},
#endif
    {"nativeCacheBegin", "(Landroid/content/Context;)J", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheBegin},
    {"nativeCacheRun", "(JZ)I", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheRun},
    {"nativeCacheCancel", "(J)V", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheCancel},
    {"nativeCacheActivate", "(J)Z", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheActivate},
    {"nativeCacheRelease", "(J)V", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheRelease},
    {"nativeCacheOwner", "(I)I", (void*)Java_org_libsdl_app_SDLActivity_nativeCacheOwner},
    {"nativePrivateMetadataPhase", "(I)I", (void*)Native_nativePrivateMetadataPhase},
    {"nativeAddJoystick", "(ILjava/lang/String;Ljava/lang/String;IIIII)I", (void*)Native_nativeAddJoystick},
    {"nativeFlipBuffers", "()V", (void*)Native_nativeFlipBuffers}, {"nativeInit", "()V", (void*)Native_nativeInit},
    {"nativeLowMemory", "()V", (void*)Native_nativeLowMemory}, {"nativePause", "()V", (void*)Native_nativePause},
    {"nativeQuit", "()V", (void*)Native_nativeQuit}, {"nativeRemoveJoystick", "(I)I", (void*)Native_nativeRemoveJoystick},
    {"nativeResume", "()V", (void*)Native_nativeResume}, {"onNativeAccel", "(FFF)V", (void*)Native_onNativeAccel},
    {"onNativeHat", "(IIII)V", (void*)Native_onNativeHat}, {"onNativeJoy", "(IIF)V", (void*)Native_onNativeJoy},
    {"onNativeKeyDown", "(I)V", (void*)Native_onNativeKeyDown}, {"onNativeKeyUp", "(I)V", (void*)Native_onNativeKeyUp},
    {"onNativeKeyboardFocusLost", "()V", (void*)Native_onNativeKeyboardFocusLost},
    {"onNativePadDown", "(II)I", (void*)Native_onNativePadDown}, {"onNativePadUp", "(II)I", (void*)Native_onNativePadUp},
    {"onNativeResize", "(III)V", (void*)Native_onNativeResize},
    {"onNativeSurfaceChanged", "()V", (void*)Native_onNativeSurfaceChanged},
    {"onNativeSurfaceDestroyed", "()V", (void*)Native_onNativeSurfaceDestroyed},
    {"onNativeTouch", "(IIIFFF)V", (void*)Native_onNativeTouch},
};
static const JNINativeMethod kInputMethods[] = {
    {"nativeCommitText", "(Ljava/lang/String;I)V", (void*)Native_nativeCommitText},
    {"nativeSetComposingText", "(Ljava/lang/String;I)V", (void*)Native_nativeSetComposingText},
};
static const JNINativeMethod kCodecMethods[] = {
    {"fmodGetSize", "(J)J", (void*)Native_fmodGetSize}, {"fmodReadAt", "(JJ[BI)I", (void*)Native_fmodReadAt},
};
static const JNINativeMethod kTelltaleMethods[] = {
    {"nativeOnPurchaseComplete", "(Ljava/lang/String;ZLjava/lang/String;)V", (void*)Native_nativeOnPurchaseComplete},
};
static const JNINativeMethod kFpsMethods[] = {
    {"nativeInitUi", "()I", (void*)InitTelltaleFpsUi},
    {"nativeRefresh", "(F)V", (void*)RefreshTelltaleFpsDisplay},
};
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
static const JNINativeMethod kTelltalePermissionMethods[] = {
    {"nativeOnPermissionComplete", "(IZ)V", (void*)Native_nativeOnPermissionComplete},
};
#endif

static bool RegisterTable(JNIEnv* env, const char* name, const JNINativeMethod* methods, jint count) {
    jclass cls = env->FindClass(name);
    if (!cls) { env->ExceptionClear(); LOGE("Class not found: %s", name); return false; }
    if (env->RegisterNatives(cls, methods, count) != JNI_OK) {
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "RegisterNatives failed: %s", name); return false;
    }
    LOGI("Registered %d natives on %s", count, name);
    return true;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
#if defined(BRIDGE_CACHE_JOB_TEST)
    return JNI_VERSION_1_6; // Probe bypasses only class registration; actual VM/job/guards remain.
#else
    if (!RegisterTable(env, "org/libsdl/app/PortFrameRate", kFpsMethods, std::size(kFpsMethods)) ||
        !RegisterTable(env, portcfg::kSdlActivityClass, kSdlMethods, std::size(kSdlMethods)) ||
        !RegisterTable(env, portcfg::kSdlInputClass, kInputMethods, std::size(kInputMethods)) ||
        !RegisterTable(env, portcfg::kFmodMediaCodecClass, kCodecMethods, std::size(kCodecMethods)) ||
        !RegisterTable(env, portcfg::kTelltaleActivityClass, kTelltaleMethods, std::size(kTelltaleMethods))) {
        return JNI_ERR;
    }
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
    if (!RegisterTable(env, portcfg::kTelltaleActivityClass,
                       kTelltalePermissionMethods, std::size(kTelltalePermissionMethods))) return JNI_ERR;
#endif
#if defined(ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE) && ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE
    LOGI("JNI_OnLoad: ARM64 Telltale host registered 35 natives including FPS UI");
#else
    LOGI("JNI_OnLoad: ARM64 Telltale host registered 34 natives including FPS UI");
#endif
    return JNI_VERSION_1_6;
#endif
}
