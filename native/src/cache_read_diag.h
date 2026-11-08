#pragma once
#include "game_port_config.h"

#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
#include <android/log.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unistd.h>

#define CACHE_DIAG(call) do { cache_diag::PreserveErrno cache_diag_saved_errno; call; } while (false)
namespace cache_diag {
struct PreserveErrno { int value = errno; ~PreserveErrno() { errno = value; } };
// A published immutable JNI identity; callback never runs under the provenance mutex.
inline std::atomic<void(*)()> before_process_exit{nullptr};
inline void BeforeProcessExit() {
    PreserveErrno preserve;
    if (auto callback = before_process_exit.load(std::memory_order_acquire)) callback();
}
struct Origin {
    uint64_t generation = 0;
    const char* kind = "UNKNOWN";
    std::string name, owner;
    int64_t start = -1, length = -1;
};
struct Stream { int fd; Origin origin; bool pushed_back = false; };
inline std::mutex mutex;
inline uint64_t generation = 0;
inline std::unordered_map<int, Origin> descriptors;
inline std::unordered_map<uint32_t, Stream> streams;
inline std::unordered_map<uint32_t, Origin> assets;
inline std::set<std::tuple<std::string, std::string, std::string, std::string>> seen;
inline unsigned records = 0;
inline bool saturated = false;
inline constexpr size_t limit = 512;

inline void Saturated() {
    if (!saturated) {
        saturated = true;
        __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_Cache",
                            "INCOMPLETE SATURATED limit=%zu", limit);
    }
}
inline bool Room() {
    if (descriptors.size() + streams.size() + assets.size() < limit) return true;
    Saturated(); return false;
}
inline std::string Text(const char* value) {
    if (!value) return {};
    const size_t n = strnlen(value, 384);
    if (n == 384) return {};
    for (size_t i = 0; i < n; ++i)
        if (static_cast<unsigned char>(value[i]) < 32 || value[i] == '\'') return {};
    return {value, n};
}
inline std::string FdPath(int fd) {
    char link[64], path[384];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    const ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(path) - 1) return {};
    path[n] = 0; return Text(path);
}
inline bool CacheName(const std::string& name) {
    return name.ends_with(".ttarch2") || name.ends_with(".obb");
}
inline Origin Fd(int fd) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex);
    const auto it = descriptors.find(fd);
    return it == descriptors.end() ? Origin{} : it->second;
}
inline void RememberFd(int fd, const char* kind, const char* name,
                       const char* owner = nullptr, int64_t start = -1, int64_t length = -1) {
    PreserveErrno preserve;
    if (fd < 0) return;
    Origin origin{0, kind, Text(name), owner ? Text(owner) : FdPath(fd), start, length};
    if (origin.name.empty()) origin.kind = "UNKNOWN";
    std::lock_guard lock(mutex);
    descriptors.erase(fd);
    if (!Room()) return;
    origin.generation = ++generation;
    descriptors.emplace(fd, std::move(origin));
}
inline void ForgetFd(int fd) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex); descriptors.erase(fd);
}
inline void RememberFile(uint32_t handle, int fd) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex);
    streams.erase(handle);
    if (!Room()) return;
    const auto it = descriptors.find(fd);
    streams.emplace(handle, Stream{fd, it == descriptors.end() ? Origin{} : it->second});
}
inline void ForgetFile(uint32_t handle) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex);
    const auto it = streams.find(handle);
    if (it == streams.end()) return;
    const auto fd = descriptors.find(it->second.fd);
    if (fd != descriptors.end() && fd->second.generation == it->second.origin.generation)
        descriptors.erase(fd);
    streams.erase(it);
}
inline void Pushback(uint32_t handle, bool value) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex);
    const auto it = streams.find(handle);
    if (it != streams.end()) it->second.pushed_back = value;
}
inline void Emit(const Origin& origin, const char* op, int64_t bytes, int64_t offset, bool mapping) {
    if ((!mapping && bytes <= 0) || (!CacheName(origin.name) && strcmp(origin.kind, "UNKNOWN"))) return;
    const auto key = std::make_tuple(std::string(origin.kind), origin.name, origin.owner, std::string(op));
    if (seen.contains(key)) return;
    if (records >= limit) { Saturated(); return; }
    seen.insert(key); ++records;
    __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_Cache",
        "%s op=%s kind=%s name='%s' owner='%s' bytes=%lld offset=%lld start=%lld length=%lld generation=%llu",
        mapping ? "MAPPING_ONLY" : "GUEST_BYTES", op, origin.kind, origin.name.c_str(), origin.owner.c_str(),
        static_cast<long long>(bytes), static_cast<long long>(offset),
        static_cast<long long>(origin.start), static_cast<long long>(origin.length),
        static_cast<unsigned long long>(origin.generation));
}
inline Origin CheckedAssetRange(const Origin& origin, int64_t bytes, int64_t offset) {
    if (strcmp(origin.kind, "APK_ASSET_FD") && strcmp(origin.kind, "EXTERNAL_CACHE_FD")) return origin;
    if (origin.start >= 0 && origin.length >= 0 && bytes > 0 && offset >= origin.start &&
        offset - origin.start <= origin.length && bytes <= origin.length - (offset - origin.start)) return origin;
    // A real APK descriptor also exposes bytes outside the handed-out asset.
    return Origin{origin.generation, "UNKNOWN", {}, origin.owner, origin.start, origin.length};
}
inline void FdDelivered(int fd, const Origin& before, const char* op, int64_t bytes,
                        int64_t offset = -1, bool mapping = false) {
    PreserveErrno preserve;
    if (!mapping && bytes <= 0) return;
    std::lock_guard lock(mutex);
    const auto it = descriptors.find(fd);
    const uint64_t now = it == descriptors.end() ? 0 : it->second.generation;
    Emit(CheckedAssetRange(now == before.generation ? before : Origin{}, bytes, offset), op, bytes, offset, mapping);
}
inline void FileDelivered(uint32_t handle, const char* op, int64_t bytes) {
    PreserveErrno preserve;
    if (bytes <= 0) return;
    std::lock_guard lock(mutex);
    const auto it = streams.find(handle);
    Origin origin;
    if (it != streams.end()) {
        const auto fd = descriptors.find(it->second.fd);
        if (!it->second.pushed_back && fd != descriptors.end() &&
            fd->second.generation == it->second.origin.generation) origin = it->second.origin;
    }
    Emit(CheckedAssetRange(origin, bytes, -1), op, bytes, -1, false);
}
inline void RememberAsset(uint32_t handle, const char* name, const char* kind = "APK_ASSET",
                          const char* owner = nullptr, int64_t start = -1, int64_t length = -1) {
    PreserveErrno preserve;
    if (!handle) return;
    std::lock_guard lock(mutex);
    assets.erase(handle);
    const auto copied = Text(name);
    if (Room()) assets.emplace(handle, Origin{++generation, copied.empty() ? "UNKNOWN" : kind, copied, Text(owner), start, length});
}
inline Origin Asset(uint32_t handle) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex);
    const auto it = assets.find(handle); return it == assets.end() ? Origin{} : it->second;
}
inline void ForgetAsset(uint32_t handle) {
    PreserveErrno preserve;
    std::lock_guard lock(mutex); assets.erase(handle);
}
inline void AssetDelivered(uint32_t handle, const Origin& before, int64_t bytes) {
    PreserveErrno preserve;
    if (bytes <= 0) return;
    std::lock_guard lock(mutex);
    const auto it = assets.find(handle);
    const uint64_t now = it == assets.end() ? 0 : it->second.generation;
    Emit(now == before.generation ? before : Origin{}, "AAsset_read", bytes, -1, false);
}
} // namespace cache_diag
#else
#define CACHE_DIAG(call) ((void)0)
#endif
