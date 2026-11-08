#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "game_port_config.h"
#include "cache_read_diag.h"
#include "cache_sources.h"
#include "thunk_types.h"
#include "thunks_opensles.h"
#include "elf_loader.h"
#include "guest_qsort_image.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <ctime>
#include <climits>
#include <limits>
#include <locale.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pwd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <filesystem>
#include <unistd.h>
#include <android/log.h>
#include <unordered_map>
#include <utility>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <sstream>

#define LOG_TAG "Arm32Bridge_Libc"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
#define VFS_DIAG_LOGI(...) LOGI(__VA_ARGS__)
#else
#define VFS_DIAG_LOGI(...) ((void)0)
#endif

extern "C" FILE *funopen(const void *cookie,
                         int (*readfn)(void *, char *, int),
                         int (*writefn)(void *, const char *, int),
                         fpos_t (*seekfn)(void *, fpos_t, int),
                         int (*closefn)(void *));

struct ApkEntry {
    char name[256];
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    char owner[384]{};
#endif
    int apk_fd = -1;
    off_t data_offset;
    off_t file_size;
    uint32_t crc32 = 0;
    bool external = false;
};

static ApkEntry g_apk_entries[512];
static int g_num_apk_entries = 0;
static std::vector<int> g_apk_fds;
static std::vector<CacheMember> g_cache_members;
static std::array<int, 7> g_cache_sources{};
static unsigned g_rejected_packaged_owners = 0;
static std::string g_cache_obb_dir;

// Set while indexing the split APKs when a split carries the widescreen marker
// asset. The marker is intentionally kept OUTSIDE assets/telltale/files/ so the
// guest never sees it; it only selects the bridge-side forced-aspect override.
static bool g_widescreen_marker_present = false;

extern "C" int TelltaleWidescreenOverrideEnabled() {
    return g_widescreen_marker_present ? 1 : 0;
}

static std::mutex g_tm_zone_cache_mutex;
static std::unordered_map<const DynarmicHost*, std::unordered_map<std::string, uint32_t>> g_tm_zone_cache;

static std::vector<GuestThreadWorker> g_thread_workers;

struct GuestThreadState {
    std::thread thread;
    std::atomic<bool> done{false};
    uint32_t result = 0;
};
static std::mutex g_guest_threads_mutex;
static std::unordered_map<uint32_t, std::shared_ptr<GuestThreadState>> g_guest_threads;
static std::atomic<uint32_t> g_next_guest_thread{0x1000};
static thread_local uint32_t g_current_guest_thread = 1;

void ClearArm32TmZoneCache(const DynarmicHost* host) {
    std::lock_guard<std::mutex> lock(g_tm_zone_cache_mutex);
    g_tm_zone_cache.erase(host);
}

struct GuestMutex { std::recursive_mutex value; };
struct GuestCond { std::condition_variable_any value; };
struct GuestSemaphore {
    std::mutex mutex;
    std::condition_variable cv;
    uint32_t count = 0;
};
static std::mutex g_sync_mutex;
static std::unordered_map<uint32_t, std::shared_ptr<GuestMutex>> g_mutexes;
static std::unordered_map<uint32_t, std::shared_ptr<GuestCond>> g_conds;
static std::unordered_map<uint32_t, std::shared_ptr<GuestSemaphore>> g_semaphores;
// ponytail: one mutex/CV for once-state metadata; split by control if contention is measured.
static std::mutex g_once_mutex;
static std::condition_variable g_once_cv;
static thread_local uint32_t g_getenv_buffer = 0;
static std::mutex g_wctype_mutex;
static std::unordered_map<uint32_t, wctype_t> g_wctype_handles;
static uint32_t g_next_wctype_handle = 1;

template <typename T>
static std::shared_ptr<T> GetSyncObject(std::unordered_map<uint32_t, std::shared_ptr<T>>& map, uint32_t addr) {
    if (!addr) return nullptr;
    std::lock_guard<std::mutex> lock(g_sync_mutex);
    auto& object = map[addr];
    if (!object) object = std::make_shared<T>();
    return object;
}

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers() {
    return g_thread_workers;
}

void AddGuestThreadWorker(uint32_t start_func, uint32_t arg) {
    g_thread_workers.push_back({start_func, arg});
}

static uint16_t ZipU16(const unsigned char* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

static uint32_t ZipU32(const unsigned char* p) {
    return ZipU16(p) | (static_cast<uint32_t>(ZipU16(p + 2)) << 16);
}

struct PendingApkIndex {
    std::vector<ApkEntry> entries;
    std::vector<int> fds;
    bool widescreen = false;
    unsigned rejected_owners = 0;
    std::vector<std::string> cache_names;
    ~PendingApkIndex() { for (int fd : fds) close(fd); }
};

static int IndexOneApk(const char* apk_path, int apk_fd, PendingApkIndex& pending,
                       const CacheMember* members = nullptr, size_t member_count = 0, int role = -1) {
    const off_t length = lseek(apk_fd, 0, SEEK_END);
    if (length < 22) return -1;
    const uint64_t file_len = static_cast<uint64_t>(length);
    auto read = [&](void* dest, size_t size, uint64_t offset) {
        if (offset > file_len || size > file_len - offset) return false;
        ssize_t got;
        do { got = pread(apk_fd, dest, size, static_cast<off_t>(offset)); }
        while (got < 0 && errno == EINTR);
        return got == static_cast<ssize_t>(size);
    };
    const size_t search_len = static_cast<size_t>(std::min<uint64_t>(file_len, 65535 + 22));
    const uint64_t search_start = file_len - search_len;
    std::vector<unsigned char> tail(search_len);
    if (!read(tail.data(), tail.size(), search_start)) return -1;
    const auto original_entries = pending.entries;
    const bool original_marker = pending.widescreen;
    const unsigned original_rejected = pending.rejected_owners;
    const auto original_names = pending.cache_names;
    PendingApkIndex fallback; // No FDs copied: the outer pending owner holds this APK.
    bool have_fallback = false, soft_rejected = false;
    auto parse_directory = [&](const unsigned char* eocd) {
        const uint16_t count = ZipU16(eocd + 10);
        const uint32_t cd_size = ZipU32(eocd + 12), cd_offset = ZipU32(eocd + 16);
        uint64_t pos = 0;
        std::vector<std::pair<uint64_t, uint64_t>> ranges;
        ranges.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            unsigned char central[46]{};
            if (pos > cd_size || sizeof(central) > cd_size - pos ||
                !read(central, sizeof(central), static_cast<uint64_t>(cd_offset) + pos) ||
                ZipU32(central) != 0x02014b50) return -1;
            const uint16_t version = ZipU16(central + 6);
            const uint16_t flags = ZipU16(central + 8), method = ZipU16(central + 10);
            const uint32_t crc = ZipU32(central + 16), csize = ZipU32(central + 20), usize = ZipU32(central + 24);
            const uint16_t name_len = ZipU16(central + 28), extra_len = ZipU16(central + 30), comment_len = ZipU16(central + 32);
            const uint32_t local_offset = ZipU32(central + 42);
            const uint64_t record_size = 46ull + name_len + extra_len + comment_len;
            if (!name_len || record_size > cd_size - pos) return -1;
            std::string name(name_len, '\0');
            if (!read(name.data(), name_len, static_cast<uint64_t>(cd_offset) + pos + 46) ||
                name.find('\0') != std::string::npos) return -1;
            const bool cache = name.starts_with("assets/telltale/files/") || name.starts_with("assets/telltale/obb/");
            const CacheMember* member = nullptr;
            if (members && cache) {
                for (size_t j = 0; j < member_count; ++j)
                    if (name == members[j].asset) { member = &members[j]; break; }
            }
            auto reject_owner = [&] {
                soft_rejected = true;
                if (role >= 0) pending.rejected_owners |= 1u << role;
                if (member) pending.rejected_owners |= 1u << member->owner;
            };
            uint64_t data_offset = 0, record_end = 0;
            bool unsafe_extent = false;
            auto valid_region = [&] {
                // Physical framing is independent of cache compatibility. Keep every
                // measurable record in the overlap check, including rejected cache.
                if (ZipU16(central + 34) || csize == UINT32_MAX || usize == UINT32_MAX ||
                    local_offset == UINT32_MAX || static_cast<uint64_t>(local_offset) + 30 > cd_offset) {
                    unsafe_extent = true; return false;
                }
                unsigned char local[30]{};
                if (!read(local, sizeof(local), local_offset) || ZipU32(local) != 0x04034b50 ||
                    ZipU32(local + 18) == UINT32_MAX || ZipU32(local + 22) == UINT32_MAX) {
                    unsafe_extent = true; return false;
                }
                data_offset = static_cast<uint64_t>(local_offset) + 30 + ZipU16(local + 26) + ZipU16(local + 28);
                const uint32_t local_size = ZipU32(local + 18);
                const uint64_t data_end = data_offset + csize;
                record_end = data_offset + std::max(csize, local_size);
                if (record_end > cd_offset) { unsafe_extent = true; return false; }
                if ((flags | ZipU16(local + 6)) & 8) {
                    // A mismatching descriptor cannot safely define a physical extent.
                    if ((local_size && local_size != csize) || data_end + 12 > cd_offset) {
                        unsafe_extent = true; return false;
                    }
                    unsigned char descriptor[16]{};
                    if (!read(descriptor, 12, data_end)) { unsafe_extent = true; return false; }
                    bool matches = ZipU32(descriptor) == crc && ZipU32(descriptor + 4) == csize && ZipU32(descriptor + 8) == usize;
                    record_end = data_end + 12;
                    if (!matches && ZipU32(descriptor) == 0x08074b50 && data_end + 16 <= cd_offset &&
                        read(descriptor + 12, 4, data_end + 12)) {
                        matches = ZipU32(descriptor + 4) == crc && ZipU32(descriptor + 8) == csize && ZipU32(descriptor + 12) == usize;
                        record_end += 4;
                    }
                    if (!matches) { unsafe_extent = true; return false; }
                }
                ranges.emplace_back(local_offset, record_end);
                if ((version != 10 && version != 20) || (method == 8 && version != 20) ||
                    (method != 0 && method != 8) || (flags & ~(0x0808u | (method == 8 ? 6u : 0u))) ||
                    (method == 0 && csize != usize) || ZipU16(local + 4) != version ||
                    ZipU16(local + 6) != flags || ZipU16(local + 8) != method ||
                    ZipU16(local + 26) != name_len) return false;
                std::string local_name(name_len, '\0');
                if (!read(local_name.data(), name_len, static_cast<uint64_t>(local_offset) + 30) || local_name != name) return false;
                for (unsigned field : {14u, 18u, 22u}) {
                    const uint32_t expected = field == 14 ? crc : field == 18 ? csize : usize;
                    const uint32_t actual = ZipU32(local + field);
                    if (actual != expected && (!(flags & 8) || actual != 0)) return false;
                }
                return true;
            };
            if (!valid_region()) {
                if (!members || !cache || unsafe_extent) return -1;
                reject_owner(); pos += record_size; continue;
            }
            if (members && cache) {
                if (!member) { pos += record_size; continue; } // Reserved unknown cache is never published.
                const bool duplicate = std::find(pending.cache_names.begin(), pending.cache_names.end(), name) != pending.cache_names.end();
                if (!duplicate) pending.cache_names.push_back(name);
                if (role != static_cast<int>(member->owner) || duplicate || method != 0 ||
                    name_len >= sizeof(ApkEntry::name) || usize != member->size || crc != member->crc32) {
                    reject_owner(); pos += record_size; continue;
                }
            }
            const bool direct = cache || name.starts_with("assets/Telltale/") ||
                name.find("FMOD") != std::string::npos || name.find(".fsb") != std::string::npos ||
                name.find(".fev") != std::string::npos || name.find("assets/data/audio") != std::string::npos;
            if (name == "assets/telltale/widescreen.enable") pending.widescreen = true;
            if (direct) {
                if (method != 0 || name_len >= sizeof(ApkEntry::name)) return -1;
                auto prior = std::find_if(pending.entries.begin(), pending.entries.end(), [&](const ApkEntry& entry) {
                    return name == entry.name;
                });
                // Cache names are unambiguous; preserve the existing later-APK generic override policy.
                if (prior != pending.entries.end() && cache) return -1;
                ApkEntry entry{};
                memcpy(entry.name, name.data(), name_len);
                entry.apk_fd = apk_fd;
                entry.data_offset = static_cast<off_t>(data_offset);
                entry.file_size = usize;
                entry.crc32 = crc;
    #if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
                const auto owner = cache_diag::Text(apk_path);
                snprintf(entry.owner, sizeof(entry.owner), "%s", owner.c_str());
    #endif
                if (prior != pending.entries.end()) *prior = entry;
                else {
                    if (pending.entries.size() >= std::size(g_apk_entries)) return -1;
                    pending.entries.push_back(entry);
                }
            }
            pos += record_size;
        }
        std::sort(ranges.begin(), ranges.end());
        for (size_t i = 1; i < ranges.size(); ++i) if (ranges[i].first < ranges[i - 1].second) return -1;
        return pos == cd_size ? 0 : -1;
    };
    // An EOCD-shaped byte sequence in a legal comment must not mask the real directory.
    for (size_t i = search_len - 22 + 1; i-- > 0;) {
        const unsigned char* candidate = tail.data() + i;
        if (ZipU32(candidate) != 0x06054b50 || i + 22 + ZipU16(candidate + 20) != search_len) continue;
        const uint16_t count = ZipU16(candidate + 10);
        const uint32_t size = ZipU32(candidate + 12), offset = ZipU32(candidate + 16);
        if (ZipU16(candidate + 4) || ZipU16(candidate + 6) || ZipU16(candidate + 8) != count ||
            count == 0xffff || size == UINT32_MAX || offset == UINT32_MAX ||
            static_cast<uint64_t>(offset) + size != search_start + i ||
            static_cast<uint64_t>(count) * 46 > size || (!count && size)) continue;
        soft_rejected = false;
        if (parse_directory(candidate) == 0) {
            if (!soft_rejected) return 0;
            // A soft-rejected EOCD-shaped comment must not mask an earlier fully
            // compatible directory. Keep the first safe fallback if none exists.
            if (!have_fallback) {
                fallback.entries = pending.entries;
                fallback.widescreen = pending.widescreen;
                fallback.rejected_owners = pending.rejected_owners;
                fallback.cache_names = pending.cache_names;
                have_fallback = true;
            }
        }
        pending.entries = original_entries;
        pending.widescreen = original_marker;
        pending.rejected_owners = original_rejected;
        pending.cache_names = original_names;
    }
    if (!have_fallback) return -1;
    pending.entries.swap(fallback.entries);
    pending.widescreen = fallback.widescreen;
    pending.rejected_owners = fallback.rejected_owners;
    pending.cache_names.swap(fallback.cache_names);
    return 0;
}

static void PublishApkIndex(PendingApkIndex& pending) {
    // Bootstrap-only publication: production calls this under g_load_mutex before any guest execution.
    std::copy(pending.entries.begin(), pending.entries.end(), g_apk_entries);
    g_num_apk_entries = static_cast<int>(pending.entries.size());
    g_widescreen_marker_present = pending.widescreen;
    g_apk_fds.swap(pending.fds); // The destructor closes old owners; live FILE/VFD duplicates stay valid.
    g_cache_members.clear();
    g_cache_sources.fill(0);
    g_rejected_packaged_owners = pending.rejected_owners;
    g_cache_obb_dir.clear();
}

void DiscardCacheSources() {
    PendingApkIndex empty;
    PublishApkIndex(empty);
}

extern "C" int IndexApks(const char* const* apk_paths, size_t apk_count) {
    if (!apk_paths || apk_count == 0 || apk_count > 64) return -1;
    PendingApkIndex pending;
    pending.fds.reserve(apk_count);
    for (size_t i = 0; i < apk_count; ++i) {
        if (!apk_paths[i]) return -1;
        const int fd = open(apk_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        pending.fds.push_back(fd); // Own even an empty/marker-only APK or a replaced generic entry.
        if (IndexOneApk(apk_paths[i], fd, pending) != 0) return -1;
    }
    PublishApkIndex(pending);
    return 0; // A valid cacheless APK permits the ordinary external-file route.
}

extern "C" int IndexApk(const char* apk_path) {
    const char* paths[] = {apk_path};
    return apk_path ? IndexApks(paths, 1) : -1;
}

// One bounded owner decision shared by every cache reader. No per-file backfill.
// ponytail: at most 512 entries, linear lookup; add a map only if this is measured hot.
int CacheOwnerSource(unsigned owner) {
    return owner < g_cache_sources.size() ? g_cache_sources[owner] : 0;
}

static const char* CacheRelative(const char* asset, bool& obb) {
    obb = false;
    if (!asset) return nullptr;
    if (strncmp(asset, "assets/telltale/files/", 22) == 0) return asset + 22;
    if (strncmp(asset, "assets/telltale/obb/", 20) == 0) { obb = true; return asset + 20; }
    return nullptr;
}

static bool ValidCacheMembers(const CacheMember* members, size_t count) {
    if (!members || !count || count > std::size(g_apk_entries)) { errno = EINVAL; return false; }
    for (size_t i = 0; i < count; ++i) {
        bool obb;
        const char* relative = CacheRelative(members[i].asset, obb);
        if (!relative || !*relative || strlen(members[i].asset) >= sizeof(ApkEntry::name) ||
            members[i].owner >= g_cache_sources.size() || members[i].size > INT32_MAX ||
            !members[i].sha256 || strlen(members[i].sha256) != 64) { errno = EINVAL; return false; }
        const char* leaf = relative;
        if (!obb && strncmp(leaf, "Net/", 4) == 0) leaf += 4;
        if (!*leaf || strchr(leaf, '/') || !strcmp(leaf, ".") || !strcmp(leaf, "..")) { errno = EINVAL; return false; }
        for (const char* p = members[i].sha256; *p; ++p)
            if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) { errno = EINVAL; return false; }
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(members[i].asset, members[j].asset)) { errno = EINVAL; return false; }
    }
    return true;
}

int PrepareCacheApks(const CacheApkInput* apks, size_t apk_count,
                     const CacheMember* members, size_t count,
                     const std::atomic<bool>* cancelled) {
    if (!apks || !apk_count || apk_count > 64 || !ValidCacheMembers(members, count)) {
        errno = EINVAL; return -1;
    }
    PendingApkIndex pending;
    pending.fds.reserve(apk_count);
    for (size_t i = 0; i < apk_count; ++i) {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) { errno = ECANCELED; return -1; }
        if (!apks[i].path || apks[i].owner < -1 || apks[i].owner > 6) { errno = EINVAL; return -1; }
        const int fd = ::open(apks[i].path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) pending.fds.push_back(fd);
        if (fd < 0 || IndexOneApk(apks[i].path, fd, pending, members, count, apks[i].owner) != 0) {
            // Only trusted cache-only optional roles may quarantine an entire APK.
            // BASE and ordinary/W APK envelopes remain fatal: they may carry required code/data.
            if (apks[i].owner <= 0) return -1;
            if (fd >= 0) { ::close(fd); pending.fds.pop_back(); }
            pending.rejected_owners |= 1u << apks[i].owner;
        }
    }
    if (cancelled && cancelled->load(std::memory_order_relaxed)) { errno = ECANCELED; return -1; }
    PublishApkIndex(pending);
    return 0;
}

int SelectCacheSources(const CacheMember* members, size_t count,
                       const char* files_dir, const char* obb_dir, bool hide_border,
                       CacheVerifier verify, void* context, const std::atomic<bool>* cancellation) {
    auto cancelled = [&] {
        if (!cancellation || !cancellation->load(std::memory_order_relaxed)) return false;
        errno = ECANCELED; return true;
    };
    if (cancelled()) return -1;
    if (!g_cache_members.empty() || !ValidCacheMembers(members, count)) {
        errno = EINVAL; return -1;
    }
    PendingApkIndex selected; // All external FDs remain owned until the final commit.
    for (int i = 0; i < g_num_apk_entries; ++i) {
        bool managed = false;
        for (size_t j = 0; j < count; ++j) managed |= !strcmp(g_apk_entries[i].name, members[j].asset);
        const std::string name = g_apk_entries[i].name;
        if (!managed && !name.starts_with("assets/telltale/files/") && !name.starts_with("assets/telltale/obb/"))
            selected.entries.push_back(g_apk_entries[i]);
    }
    std::array<int, 7> sources{};
    for (unsigned owner = 0; owner < sources.size(); ++owner) {
        if (cancelled()) return -1;
        if (owner == 5 && !hide_border) continue;
        std::vector<ApkEntry> cohort;
        bool packaged = !(g_rejected_packaged_owners & (1u << owner)), present = false;
        int package_fd = -1;
        for (size_t j = 0; j < count; ++j) {
            if (members[j].owner != owner) continue;
            present = true;
            const ApkEntry* found = nullptr;
            for (int i = 0; i < g_num_apk_entries; ++i)
                if (!strcmp(g_apk_entries[i].name, members[j].asset)) { found = &g_apk_entries[i]; break; }
            if (!found || found->external || found->file_size != static_cast<off_t>(members[j].size) ||
                found->crc32 != members[j].crc32 || (package_fd >= 0 && package_fd != found->apk_fd)) {
                packaged = false;
            } else { package_fd = found->apk_fd; cohort.push_back(*found); }
        }
        if (!present) { if (!owner) { errno = EINVAL; return -1; } continue; }
        if (packaged) sources[owner] = 1;
        else {
            cohort.clear();
            const size_t first_fd = selected.fds.size();
            int files = -1, net = -1, obbs = -1;
            bool external = verify != nullptr;
            for (size_t j = 0; j < count && external; ++j) {
                const CacheMember& member = members[j];
                if (member.owner != owner) continue;
                if (cancellation && cancellation->load(std::memory_order_relaxed)) { external = false; break; }
                bool obb;
                const char* relative = CacheRelative(member.asset, obb);
                int* directory = obb ? &obbs : &files;
                if (*directory < 0) {
                    const char* path = obb ? obb_dir : files_dir;
                    if (path && *path) *directory = ::open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                }
                if (!obb && strncmp(relative, "Net/", 4) == 0) {
                    if (files >= 0 && net < 0) net = ::openat(files, "Net", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    directory = &net; relative += 4;
                }
                const int fd = *directory < 0 ? -1 : ::openat(*directory, relative, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) { external = false; break; }
                selected.fds.push_back(fd);
                struct stat before{}, after{};
                external = ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
                    before.st_size == static_cast<off_t>(member.size) && verify(fd, member, context) &&
                    ::fstat(fd, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
                    before.st_mode == after.st_mode && before.st_size == after.st_size &&
                    before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
                    before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
                if (!external || (cancellation && cancellation->load(std::memory_order_relaxed))) break;
                ApkEntry entry{};
                snprintf(entry.name, sizeof(entry.name), "%s", member.asset);
                entry.apk_fd = fd; entry.data_offset = 0; entry.file_size = member.size;
                entry.crc32 = member.crc32; entry.external = true;
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
                snprintf(entry.owner, sizeof(entry.owner), "%s/%s", obb ? obb_dir : files_dir,
                         CacheRelative(member.asset, obb));
#endif
                cohort.push_back(entry);
            }
            for (int fd : {net, files, obbs}) if (fd >= 0) ::close(fd);
            if (cancelled()) return -1;
            if (external) sources[owner] = 2;
            else {
                for (size_t i = first_fd; i < selected.fds.size(); ++i) ::close(selected.fds[i]);
                selected.fds.resize(first_fd); cohort.clear();
                if (!owner) { errno = ENOENT; return -1; }
            }
        }
        selected.entries.insert(selected.entries.end(), cohort.begin(), cohort.end());
    }
    if (selected.entries.size() > std::size(g_apk_entries)) { errno = EOVERFLOW; return -1; }
    std::vector<CacheMember> manifest(members, members + count);
    std::string selected_obb_dir = obb_dir ? std::filesystem::path(obb_dir).lexically_normal().generic_string() : "";
    if (selected_obb_dir.size() > 1 && selected_obb_dir.back() == '/') selected_obb_dir.pop_back();
    g_apk_fds.reserve(g_apk_fds.size() + selected.fds.size());
    if (cancelled()) return -1;
    // Bootstrap-only publication; all allocating preparation precedes this commit.
    std::copy(selected.entries.begin(), selected.entries.end(), g_apk_entries);
    g_num_apk_entries = selected.entries.size();
    g_apk_fds.insert(g_apk_fds.end(), selected.fds.begin(), selected.fds.end());
    selected.fds.clear();
    g_cache_members.swap(manifest);
    g_cache_obb_dir.swap(selected_obb_dir);
    g_cache_sources = sources;
    return 0;
}

static std::string PackagedFilesEntry(const char* path) {
    if (!path) return {};
    const char* marker = strstr(path, "/files");
    while (marker && marker[6] && marker[6] != '/') marker = strstr(marker + 1, "/files");
    if (!marker) {
        if (strncmp(path, "files/", 6) == 0) return std::string("assets/telltale/files/") + (path + 6);
        return {};
    }
    const char* relative = marker + 6;
    if (*relative == '/') ++relative;
    if (*relative == '\0') return "assets/telltale/files/";
    return std::string("assets/telltale/files/") + relative;
}

static std::string PackagedAssetEntry(const char* path) {
    if (!path) return {};
    const char* marker = strstr(path, "/files/");
    if (!marker) {
        if (strncmp(path, "files/", 6) == 0) return std::string("assets/") + (path + 6);
        return {};
    }
    return std::string("assets/") + (marker + 7);
}

static const CacheMember* ManagedCacheMember(const char* path) {
    if (!path || g_cache_members.empty()) return nullptr;
    const std::string normalized = std::filesystem::path(path).lexically_normal().generic_string();
    const char* resolved = normalized.c_str();
    const std::string packaged = std::filesystem::path(PackagedFilesEntry(resolved)).lexically_normal().generic_string();
    const char* slash = strrchr(resolved, '/');
    const char* leaf = slash ? slash + 1 : resolved;
    for (const CacheMember& member : g_cache_members) {
        bool obb;
        const char* relative = CacheRelative(member.asset, obb);
        if (!strcmp(resolved, member.asset) || !strcmp(resolved, member.asset + 7) ||
            (!packaged.empty() && packaged == member.asset) ||
            (obb && !strcmp(leaf, relative))) return &member;
    }
    return nullptr;
}

static bool CacheReadPath(const char* path) {
    if (!path || g_cache_members.empty()) return false;
    if (ManagedCacheMember(path)) return true;
    const std::string name = std::filesystem::path(path).lexically_normal().generic_string();
    if (name.starts_with("assets/telltale/files/") || name.starts_with("assets/telltale/obb/") ||
        name.starts_with("telltale/files/") || name.starts_with("telltale/obb/")) return true;
    const std::string packaged = std::filesystem::path(PackagedFilesEntry(name.c_str())).lexically_normal().generic_string();
    if (packaged.starts_with("assets/telltale/files/Net/") ||
        (packaged.starts_with("assets/telltale/files/") && packaged.ends_with(".mft"))) return true;
    return !g_cache_obb_dir.empty() && name.starts_with(g_cache_obb_dir + "/");
}

static ApkEntry* FindApkEntry(const char* path) {
    if (!path) return nullptr;
    if (const CacheMember* member = ManagedCacheMember(path)) {
        for (int i = 0; i < g_num_apk_entries; ++i)
            if (!strcmp(g_apk_entries[i].name, member->asset)) return &g_apk_entries[i];
        return nullptr; // Unavailable owner must not fall through to loose disk files.
    }
    if (CacheReadPath(path)) return nullptr;
    if (g_num_apk_entries == 0) return nullptr;
    const std::string packaged_files = PackagedFilesEntry(path);
    const std::string packaged_assets = PackagedAssetEntry(path);
    const char* slash = strrchr(path, '/');
    const char* base = slash ? slash + 1 : path;
#if defined(ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE
    if (strcmp(base, "ui_vignette1.d3dtx") == 0 || strcmp(base, "ui_vignette2.d3dtx") == 0) {
        char vignette_entry[160];
        snprintf(vignette_entry, sizeof(vignette_entry), "assets/telltale/files/Net/%s", base);
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (strcmp(g_apk_entries[i].name, vignette_entry) == 0) return &g_apk_entries[i];
        }
    }
#endif

    char preferred[256];
    snprintf(preferred, sizeof(preferred), "assets/data/audio/%s", base);
    // Plain assets/<basename>: this is the rule that catches an absolute path the engine
    // built for a file that no longer exists on disk -- e.g. an expansion file the engine
    // still looks for under /storage/emulated/0/Android/obb/<pkg>/ while it actually ships
    // as assets/main.<ver>.<pkg>.obb inside the APK.
    char in_assets[256];
    snprintf(in_assets, sizeof(in_assets), "assets/%s", base);
    char in_telltale_obb[256];
    snprintf(in_telltale_obb, sizeof(in_telltale_obb), "assets/telltale/obb/%s", base);
    for (int i = 0; i < g_num_apk_entries; ++i) {
        if ((!packaged_files.empty() && g_apk_entries[i].name == packaged_files)
            || (!packaged_assets.empty() && g_apk_entries[i].name == packaged_assets)
            || strcmp(g_apk_entries[i].name, preferred) == 0 || strcmp(g_apk_entries[i].name, path) == 0
            || strcmp(g_apk_entries[i].name, in_assets) == 0
            || strcmp(g_apk_entries[i].name, in_telltale_obb) == 0) {
            return &g_apk_entries[i];
        }
    }

    // 3. Language suffix fallback (e.g. VOICE.fsb -> VOICE_eng.fsb)
    std::string base_str(base);
    if (base_str.size() > 4 && base_str.substr(base_str.size() - 4) == ".fsb") {
        std::string stem = base_str.substr(0, base_str.size() - 4);
        std::string eng_variant = "assets/data/audio/" + stem + "_eng.fsb";
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (g_apk_entries[i].name == eng_variant || strstr(g_apk_entries[i].name, (stem + "_eng").c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (strstr(g_apk_entries[i].name, stem.c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
    }
    return nullptr;
}

int OpenCacheAssetRegion(const char* name, CacheAssetRegion& region) {
    if (!name || g_cache_members.empty() ||
        (strncmp(name, "telltale/files/", 15) && strncmp(name, "telltale/obb/", 13))) return 0;
    const std::string asset = std::string("assets/") + name;
    const CacheMember* member = nullptr;
    for (const CacheMember& candidate : g_cache_members)
        if (asset == candidate.asset) { member = &candidate; break; }
    const ApkEntry* entry = member ? FindApkEntry(asset.c_str()) : nullptr;
    if (!entry) { errno = ENOENT; return -1; }
    region.fd = ::dup(entry->apk_fd);
    if (region.fd < 0) return -1;
    region.offset = entry->data_offset; region.length = entry->file_size;
    region.external = entry->external;
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    snprintf(region.owner, sizeof(region.owner), "%s", entry->owner);
#endif
    return 1;
}

bool CacheAssetDirectory(const char* name, std::vector<std::string>& names) {
    if (!name || g_cache_members.empty() ||
        !((!strncmp(name, "telltale/files", 14) && (!name[14] || name[14] == '/')) ||
          (!strncmp(name, "telltale/obb", 12) && (!name[12] || name[12] == '/')))) return false;
    names.clear();
    std::string prefix = std::string("assets/") + name;
    if (prefix.back() != '/') prefix.push_back('/');
    for (int i = 0; i < g_num_apk_entries; ++i) {
        const char* asset = g_apk_entries[i].name;
        if (strncmp(asset, prefix.c_str(), prefix.size())) continue;
        const char* leaf = asset + prefix.size();
        const bool declared = std::any_of(g_cache_members.begin(),g_cache_members.end(),
            [&](const CacheMember& member) { return !strcmp(asset,member.asset); });
        if (*leaf && !strchr(leaf, '/') && declared) names.emplace_back(leaf);
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return true;
}

struct PackagedDirEntry {
    std::string name;
    unsigned char type = DT_REG;
};

static std::vector<PackagedDirEntry> FindPackagedDirectoryEntries(const char* path) {
    std::vector<PackagedDirEntry> result;
    std::string prefix = PackagedFilesEntry(path);
    if (prefix.empty()) return result;
    if (prefix.back() != '/') prefix.push_back('/');

    for (int i = 0; i < g_num_apk_entries; ++i) {
        const char* name = g_apk_entries[i].name;
        if (strncmp(name, prefix.c_str(), prefix.size()) != 0) continue;
        const char* rest = name + prefix.size();
        if (!*rest) continue;
        const char* slash = strchr(rest, '/');
        const std::string child(rest, slash ? static_cast<size_t>(slash - rest) : strlen(rest));
        if (child.empty()) continue;
        const unsigned char type = slash ? DT_DIR : DT_REG;
        auto existing = std::find_if(result.begin(), result.end(), [&](const PackagedDirEntry& entry) {
            return entry.name == child;
        });
        if (existing == result.end()) result.push_back({child, type});
        else if (type == DT_DIR) existing->type = DT_DIR;
    }
    return result;
}

// A file region already laid into the guest arena. The mmap thunk consults this before
// making a new mapping: the arena is bump-allocated, so mapping the same 345 MB expansion
// file a second time is a second permanent hole. Engines do exactly that -- a "reinstall"
// or "reload paks" path closes every archive and reopens it.
struct GuestFileMapping {
    dev_t  dev;
    ino_t  ino;
    off_t  off;      // page-aligned file offset
    size_t span;     // page-aligned length
    uint32_t va;     // guest address
};
static std::vector<GuestFileMapping> g_guest_file_maps;
static std::mutex g_mapping_mutex;

struct VirtualFd {
    int real_apk_fd;
    size_t file_size;
    off_t file_offset; // offset within APK
    off_t current_pos; // 0 .. file_size
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    uint32_t trace_count = 0;
#endif
};
static std::unordered_map<int, VirtualFd> g_vfd_map;
static int g_next_vfd = 1000;
static std::mutex g_vfd_mutex;

static int OpenApkFd(const ApkEntry& entry) {
    const int real = ::dup(entry.apk_fd);
    if (real < 0) return -1;
    std::lock_guard lock(g_vfd_mutex);
    const int fd = g_next_vfd++;
    g_vfd_map[fd] = {real, static_cast<size_t>(entry.file_size), entry.data_offset, 0};
    CACHE_DIAG(cache_diag::RememberFd(fd, entry.external ? "EXTERNAL_VERIFIED_VFS" : "APK_VFS", entry.name, entry.owner, entry.data_offset, entry.file_size));
    return fd;
}

static int CloseGuestFd(int fd) {
    CACHE_DIAG(cache_diag::ForgetFd(fd));
    std::lock_guard lock(g_vfd_mutex);
    auto it = g_vfd_map.find(fd);
    if (it == g_vfd_map.end()) return ::close(fd);
    const int result = ::close(it->second.real_apk_fd);
    g_vfd_map.erase(it);
    return result;
}

struct ApkCookie { int fd; };

static int ApkRead(void* cookie, char* buffer, int size) {
    if (size <= 0) return 0;
    std::lock_guard lock(g_vfd_mutex);
    auto it = g_vfd_map.find(static_cast<ApkCookie*>(cookie)->fd);
    if (it == g_vfd_map.end()) { errno = EBADF; return -1; }
    auto& fd = it->second;
    if (fd.current_pos >= static_cast<off_t>(fd.file_size)) return 0;
    const size_t count = std::min(static_cast<size_t>(size), fd.file_size - fd.current_pos);
    const ssize_t result = ::pread(fd.real_apk_fd, buffer, count, fd.file_offset + fd.current_pos);
    if (result > 0) fd.current_pos += result;
    return static_cast<int>(result);
}

static fpos_t ApkSeek(void* cookie, fpos_t offset, int whence) {
    std::lock_guard lock(g_vfd_mutex);
    auto it = g_vfd_map.find(static_cast<ApkCookie*>(cookie)->fd);
    if (it == g_vfd_map.end()) { errno = EBADF; return -1; }
    auto& fd = it->second;
    off_t origin = 0, target;
    if (whence == SEEK_CUR) origin = fd.current_pos;
    else if (whence == SEEK_END) origin = fd.file_size;
    else if (whence != SEEK_SET) { errno = EINVAL; return -1; }
    if (__builtin_add_overflow(origin, offset, &target)) { errno = EOVERFLOW; return -1; }
    if (target < 0) { errno = EINVAL; return -1; }
    fd.current_pos = target; // Seek beyond EOF succeeds; the next read is empty.
    return target;
}

static int ApkClose(void* value) {
    auto* cookie = static_cast<ApkCookie*>(value);
    const int result = CloseGuestFd(cookie->fd);
    ::free(cookie);
    return result;
}

static FILE* ApkFdOpen(int fd) {
    auto* cookie = static_cast<ApkCookie*>(::malloc(sizeof(ApkCookie)));
    if (!cookie) { errno = ENOMEM; return nullptr; }
    cookie->fd = fd;
    FILE* stream = ::funopen(cookie, ApkRead, nullptr, ApkSeek, ApkClose);
    if (!stream) ::free(cookie); // Failed fdopen leaves the caller's descriptor open.
    return stream;
}

static FILE* OpenGuestStream(const char* path, const char* mode, int& fd) {
    fd = -1;
    const bool managed = CacheReadPath(path);
    if (managed && (mode[0] != 'r' || strchr(mode, '+'))) { errno = EROFS; return nullptr; }
    if (mode[0] == 'r' && !strchr(mode, '+')) {
        if (const ApkEntry* entry = FindApkEntry(path)) {
            fd = OpenApkFd(*entry);
            if (fd < 0) return nullptr;
            FILE* stream = ApkFdOpen(fd);
            if (!stream) { const int error = errno; CloseGuestFd(fd); errno = error; }
            return stream;
        }
    }
    if (managed) { errno = ENOENT; return nullptr; }
    FILE* stream = ::fopen(path, mode); // Saves/updates/writes remain real; never fall back to APK.
    CACHE_DIAG(if (stream) cache_diag::RememberFd(::fileno(stream), "DISK_PATH", path));
    return stream;
}

static int GuestRealFd(int fd) {
    std::lock_guard<std::mutex> lock(g_vfd_mutex);
    auto it = g_vfd_map.find(fd);
    return it != g_vfd_map.end() ? it->second.real_apk_fd : fd;
}

static bool IsPackagedFd(int fd) {
    std::lock_guard<std::mutex> lock(g_vfd_mutex);
    return g_vfd_map.find(fd) != g_vfd_map.end();
}

static void SetGuestErrno(DynarmicHost& host, int error) {
    errno = error;
    const uint32_t address = host.CurrentGuestErrnoAddress();
    host.MemoryWrite32(address ? address : 0x300, static_cast<uint32_t>(error));
}

static void FailPosix(Dynarmic::A32::Jit& jit, DynarmicHost& host, int error) {
    SetGuestErrno(host, error);
    jit.Regs()[0] = UINT32_MAX;
}

static void LogLibcPolicy(Dynarmic::A32::Jit& jit, const char* name, const char* contract) {
    static std::mutex mutex;
    static std::unordered_map<std::string, bool> logged;
    std::lock_guard<std::mutex> lock(mutex);
    const std::string key = std::string(name) + ':' + std::to_string(jit.Regs()[14]);
    if (logged.size() < 64 && logged.emplace(key, true).second)
        LOGI("[LIBC_POLICY] %s: %s LR=0x%08X args=%08X,%08X,%08X,%08X", name, contract,
             jit.Regs()[14], jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
}

static const char* CheckedGuestString(DynarmicHost& host, uint32_t address) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return nullptr;
    const char* text = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), address));
    return memchr(text, '\0', host.GetGuestMemorySize() - address) ? text : nullptr;
}

static const wchar_t* CheckedGuestWideString(DynarmicHost& host, uint32_t address) {
    static_assert(sizeof(wchar_t) == 4);
    if (address % alignof(wchar_t) || !GuestRangeValid(host.GetGuestMemorySize(), address, sizeof(wchar_t))) return nullptr;
    const auto* text = static_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), address));
    const size_t count = (host.GetGuestMemorySize() - address) / sizeof(wchar_t);
    return wmemchr(text, L'\0', count) ? text : nullptr;
}

// Guest address of the real archive-open function, resolved by
// InstallAssetOverrideHook and tail-called from the veneer.
static uint32_t g_asset_override_real_fn = 0;

// FILE and its guest descriptor share the existing virtual-FD cursor/lifetime.
static std::unordered_map<uint32_t, std::pair<FILE*, int>> g_file_map;
// ponytail: one registry lock covers handles and live FILE use; split only after measured stdio contention.
static std::mutex g_file_registry_mutex;
static uint32_t g_next_file_handle = 0x10001000;
static std::mutex g_resource_name_mutex;
static std::unordered_map<uint64_t, std::string> g_resource_names;
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
static std::atomic<uint32_t> g_path_trace_count{0};

static bool TracePathCall() {
    return g_path_trace_count.fetch_add(1, std::memory_order_relaxed) < 64;
}

#define PATH_DIAG_LOGI(...) do { if (TracePathCall()) LOGI(__VA_ARGS__); } while (false)
#else
#define PATH_DIAG_LOGI(...) ((void)0)
#endif

static std::string GuestStringValue(DynarmicHost& host, uint32_t object) {
    const uint32_t data = object ? host.MemoryRead32(object) : 0;
    const uint32_t length = data ? host.MemoryRead32(data - 12) : 0;
    if (!data || !length || length > 4096) return {};
    const char* text = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), data));
    return text ? std::string(text, length) : std::string{};
}

static uint32_t GuestStrtokNext(DynarmicHost& host, uint32_t input, uint32_t delimiters,
                                uint32_t* state) {
    char* cursor = input ? static_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), input))
                         : (state && *state ? static_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), *state)) : nullptr);
    const char* delim = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), delimiters));
    if (!cursor || !delim) return 0;
    while (*cursor && strchr(delim, static_cast<unsigned char>(*cursor))) ++cursor;
    if (!*cursor) {
        if (state) *state = 0;
        return 0;
    }
    char* token = cursor;
    while (*cursor && !strchr(delim, static_cast<unsigned char>(*cursor))) ++cursor;
    if (*cursor) *cursor++ = '\0';
    if (state) *state = cursor && *cursor ? HostToGuest(host.GetGuestMemoryBase(), cursor) : 0;
    return HostToGuest(host.GetGuestMemoryBase(), token);
}

static uint32_t CopyGuestText(DynarmicHost& host, const char* text);

static constexpr size_t kArm32TmSize = 44;
static constexpr size_t kArm32StatfsSize = 88;
static constexpr size_t kArm32PasswdSize = 24;
static constexpr size_t kArm32HostentSize = 20;
static constexpr size_t kArm32MbstateSize = 4;

static bool ReadArm32Time(DynarmicHost& host, uint32_t address, time_t& value) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, sizeof(int32_t))) return false;
    value = static_cast<time_t>(static_cast<int32_t>(host.MemoryRead32(address)));
    return true;
}

static bool ReadArm32Tm(DynarmicHost& host, uint32_t address, struct tm& value) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, kArm32TmSize)) return false;
    memset(&value, 0, sizeof(value));
    value.tm_sec = static_cast<int>(host.MemoryRead32(address + 0));
    value.tm_min = static_cast<int>(host.MemoryRead32(address + 4));
    value.tm_hour = static_cast<int>(host.MemoryRead32(address + 8));
    value.tm_mday = static_cast<int>(host.MemoryRead32(address + 12));
    value.tm_mon = static_cast<int>(host.MemoryRead32(address + 16));
    value.tm_year = static_cast<int>(host.MemoryRead32(address + 20));
    value.tm_wday = static_cast<int>(host.MemoryRead32(address + 24));
    value.tm_yday = static_cast<int>(host.MemoryRead32(address + 28));
    value.tm_isdst = static_cast<int>(host.MemoryRead32(address + 32));
#if defined(__BIONIC__) || defined(__ANDROID__)
    value.tm_gmtoff = static_cast<long>(static_cast<int32_t>(host.MemoryRead32(address + 36)));
    const uint32_t zone = host.MemoryRead32(address + 40);
    value.tm_zone = zone ? CheckedGuestString(host, zone) : nullptr;
    if (zone && !value.tm_zone) return false;
#endif
    return true;
}

static bool WriteArm32Tm(DynarmicHost& host, uint32_t address, const struct tm& value) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, kArm32TmSize)) return false;
    uint32_t zone = 0;
#if defined(__BIONIC__) || defined(__ANDROID__)
    // libc owns tm_zone: keep copies per host so guest addresses die with the arena.
    if (value.tm_zone) {
        std::lock_guard<std::mutex> lock(g_tm_zone_cache_mutex);
        auto& zones = g_tm_zone_cache[&host];
        auto& cached = zones[value.tm_zone];
        if (!cached) cached = CopyGuestText(host, value.tm_zone);
        if (!cached) return false;
        zone = cached;
    }
#endif
    const int fields[] = {value.tm_sec, value.tm_min, value.tm_hour, value.tm_mday, value.tm_mon,
                          value.tm_year, value.tm_wday, value.tm_yday, value.tm_isdst};
    for (size_t i = 0; i < std::size(fields); ++i) host.MemoryWrite32(address + static_cast<uint32_t>(i * 4), fields[i]);
#if defined(__BIONIC__) || defined(__ANDROID__)
    host.MemoryWrite32(address + 36, static_cast<uint32_t>(value.tm_gmtoff));
#else
    host.MemoryWrite32(address + 36, 0);
#endif
    host.MemoryWrite32(address + 40, zone);
    return true;
}

static bool WriteArm32Statfs(DynarmicHost& host, uint32_t output, const struct statfs& value) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), output, kArm32StatfsSize)) return false;
    memset(GuestToHost(host.GetGuestMemoryBase(), output), 0, kArm32StatfsSize);
    host.MemoryWrite32(output + 0, static_cast<uint32_t>(value.f_type));
    host.MemoryWrite32(output + 4, static_cast<uint32_t>(value.f_bsize));
    const uint64_t counts[] = {value.f_blocks, value.f_bfree, value.f_bavail, value.f_files, value.f_ffree};
    for (uint32_t i = 0; i < std::size(counts); ++i) host.MemoryWrite64(output + 8 + i * 8, counts[i]);
    host.MemoryWrite32(output + 48, value.f_fsid.__val[0]);
    host.MemoryWrite32(output + 52, value.f_fsid.__val[1]);
    host.MemoryWrite32(output + 56, static_cast<uint32_t>(value.f_namelen));
    host.MemoryWrite32(output + 60, static_cast<uint32_t>(value.f_frsize));
    host.MemoryWrite32(output + 64, static_cast<uint32_t>(value.f_flags));
    for (uint32_t i = 0; i < 4; ++i) host.MemoryWrite32(output + 68 + i * 4, static_cast<uint32_t>(value.f_spare[i]));
    return true;
}

static bool ReadArm32Mbstate(DynarmicHost& host, uint32_t address, mbstate_t& state) {
    static_assert(sizeof(state.__seq) == kArm32MbstateSize);
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, kArm32MbstateSize)) return false;
    memset(&state, 0, sizeof(state));
    memcpy(state.__seq, GuestToHost(host.GetGuestMemoryBase(), address), kArm32MbstateSize);
    return true;
}

static void WriteArm32Mbstate(DynarmicHost& host, uint32_t address, const mbstate_t& state) {
    memcpy(GuestToHost(host.GetGuestMemoryBase(), address), state.__seq, kArm32MbstateSize);
}

static uint32_t CopyGuestText(DynarmicHost& host, const char* text) {
    if (!text) return 0;
    const size_t size = strlen(text) + 1;
    const uint32_t address = host.GuestAlloc(size, 1);
    if (address) memcpy(GuestToHost(host.GetGuestMemoryBase(), address), text, size);
    return address;
}

static size_t Arm32PasswdBytes(const struct passwd& value) {
    size_t size = kArm32PasswdSize;
    for (const char* text : {value.pw_name, value.pw_passwd, value.pw_dir, value.pw_shell})
        if (text) size += strlen(text) + 1;
    return size;
}

static bool WriteArm32Passwd(DynarmicHost& host, uint32_t output, const struct passwd& value) {
    const size_t size = Arm32PasswdBytes(value);
    if (!GuestRangeValid(host.GetGuestMemorySize(), output, size)) return false;
    host.MemoryWrite32(output + 8, static_cast<uint32_t>(value.pw_uid));
    host.MemoryWrite32(output + 12, static_cast<uint32_t>(value.pw_gid));
    const char* strings[] = {value.pw_name, value.pw_passwd, value.pw_dir, value.pw_shell};
    const uint32_t offsets[] = {0, 4, 16, 20}; // ARM32 has no independent pw_gecos field.
    uint32_t cursor = output + kArm32PasswdSize;
    for (size_t i = 0; i < std::size(strings); ++i) {
        host.MemoryWrite32(output + offsets[i], strings[i] ? cursor : 0);
        if (strings[i]) {
            const size_t length = strlen(strings[i]) + 1;
            memcpy(GuestToHost(host.GetGuestMemoryBase(), cursor), strings[i], length);
            cursor += static_cast<uint32_t>(length);
        }
    }
    return true;
}

static uint32_t GuestCRC64(DynarmicHost& host, const std::string& text) {
    const ElfLoader* game_engine = host.FindModule("libGameEngine.so");
    if (!game_engine) return 0;
    const uint32_t base = game_engine->GetBaseAddress();
    const uint32_t byte_table = base + 0x1019E50;
    const uint32_t word_table = base + 0x1019F50;
    uint64_t crc = 0;
    for (unsigned char c : text) {
        const uint8_t mapped = host.MemoryRead8(byte_table + c);
        const uint32_t index = mapped ^ static_cast<uint32_t>(crc >> 56);
        crc = host.MemoryRead64(word_table + index * 8) ^ (crc << 8);
    }
    return crc;
}

static std::string GuestLuaTopError(DynarmicHost& host, uint32_t state) {
    if (!state) return {};
    const uint32_t top = host.MemoryRead32(state + 8);
    if (top < 8) return {};
    const uint32_t value = host.MemoryRead32(top - 8);
    const uint32_t type = host.MemoryRead32(top - 4) & 0xF;
    if (type != 4 || !value) return {};
    const uint32_t length = host.MemoryRead32(value + 12);
    if (!length || length > 4096) return {};
    const char* text = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), value + 16));
    return text ? std::string(text, length) : std::string{};
}

struct GuestDirectory {
    DIR* dir = nullptr;
    uint32_t entry = 0;
    std::vector<PackagedDirEntry> packaged_entries;
    std::vector<std::string> disk_names;
    std::string path;
    size_t packaged_index = 0;
    unsigned int packaged_dot_index = 2;
};
static std::mutex g_directory_mutex;
static std::unordered_map<uint32_t, GuestDirectory> g_directories;
static uint32_t g_next_directory_handle = 0x18001000;

static thread_local std::unordered_map<uint32_t, uint32_t> g_tls_map;
static std::atomic<uint32_t> g_next_tls_key{1};

struct GuestJumpState {
    std::array<uint32_t, 8> r4_r11{};
    uint32_t sp = 0;
    uint32_t lr = 0;
    uint32_t cpsr = 0;
    uint32_t thread = 0;
};
static std::mutex g_jump_mutex;
static std::unordered_map<uint32_t, GuestJumpState> g_jump_states;
static std::atomic<uint32_t> g_jump_trace_count{0};

#undef st_atime
#undef st_mtime
#undef st_ctime
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

// Android ARM32 uses the 64-bit stat ABI even though pointers and long are 32-bit.
// Game code reads st_mode at +16 and st_size at +48; the legacy 64-byte Linux
// layout silently classified every OBB/archive as non-regular and mounted nothing.
struct Arm32Stat {
    uint64_t st_dev;
    uint8_t pad0[4];
    uint32_t old_st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint8_t pad3[4];
    uint32_t pad4;
    int64_t st_size;
    uint32_t st_blksize;
    uint32_t pad5;
    uint64_t st_blocks;
    uint32_t st_atime;
    uint32_t st_atime_nsec;
    uint32_t st_mtime;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime;
    uint32_t st_ctime_nsec;
    uint64_t st_ino;
};
static_assert(sizeof(Arm32Stat) == 104);

static void WriteArm32Stat(uint8_t* guest_base, uint32_t gaddr, const struct stat& st) {
    if (!gaddr) return;
    Arm32Stat* arm_st = reinterpret_cast<Arm32Stat*>(GuestToHost(guest_base, gaddr));
    if (!arm_st) return;
    memset(arm_st, 0, sizeof(Arm32Stat));
    arm_st->st_dev = static_cast<uint64_t>(st.st_dev);
    arm_st->old_st_ino = static_cast<uint32_t>(st.st_ino);
    arm_st->st_mode = static_cast<uint32_t>(st.st_mode);
    arm_st->st_nlink = static_cast<uint32_t>(st.st_nlink);
    arm_st->st_uid = static_cast<uint32_t>(st.st_uid);
    arm_st->st_gid = static_cast<uint32_t>(st.st_gid);
    arm_st->st_rdev = static_cast<uint64_t>(st.st_rdev);
    arm_st->st_size = static_cast<int64_t>(st.st_size);
    arm_st->st_blksize = static_cast<uint32_t>(st.st_blksize);
    arm_st->st_blocks = static_cast<uint64_t>(st.st_blocks);
    arm_st->st_atime = static_cast<uint32_t>(st.st_atim.tv_sec);
    arm_st->st_atime_nsec = static_cast<uint32_t>(st.st_atim.tv_nsec);
    arm_st->st_mtime = static_cast<uint32_t>(st.st_mtim.tv_sec);
    arm_st->st_mtime_nsec = static_cast<uint32_t>(st.st_mtim.tv_nsec);
    arm_st->st_ctime = static_cast<uint32_t>(st.st_ctim.tv_sec);
    arm_st->st_ctime_nsec = static_cast<uint32_t>(st.st_ctim.tv_nsec);
    arm_st->st_ino = static_cast<uint64_t>(st.st_ino);
}

// Guest printf formatter. AAPCS32 variadic doubles/64-bit integers are aligned to
// an even core-register pair or an 8-byte stack slot; float arguments are promoted
// to double. Getting this wrong corrupts both diagnostics and paths built by sprintf.
static std::optional<std::string> FormatGuestString(Dynarmic::A32::Jit& jit, DynarmicHost& host,
        const char* fmt, int first_arg_reg, std::optional<uint32_t> guest_va = std::nullopt) {
    // ponytail: cap one formatted string at 1 MiB; raise only for a measured larger caller.
    constexpr size_t limit = 1u << 20;
    auto fail = [&](int error) -> std::optional<std::string> {
        LogLibcPolicy(jit, "printf-family", "format/argument rejected; no host va_list forwarded");
        SetGuestErrno(host, error);
        return std::nullopt;
    };
    if (!fmt) return fail(EFAULT);
    if (strnlen(fmt, 4097) > 4096) return fail(EOVERFLOW);
    std::string result;
    int reg = guest_va ? 4 : first_arg_reg, error = 0;
    uint64_t cursor = guest_va.value_or(jit.Regs()[13]);
    auto get32 = [&]() -> uint32_t {
        if (reg < 4) return jit.Regs()[reg++];
        if (cursor > UINT32_MAX || !GuestRangeValid(host.GetGuestMemorySize(), static_cast<uint32_t>(cursor), 4)) {
            error = EFAULT; return 0;
        }
        const uint32_t value = host.MemoryRead32(static_cast<uint32_t>(cursor));
        cursor += 4;
        return value;
    };
    auto get64 = [&]() -> uint64_t {
        if (reg < 4) reg = (reg + 1) & ~1;
        if (reg >= 4) cursor = (cursor + 7) & ~uint64_t{7};
        const uint64_t low = get32(), high = get32();
        return low | (high << 32);
    };
    const char* p = fmt;
    while (*p) {
        if (*p != '%') {
            result += *p++;
            if (result.size() > limit) return fail(EOVERFLOW);
            continue;
        }
        const char* begin = p++;
        if (*p == '%') {
            result += *p++;
            if (result.size() > limit) return fail(EOVERFLOW);
            continue;
        }
        while (*p && strchr("-+ #0'", *p)) ++p;
        int stars[2]{}, star_count = 0, precision = -1;
        auto number = [&]() {
            int value = 0;
            while (*p >= '0' && *p <= '9') {
                if (value > static_cast<int>(limit) / 10) { error = EOVERFLOW; return 0; }
                value = value * 10 + (*p++ - '0');
            }
            if (value > static_cast<int>(limit)) error = EOVERFLOW;
            return value;
        };
        auto star = [&](bool width) {
            const int value = static_cast<int32_t>(get32());
            if (static_cast<int64_t>(value) > static_cast<int64_t>(limit) ||
                (width && -static_cast<int64_t>(value) > static_cast<int64_t>(limit))) error = EOVERFLOW;
            stars[star_count++] = value;
            ++p;
            return value;
        };
        if (*p == '*') star(true); else number();
        if (*p == '.') { ++p; precision = *p == '*' ? star(false) : number(); }
        if (error) return fail(error);
        const char* modifier = p;
        std::string length;
        if (*p && strchr("hljztL", *p)) {
            length += *p++;
            if ((length == "h" || length == "l") && *p == length[0]) length += *p++;
        }
        const char spec = *p ? *p++ : 0;
        const bool wide_int = length == "ll" || length == "j";
        std::string field(begin, modifier);
        auto append = [&](auto value) {
            if (error) return;
            auto print = [&](char* output, size_t capacity) {
                if (star_count == 2) return std::snprintf(output, capacity, field.c_str(), stars[0], stars[1], value);
                if (star_count == 1) return std::snprintf(output, capacity, field.c_str(), stars[0], value);
                return std::snprintf(output, capacity, field.c_str(), value);
            };
            const int size = print(nullptr, 0);
            if (size < 0) { error = EINVAL; return; }
            if (static_cast<size_t>(size) > limit - result.size()) { error = EOVERFLOW; return; }
            const size_t old_size = result.size();
            result.resize(old_size + size);
            if (print(result.data() + old_size, static_cast<size_t>(size) + 1) != size) error = EINVAL;
        };
        if (spec && strchr("diuoxX", spec) && length != "L") {
            // long, size_t and ptrdiff_t are 32 bits in the guest; intmax_t is 64 bits.
            field += wide_int ? "ll" : ((length == "h" || length == "hh") ? length : "");
            field += spec;
            if (spec == 'd' || spec == 'i') {
                if (wide_int) append(static_cast<long long>(get64()));
                else append(static_cast<int32_t>(get32()));
            } else {
                if (wide_int) append(static_cast<unsigned long long>(get64()));
                else append(static_cast<unsigned int>(get32()));
            }
        } else if (spec && strchr("fFeEgGaA", spec) && (length.empty() || length == "l" || length == "L")) {
            // ARM32 Android long double is also binary64, not the host's binary128.
            field += spec;
            const uint64_t bits = get64();
            double value;
            memcpy(&value, &bits, 8);
            append(value);
        } else if (spec == 's' && length.empty()) {
            field += spec;
            const uint32_t address = get32();
            const char* value = "(null)";
            if (address && precision != 0) {
                if (!GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return fail(EFAULT);
                const size_t requested = precision >= 0 ? static_cast<size_t>(precision) : limit + 1;
                const size_t available = std::min(requested, host.GetGuestMemorySize() - address);
                value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
                if (!memchr(value, 0, available) && (precision < 0 || available < requested)) return fail(EOVERFLOW);
            } else if (precision == 0) value = "";
            append(value);
        } else if (spec == 'c' && length.empty()) {
            field += spec;
            append(static_cast<int>(get32()));
        } else if (spec == 'p' && length.empty()) {
            field += spec;
            append(reinterpret_cast<void*>(static_cast<uintptr_t>(get32())));
        } else if (spec == 'n' && length != "L") {
            const uint32_t address = get32();
            const size_t size = wide_int ? 8 : length == "hh" ? 1 : length == "h" ? 2 : 4;
            if (!GuestRangeValid(host.GetGuestMemorySize(), address, size)) return fail(EFAULT);
            const uint64_t count = result.size();
            if (!error) memcpy(host.GetGuestMemoryBase() + address, &count, size);
        } else return fail(ENOSYS); // Positional and wide-character formats are not silently misformatted.
        if (error) return fail(error);
    }
    return result;
}

static void StoreFormattedString(Dynarmic::A32::Jit& jit, DynarmicHost& host, uint32_t address,
                                 size_t capacity, const std::optional<std::string>& text) {
    if (!text) { jit.Regs()[0] = UINT32_MAX; return; }
    if (capacity) {
        auto* output = static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, capacity));
        if (!output) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return; }
        const size_t size = std::min(capacity - 1, text->size());
        memcpy(output, text->data(), size);
        output[size] = 0;
    }
    jit.Regs()[0] = static_cast<uint32_t>(text->size());
}

static bool LibcAbiSelfCheck(DynarmicHost& host) {
    const uint32_t scratch = host.GuestAlloc(256, 8);
    if (!scratch) { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "LibcAbiSelfCheck FAILED: allocation"); return false; }
    bool ok = true;
    auto check = [&](bool condition, const char* name) {
        if (!condition) { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "LibcAbiSelfCheck FAILED: %s", name); ok = false; }
    };
    const uint32_t output = scratch + 8;
    auto reset = [&]() { memset(GuestToHost(host.GetGuestMemoryBase(), scratch), 0xA5, 256); };
    auto guards = [&](size_t size) {
        return host.MemoryRead32(output - 4) == 0xA5A5A5A5u &&
               host.MemoryRead32(output + static_cast<uint32_t>(size)) == 0xA5A5A5A5u;
    };
    reset();
    host.MemoryWrite32(output, UINT32_MAX);
    time_t timestamp = 0;
    check(ReadArm32Time(host, output, timestamp) && timestamp == -1, "signed 32-bit time_t pointer");
    struct tm value{};
    value.tm_sec = 59; value.tm_mon = 8; value.tm_year = 126; value.tm_isdst = -1;
    value.tm_gmtoff = -3600; value.tm_zone = "UTC";
    reset();
    check(WriteArm32Tm(host, output, value), "tm write");
    struct tm roundtrip{};
    check(ReadArm32Tm(host, output, roundtrip) && roundtrip.tm_sec == 59 && roundtrip.tm_year == 126 &&
          roundtrip.tm_isdst == -1 && roundtrip.tm_gmtoff == -3600 && roundtrip.tm_zone &&
          strcmp(roundtrip.tm_zone, "UTC") == 0 && guards(kArm32TmSize), "44-byte tm roundtrip and bounds");
    struct statfs filesystem{};
    filesystem.f_blocks = 0x1122334455667788ULL;
    filesystem.f_fsid.__val[1] = 0x1234; filesystem.f_flags = 0x55;
    reset();
    check(WriteArm32Statfs(host, output, filesystem) &&
          host.MemoryRead64(output + 8) == filesystem.f_blocks && host.MemoryRead32(output + 52) == 0x1234 &&
          host.MemoryRead32(output + 64) == 0x55 && host.MemoryRead32(output + 84) == 0 &&
          guards(kArm32StatfsSize), "88-byte statfs fields, padding and bounds");
    struct passwd account{};
    account.pw_name = const_cast<char*>("player"); account.pw_uid = 10000; account.pw_gid = 10001;
    account.pw_dir = const_cast<char*>("/data"); account.pw_shell = const_cast<char*>("/bin/sh");
    reset();
    const size_t account_size = Arm32PasswdBytes(account);
    check(WriteArm32Passwd(host, output, account) && host.MemoryRead32(output) == output + kArm32PasswdSize &&
          host.MemoryRead32(output + 4) == 0 && host.MemoryRead32(output + 8) == 10000 &&
          host.MemoryRead32(output + 12) == 10001 && guards(account_size), "24-byte passwd and owned strings");
    reset();
    host.MemoryWrite32(output, 0x03020100);
    mbstate_t state{};
    check(ReadArm32Mbstate(host, output, state), "mbstate read");
    WriteArm32Mbstate(host, output + 8, state);
    check(host.MemoryRead32(output + 8) == 0x03020100 && host.MemoryRead32(output + 12) == 0xA5A5A5A5u,
          "4-byte mbstate copy does not overwrite its neighbor");
    const uint32_t near_end = static_cast<uint32_t>(host.GetGuestMemorySize() - 4);
    check(!WriteArm32Tm(host, near_end, value) && !WriteArm32Statfs(host, near_end, filesystem) &&
          !WriteArm32Passwd(host, near_end, account), "serializers reject arena overflow");
    host.GuestFree(scratch);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, LOG_TAG,
                       "LibcAbiSelfCheck %s", ok ? "OK" : "FAILED");
    return ok;
}

void ThunkManager::RegisterLibcThunks() {
    if (!LibcAbiSelfCheck(m_host)) return;
    uint8_t* mem = m_host.GetGuestMemoryBase();

    *reinterpret_cast<uint32_t*>(mem + 0x100) = 0xDEADBEEF;
    *reinterpret_cast<uint32_t*>(mem + 0x300) = 0;

    RegisterDataSymbol("__stack_chk_guard", 0x100);
    RegisterDataSymbol("__sF", 0x200);

    RegisterThunk("__errno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t address = host.CurrentGuestErrnoAddress();
        jit.Regs()[0] = address ? address : 0x300;
    });

    // -------------------------------------------------------------
    // Additional POSIX & Math Thunks for FMOD
    // -------------------------------------------------------------

    auto read_double_01 = [](const Dynarmic::A32::Jit& jit) -> double {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        return val;
    };
    auto write_double_01 = [](Dynarmic::A32::Jit& jit, double val) {
        uint64_t raw;
        memcpy(&raw, &val, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((raw >> 32) & 0xFFFFFFFF);
    };

    RegisterThunk("sin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sin(read_double_01(jit)));
    });
    RegisterThunk("cos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, cos(read_double_01(jit)));
    });
    RegisterThunk("tan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, tan(read_double_01(jit)));
    });
    RegisterThunk("acos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, acos(read_double_01(jit)));
    });
    RegisterThunk("asin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, asin(read_double_01(jit)));
    });
    RegisterThunk("atan2", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double y = read_double_01(jit);
        uint64_t raw_x = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double x;
        memcpy(&x, &raw_x, sizeof(double));
        write_double_01(jit, atan2(y, x));
    });
    RegisterThunk("exp", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, exp(read_double_01(jit)));
    });
    RegisterThunk("log", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log(read_double_01(jit)));
    });
    RegisterThunk("log10", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log10(read_double_01(jit)));
    });
    RegisterThunk("log10f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = log10f(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });
    RegisterThunk("pow", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, pow(x, y));
    });
    RegisterThunk("sqrt", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sqrt(read_double_01(jit)));
    });
    RegisterThunk("floor", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, floor(read_double_01(jit)));
    });
    RegisterThunk("ceil", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, ceil(read_double_01(jit)));
    });
    RegisterThunk("rint", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, rint(read_double_01(jit)));
    });
    RegisterThunk("lrintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(lrintf(val));
    });
    RegisterThunk("frexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        uint32_t exp_ptr = jit.Regs()[2];
        int exp_val = 0;
        double res = frexp(val, &exp_val);
        if (exp_ptr) host.MemoryWrite32(exp_ptr, static_cast<uint32_t>(exp_val));
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("ldexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        int exp_val = static_cast<int>(jit.Regs()[2]);
        double res = ldexp(val, exp_val);
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });

    // Memory & Strings
    RegisterThunk("memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        void* h_dst = GuestToHost(host.GetGuestMemoryBase(), dst);
        const void* h_src = GuestToHost(host.GetGuestMemoryBase(), src);
        if (h_dst && h_src && n > 0) memmove(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("memmem", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t haystack = jit.Regs()[0];
        uint32_t hlen = jit.Regs()[1];
        uint32_t needle = jit.Regs()[2];
        uint32_t nlen = jit.Regs()[3];
        const void* h_hay = GuestToHost(host.GetGuestMemoryBase(), haystack);
        const void* h_nee = GuestToHost(host.GetGuestMemoryBase(), needle);
        if (h_hay && h_nee && hlen >= nlen) {
            const void* found = memmem(h_hay, hlen, h_nee, nlen);
            if (found) {
                uint32_t offset = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - reinterpret_cast<const uint8_t*>(h_hay));
                jit.Regs()[0] = haystack + offset;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("strcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src) strcat(h_dst, h_src);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = jit.Regs()[0];
        const char* text = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), base));
        const char* found = text ? ::strchr(text, static_cast<int>(jit.Regs()[1])) : nullptr;
        jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - text) : 0;
    });
    RegisterThunk("strstr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t haystack = jit.Regs()[0];
        const char* first = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), haystack));
        const char* second = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* found = (first && second) ? ::strstr(first, second) : nullptr;
        jit.Regs()[0] = found ? haystack + static_cast<uint32_t>(found - first) : 0;
    });
    RegisterThunk("strpbrk", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = jit.Regs()[0];
        const char* text = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), base));
        const char* accept = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* found = (text && accept) ? ::strpbrk(text, accept) : nullptr;
        jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - text) : 0;
    });
    RegisterThunk("strncpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src && n > 0) strncpy(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strlcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const size_t size = jit.Regs()[2];
        const size_t length = src ? strlen(src) : 0;
        if (dst && size) {
            const size_t copy = std::min(length, size - 1);
            if (copy) memcpy(dst, src, copy);
            dst[copy] = 0;
        }
        jit.Regs()[0] = static_cast<uint32_t>(length);
    });
    RegisterThunk("strncasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s1 = jit.Regs()[0];
        uint32_t s2 = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        const char* h_s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s1));
        const char* h_s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s2));
        jit.Regs()[0] = (h_s1 && h_s2) ? static_cast<uint32_t>(strncasecmp(h_s1, h_s2, n)) : 0;
    });
    RegisterThunk("strtol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t nptr = jit.Regs()[0];
        uint32_t endptr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        const char* h_nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        if (!h_nptr) { jit.Regs()[0] = 0; return; }
        char* h_end = nullptr;
        long val = strtol(h_nptr, &h_end, base);
        if (endptr && h_end) {
            uint32_t offset = static_cast<uint32_t>(h_end - h_nptr);
            host.MemoryWrite32(endptr, nptr + offset);
        }
        jit.Regs()[0] = static_cast<uint32_t>(val);
    });
    RegisterThunk("strtod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t nptr = jit.Regs()[0];
        const uint32_t endptr = jit.Regs()[1];
        const char* text = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        char* end = nullptr;
        const double value = text ? ::strtod(text, &end) : 0.0;
        if (endptr) {
            host.MemoryWrite32(endptr, text && end ? nptr + static_cast<uint32_t>(end - text) : nptr);
        }
        uint64_t bits = 0;
        memcpy(&bits, &value, sizeof(bits));
        jit.Regs()[0] = static_cast<uint32_t>(bits);
        jit.Regs()[1] = static_cast<uint32_t>(bits >> 32);
    });
    RegisterThunk("wctype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wctype_t descriptor = name ? ::wctype(name) : 0;
        if (!descriptor) { jit.Regs()[0] = 0; return; }
        std::lock_guard<std::mutex> lock(g_wctype_mutex);
        for (const auto& [handle, existing] : g_wctype_handles) {
            if (existing == descriptor) { jit.Regs()[0] = handle; return; }
        }
        const uint32_t handle = g_next_wctype_handle++;
        g_wctype_handles[handle] = descriptor;
        jit.Regs()[0] = handle;
    });
    RegisterThunk("iswctype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lock(g_wctype_mutex);
        auto it = g_wctype_handles.find(jit.Regs()[1]);
        jit.Regs()[0] = it == g_wctype_handles.end() ? 0 : static_cast<uint32_t>(::iswctype(static_cast<wint_t>(jit.Regs()[0]), it->second));
    });
    RegisterThunk("towlower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = static_cast<uint32_t>(::towlower(jit.Regs()[0])); });
    RegisterThunk("towupper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = static_cast<uint32_t>(::towupper(jit.Regs()[0])); });
    RegisterThunk("wctob", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wint_t value = static_cast<wint_t>(jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(value <= 0xFF ? static_cast<unsigned char>(value) : EOF);
    });
    RegisterThunk("btowc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int value = static_cast<int>(jit.Regs()[0]);
        jit.Regs()[0] = value == EOF ? static_cast<uint32_t>(WEOF) : static_cast<uint32_t>(static_cast<unsigned char>(value));
    });
    RegisterThunk("puts", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s = jit.Regs()[0];
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s));
        if (str) LOGI("[puts] %s", str);
        jit.Regs()[0] = 1;
    });
    // provider-policy: vsnprintf enosys-branch scalar AAPCS formats supported; positional/wide formats rejected.
    RegisterThunk("vsnprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[2]), 4, jit.Regs()[3]);
        StoreFormattedString(jit, host, jit.Regs()[0], jit.Regs()[1], text);
    });

    // Time & Threading
    RegisterThunk("getenv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* value = name ? ::getenv(name) : nullptr;
        if (!value) { jit.Regs()[0] = 0; return; }
        if (!g_getenv_buffer) g_getenv_buffer = host.GuestAlloc(1024, 8);
        if (!g_getenv_buffer) { jit.Regs()[0] = 0; return; }
        strlcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + g_getenv_buffer), value, 1024);
        jit.Regs()[0] = g_getenv_buffer;
    });
    RegisterThunk("clock_gettime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const clockid_t clock_id = static_cast<clockid_t>(jit.Regs()[0]);
        const uint32_t guest_timespec = jit.Regs()[1];
        if (!GuestRangeValid(host.GetGuestMemorySize(), guest_timespec, 8)) {
            SetGuestErrno(host, EFAULT);
            jit.Regs()[0] = UINT32_MAX;
            return;
        }
        struct timespec value {};
        if (::clock_gettime(clock_id, &value) != 0) {
            SetGuestErrno(host, errno);
            jit.Regs()[0] = UINT32_MAX;
            return;
        }
        // The guest is ILP32: ARM32 timespec is two signed 32-bit longs even
        // though the AArch64 host uses two 64-bit longs.
        host.MemoryWrite32(guest_timespec, static_cast<uint32_t>(value.tv_sec));
        host.MemoryWrite32(guest_timespec + 4, static_cast<uint32_t>(value.tv_nsec));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("gettimeofday", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t tv_ptr = jit.Regs()[0];
        if (tv_ptr) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            host.MemoryWrite32(tv_ptr + 0, static_cast<uint32_t>(tv.tv_sec));
            host.MemoryWrite32(tv_ptr + 4, static_cast<uint32_t>(tv.tv_usec));
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("usleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(::usleep(jit.Regs()[0]));
    });
    RegisterThunk("nanosleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t request = jit.Regs()[0];
        const uint32_t remainder = jit.Regs()[1];
        if (!request) {
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }
        struct timespec req {
            static_cast<time_t>(static_cast<int32_t>(host.MemoryRead32(request))),
            static_cast<long>(static_cast<int32_t>(host.MemoryRead32(request + 4)))
        };
        struct timespec rem {};
        const int result = ::nanosleep(&req, remainder ? &rem : nullptr);
        if (remainder) {
            host.MemoryWrite32(remainder, static_cast<uint32_t>(rem.tv_sec));
            host.MemoryWrite32(remainder + 4, static_cast<uint32_t>(rem.tv_nsec));
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("sleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = ::sleep(jit.Regs()[0]);
    });
    RegisterThunk("lrand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(lrand48());
    });
    RegisterThunk("srand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        srand48(static_cast<long>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("utime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("chown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fcntl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // Semaphores & Pthread
    RegisterThunk("sem_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t pshared = jit.Regs()[1];
        const uint32_t value = jit.Regs()[2];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        if (pshared) { FailPosix(jit, host, ENOSYS); return; }
        if (value > SEM_VALUE_MAX) { FailPosix(jit, host, EINVAL); return; }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        {
            std::lock_guard<std::mutex> lock(sem->mutex);
            sem->count = value;
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        g_semaphores.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        std::unique_lock<std::mutex> lock(sem->mutex);
        sem->cv.wait(lock, [&] { return sem->count != 0; });
        --sem->count;
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_timedwait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t timeout_addr = jit.Regs()[1];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), timeout_addr, 8)) {
            FailPosix(jit, host, EFAULT); return;
        }
        const int32_t seconds = static_cast<int32_t>(host.MemoryRead32(timeout_addr));
        const int32_t nanoseconds = static_cast<int32_t>(host.MemoryRead32(timeout_addr + 4));
        if (seconds < 0 || nanoseconds < 0 || nanoseconds >= 1000000000) {
            FailPosix(jit, host, EINVAL); return;
        }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        const auto deadline = std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::seconds(seconds) + std::chrono::nanoseconds(nanoseconds)));
        std::unique_lock<std::mutex> lock(sem->mutex);
        if (sem->count == 0 && !sem->cv.wait_until(lock, deadline, [&] { return sem->count != 0; })) {
            FailPosix(jit, host, ETIMEDOUT); return;
        }
        --sem->count;
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_trywait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        std::lock_guard<std::mutex> lock(sem->mutex);
        if (!sem->count) { FailPosix(jit, host, EAGAIN); return; }
        --sem->count;
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        {
            std::lock_guard<std::mutex> lock(sem->mutex);
            if (sem->count == SEM_VALUE_MAX) { FailPosix(jit, host, EOVERFLOW); return; }
            ++sem->count;
        }
        sem->cv.notify_one();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_getvalue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t output = jit.Regs()[1];
        if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(uint32_t))) {
            FailPosix(jit, host, EINVAL); return;
        }
        if ((output & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), output, sizeof(uint32_t))) {
            FailPosix(jit, host, EFAULT); return;
        }
        auto sem = GetSyncObject(g_semaphores, addr);
        if (!sem) { FailPosix(jit, host, EINVAL); return; }
        std::lock_guard<std::mutex> lock(sem->mutex);
        host.MemoryWrite32(output, sem->count);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { FailPosix(jit, host, ENOSYS); });
    RegisterThunk("sem_unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { FailPosix(jit, host, ENOSYS); });
    RegisterThunk("sysconf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const long value = ::sysconf(static_cast<int>(jit.Regs()[0]));
        jit.Regs()[0] = static_cast<uint32_t>(value);
    });
    RegisterThunk("getauxval", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        switch (jit.Regs()[0]) {
            case 6:  jit.Regs()[0] = 4096; break;   // AT_PAGESZ
            case 16: jit.Regs()[0] = 0x1000; break; // AT_HWCAP: ARM HWCAP_NEON
            case 26: jit.Regs()[0] = 0; break;      // AT_HWCAP2
            default: jit.Regs()[0] = 0; break;
        }
    });
    RegisterThunk("gettid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(::syscall(SYS_gettid));
    });
    RegisterThunk("setpriority", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(::setpriority(static_cast<int>(jit.Regs()[0]), static_cast<id_t>(jit.Regs()[1]), static_cast<int>(jit.Regs()[2])));
    });
    RegisterThunk("pthread_setname_np", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = name ? static_cast<uint32_t>(::pthread_setname_np(pthread_self(), name)) : EINVAL;
    });
    RegisterThunk("syscall", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = static_cast<uint32_t>(-1);
    });

    RegisterThunk("pthread_self", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = g_current_guest_thread;
    });
    RegisterThunk("pthread_equal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = jit.Regs()[0] == jit.Regs()[1] ? 1 : 0;
    });

    RegisterThunk("setjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t env = jit.Regs()[0];
        if (!env) {
            jit.Regs()[0] = 0;
            return;
        }
        GuestJumpState state;
        for (size_t i = 0; i < state.r4_r11.size(); ++i) state.r4_r11[i] = jit.Regs()[4 + i];
        state.sp = jit.Regs()[13];
        state.lr = jit.Regs()[14];
        state.cpsr = jit.Cpsr();
        state.thread = g_current_guest_thread;
        {
            std::lock_guard<std::mutex> lock(g_jump_mutex);
            g_jump_states[env] = state;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("longjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t env = jit.Regs()[0];
        const uint32_t value = jit.Regs()[1] ? jit.Regs()[1] : 1;
        GuestJumpState state;
        {
            std::lock_guard<std::mutex> lock(g_jump_mutex);
            auto it = g_jump_states.find(env);
            if (it == g_jump_states.end() || it->second.thread != g_current_guest_thread) {
                LOGE("longjmp missing state env=0x%08X thread=%u", env, g_current_guest_thread);
                jit.Regs()[0] = value;
                return;
            }
            state = it->second;
        }
        const uint32_t trace = g_jump_trace_count.fetch_add(1, std::memory_order_relaxed);
        if (trace < 16) {
            const uint32_t lua_state = env >= 0x14 ? host.MemoryRead32(env - 0x14) : 0;
            const uint32_t top = lua_state ? host.MemoryRead32(lua_state + 8) : 0;
            const uint32_t value = top >= 8 ? host.MemoryRead32(top - 8) : 0;
            const uint32_t type = top >= 8 ? host.MemoryRead32(top - 4) : 0;
            const char* message = (value && (type & 0xF) == 4)
                ? reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), value + 16)) : nullptr;
            LOGI("longjmp #%u status=%u message='%s'", trace + 1, host.MemoryRead32(env + 256), message ? message : "");
            if (trace == 0) {
                static constexpr char needle[] = "rawset(_G, \"_currentDirectory\", \"";
                const uint8_t* begin = host.GetGuestMemoryBase() + 0x50000000;
                size_t remaining = 0x06000000;
                for (int i = 0; i < 4; ++i) {
                    const char* found = static_cast<const char*>(memmem(begin, remaining, needle, sizeof(needle) - 1));
                    if (!found) break;
                    const uint32_t address = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - host.GetGuestMemoryBase());
                    LOGI("currentDirectory source[%d] at 0x%08X len=%u cap=%u text='%s'", i, address,
                         host.MemoryRead32(address - 12), host.MemoryRead32(address - 8), found);
                    const size_t consumed = static_cast<size_t>(reinterpret_cast<const uint8_t*>(found) - begin) + 1;
                    begin += consumed;
                    remaining -= consumed;
                }
            }
        }
        for (size_t i = 0; i < state.r4_r11.size(); ++i) jit.Regs()[4 + i] = state.r4_r11[i];
        jit.Regs()[0] = value;
        jit.Regs()[13] = state.sp;
        jit.Regs()[14] = state.lr;
        jit.SetCpsr((state.cpsr & ~0x20u) | ((state.lr & 1) ? 0x20u : 0u));
        jit.Regs()[15] = state.lr & ~1u;
    });

    RegisterThunk("pthread_attr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setdetachstate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setstacksize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GetSyncObject(g_mutexes, jit.Regs()[0]) ? 0 : EINVAL;
    });
    RegisterThunk("pthread_mutex_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        g_mutexes.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_settype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t thread_out = jit.Regs()[0];
        const uint32_t start_func = jit.Regs()[2];
        const uint32_t arg = jit.Regs()[3];
        if (!thread_out || !start_func) { jit.Regs()[0] = EINVAL; return; }

        const uint32_t handle = g_next_guest_thread.fetch_add(1);
        auto state = std::make_shared<GuestThreadState>();
        {
            std::lock_guard<std::mutex> lock(g_guest_threads_mutex);
            g_guest_threads.emplace(handle, state);
        }
        host.MemoryWrite32(thread_out, handle);
        AddGuestThreadWorker(start_func, arg);
        state->thread = std::thread([state, handle, start_func, arg, &host]() {
            g_current_guest_thread = handle;
            LOGI("guest thread %u enter 0x%08X", handle, start_func);
            state->result = host.RunFunction(start_func, {arg});
            state->done.store(true, std::memory_order_release);
            LOGI("guest thread %u returned 0x%08X", handle, state->result);
        });
        const uint32_t callback = arg ? host.MemoryRead32(arg + 2084) : 0;
        const uint32_t callback_arg = arg ? host.MemoryRead32(arg + 2088) : 0;
        LOGI("pthread_create: handle=%u func=0x%08X arg=0x%08X callback=0x%08X callbackArg=0x%08X",
             handle, start_func, arg, callback, callback_arg);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_join", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        const uint32_t result_out = jit.Regs()[1];
        std::shared_ptr<GuestThreadState> state;
        {
            std::lock_guard<std::mutex> lock(g_guest_threads_mutex);
            auto it = g_guest_threads.find(handle);
            if (it == g_guest_threads.end()) { jit.Regs()[0] = ESRCH; return; }
            state = it->second;
        }
        if (state->thread.joinable()) state->thread.join();
        if (result_out) host.MemoryWrite32(result_out, state->result);
        {
            std::lock_guard<std::mutex> lock(g_guest_threads_mutex);
            g_guest_threads.erase(handle);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_detach", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        std::shared_ptr<GuestThreadState> state;
        {
            std::lock_guard<std::mutex> lock(g_guest_threads_mutex);
            auto it = g_guest_threads.find(handle);
            if (it == g_guest_threads.end()) { jit.Regs()[0] = ESRCH; return; }
            state = it->second;
            g_guest_threads.erase(it);
        }
        if (state->thread.joinable()) state->thread.detach();
        jit.Regs()[0] = 0;
    });

    // Sockets & Net (Stubs)
    RegisterThunk("socket", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("bind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("listen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("accept", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("connect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("send", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("recv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("select", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("setsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("inet_addr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    // provider-policy: gethostbyname offline DNS is disabled for the offline game.
    RegisterThunk("gethostbyname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "gethostbyname", "offline DNS: null result");
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = 0;
    });
    // provider-policy: gethostbyname_r offline DNS returns no guest or host-owned result.
    RegisterThunk("gethostbyname_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "gethostbyname_r", "offline DNS: ENOSYS, NO_RECOVERY, null result");
        const uint32_t sp = jit.Regs()[13];
        if (!GuestRangeValid(host.GetGuestMemorySize(), sp, 8)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = EFAULT; return;
        }
        const uint32_t result = host.MemoryRead32(sp);
        const uint32_t error = host.MemoryRead32(sp + 4);
        if (!GuestRangeValid(host.GetGuestMemorySize(), result, 4) ||
            !GuestRangeValid(host.GetGuestMemorySize(), error, 4)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = EFAULT; return;
        }
        host.MemoryWrite32(result, 0);
        host.MemoryWrite32(error, NO_RECOVERY);
        if (!CheckedGuestString(host, jit.Regs()[0]) ||
            !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], kArm32HostentSize) ||
            !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2], jit.Regs()[3])) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = EFAULT; return;
        }
        memset(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]), 0, kArm32HostentSize);
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = ENOSYS;
    });

    // Android & Runtime
    RegisterThunk("__android_log_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        uint32_t tag_ptr = jit.Regs()[1];
        uint32_t msg_ptr = jit.Regs()[2];
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), tag_ptr));
        const char* msg = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), msg_ptr));
        if (tag && msg) __android_log_write(prio, tag, msg);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__aeabi_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_pure_virtual", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("__cxa_pure_virtual called!");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("__cxa_type_match", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_begin_cleanup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_call_unexpected", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_Unwind_Find_exidx", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t name_ptr = jit.Regs()[0];
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), name_ptr));
        LOGI("dlopen('%s', %d)", name ? name : "NULL", jit.Regs()[1]);
        jit.Regs()[0] = 0x50005000; // Non-null handle
    });
    RegisterThunk("dlclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlsym", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sym_ptr = jit.Regs()[1];
        const char* sym = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), sym_ptr));
        LOGI("dlsym(handle, '%s')", sym ? sym : "NULL");
        if (sym) {
            if (strncmp(sym, "SL_IID_", 7) == 0) {
                uint32_t iid_ptr = GetOpenSLESInterfacePointer(sym);
                if (iid_ptr != 0) {
                    jit.Regs()[0] = iid_ptr;
                    return;
                }
            }
            if (strcmp(sym, "slCreateEngine") == 0) {
                jit.Regs()[0] = host.GetThunkManager().GetOrCreateThunkAddress("slCreateEngine");
                return;
            }
            auto it = host.GetThunkManager().GetThunkSymbolTable().find(sym);
            if (it != host.GetThunkManager().GetThunkSymbolTable().end()) {
                jit.Regs()[0] = it->second;
                return;
            }
            if (uint32_t addr = host.FindSymbol(sym)) { jit.Regs()[0] = addr; return; }
            uint32_t addr = host.GetThunkManager().GetOrCreateThunkAddress(sym);
            jit.Regs()[0] = addr;
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("__system_property_get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t val_ptr = jit.Regs()[1];
        LOGI("__system_property_get('%s')", name ? name : "null");
        if (name && val_ptr) {
            char* out = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), val_ptr));
            if (strcmp(name, "ro.build.version.sdk") == 0) {
                strcpy(out, "28");
                jit.Regs()[0] = 2;
                return;
            }
            strcpy(out, "");
        }
        jit.Regs()[0] = 0;
    });

    // C++ Memory Allocation operators
    RegisterThunk("_Znaj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_Znwj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnajRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnwjRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZdaPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZdlPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZNSt8ios_base4InitC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_ZNSt8ios_base4InitD1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // Memory Allocation inside guest space
    RegisterThunk("malloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("calloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t num = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        uint32_t addr = host.GuestAlloc(num * size, 8);
        if (addr) {
            memset(GuestToHost(host.GetGuestMemoryBase(), addr), 0, num * size);
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("realloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t old_addr = jit.Regs()[0];
        const size_t new_size = jit.Regs()[1];
        if (!old_addr) {
            jit.Regs()[0] = host.GuestAlloc(new_size, 8);
            return;
        }
        if (!new_size) {
            host.GuestFree(old_addr);
            jit.Regs()[0] = 0;
            return;
        }

        const uint32_t old_size = host.GuestAllocSize(old_addr);
        const uint32_t new_addr = host.GuestAlloc(new_size, 8);
        if (!new_addr) {
            jit.Regs()[0] = 0;
            return;
        }
        if (old_size) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), new_addr),
                   GuestToHost(host.GetGuestMemoryBase(), old_addr), std::min<size_t>(old_size, new_size));
            host.GuestFree(old_addr);
        }
        jit.Regs()[0] = new_addr;
    });

    RegisterThunk("free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("memalign", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t alignment = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        jit.Regs()[0] = host.GuestAlloc(size, alignment);
    });

    // Logging & Formatted output
    RegisterThunk("__android_log_print", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = CheckedGuestString(host, jit.Regs()[1]);
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[2]), 3);
        jit.Regs()[0] = text ? static_cast<uint32_t>(__android_log_print(prio, tag ? tag : "Arm32Bridge_Guest", "[GUEST] %s", text->c_str())) : UINT32_MAX;
    });

    RegisterThunk("printf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[0]), 1);
        if (text) LOGI("[printf] %s", text->c_str());
        jit.Regs()[0] = text ? static_cast<uint32_t>(text->size()) : UINT32_MAX;
    });

    RegisterThunk("fprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[1]), 2);
        if (text) LOGI("[fprintf] %s", text->c_str());
        jit.Regs()[0] = text ? static_cast<uint32_t>(text->size()) : UINT32_MAX;
    });

    RegisterThunk("sprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[1]), 2);
        StoreFormattedString(jit, host, jit.Regs()[0], text ? text->size() + 1 : 0, text);
    });

    RegisterThunk("snprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[2]), 3);
        StoreFormattedString(jit, host, jit.Regs()[0], jit.Regs()[1], text);
    });

    // provider-policy: sscanf enosys-branch measured meminfo/URL scansets supported; other formats rejected.
    RegisterThunk("sscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* text = CheckedGuestString(host, jit.Regs()[0]);
        const char* format = CheckedGuestString(host, jit.Regs()[1]);
        if (!text || !format) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return; }
        const bool meminfo = !strcmp(format, "MemTotal:%[ \t]%d kB") || !strcmp(format, "MemFree:%[ \t]%d kB");
        const bool two_strings = !strcmp(format, "%15[^:]:%[^\n]") || !strcmp(format, "%[^\n/?]%[^\n]");
        const bool three_strings = !strcmp(format, "%15[^\n:]://%[^\n/?]%[^\n]");
        const bool ipv6_probe = !strcmp(format, "[%*45[0123456789abcdefABCDEF:.]%c");
        if (!meminfo && !two_strings && !three_strings && !ipv6_probe) {
            LogLibcPolicy(jit, "sscanf", "ENOSYS/EOF for unsupported format; no variadic pointers forwarded");
            SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX; return;
        }
        const size_t length = strnlen(text, 4097);
        if (length > 4096) { SetGuestErrno(host, EOVERFLOW); jit.Regs()[0] = UINT32_MAX; return; }
        std::vector<char> first(length + 1), second(length + 1), third(length + 1);
        int value = 0;
        // These exact signatures use only local typed outputs; scansets cannot exceed the input length.
        const int count = meminfo ? std::sscanf(text, format, first.data(), &value)
            : three_strings ? std::sscanf(text, format, first.data(), second.data(), third.data())
            : ipv6_probe ? std::sscanf(text, format, first.data())
                         : std::sscanf(text, format, first.data(), second.data());
        uint32_t destinations[] = {jit.Regs()[2], jit.Regs()[3], 0};
        if (count >= 3) {
            if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[13], 4)) {
                SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
            }
            destinations[2] = host.MemoryRead32(jit.Regs()[13]);
        }
        const void* outputs[] = {first.data(), meminfo ? static_cast<const void*>(&value) : second.data(), third.data()};
        const size_t sizes[] = {ipv6_probe ? 1 : strlen(first.data()) + 1, meminfo ? sizeof(value) : strlen(second.data()) + 1, strlen(third.data()) + 1};
        for (int i = 0; i < count; ++i) {
            if (!GuestRangeValid(host.GetGuestMemorySize(), destinations[i], sizes[i])) {
                SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
            }
        }
        for (int i = 0; i < count; ++i) memcpy(host.GetGuestMemoryBase() + destinations[i], outputs[i], sizes[i]);
        jit.Regs()[0] = static_cast<uint32_t>(count);
    });
    // provider-policy: vfprintf enosys guest va_list cannot be passed to host stdio.
    RegisterThunk("vfprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "vfprintf", "ENOSYS; no guest va_list or FILE pointer forwarded");
        SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX;
    });
    RegisterThunk("vasprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("putc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });
    RegisterThunk("fputc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });

    // fputs(const char *s, FILE *stream). Lesson 2.16: on Android fd 1 and 2 go nowhere, and
    // that is exactly where a C++ runtime writes the reason it is giving up. A stream the
    // guest really opened is written for real; anything else goes to the log instead of being
    // swallowed. In Angry Birds Go this was the last default stub still firing on a cold
    // start, and the first run with a real thunk printed what had been thrown away for
    // weeks: "io::IOException".
    RegisterThunk("fputs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!s) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        auto it = g_file_map.find(jit.Regs()[1]);
        if (it != g_file_map.end()) {
            jit.Regs()[0] = static_cast<uint32_t>(fputs(s, it->second.first));
            return;
        }
        LOGI("[guest fputs] %s", s);
        jit.Regs()[0] = static_cast<uint32_t>(strlen(s));
    });

    // Math functions
    RegisterThunk("sinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sinf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("cosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = cosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("tanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = tanf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("sqrtf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sqrtf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("floorf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = floorf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("frexpf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        int exponent = 0;
        float res = frexpf(val, &exponent);
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(exponent));
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("atanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = atanf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("acosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = acosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("powf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float base = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float exp = *reinterpret_cast<float*>(&jit.Regs()[1]);
        float res = powf(base, exp);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    auto register_float_unary = [this](const char* name, float (*fn)(float)) {
        RegisterThunk(name, [fn](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            const float value = ReadSF(jit, 0);
            WriteSF(jit, 0, fn(value));
        });
    };
    auto register_float_binary = [this](const char* name, float (*fn)(float, float)) {
        RegisterThunk(name, [fn](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            WriteSF(jit, 0, fn(ReadSF(jit, 0), ReadSF(jit, 1)));
        });
    };
    register_float_unary("logf", logf);
    register_float_unary("asinf", asinf);
    register_float_unary("coshf", coshf);
    register_float_unary("expf", expf);
    register_float_unary("sinhf", sinhf);
    register_float_unary("tanhf", tanhf);
    register_float_unary("ceilf", ceilf);
    register_float_binary("atan2f", atan2f);
    register_float_binary("fmodf", fmodf);
    RegisterThunk("ldexpf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        WriteSF(jit, 0, ldexpf(ReadSF(jit, 0), static_cast<int>(jit.Regs()[1])));
    });
    RegisterThunk("modff", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float integer = 0.0f;
        const float fraction = modff(ReadSF(jit, 0), &integer);
        if (jit.Regs()[1]) {
            uint32_t raw = 0;
            memcpy(&raw, &integer, sizeof(raw));
            host.MemoryWrite32(jit.Regs()[1], raw);
        }
        WriteSF(jit, 0, fraction);
    });
    RegisterThunk("__isinf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = std::isinf(ReadDF(jit, 0)) ? 1u : 0u;
    });
    RegisterThunk("atan", [=](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        write_double_01(jit, atan(read_double_01(jit)));
    });
    RegisterThunk("fmod", [=](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint64_t raw = static_cast<uint64_t>(jit.Regs()[3]) << 32 | jit.Regs()[2];
        double divisor = 0.0;
        memcpy(&divisor, &raw, sizeof(divisor));
        write_double_01(jit, fmod(read_double_01(jit), divisor));
    });
    RegisterThunk("scalbn", [=](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        write_double_01(jit, scalbn(read_double_01(jit), static_cast<int>(jit.Regs()[2])));
    });

    // String & Memory functions
    RegisterThunk("strcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcmp(s1, s2) : 0;
    });

    RegisterThunk("strncmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? strncmp(s1, s2, n) : 0;
    });

    RegisterThunk("strcasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcasecmp(s1, s2) : 0;
    });

    RegisterThunk("strlen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(strlen(s)) : 0;
    });

    RegisterThunk("strcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) strcpy(dest, src);
    });

    RegisterThunk("strdup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!src) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(src) + 1;
        uint32_t dest_addr = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest_addr), src, len);
        jit.Regs()[0] = dest_addr;
    });

    RegisterThunk("strrchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strrchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    // strerror hands back storage the caller does not own and never frees, so a
    // fresh block per call is a block per failed open - and a guest that probes
    // for files that are not there does that constantly. One block per errno.
    RegisterThunk("strerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::mutex m;
        static std::unordered_map<int, uint32_t> cache;
        int err_no = static_cast<int>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(m);
        auto it = cache.find(err_no);
        if (it == cache.end()) {
            const char* err = strerror(err_no);
            size_t len = strlen(err) + 1;
            uint32_t dest = host.GuestAlloc(len);
            if (dest) memcpy(GuestToHost(host.GetGuestMemoryBase(), dest), err, len);
            it = cache.emplace(err_no, dest).first;
        }
        jit.Regs()[0] = it->second;
    });

    RegisterThunk("strtoul", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = nptr ? static_cast<uint32_t>(strtoul(nptr, nullptr, base)) : 0;
    });

    RegisterThunk("strtoull", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        char* end = nullptr;
        const unsigned long long value = nptr ? strtoull(nptr, &end, static_cast<int>(jit.Regs()[2])) : 0;
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], end ? HostToGuest(host.GetGuestMemoryBase(), end) : 0);
        jit.Regs()[0] = static_cast<uint32_t>(value);
        jit.Regs()[1] = static_cast<uint32_t>(value >> 32);
    });

    RegisterThunk("strspn", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* text = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* accept = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = text && accept ? static_cast<uint32_t>(strspn(text, accept)) : 0;
    });
    RegisterThunk("strtoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* text = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        char* end = nullptr;
        const long long value = text ? strtoll(text, &end, static_cast<int>(jit.Regs()[2])) : 0;
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], end ? HostToGuest(host.GetGuestMemoryBase(), end) : 0);
        jit.Regs()[0] = static_cast<uint32_t>(value);
        jit.Regs()[1] = static_cast<uint32_t>(static_cast<unsigned long long>(value) >> 32);
    });
    RegisterThunk("strtok", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t state = 0;
        jit.Regs()[0] = GuestStrtokNext(host, jit.Regs()[0], jit.Regs()[1], &state);
    });
    RegisterThunk("strtok_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t saveptr = jit.Regs()[2];
        if (!saveptr || !GuestRangeValid(host.GetGuestMemorySize(), saveptr, sizeof(uint32_t))) {
            jit.Regs()[0] = 0;
            return;
        }
        uint32_t state = host.MemoryRead32(saveptr);
        jit.Regs()[0] = GuestStrtokNext(host, jit.Regs()[0], jit.Regs()[1], &state);
        host.MemoryWrite32(saveptr, state);
    });
    RegisterThunk("strlcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = static_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const size_t size = jit.Regs()[2];
        if (!dest || !src) { jit.Regs()[0] = 0; return; }
        const size_t dest_len = strnlen(dest, size);
        const size_t src_len = strlen(src);
        if (dest_len < size) {
            const size_t copy = std::min(src_len, size - dest_len - 1);
            memcpy(dest + dest_len, src, copy);
            dest[dest_len + copy] = '\0';
        }
        jit.Regs()[0] = static_cast<uint32_t>(dest_len + src_len);
    });
    RegisterThunk("strxfrm", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = jit.Regs()[2] ? static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], jit.Regs()[2])) : nullptr;
        const char* src = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = dest && src ? static_cast<uint32_t>(strxfrm(dest, src, jit.Regs()[2])) : 0;
    });
    RegisterThunk("strcoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* left = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* right = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = left && right ? static_cast<uint32_t>(strcoll(left, right)) : 0;
    });
    RegisterThunk("strerror_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* buffer = static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]));
        if (!buffer || !jit.Regs()[2]) { jit.Regs()[0] = EINVAL; return; }
        const char* result = strerror_r(static_cast<int>(jit.Regs()[0]), buffer, jit.Regs()[2]);
        if (result && result != buffer) {
            strncpy(buffer, result, jit.Regs()[2] - 1);
            buffer[jit.Regs()[2] - 1] = '\0';
        }
        jit.Regs()[0] = result ? 0u : static_cast<uint32_t>(errno);
    });

    RegisterThunk("atoi", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = str ? atoi(str) : 0;
    });

    RegisterThunk("islower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = islower(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("isxdigit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = isxdigit(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("memset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (s) memset(s, c, n);
    });

    RegisterThunk("memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* dest = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (dest && src) memcpy(dest, src, n);
    });

    RegisterThunk("memcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s1 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s2 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? memcmp(s1, s2, n) : 0;
    });

    RegisterThunk("memchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        void* res = s ? const_cast<void*>(memchr(s, c, n)) : nullptr;
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });

    // Install before guest threads start; executable bytes live until host teardown.
    static_assert(kGuestQsortEntryOffset % 4 == 0 && kGuestQsortEntryOffset < sizeof(kGuestQsortCode));
    const uint32_t qsort_code = m_host.GuestAlloc(sizeof(kGuestQsortCode), 4);
    if (!qsort_code) { LOGE("qsort helper allocation failed; provider not registered"); return; }
    memcpy(mem + qsort_code, kGuestQsortCode, sizeof(kGuestQsortCode));
    m_host.InvalidateGuestCode(qsort_code, sizeof(kGuestQsortCode));
    m_host.AddExecutableRange(qsort_code, sizeof(kGuestQsortCode));
    const uint32_t qsort_entry = qsort_code + kGuestQsortEntryOffset;
    RegisterThunk("qsort", [qsort_entry](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = jit.Regs()[0], count = jit.Regs()[1], size = jit.Regs()[2];
        if (count < 2) return;
        const uint32_t comparator = jit.Regs()[3], code = comparator & ~1u;
        const uint64_t bytes = static_cast<uint64_t>(count) * size;
        if (!size || bytes > UINT32_MAX || !GuestRangeValid(host.GetGuestMemorySize(), base, bytes) ||
            !host.IsExecutableAddress(code) || (!(comparator & 1) && (code & 3)) ||
            !GuestRangeValid(host.GetGuestMemorySize(), code, (comparator & 1) ? 2 : 4) ||
            (jit.Regs()[13] & 7)) {
            LOGE("qsort rejected base=0x%08X count=%u size=%u comparator=0x%08X SP=0x%08X; input unchanged",
                 base, count, size, comparator, jit.Regs()[13]);
            SetGuestErrno(host, EINVAL);
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
            return;
        }
        // Same-JIT tail call: helper BLX invokes guest comparators; original LR returns to the caller.
        jit.Regs()[15] = qsort_entry;
        jit.SetCpsr(jit.Cpsr() & ~(0x20u | 0x0600FC00u)); // ARM state, no stale Thumb IT bits.
    });

    // ARM AEABI Helpers
    RegisterThunk("__aeabi_idiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_uidiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_idivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uidivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uldivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t num = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        uint64_t den = static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            uint64_t q = num / den;
            uint64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__gnu_ldivmod_helper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t num = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        int64_t den = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            int64_t q = num / den;
            int64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__aeabi_f2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        int64_t i = static_cast<int64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(i & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(i >> 32);
    });

    RegisterThunk("__aeabi_f2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        uint64_t u = static_cast<uint64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    RegisterThunk("__aeabi_l2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(i);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_ul2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t u = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(u);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_l2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        double d = static_cast<double>(i);
        uint64_t u = *reinterpret_cast<uint64_t*>(&d);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    // AEABI memory functions
    auto aeabi_memclr_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), 0, n);
        }
    };
    RegisterThunk("__aeabi_memclr", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr4", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr8", aeabi_memclr_handler);

    auto aeabi_memset_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), c, n);
        }
    };
    RegisterThunk("__aeabi_memset", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset4", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset8", aeabi_memset_handler);

    auto aeabi_memcpy_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), dest),
                   GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memcpy", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy4", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy8", aeabi_memcpy_handler);

    auto aeabi_memmove_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memmove", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove4", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove8", aeabi_memmove_handler);

    RegisterThunk("sigaction", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_sigmask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__google_potentially_blocking_region_begin", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__google_potentially_blocking_region_end", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Pthreads
    RegisterThunk("pthread_mutex_lock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto mutex = GetSyncObject(g_mutexes, jit.Regs()[0]);
        if (!mutex) { jit.Regs()[0] = EINVAL; return; }
        mutex->value.lock();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_trylock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto mutex = GetSyncObject(g_mutexes, jit.Regs()[0]);
        if (!mutex) { jit.Regs()[0] = EINVAL; return; }
        jit.Regs()[0] = mutex->value.try_lock() ? 0 : EBUSY;
    });
    RegisterThunk("pthread_mutex_unlock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto mutex = GetSyncObject(g_mutexes, jit.Regs()[0]);
        if (!mutex) { jit.Regs()[0] = EINVAL; return; }
        mutex->value.unlock();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GetSyncObject(g_conds, jit.Regs()[0]) ? 0 : EINVAL;
    });
    RegisterThunk("pthread_cond_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        g_conds.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto cond = GetSyncObject(g_conds, jit.Regs()[0]);
        auto mutex = GetSyncObject(g_mutexes, jit.Regs()[1]);
        if (!cond || !mutex) { jit.Regs()[0] = EINVAL; return; }
        std::unique_lock<std::recursive_mutex> lock(mutex->value, std::adopt_lock);
        cond->value.wait(lock);
        lock.release();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_timedwait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto cond = GetSyncObject(g_conds, jit.Regs()[0]);
        auto mutex = GetSyncObject(g_mutexes, jit.Regs()[1]);
        const uint32_t ts = jit.Regs()[2];
        if (!cond || !mutex) { jit.Regs()[0] = EINVAL; return; }
        if (!ts) {
            std::unique_lock<std::recursive_mutex> lock(mutex->value, std::adopt_lock);
            cond->value.wait(lock);
            lock.release();
            jit.Regs()[0] = 0;
            return;
        }
        if ((ts & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), ts, 8)) {
            jit.Regs()[0] = EINVAL; return;
        }
        const int32_t seconds = static_cast<int32_t>(host.MemoryRead32(ts));
        const int32_t nanoseconds = static_cast<int32_t>(host.MemoryRead32(ts + 4));
        if (nanoseconds < 0 || nanoseconds >= 1000000000) {
            jit.Regs()[0] = EINVAL; return;
        }
        if (seconds < 0) { jit.Regs()[0] = ETIMEDOUT; return; }
        const auto duration = std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::seconds(seconds) + std::chrono::nanoseconds(nanoseconds));
        const auto deadline = std::chrono::system_clock::time_point(duration);
        std::unique_lock<std::recursive_mutex> lock(mutex->value, std::adopt_lock);
        const auto status = cond->value.wait_until(lock, deadline);
        lock.release();
        jit.Regs()[0] = status == std::cv_status::timeout ? ETIMEDOUT : 0;
    });
    RegisterThunk("pthread_cond_signal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto cond = GetSyncObject(g_conds, jit.Regs()[0]);
        if (!cond) { jit.Regs()[0] = EINVAL; return; }
        cond->value.notify_one();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_broadcast", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto cond = GetSyncObject(g_conds, jit.Regs()[0]);
        if (!cond) { jit.Regs()[0] = EINVAL; return; }
        cond->value.notify_all();
        jit.Regs()[0] = 0;
    });

    const uint32_t once_complete = RegisterThunk("__bridge_pthread_once_complete", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t control = jit.Regs()[0];
        {
            std::lock_guard lock(g_once_mutex);
            if ((control & 3) || !GuestRangeValid(host.GetGuestMemorySize(), control, 4) ||
                host.MemoryRead32(control) != 1) {
                __android_log_assert(nullptr, LOG_TAG, "pthread_once invalid completion control=0x%08X", control);
            }
            host.MemoryWrite32(control, 2); // Bionic: initialization complete only after the callback returns.
        }
        g_once_cv.notify_all();
        jit.Regs()[0] = 0;
    });
    const uint32_t once_code[] = {
        0xE92D4010, 0xE1A04000, 0xE12FFF31, 0xE1A00004, // push r4,lr; preserve control; BLX initializer; restore control
        m_host.MemoryRead32(once_complete), 0xE8BD4010, 0xE12FFF1E // completion SVC; pop r4,lr; BX original caller
    };
    const uint32_t once_entry = m_host.GuestAlloc(sizeof(once_code), 4);
    if (!once_entry) { LOGE("pthread_once helper allocation failed; provider not registered"); return; }
    memcpy(mem + once_entry, once_code, sizeof(once_code));
    m_host.InvalidateGuestCode(once_entry, sizeof(once_code));
    m_host.AddExecutableRange(once_entry, sizeof(once_code));
    RegisterThunk("pthread_once", [once_entry](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t control = jit.Regs()[0], init = jit.Regs()[1], code = init & ~1u;
        if ((control & 3) || !GuestRangeValid(host.GetGuestMemorySize(), control, 4)) {
            jit.Regs()[0] = EINVAL; return;
        }
        std::unique_lock lock(g_once_mutex);
        g_once_cv.wait(lock, [&] { return host.MemoryRead32(control) != 1; });
        const uint32_t state = host.MemoryRead32(control);
        if (state == 2) { jit.Regs()[0] = 0; return; }
        if (state != 0 || !init || (! (init & 1) && (code & 3)) ||
            !GuestRangeValid(host.GetGuestMemorySize(), code, (init & 1) ? 2 : 4) ||
            !host.IsExecutableAddress(code) || (jit.Regs()[13] & 7)) {
            jit.Regs()[0] = EINVAL; return;
        }
        host.MemoryWrite32(control, 1);
        jit.Regs()[15] = once_entry;
        jit.SetCpsr(jit.Cpsr() & ~(0x20u | 0x0600FC00u)); // ARM veneer, no stale Thumb IT bits.
        // The lock is released before the JIT invokes the initializer, including nested once calls.
    });

    RegisterThunk("pthread_key_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key_ptr = jit.Regs()[0];
        if (key_ptr) host.MemoryWrite32(key_ptr, g_next_tls_key.fetch_add(1));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_key_delete", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        g_tls_map.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_setspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        uint32_t val = jit.Regs()[1];
        g_tls_map[key] = val;
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_getspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        auto it = g_tls_map.find(key);
        jit.Regs()[0] = (it != g_tls_map.end()) ? it->second : 0;
    });

    RegisterThunk("fopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        const char* mode = CheckedGuestString(host, jit.Regs()[1]);
        if (!path || !mode) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = 0; return; }
        int fd;
        FILE* stream = OpenGuestStream(path, mode, fd);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) {
            LOGI("fopen write path='%s' mode='%s' success=%d errno=%d", path, mode,
                 stream != nullptr, stream ? 0 : errno);
        }
#endif
        if (!stream) { SetGuestErrno(host, errno); jit.Regs()[0] = 0; return; }
        const uint32_t handle = g_next_file_handle++;
        g_file_map[handle] = {stream, fd};
        CACHE_DIAG(cache_diag::RememberFile(handle, fd >= 0 ? fd : ::fileno(stream)));
        jit.Regs()[0] = handle;
        PATH_DIAG_LOGI("fopen path='%s' mode='%s' source=%s handle=0x%08X", path,
                       mode, fd >= 0 ? "apk" : "disk", handle);
    });

    RegisterThunk("fdopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const int fd = static_cast<int>(jit.Regs()[0]);
        const char* mode = CheckedGuestString(host, jit.Regs()[1]);
        if (!mode) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = 0; return; }
        const bool packaged = IsPackagedFd(fd);
        if (packaged && (mode[0] != 'r' || strchr(mode, '+'))) {
            SetGuestErrno(host, EINVAL); jit.Regs()[0] = 0; return;
        }
        FILE* stream = packaged ? ApkFdOpen(fd) : ::fdopen(fd, mode);
        if (!stream) { SetGuestErrno(host, errno); jit.Regs()[0] = 0; return; }
        const uint32_t handle = g_next_file_handle++;
        g_file_map[handle] = {stream, packaged ? fd : -1};
        CACHE_DIAG(cache_diag::RememberFile(handle, fd));
        jit.Regs()[0] = handle;
    });

    RegisterThunk("fclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) {
            const int result = ::fclose(it->second.first);
            CACHE_DIAG(cache_diag::ForgetFile(handle));
            g_file_map.erase(it);
            if (result < 0) SetGuestErrno(host, errno);
            jit.Regs()[0] = result;
        } else {
            jit.Regs()[0] = -1;
        }
    });

    RegisterThunk("fgets", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        char* buffer = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const int size = static_cast<int>(jit.Regs()[1]);
        auto it = g_file_map.find(jit.Regs()[2]);
        const uint32_t handle = jit.Regs()[2];
        const bool delivered = buffer && size > 0 && it != g_file_map.end() && fgets(buffer, size, it->second.first);
        CACHE_DIAG(if (delivered && size > 1) cache_diag::FileDelivered(handle, "fgets_at_least", 1));
        jit.Regs()[0] = delivered ? jit.Regs()[0] : 0;
    });
    RegisterThunk("fread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        size_t res = (it != g_file_map.end() && ptr) ? fread(ptr, size, count, it->second.first) : 0;
        CACHE_DIAG(cache_diag::FileDelivered(handle, "fread", static_cast<int64_t>(res * size)));
        jit.Regs()[0] = res;
    });

    RegisterThunk("fwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end() && ptr) ? fwrite(ptr, size, count, it->second.first) : 0;
    });

    RegisterThunk("fseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        long offset = static_cast<long>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseek(it->second.first, offset, whence) : -1;
        CACHE_DIAG(if (!res) cache_diag::Pushback(handle, false));
        jit.Regs()[0] = res;
    });

    RegisterThunk("fseeko", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseeko(it->second.first, offset, whence) : -1;
        CACHE_DIAG(if (!res) cache_diag::Pushback(handle, false));
        jit.Regs()[0] = res;
    });

    RegisterThunk("ftell", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? static_cast<uint32_t>(ftell(it->second.first)) : 0;
    });

    RegisterThunk("ftello", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        off_t res = (it != g_file_map.end()) ? ftello(it->second.first) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("fileno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const auto it = g_file_map.find(jit.Regs()[0]);
        if (it == g_file_map.end()) { SetGuestErrno(host, EBADF); jit.Regs()[0] = UINT32_MAX; return; }
        jit.Regs()[0] = static_cast<uint32_t>(it->second.second >= 0
            ? it->second.second : ::fileno(it->second.first));
    });

    RegisterThunk("clearerr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) clearerr(it->second.first);
    });

    RegisterThunk("ferror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? ferror(it->second.first) : 0;
    });

    RegisterThunk("open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int flags = static_cast<int>(jit.Regs()[1]);
        int mode = static_cast<int>(jit.Regs()[2]);

        int fd = -1;
        const bool managed = CacheReadPath(path);
        if (managed && (flags & (O_CREAT | O_TRUNC | O_APPEND | O_WRONLY | O_RDWR))) {
            FailPosix(jit, host, EROFS); return;
        }
        if (path && (flags & O_CREAT) == 0 && (flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && entry->apk_fd >= 0) {
                const int vfd = OpenApkFd(*entry);
                if (vfd < 0) { SetGuestErrno(host, errno); jit.Regs()[0] = UINT32_MAX; return; }
                jit.Regs()[0] = static_cast<uint32_t>(vfd);
                return;
            }
        }

        if (managed) { FailPosix(jit, host, ENOENT); return; }
        fd = open(path ? path : "", flags, mode);
        CACHE_DIAG(cache_diag::RememberFd(fd, "DISK_PATH", path));
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        if (flags & (O_CREAT | O_WRONLY | O_RDWR)) {
            LOGI("open write path='%s' flags=0x%X fd=%d errno=%d", path ? path : "(null)", flags,
                 fd, fd >= 0 ? 0 : errno);
        }
#endif
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(fd) : static_cast<uint32_t>(-1);
        PATH_DIAG_LOGI("open path='%s' flags=0x%X fd=%d", path ? path : "(null)", flags, fd);
    });

    RegisterThunk("close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int result = CloseGuestFd(static_cast<int>(jit.Regs()[0]));
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        const auto origin = cache_diag::Fd(fd);
#endif
        if (!buf) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                if (vfd.current_pos >= static_cast<off_t>(vfd.file_size)) {
                    jit.Regs()[0] = 0; // EOF
                    return;
                }
                size_t avail = vfd.file_size - vfd.current_pos;
                size_t to_read = (count < avail) ? count : avail;
                const off_t read_offset = vfd.current_pos;
                ssize_t nread = pread(vfd.real_apk_fd, buf, to_read, vfd.file_offset + read_offset);
                if (nread > 0) {
                    vfd.current_pos += nread;
                }
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
                const uint32_t trace = vfd.trace_count++;
                if (trace < 8) {
                    LOGI("read vfd=%d off=%lld count=%zu n=%zd first=0x%02X", fd,
                         static_cast<long long>(read_offset), to_read, nread,
                         nread > 0 ? static_cast<unsigned int>(static_cast<unsigned char*>(buf)[0]) : 0);
                }
#endif
                CACHE_DIAG(cache_diag::FdDelivered(fd, origin, "read", nread, read_offset));
                jit.Regs()[0] = (nread >= 0) ? static_cast<uint32_t>(nread) : static_cast<uint32_t>(-1);
                return;
            }
        }

        ssize_t res = (fd >= 0) ? read(fd, buf, count) : -1;
        CACHE_DIAG(cache_diag::FdDelivered(fd, origin, "read", res));
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("pread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        const auto origin = cache_diag::Fd(fd);
#endif
        const size_t count = jit.Regs()[2];
        void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], count);
        const off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[3]));
        if (!buffer || offset < 0) {
            SetGuestErrno(host, buffer ? EINVAL : EFAULT);
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                if (offset >= static_cast<off_t>(vfd.file_size)) {
                    jit.Regs()[0] = 0; // Reads beyond EOF, not only exactly at EOF, are empty.
                    return;
                }
                const size_t available = vfd.file_size - static_cast<size_t>(offset);
                const size_t to_read = std::min(count, available);
                const ssize_t result = ::pread(vfd.real_apk_fd, buffer, to_read, vfd.file_offset + offset);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
                const uint32_t trace = vfd.trace_count++;
                if (trace < 8) {
                    LOGI("pread vfd=%d off=%lld count=%zu n=%zd first=0x%02X", fd,
                         static_cast<long long>(offset), to_read, result,
                         result > 0 ? static_cast<unsigned int>(static_cast<unsigned char*>(buffer)[0]) : 0);
                }
#endif
                CACHE_DIAG(cache_diag::FdDelivered(fd, origin, "pread", result, offset));
                jit.Regs()[0] = static_cast<uint32_t>(result);
                return;
            }
        }

        const ssize_t result = fd >= 0 ? ::pread(fd, buffer, count, offset) : -1;
        CACHE_DIAG(cache_diag::FdDelivered(fd, origin, "pread", result, offset));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        if (IsPackagedFd(fd)) { SetGuestErrno(host, EBADF); jit.Regs()[0] = UINT32_MAX; return; }
        ssize_t res = (buf && fd >= 0) ? write(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                off_t new_pos = vfd.current_pos;
                if (whence == SEEK_SET) new_pos = offset;
                else if (whence == SEEK_CUR) new_pos += offset;
                else if (whence == SEEK_END) new_pos = static_cast<off_t>(vfd.file_size) + offset;
                else { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

                if (new_pos < 0 || new_pos > INT32_MAX) {
                    SetGuestErrno(host, new_pos < 0 ? EINVAL : EOVERFLOW);
                    jit.Regs()[0] = static_cast<uint32_t>(-1); return;
                }
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos);
                return;
            }
        }

        off_t res = (fd >= 0) ? lseek(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const int64_t offset = static_cast<int64_t>(static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32));
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[13], 4)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; jit.Regs()[1] = UINT32_MAX; return;
        }
        int whence = static_cast<int>(host.MemoryRead32(jit.Regs()[13]));

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                int64_t origin = 0;
                if (whence == SEEK_CUR) origin = vfd.current_pos;
                else if (whence == SEEK_END) origin = static_cast<int64_t>(vfd.file_size);
                else if (whence != SEEK_SET) {
                    SetGuestErrno(host, EINVAL); jit.Regs()[0] = UINT32_MAX; jit.Regs()[1] = UINT32_MAX; return;
                }
                if (offset > INT64_MAX - origin || offset < -origin) {
                    SetGuestErrno(host, offset < -origin ? EINVAL : EOVERFLOW);
                    jit.Regs()[0] = UINT32_MAX; jit.Regs()[1] = UINT32_MAX; return;
                }
                const int64_t new_pos = origin + offset;
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos & 0xFFFFFFFF);
                jit.Regs()[1] = static_cast<uint32_t>(new_pos >> 32);
                return;
            }
        }

        off64_t res = (fd >= 0) ? lseek64(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(res >> 32);
    });

    RegisterThunk("mkdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const int result = path ? ::mkdir(path, static_cast<mode_t>(jit.Regs()[1])) : -1;
        VFS_DIAG_LOGI("mkdir path='%s' result=%d errno=%d", path ? path : "(null)", result,
                      result == 0 ? 0 : errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("opendir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        DIR* dir = path ? ::opendir(path) : nullptr;
        std::vector<PackagedDirEntry> packaged = FindPackagedDirectoryEntries(path);
        if (!dir && packaged.empty()) {
            jit.Regs()[0] = 0;
            PATH_DIAG_LOGI("opendir miss path='%s'", path ? path : "(null)");
            return;
        }
        const uint32_t entry = host.GuestAlloc(sizeof(struct dirent), 8);
        if (!entry) {
            if (dir) ::closedir(dir);
            jit.Regs()[0] = 0;
            return;
        }
        GuestDirectory guest;
        guest.dir = dir;
        guest.entry = entry;
        guest.path = path ? path : "";
        guest.packaged_entries = std::move(packaged);
        guest.packaged_dot_index = dir ? 2 : 0;
        std::lock_guard<std::mutex> lock(g_directory_mutex);
        const uint32_t handle = g_next_directory_handle++;
        g_directories.emplace(handle, std::move(guest));
        jit.Regs()[0] = handle;
        PATH_DIAG_LOGI("opendir path='%s' handle=0x%08X packaged=%zu", path ? path : "(null)", handle,
                       g_directories[handle].packaged_entries.size());
    });

    RegisterThunk("readdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lock(g_directory_mutex);
        auto it = g_directories.find(jit.Regs()[0]);
        if (it == g_directories.end()) {
            jit.Regs()[0] = 0;
            return;
        }
        GuestDirectory& directory = it->second;
        if (directory.dir) {
            while (struct dirent* entry = ::readdir(directory.dir)) {
                if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..") &&
                    CacheReadPath((directory.path + "/" + entry->d_name).c_str())) continue;
                if (std::any_of(directory.packaged_entries.begin(), directory.packaged_entries.end(),
                    [&](const auto& packaged) { return packaged.name == entry->d_name; })) continue;
                if (entry->d_name[0] != '.' || (entry->d_name[1] != '\0' &&
                                                !(entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
                    directory.disk_names.emplace_back(entry->d_name);
                }
                memcpy(GuestToHost(host.GetGuestMemoryBase(), directory.entry), entry, sizeof(*entry));
                jit.Regs()[0] = directory.entry;
                PATH_DIAG_LOGI("readdir handle=0x%08X name='%s' type=%u", jit.Regs()[0],
                               entry->d_name, entry->d_type);
                return;
            }
        }
        if (directory.packaged_dot_index < 2) {
            struct dirent* entry = reinterpret_cast<struct dirent*>(GuestToHost(host.GetGuestMemoryBase(), directory.entry));
            memset(entry, 0, sizeof(*entry));
            entry->d_type = DT_DIR;
            snprintf(entry->d_name, sizeof(entry->d_name), "%s", directory.packaged_dot_index++ == 0 ? "." : "..");
            jit.Regs()[0] = directory.entry;
            return;
        }
        while (directory.packaged_index < directory.packaged_entries.size()) {
            const PackagedDirEntry& packaged = directory.packaged_entries[directory.packaged_index++];
            if (std::find(directory.disk_names.begin(), directory.disk_names.end(), packaged.name) != directory.disk_names.end()) continue;
            struct dirent* entry = reinterpret_cast<struct dirent*>(GuestToHost(host.GetGuestMemoryBase(), directory.entry));
            memset(entry, 0, sizeof(*entry));
            entry->d_type = packaged.type;
            snprintf(entry->d_name, sizeof(entry->d_name), "%s", packaged.name.c_str());
            jit.Regs()[0] = directory.entry;
            PATH_DIAG_LOGI("readdir packaged handle=0x%08X name='%s' type=%u", jit.Regs()[0],
                           entry->d_name, entry->d_type);
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("closedir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestDirectory directory;
        {
            std::lock_guard<std::mutex> lock(g_directory_mutex);
            auto it = g_directories.find(jit.Regs()[0]);
            if (it == g_directories.end()) {
                jit.Regs()[0] = static_cast<uint32_t>(-1);
                return;
            }
            directory = it->second;
            g_directories.erase(it);
        }
        const int result = directory.dir ? ::closedir(directory.dir) : 0;
        host.GuestFree(directory.entry);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("access", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        const int mode = static_cast<int>(jit.Regs()[1]);
        if (!path) { FailPosix(jit, host, EFAULT); return; }
        const bool managed = CacheReadPath(path);
        const int result = (mode == F_OK || mode == R_OK) && FindApkEntry(path)
            ? 0 : managed ? (errno = EACCES, -1) : ::access(path, mode); // Write/execute checks are checks of real disk access.
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("stat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        const uint32_t output = jit.Regs()[1];
        if (!path || !GuestRangeValid(host.GetGuestMemorySize(), output, sizeof(Arm32Stat))) {
            FailPosix(jit, host, EFAULT); return;
        }
        struct stat value{};
        const ApkEntry* entry = FindApkEntry(path);
        int result = 0;
        if (entry) {
            value.st_size = entry->file_size;
            value.st_mode = S_IFREG | 0444;
            value.st_nlink = 1;
        } else if (CacheReadPath(path)) { errno = ENOENT; result = -1; }
        else result = ::stat(path, &value);
        if (result == 0) WriteArm32Stat(host.GetGuestMemoryBase(), output, value);
        else SetGuestErrno(host, errno);
        PATH_DIAG_LOGI("stat path='%s' result=%d source=%s size=%lld", path, result,
                       entry ? "apk" : "disk", result == 0 ? static_cast<long long>(value.st_size) : -1LL);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("feof", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? feof(it->second.first) : 1;
    });

    RegisterThunk("fflush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const uint32_t handle = jit.Regs()[0];
        if (!handle) { jit.Regs()[0] = ::fflush(nullptr); return; }
        const auto it = g_file_map.find(handle);
        if (it == g_file_map.end()) { FailPosix(jit, host, EBADF); return; }
        FILE* stream = it->second.first;
        int result;
        if (it->second.second >= 0) {
            // Bionic fflush rejects read-only funopen; synchronize without disabling buffering.
            ::flockfile(stream);
            const off_t position = ::ftello(stream);
            result = position < 0 ? EOF : ::fpurge(stream);
            if (result == 0) {
                std::lock_guard lock(g_vfd_mutex);
                auto fd = g_vfd_map.find(it->second.second);
                if (fd == g_vfd_map.end()) { errno = EBADF; result = EOF; }
                else fd->second.current_pos = position;
            }
            ::funlockfile(stream);
        } else result = ::fflush(stream);
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("setvbuf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // mmap/munmap. Do NOT stub these as "hand out a fresh heap block": a caller that checks
    // the returned address (Boehm does, see lesson 2.15) will abort, and an engine that maps
    // its archive gets 345 MB of zeroes -- which reads as "the pak has no entries", not as an
    // error, and parks the boot on a download screen.
    //
    // The guest arena is one anonymous MAP_PRIVATE reservation, so a file mapping can be laid
    // straight into it with MAP_FIXED and the guest reads it at base + vaddr like any other
    // memory: no copy, no RSS. MAP_PRIVATE, never MAP_SHARED, so a stray guest write cannot
    // reach the file on disk.
    RegisterThunk("mmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t len   = jit.Regs()[1];
        const uint32_t flags = jit.Regs()[3];
        const uint32_t sp    = jit.Regs()[13];         // AAPCS: args 5 and 6 are on the stack
        if (!GuestRangeValid(host.GetGuestMemorySize(), sp, 8)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        int            fd    = static_cast<int>(host.MemoryRead32(sp));
        off_t          off   = static_cast<off_t>(static_cast<int32_t>(host.MemoryRead32(sp + 4)));

#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        const int source_fd = fd;
        const off_t source_offset = off;
        const auto origin = cache_diag::Fd(fd);
#endif
        constexpr uint32_t kMapAnonymous = 0x20;       // Linux MAP_ANONYMOUS on arm
        constexpr uint32_t kMapFailed    = 0xFFFFFFFF;
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));

        if (len == 0 || off < 0) { SetGuestErrno(host, EINVAL); jit.Regs()[0] = kMapFailed; return; }

        if (flags & kMapAnonymous) {
            // Anonymous: fresh mapping space, which the arena zero-fills for us.
            const uint32_t va = host.GuestAllocMapping((len + page - 1) & ~(page - 1), page);
            jit.Regs()[0] = va ? va : kMapFailed;
            return;
        }

        // A virtual fd is an entry inside the APK: map the real APK descriptor at the entry's
        // offset instead. This is what lets an expansion file ship inside the APK -- the
        // engine fopen()s the external path, the APK fallback answers, and the mmap that
        // follows lands on the same bytes without anything being unpacked.
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                if (static_cast<uint64_t>(off) > it->second.file_size ||
                    len > it->second.file_size - static_cast<size_t>(off)) {
                    SetGuestErrno(host, EINVAL); jit.Regs()[0] = kMapFailed; return;
                }
                off += it->second.file_offset;
                fd = it->second.real_apk_fd;
            }
        }
        if (fd < 0) { SetGuestErrno(host, EBADF); jit.Regs()[0] = kMapFailed; return; }

        // mmap needs a page-aligned file offset; keep the remainder as a bias on the result.
        const off_t  aligned = off & ~static_cast<off_t>(page - 1);
        const size_t bias    = static_cast<size_t>(off - aligned);
        const size_t span    = (len + bias + page - 1) & ~(page - 1);

        struct stat fst{};
        if (fstat(fd, &fst) == 0) {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (m.dev == fst.st_dev && m.ino == fst.st_ino && m.off == aligned && m.span == span) {
                    CACHE_DIAG(cache_diag::FdDelivered(source_fd, origin, "mmap", len, source_offset, true));
                    jit.Regs()[0] = m.va + static_cast<uint32_t>(bias);
                    return;
                }
            }
        }

        const uint32_t va = host.GuestAllocMapping(span, page);
        if (!va) { LOGE("mmap: no guest arena for %zu bytes", span); jit.Regs()[0] = kMapFailed; return; }
        if (static_cast<uint64_t>(va) + span > host.GetGuestMemorySize()) {
            LOGE("mmap: 0x%08X + %zu would run past the guest arena", va, span);
            jit.Regs()[0] = kMapFailed;
            return;
        }
        void* want = host.GetGuestMemoryBase() + va;
        void* got = ::mmap(want, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, aligned);
        if (got == MAP_FAILED) {
            LOGE("mmap(fd=%d, len=%u, off=%lld) failed: %s", fd, len,
                 static_cast<long long>(off), strerror(errno));
            jit.Regs()[0] = kMapFailed;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            g_guest_file_maps.push_back({fst.st_dev, fst.st_ino, aligned, span, va});
        }
        VFS_DIAG_LOGI("mmap: fd=%d len=%u off=%lld -> guest 0x%08X", fd, len,
                      static_cast<long long>(off), va + static_cast<uint32_t>(bias));
        CACHE_DIAG(cache_diag::FdDelivered(source_fd, origin, "mmap", len, source_offset, true));
        jit.Regs()[0] = va + static_cast<uint32_t>(bias);
    });

    // provider-policy: mremap enosys the guest arena/cache cannot be moved by host mremap.
    RegisterThunk("mremap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // ponytail: no remapping semantics; add tracked guest mapping resize only if invoked.
        LogLibcPolicy(jit, "mremap", "ENOSYS/MAP_FAILED; mappings left unchanged");
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = UINT32_MAX;
    });

    RegisterThunk("munmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t len  = jit.Regs()[1];
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        if (!addr || !len) { jit.Regs()[0] = 0; return; }

        const uint32_t base_va = addr & ~static_cast<uint32_t>(page - 1);
        const size_t span = (static_cast<uint64_t>(len) + (addr - base_va) + page - 1) & ~(page - 1);

        // A cached file mapping stays: another filesystem may still be reading through it,
        // and the arena address is never reused anyway.
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (base_va >= m.va && base_va < m.va + m.span) { jit.Regs()[0] = 0; return; }
            }
        }
        // MAP_FIXED writes to *host* address space, and both the address and the length come
        // straight from the guest -- an out-of-range pair would unmap whatever the host keeps
        // after the arena, and that surfaces half a second later as a SIGSEGV in an unrelated
        // free(). Bounds-check before touching anything.
        if (static_cast<uint64_t>(base_va) + span > host.GetGuestMemorySize()) {
            LOGE("munmap(0x%08X, %u) out of arena, ignored", addr, len);
            jit.Regs()[0] = 0;
            return;
        }
        // Put anonymous pages back rather than leaving a hole: the arena has to stay one
        // continuous mapping or the next access through base + vaddr faults.
        ::mmap(host.GetGuestMemoryBase() + base_va, span, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("fstat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = -1;
        if (!GuestRangeValid(host.GetGuestMemorySize(), buf_gaddr, sizeof(Arm32Stat))) {
            FailPosix(jit, host, EFAULT); return;
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                memset(&st, 0, sizeof(st));
                st.st_size = it->second.file_size;
                st.st_mode = S_IFREG | 0444;
                st.st_nlink = 1;
                res = 0;
            }
        }

        if (res != 0) {
            res = fstat(fd, &st);
        }

        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("remove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (CacheReadPath(path)) { FailPosix(jit, host, EROFS); return; }
        const int result = remove(path ? path : "");
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("rename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* oldp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* newp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (CacheReadPath(oldp) || CacheReadPath(newp)) { FailPosix(jit, host, EROFS); return; }
        const int result = rename(oldp ? oldp : "", newp ? newp : "");
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    RegisterThunk("chmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("umask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("mkstemp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = -1; });
    RegisterThunk("getpid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getpid(); });

    RegisterThunk("time", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t output = jit.Regs()[0];
        if (output && !GuestRangeValid(host.GetGuestMemorySize(), output, 4)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        const time_t value = ::time(nullptr);
        if (value < INT32_MIN || value > INT32_MAX) {
            SetGuestErrno(host, EOVERFLOW); jit.Regs()[0] = UINT32_MAX; return;
        }
        if (output) host.MemoryWrite32(output, static_cast<uint32_t>(value));
        jit.Regs()[0] = static_cast<uint32_t>(value);
    });

    // libc owns these results: one 44-byte guest tm per thread, not a host tm.
    auto convert_time = [](Dynarmic::A32::Jit& jit, DynarmicHost& host, bool utc, bool reentrant) {
        static thread_local uint32_t buffer = 0;
        time_t value{};
        struct tm converted{};
        if (!ReadArm32Time(host, jit.Regs()[0], value) ||
            (reentrant && !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], kArm32TmSize))) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = 0; return;
        }
        if (!(utc ? ::gmtime_r(&value, &converted) : ::localtime_r(&value, &converted))) {
            SetGuestErrno(host, errno); jit.Regs()[0] = 0; return;
        }
        if (!reentrant && !buffer) buffer = host.GuestAlloc(kArm32TmSize, 4);
        const uint32_t output = reentrant ? jit.Regs()[1] : buffer;
        jit.Regs()[0] = WriteArm32Tm(host, output, converted) ? output : 0;
    };
    RegisterThunk("localtime", [convert_time](Dynarmic::A32::Jit& jit, DynarmicHost& host) { convert_time(jit, host, false, false); });
    RegisterThunk("localtime_r", [convert_time](Dynarmic::A32::Jit& jit, DynarmicHost& host) { convert_time(jit, host, false, true); });
    RegisterThunk("gmtime", [convert_time](Dynarmic::A32::Jit& jit, DynarmicHost& host) { convert_time(jit, host, true, false); });
    RegisterThunk("gmtime_r", [convert_time](Dynarmic::A32::Jit& jit, DynarmicHost& host) { convert_time(jit, host, true, true); });

    RegisterThunk("mktime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t address = jit.Regs()[0];
        struct tm value{};
        if (!ReadArm32Tm(host, address, value)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        const time_t result = ::mktime(&value);
        if (result < INT32_MIN || result > INT32_MAX) {
            SetGuestErrno(host, EOVERFLOW); jit.Regs()[0] = UINT32_MAX; return;
        }
        if (!WriteArm32Tm(host, address, value)) {
            SetGuestErrno(host, ENOMEM); jit.Regs()[0] = UINT32_MAX; return;
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("asctime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t buffer = 0;
        struct tm value{};
        char text[26]{};
        if (!ReadArm32Tm(host, jit.Regs()[0], value)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = 0; return;
        }
        if (!::asctime_r(&value, text)) { SetGuestErrno(host, errno); jit.Regs()[0] = 0; return; }
        if (!buffer) buffer = host.GuestAlloc(sizeof(text), 1);
        if (buffer) memcpy(GuestToHost(host.GetGuestMemoryBase(), buffer), text, sizeof(text));
        jit.Regs()[0] = buffer;
    });
    RegisterThunk("difftime", [=](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        write_double_01(jit, difftime(static_cast<time_t>(static_cast<int32_t>(jit.Regs()[0])),
                                      static_cast<time_t>(static_cast<int32_t>(jit.Regs()[1]))));
    });
    RegisterThunk("clock", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(::clock());
    });
    RegisterThunk("strftime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = jit.Regs()[1] ? static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], jit.Regs()[1])) : nullptr;
        const char* format = CheckedGuestString(host, jit.Regs()[2]);
        struct tm value{};
        jit.Regs()[0] = dest && format && ReadArm32Tm(host, jit.Regs()[3], value)
            ? static_cast<uint32_t>(strftime(dest, jit.Regs()[1], format, &value)) : 0;
    });
    RegisterThunk("wcsftime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = jit.Regs()[1] ? static_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], static_cast<size_t>(jit.Regs()[1]) * sizeof(wchar_t))) : nullptr;
        const wchar_t* format = CheckedGuestWideString(host, jit.Regs()[2]);
        struct tm value{};
        jit.Regs()[0] = dest && format && ReadArm32Tm(host, jit.Regs()[3], value)
            ? static_cast<uint32_t>(wcsftime(dest, jit.Regs()[1], format, &value)) : 0;
    });
    RegisterThunk("wcslen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* value = CheckedGuestWideString(host, jit.Regs()[0]);
        jit.Regs()[0] = value ? static_cast<uint32_t>(wcslen(value)) : 0;
    });
    RegisterThunk("wcsxfrm", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = jit.Regs()[2] ? static_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], static_cast<size_t>(jit.Regs()[2]) * sizeof(wchar_t))) : nullptr;
        const wchar_t* src = CheckedGuestWideString(host, jit.Regs()[1]);
        jit.Regs()[0] = dest && src ? static_cast<uint32_t>(wcsxfrm(dest, src, jit.Regs()[2])) : 0;
    });
    RegisterThunk("wcscoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* left = CheckedGuestWideString(host, jit.Regs()[0]);
        const wchar_t* right = CheckedGuestWideString(host, jit.Regs()[1]);
        jit.Regs()[0] = left && right ? static_cast<uint32_t>(wcscoll(left, right)) : 0;
    });
    RegisterThunk("wmemcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[2];
        wchar_t* dest = static_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(wchar_t)));
        const wchar_t* src = static_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], count * sizeof(wchar_t)));
        jit.Regs()[0] = dest && src ? HostToGuest(host.GetGuestMemoryBase(), wmemcpy(dest, src, count)) : 0;
    });
    RegisterThunk("wmemmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[2];
        wchar_t* dest = static_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(wchar_t)));
        const wchar_t* src = static_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], count * sizeof(wchar_t)));
        jit.Regs()[0] = dest && src ? HostToGuest(host.GetGuestMemoryBase(), wmemmove(dest, src, count)) : 0;
    });
    RegisterThunk("wmemset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[2];
        wchar_t* dest = static_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(wchar_t)));
        jit.Regs()[0] = dest ? HostToGuest(host.GetGuestMemoryBase(), wmemset(dest, static_cast<wchar_t>(jit.Regs()[1]), count)) : 0;
    });
    RegisterThunk("wmemchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[2];
        const wchar_t* text = static_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(wchar_t)));
        const wchar_t* found = text ? wmemchr(text, static_cast<wchar_t>(jit.Regs()[1]), count) : nullptr;
        jit.Regs()[0] = found ? HostToGuest(host.GetGuestMemoryBase(), const_cast<wchar_t*>(found)) : 0;
    });
    RegisterThunk("wmemcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[2];
        const wchar_t* left = static_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(wchar_t)));
        const wchar_t* right = static_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], count * sizeof(wchar_t)));
        jit.Regs()[0] = left && right ? static_cast<uint32_t>(wmemcmp(left, right, count)) : 0;
    });
    RegisterThunk("mbrtowc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local mbstate_t implicit_state{};
        mbstate_t state = implicit_state;
        const uint32_t output = jit.Regs()[0], input = jit.Regs()[1], state_address = jit.Regs()[3];
        const size_t count = jit.Regs()[2];
        if ((state_address && !ReadArm32Mbstate(host, state_address, state)) ||
            (input && !GuestRangeValid(host.GetGuestMemorySize(), input, count)) ||
            (input && output && !GuestRangeValid(host.GetGuestMemorySize(), output, sizeof(wchar_t)))) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        wchar_t converted{};
        const size_t result = ::mbrtowc(&converted, input ? static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), input)) : nullptr, count, &state);
        if (input && output && result != static_cast<size_t>(-1) && result != static_cast<size_t>(-2))
            host.MemoryWrite32(output, static_cast<uint32_t>(converted));
        if (state_address) WriteArm32Mbstate(host, state_address, state);
        else implicit_state = state;
        if (result == static_cast<size_t>(-1)) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("wcrtomb", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local mbstate_t implicit_state{};
        mbstate_t state = implicit_state;
        const uint32_t output = jit.Regs()[0], state_address = jit.Regs()[2];
        if (state_address && !ReadArm32Mbstate(host, state_address, state)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        char converted[MB_LEN_MAX]{};
        const size_t result = ::wcrtomb(output ? converted : nullptr, static_cast<wchar_t>(jit.Regs()[1]), &state);
        if (output && result != static_cast<size_t>(-1)) {
            void* destination = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), output, result);
            if (!destination) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return; }
            memcpy(destination, converted, result);
        }
        if (state_address) WriteArm32Mbstate(host, state_address, state);
        else implicit_state = state;
        if (result == static_cast<size_t>(-1)) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("setlocale", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* locale = jit.Regs()[1] ? CheckedGuestString(host, jit.Regs()[1]) : nullptr;
        if (jit.Regs()[1] && !locale) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = 0; return; }
        static std::mutex mutex;
        static std::unordered_map<std::string, uint32_t> results;
        std::lock_guard<std::mutex> lock(mutex);
        const char* result = ::setlocale(static_cast<int>(jit.Regs()[0]), locale);
        if (!result) { jit.Regs()[0] = 0; return; }
        auto& cached = results[result];
        if (!cached) cached = CopyGuestText(host, result);
        jit.Regs()[0] = cached;
    });
    RegisterThunk("atol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* text = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = text ? static_cast<uint32_t>(static_cast<int32_t>(strtol(text, nullptr, 10))) : 0;
    });
    RegisterThunk("basename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* path = static_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!path) { jit.Regs()[0] = 0; return; }
        char* slash = strrchr(path, '/');
        jit.Regs()[0] = HostToGuest(host.GetGuestMemoryBase(), slash ? slash + 1 : path);
    });

    RegisterThunk("raise", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("pwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        const void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]);
        const off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[3]));
        if (!buffer || IsPackagedFd(fd)) {
            SetGuestErrno(host, buffer ? EBADF : EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        const ssize_t result = ::pwrite(fd, buffer, jit.Regs()[2], offset);
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("ftruncate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        // ARM32 off_t is one signed word; only explicitly named *64 APIs use an aligned pair.
        const off_t length = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        if (IsPackagedFd(fd)) { SetGuestErrno(host, EBADF); jit.Regs()[0] = UINT32_MAX; return; }
        const int result = ::ftruncate(fd, length);
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("fsync", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(::fsync(GuestRealFd(static_cast<int>(jit.Regs()[0]))));
    });
    RegisterThunk("fchmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        if (IsPackagedFd(fd)) { SetGuestErrno(host, EROFS); jit.Regs()[0] = UINT32_MAX; return; }
        const int result = ::fchmod(fd, static_cast<mode_t>(jit.Regs()[1]));
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("fchown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        if (IsPackagedFd(fd)) { SetGuestErrno(host, EROFS); jit.Regs()[0] = UINT32_MAX; return; }
        const int result = ::fchown(fd, static_cast<uid_t>(jit.Regs()[1]), static_cast<gid_t>(jit.Regs()[2]));
        if (result < 0) SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("statfs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        const uint32_t output = jit.Regs()[1];
        if (!path || !GuestRangeValid(host.GetGuestMemorySize(), output, kArm32StatfsSize)) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = UINT32_MAX; return;
        }
        struct statfs value{};
        const int result = ::statfs(path, &value);
        if (result == 0) WriteArm32Statfs(host, output, value);
        else SetGuestErrno(host, errno);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("getcwd", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* buffer = static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], jit.Regs()[1]));
        char* result = buffer ? ::getcwd(buffer, jit.Regs()[1]) : nullptr;
        jit.Regs()[0] = result ? HostToGuest(host.GetGuestMemoryBase(), result) : 0;
    });
    RegisterThunk("rmdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(path ? ::rmdir(path) : -1);
    });
    RegisterThunk("freopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const char* path = jit.Regs()[0] ? CheckedGuestString(host, jit.Regs()[0]) : nullptr;
        const char* mode = CheckedGuestString(host, jit.Regs()[1]);
        const uint32_t handle = jit.Regs()[2];
        auto it = g_file_map.find(handle);
        if ((jit.Regs()[0] && !path) || !mode || it == g_file_map.end()) {
            SetGuestErrno(host, it == g_file_map.end() ? EBADF : EFAULT); jit.Regs()[0] = 0; return;
        }
        CACHE_DIAG(cache_diag::ForgetFile(handle));
        int fd = -1;
        FILE* result;
        if (path && (CacheReadPath(path) ||
                     (mode[0] == 'r' && !strchr(mode, '+') && FindApkEntry(path)))) {
            ::fclose(it->second.first);
            result = OpenGuestStream(path, mode, fd);
        } else result = ::freopen(path, mode, it->second.first);
        if (result) {
            it->second = {result, fd};
            CACHE_DIAG(if (fd < 0) cache_diag::RememberFd(::fileno(result), "DISK_PATH", path));
            CACHE_DIAG(cache_diag::RememberFile(handle, fd >= 0 ? fd : ::fileno(result)));
        }
        else { SetGuestErrno(host, errno); g_file_map.erase(it); }
        jit.Regs()[0] = result ? handle : 0;
    });

    RegisterThunk("getc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        const int result = it != g_file_map.end() ? ::getc(it->second.first) : EOF;
        CACHE_DIAG(if (result != EOF) cache_diag::FileDelivered(handle, "getc", 1));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("ungetc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        std::lock_guard file_lock(g_file_registry_mutex);
        const uint32_t handle = jit.Regs()[1];
        auto it = g_file_map.find(handle);
        const int result = it != g_file_map.end() ? ::ungetc(static_cast<int>(jit.Regs()[0]), it->second.first) : EOF;
        CACHE_DIAG(if (result != EOF) cache_diag::Pushback(handle, true));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    RegisterThunk("getwc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        std::lock_guard file_lock(g_file_registry_mutex);
        auto it = g_file_map.find(jit.Regs()[0]);
        jit.Regs()[0] = it != g_file_map.end() ? static_cast<uint32_t>(::fgetwc(it->second.first)) : static_cast<uint32_t>(WEOF);
    });
    RegisterThunk("ungetwc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        std::lock_guard file_lock(g_file_registry_mutex);
        auto it = g_file_map.find(jit.Regs()[1]);
        jit.Regs()[0] = it != g_file_map.end()
            ? static_cast<uint32_t>(::ungetwc(static_cast<wchar_t>(jit.Regs()[0]), it->second.first))
            : static_cast<uint32_t>(WEOF);
    });
    RegisterThunk("putwc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        std::lock_guard file_lock(g_file_registry_mutex);
        auto it = g_file_map.find(jit.Regs()[1]);
        jit.Regs()[0] = it != g_file_map.end()
            ? static_cast<uint32_t>(::fputwc(static_cast<wchar_t>(jit.Regs()[0]), it->second.first))
            : static_cast<uint32_t>(WEOF);
    });
    RegisterThunk("tmpfile", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard file_lock(g_file_registry_mutex);
        FILE* file = ::tmpfile();
        if (!file) { jit.Regs()[0] = 0; return; }
        const uint32_t handle = g_next_file_handle++;
        g_file_map[handle] = {file, -1};
        jit.Regs()[0] = handle;
    });
    RegisterThunk("tmpnam", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t buffer = 0;
        char local[L_tmpnam] = {};
        if (!::tmpnam(local)) { jit.Regs()[0] = 0; return; }
        if (jit.Regs()[0]) {
            char* output = static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], sizeof(local)));
            if (!output) { jit.Regs()[0] = 0; return; }
            memcpy(output, local, sizeof(local));
            return;
        }
        if (!buffer) buffer = host.GuestAlloc(sizeof(local), 1);
        if (buffer) memcpy(GuestToHost(host.GetGuestMemoryBase(), buffer), local, sizeof(local));
        jit.Regs()[0] = buffer;
    });
    RegisterThunk("utimes", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = CheckedGuestString(host, jit.Regs()[0]);
        const uint32_t times = jit.Regs()[1];
        struct timeval host_times[2]{};
        const bool valid = !times || GuestRangeValid(host.GetGuestMemorySize(), times, 16);
        if (times && valid) {
            for (uint32_t i = 0; i < 2; ++i) {
                host_times[i].tv_sec = static_cast<time_t>(static_cast<int32_t>(host.MemoryRead32(times + i * 8)));
                host_times[i].tv_usec = static_cast<suseconds_t>(static_cast<int32_t>(host.MemoryRead32(times + i * 8 + 4)));
            }
        }
        jit.Regs()[0] = path && valid ? static_cast<uint32_t>(::utimes(path, times ? host_times : nullptr)) : static_cast<uint32_t>(-1);
    });
    // provider-policy: fscanf enosys guest variadic output pointers need typed conversion.
    RegisterThunk("fscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "fscanf", "ENOSYS/EOF; no FILE or variadic pointers forwarded");
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = static_cast<uint32_t>(EOF);
    });

    RegisterThunk("getuid", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(::getuid()); });
    RegisterThunk("geteuid", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(::geteuid()); });
    RegisterThunk("getgid", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(::getgid()); });
    RegisterThunk("getegid", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(::getegid()); });
    RegisterThunk("_exit", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const int status = static_cast<int32_t>(jit.Regs()[0]);
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Guest requested _exit(%d)", status);
        CACHE_DIAG(cache_diag::BeforeProcessExit());
        ::_exit(status);
    });
    RegisterThunk("exit", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const int status = static_cast<int32_t>(jit.Regs()[0]);
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Guest requested exit(%d)", status);
        CACHE_DIAG(cache_diag::BeforeProcessExit());
        ::exit(status);
    });
    RegisterThunk("alarm", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    RegisterThunk("bsd_signal", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    RegisterThunk("setenv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* value = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = name && value ? static_cast<uint32_t>(::setenv(name, value, jit.Regs()[2] != 0)) : static_cast<uint32_t>(-1);
    });
    // provider-policy: system enosys guest command execution is not supported.
    RegisterThunk("system", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "system", "ENOSYS; no command executed");
        SetGuestErrno(host, ENOSYS);
        jit.Regs()[0] = static_cast<uint32_t>(-1);
    });
    RegisterThunk("sched_get_priority_max", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(::sched_get_priority_max(static_cast<int>(jit.Regs()[0])));
    });
    RegisterThunk("sched_get_priority_min", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(::sched_get_priority_min(static_cast<int>(jit.Regs()[0])));
    });
    RegisterThunk("pthread_getschedparam", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], 0);
        if (jit.Regs()[2]) host.MemoryWrite32(jit.Regs()[2], 0);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_setschedparam", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_mutexattr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    RegisterThunk("getpwuid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t result = 0;
        static thread_local size_t capacity = 0;
        struct passwd value{}, *found = nullptr;
        std::vector<char> storage(1024);
        int error;
        // ponytail: cap one account record at 1 MiB; raise only for a measured larger record.
        while ((error = ::getpwuid_r(static_cast<uid_t>(jit.Regs()[0]), &value, storage.data(), storage.size(), &found)) == ERANGE && storage.size() < 1024 * 1024)
            storage.resize(storage.size() * 2);
        if (error || !found) { SetGuestErrno(host, error); jit.Regs()[0] = 0; return; }
        const size_t needed = Arm32PasswdBytes(value);
        if (needed > capacity) {
            const uint32_t replacement = host.GuestAlloc(needed, 4);
            if (!replacement) { SetGuestErrno(host, ENOMEM); jit.Regs()[0] = 0; return; }
            host.GuestFree(result);
            result = replacement;
            capacity = needed;
        }
        jit.Regs()[0] = WriteArm32Passwd(host, result, value) ? result : 0;
    });

    // provider-policy: getaddrinfo offline DNS never creates host addrinfo objects for the guest.
    RegisterThunk("getaddrinfo", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "getaddrinfo", "offline DNS: EAI_FAIL, null result");
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], sizeof(uint32_t))) {
            SetGuestErrno(host, EFAULT); jit.Regs()[0] = EAI_SYSTEM; return;
        }
        host.MemoryWrite32(jit.Regs()[3], 0);
        jit.Regs()[0] = EAI_FAIL;
    });
    // provider-policy: freeaddrinfo offline getaddrinfo never returns an allocated result.
    RegisterThunk("freeaddrinfo", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        LogLibcPolicy(jit, "freeaddrinfo", "offline DNS: no allocated results to free");
    });
    // provider-policy: getsockopt enosys no outputs are touched on failure (arg5 is on the stack, not r4).
    RegisterThunk("getsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "getsockopt", "offline sockets: ENOSYS, outputs unchanged");
        SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX;
    });
    // provider-policy: getsockname enosys offline sockets, address and addrlen remain unchanged.
    RegisterThunk("getsockname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "getsockname", "offline sockets: ENOSYS, outputs unchanged");
        SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX;
    });
    // provider-policy: getpeername enosys offline sockets, address and addrlen remain unchanged.
    RegisterThunk("getpeername", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "getpeername", "offline sockets: ENOSYS, outputs unchanged");
        SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX;
    });
    RegisterThunk("inet_pton", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* source = static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const size_t size = jit.Regs()[0] == AF_INET6 ? 16 : 4;
        void* destination = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[2], size);
        jit.Regs()[0] = source && destination ? static_cast<uint32_t>(::inet_pton(static_cast<int>(jit.Regs()[0]), source, destination)) : static_cast<uint32_t>(-1);
    });
    RegisterThunk("poll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[1];
        struct pollfd* fds = static_cast<struct pollfd*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], count * sizeof(struct pollfd)));
        if (!fds && count) { SetGuestErrno(host, EFAULT); jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        for (size_t i = 0; i < count; ++i) fds[i].revents = 0;
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sendto", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX; });
    RegisterThunk("recvfrom", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX; });
    RegisterThunk("shutdown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { SetGuestErrno(host, ENOSYS); jit.Regs()[0] = UINT32_MAX; });
    RegisterThunk("ioctl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { SetGuestErrno(host, ENOTTY); jit.Regs()[0] = UINT32_MAX; });

    RegisterThunk("sigsetjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t env = jit.Regs()[0];
        if (!env) { jit.Regs()[0] = 0; return; }
        GuestJumpState state;
        for (size_t i = 0; i < state.r4_r11.size(); ++i) state.r4_r11[i] = jit.Regs()[4 + i];
        state.sp = jit.Regs()[13]; state.lr = jit.Regs()[14]; state.cpsr = jit.Cpsr(); state.thread = g_current_guest_thread;
        std::lock_guard<std::mutex> lock(g_jump_mutex);
        g_jump_states[env] = state;
        jit.Regs()[0] = 0;
    });
    RegisterThunk("siglongjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t env = jit.Regs()[0];
        const uint32_t value = jit.Regs()[1] ? jit.Regs()[1] : 1;
        GuestJumpState state;
        {
            std::lock_guard<std::mutex> lock(g_jump_mutex);
            auto it = g_jump_states.find(env);
            if (it == g_jump_states.end() || it->second.thread != g_current_guest_thread) { jit.Regs()[0] = value; return; }
            state = it->second;
        }
        for (size_t i = 0; i < state.r4_r11.size(); ++i) jit.Regs()[4 + i] = state.r4_r11[i];
        jit.Regs()[0] = value;
        jit.Regs()[13] = state.sp;
        jit.Regs()[14] = state.lr;
        jit.SetCpsr((state.cpsr & ~0x20u) | ((state.lr & 1) ? 0x20u : 0u));
        jit.Regs()[15] = state.lr & ~1u;
    });
    RegisterThunk("__android_log_vprint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = CheckedGuestString(host, jit.Regs()[1]);
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[2]), 4, jit.Regs()[3]);
        jit.Regs()[0] = text ? static_cast<uint32_t>(__android_log_print(prio, tag ? tag : "Arm32Bridge_Guest", "%s", text->c_str())) : UINT32_MAX;
    });
    // provider-policy: vsprintf enosys-branch scalar AAPCS formats supported; positional/wide formats rejected.
    RegisterThunk("vsprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const auto text = FormatGuestString(jit, host, CheckedGuestString(host, jit.Regs()[1]), 4, jit.Regs()[2]);
        StoreFormattedString(jit, host, jit.Regs()[0], text ? text->size() + 1 : 0, text);
    });
    // provider-policy: vsscanf enosys guest va_list and output pointers require typed conversion.
    RegisterThunk("vsscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LogLibcPolicy(jit, "vsscanf", "ENOSYS/EOF; no guest va_list forwarded");
        SetGuestErrno(host, ENOSYS); jit.Regs()[0] = static_cast<uint32_t>(EOF);
    });

    // Runtime guards & hooks
    RegisterThunk("__stack_chk_fail", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        __android_log_assert(nullptr, LOG_TAG, "Guest stack check failed at PC: 0x%08X", jit.Regs()[15]);
    });

    RegisterThunk("abort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        __android_log_assert(nullptr, LOG_TAG, "Guest called abort() at PC=0x%08X LR=0x%08X SP=0x%08X", jit.Regs()[15], jit.Regs()[14], jit.Regs()[13]);
    });

    RegisterThunk("__assert2", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* file = CheckedGuestString(host, jit.Regs()[0]);
        int line = static_cast<int>(jit.Regs()[1]);
        const char* func = CheckedGuestString(host, jit.Regs()[2]);
        const char* expr = CheckedGuestString(host, jit.Regs()[3]);
        __android_log_assert(nullptr, LOG_TAG, "Assertion failed: %.256s at %.256s:%d (%.256s)", expr ? expr : "", file ? file : "", line, func ? func : "");
    });

    RegisterThunk("__cxa_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_finalize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_RaiseException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_DeleteException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_GetLanguageSpecificData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_GetRegionStart", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Set", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_unwind_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("telltale_fix_current_directory_script", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static constexpr char directory_prefix[] = "rawset(_G, \"_currentDirectory\", \"";
        static constexpr char file_prefix[] = "rawset(_G, \"_currentFile\", \"";
        const uint32_t code_object = jit.Regs()[1];
        const uint32_t code_data = code_object ? host.MemoryRead32(code_object) : 0;
        const char* code = code_data
            ? reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), code_data)) : nullptr;
        if (!code || strstr(code, "\")") != nullptr) return;

        const char* prefix = nullptr;
        bool want_directory = false;
        if (strncmp(code, directory_prefix, sizeof(directory_prefix) - 1) == 0) {
            prefix = directory_prefix;
            want_directory = true;
        } else if (strncmp(code, file_prefix, sizeof(file_prefix) - 1) == 0) {
            prefix = file_prefix;
        } else {
            return;
        }

        // The caller's R8 is the current resource-directory entry. Its String data
        // pointer at +0x14 is the exact archive/file-qualified resource address.
        const uint32_t resource_entry = jit.Regs()[8];
        const uint32_t path_data = resource_entry ? host.MemoryRead32(resource_entry + 0x14) : 0;
        const uint32_t path_length = path_data ? host.MemoryRead32(path_data - 12) : 0;
        const char* path = path_data
            ? reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), path_data)) : nullptr;
        if (!path || !path_length || path_length > 4096) return;

        const char* slash = nullptr;
        for (uint32_t i = path_length; i > 0; --i) {
            if (path[i - 1] == '/') { slash = path + i - 1; break; }
        }
        const uint32_t dir_length = slash ? static_cast<uint32_t>(slash - path + 1) : 0;
        const uint32_t file_offset = dir_length;
        const uint32_t file_length = path_length - file_offset;

        std::string escaped_dir;
        escaped_dir.reserve(dir_length);
        for (uint32_t i = 0; i < dir_length; ++i) {
            const char c = path[i];
            if (c == '\\') {
                escaped_dir.push_back('/');
            } else {
                if (c == '"') escaped_dir.push_back('\\');
                escaped_dir.push_back(c);
            }
        }

        std::string escaped_file;
        escaped_file.reserve(file_length);
        for (uint32_t i = 0; i < file_length; ++i) {
            const char c = path[file_offset + i];
            if (c == '\\') {
                escaped_file.push_back('/');
            } else {
                if (c == '"') escaped_file.push_back('\\');
                escaped_file.push_back(c);
            }
        }

        const std::string source = std::string("rawset(_G, \"_currentDirectory\", \"") + escaped_dir + "\") \n" +
                                   std::string("rawset(_G, \"_currentFile\", \"") + escaped_file + "\") \n" +
                                   std::string("rawset(_G, \"_registerCollections\", true ) \n");

        uint32_t destination = code_data;
        const uint32_t capacity = code_data ? host.MemoryRead32(code_data - 8) : 0;
        if (capacity < source.size()) {
            const uint32_t rep = host.GuestAlloc(source.size() + 13, 8);
            if (!rep) return;
            destination = rep + 12;
            host.MemoryWrite32(rep, static_cast<uint32_t>(source.size()));
            host.MemoryWrite32(rep + 4, static_cast<uint32_t>(source.size()));
            host.MemoryWrite32(rep + 8, 0);
            host.MemoryWrite32(code_object, destination);
        } else {
            host.MemoryWrite32(destination - 12, static_cast<uint32_t>(source.size()));
            host.MemoryWrite32(destination - 4, 0);
        }
        char* output = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), destination));
        memcpy(output, source.data(), source.size());
        output[source.size()] = 0;
        LOGI("Repaired Telltale context script: %s", output);
    });

    RegisterThunk("telltale_fix_lua_source", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static constexpr char directory_prefix[] = "rawset(_G, \"_currentDirectory\", \"";
        static constexpr char file_prefix[] = "rawset(_G, \"_currentFile\", \"";
        const char* code = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!code || strstr(code, "\")") != nullptr) return;

        const char* prefix = nullptr;
        bool want_directory = false;
        if (strncmp(code, directory_prefix, sizeof(directory_prefix) - 1) == 0) {
            prefix = directory_prefix;
            want_directory = true;
        } else if (strncmp(code, file_prefix, sizeof(file_prefix) - 1) == 0) {
            prefix = file_prefix;
        } else {
            return;
        }

        const uint32_t resource_entry = jit.Regs()[8];
        const uint32_t path_data = resource_entry ? host.MemoryRead32(resource_entry + 0x14) : 0;
        const uint32_t path_length = path_data ? host.MemoryRead32(path_data - 12) : 0;
        const char* path = path_data
            ? reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), path_data)) : nullptr;
        if (!path || !path_length || path_length > 4096) return;

        const char* slash = nullptr;
        for (uint32_t i = path_length; i > 0; --i) {
            if (path[i - 1] == '/') { slash = path + i - 1; break; }
        }
        const uint32_t value_offset = want_directory ? 0 : (slash ? static_cast<uint32_t>(slash - path + 1) : 0);
        const uint32_t value_length = want_directory ? (slash ? static_cast<uint32_t>(slash - path + 1) : 0)
                                                     : path_length - value_offset;
        std::string escaped;
        escaped.reserve(value_length);
        for (uint32_t i = 0; i < value_length; ++i) {
            const char c = path[value_offset + i];
            if (c == '\\') escaped.push_back('/');
            else { if (c == '"') escaped.push_back('\\'); escaped.push_back(c); }
        }
        const std::string source = std::string(prefix) + escaped + "\") \n";
        const uint32_t address = host.GuestAlloc(source.size() + 1, 4);
        if (!address) return;
        char* output = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), address));
        memcpy(output, source.data(), source.size());
        output[source.size()] = 0;
        jit.Regs()[1] = address;
        LOGI("Repaired Lua source at load: %s", output);
    });

    RegisterThunk("telltale_log_render", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 10) LOGI("GameEngine::Render entry #%u", count);
    });
    RegisterThunk("telltale_log_render_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 20) LOGI("GameRender::RenderFrame entry #%u this=0x%08X", count, jit.Regs()[0]);
    });
    RegisterThunk("telltale_log_render_execute", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 20) {
            const uint32_t frame = host.MemoryRead32(jit.Regs()[0] + 0x44);
            LOGI("RenderThreadFrame::Execute_DefaultFrame entry #%u this=0x%08X update=0x%08X frame=0x%08X views=%u",
                 count, jit.Regs()[0], host.MemoryRead32(jit.Regs()[0] + 0x40), frame,
                 frame ? host.MemoryRead32(frame + 0x1C) : 0);
        }
    });
    RegisterThunk("telltale_log_scene_add", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 32) {
            LOGI("Scene::AddScene #%u address='%s' name='%s'", count,
                 GuestStringValue(host, jit.Regs()[1]).c_str(),
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_scene_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 32) {
            LOGI("Scene::OpenScene #%u address='%s' name='%s'", count,
                 GuestStringValue(host, jit.Regs()[1]).c_str(),
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_doload", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ScriptManager::DoLoad #%u path='%s'", count, GuestStringValue(host, jit.Regs()[0]).c_str());
        }
    });
    RegisterThunk("telltale_log_doload_result", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ScriptManager::DoLoad result #%u ok=%u path='%s'", count, jit.Regs()[0],
                 GuestStringValue(host, jit.Regs()[1]).c_str());
        }
    });
    RegisterThunk("telltale_log_loadresource_result", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ScriptManager::LoadResource result #%u code=%u path='%s'", count, jit.Regs()[0],
                 GuestStringValue(host, jit.Regs()[7]).c_str());
        }
    });
    RegisterThunk("telltale_log_ttpcall_result", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ScriptManager::TTPCall result #%u ok=%u path='%s'", count, jit.Regs()[0],
                 GuestStringValue(host, jit.Regs()[7]).c_str());
        }
    });
    RegisterThunk("telltale_log_ttpcall_error", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const uint32_t state = jit.Regs()[0];
            const uint32_t top = state ? host.MemoryRead32(state + 8) : 0;
            const uint32_t type = top >= 8 ? host.MemoryRead32(top - 4) : 0;
            LOGI("ScriptManager::TTPCall error #%u code=%u luaState=0x%08X top=0x%08X type=0x%08X message='%s'", count,
                 jit.Regs()[5], state, top, type, GuestLuaTopError(host, state).c_str());
        }
    });
    RegisterThunk("telltale_log_ttarchive_result", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const uint32_t output = jit.Regs()[0];
            const uint32_t location = output ? host.MemoryRead32(output) : 0;
            const uint32_t archive = location ? host.MemoryRead32(location + 0x40) : 0;
            LOGI("ResourceLocationFactory::CreateTTArchive result #%u output=0x%08X location=0x%08X archive=0x%08X entries=%u capacity=%u data=0x%08X version=%u symbol=0x%08X%08X stream=0x%08X compressed=%u",
                 count, output, location, archive,
                 archive ? host.MemoryRead32(archive + 0x24) : 0,
                 archive ? host.MemoryRead32(archive + 0x28) : 0,
                 archive ? host.MemoryRead32(archive + 0x2C) : 0,
                 archive ? host.MemoryRead32(archive + 0x34) : 0,
                 jit.Regs()[7] ? host.MemoryRead32(jit.Regs()[7] + 4) : 0,
                 jit.Regs()[7] ? host.MemoryRead32(jit.Regs()[7]) : 0, jit.Regs()[5], jit.Regs()[6]);
        }
    });
    RegisterThunk("telltale_log_mount_directory", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 64) {
            const char* package = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
            const char* directory = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
            LOGI("T3_MOUNT_DIRECTORY #%u package='%s' directory='%s'", count,
                 package ? package : "", directory ? directory : "");
        }
    });
    RegisterThunk("telltale_log_resource_directory_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ResourceDirectory::Create #%u path='%s' flag=%u", count,
                 GuestStringValue(host, jit.Regs()[1]).c_str(), jit.Regs()[2]);
        }
    });
    RegisterThunk("telltale_log_resource_location_directory", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const uint32_t symbol = jit.Regs()[1];
            LOGI("ResourceLocationFactory::CreateDirectory #%u out=0x%08X symbol=0x%08X%08X resourceDir=0x%08X",
                 count, jit.Regs()[0], symbol ? host.MemoryRead32(symbol + 4) : 0,
                 symbol ? host.MemoryRead32(symbol) : 0, jit.Regs()[2] ? host.MemoryRead32(jit.Regs()[2]) : 0);
        }
    });
    RegisterThunk("telltale_log_concrete_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ResourceConcreteLocation::GetResources #%u location=0x%08X output=0x%08X mask=0x%08X text='%s'",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_concrete_ptr_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ResourceConcreteLocation::GetResources<Ptr> #%u location=0x%08X output=0x%08X mask=0x%08X text='%s'",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_directory_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ResourceConcreteLocation_Directory::GetResources #%u location=0x%08X output=0x%08X mask=0x%08X text='%s'",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_bundle_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("ResourceConcreteLocation_Bundle::GetResources #%u location=0x%08X output=0x%08X mask=0x%08X text='%s'",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_ttarchive_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("TTArchive2::GetResources #%u archive=0x%08X output=0x%08X mask=0x%08X text='%s'",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str());
        }
    });
    RegisterThunk("telltale_log_mask_compare", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* mask = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* candidate = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if ((mask && strstr(mask, "project_")) || (candidate && strstr(candidate, "Struggle"))) {
            const ElfLoader* game_engine = host.FindModule("libGameEngine.so");
            const uint32_t base = game_engine ? game_engine->GetBaseAddress() : 0;
            const uint32_t flag = base ? host.MemoryRead8(base + 0x1085214) : 0;
            const uint32_t object = base ? host.MemoryRead32(base + 0x107B2D4) : 0;
            const uint32_t table = object ? host.MemoryRead32(object) : 0;
            LOGI("StringMask::MaskCompare mask='%s' candidate='%s' result=%u mode=%u flag=%u "
                 "toupperObject=0x%08X table=0x%08X chars=%02X%02X%02X%02X",
                 mask ? mask : "", candidate ? candidate : "", jit.Regs()[2], jit.Regs()[3], flag, object, table,
                 table ? host.MemoryRead8(table) : 0, table ? host.MemoryRead8(table + 1) : 0,
                 table ? host.MemoryRead8(table + 2) : 0, table ? host.MemoryRead8(table + 3) : 0);
        }
    });
    RegisterThunk("telltale_log_project_pref_enum", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 16) {
            const uint32_t location = jit.Regs()[0];
            LOGI("GameEngine::OpenProjectPrefs enumeration #%u location=0x%08X vtable=0x%08X target=0x%08X "
                 "output=0x%08X mask=0x%08X text='%s' lr=0x%08X",
                 count, location, location ? host.MemoryRead32(location) : 0, jit.Regs()[3], jit.Regs()[1], jit.Regs()[2],
                 GuestStringValue(host, jit.Regs()[2]).c_str(), jit.Regs()[14]);
        }
    });
    RegisterThunk("telltale_log_logical_get_resources", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const std::string mask_text = GuestStringValue(host, jit.Regs()[2]);
        if (count <= 16 || !mask_text.empty()) {
            const auto word = [&host](uint32_t addr) -> uint32_t {
                return addr && static_cast<uint64_t>(addr) + 4 <= host.GetGuestMemorySize()
                    ? host.MemoryRead32(addr) : 0;
            };
            const uint32_t location = jit.Regs()[0];
            uint32_t node = word(location + 0x24);
            const uint32_t sentinel = location + 0x1C;
            LOGI("ResourceLogicalLocation::GetResources #%u location=0x%08X vtable=0x%08X mask=0x%08X text='%s' head=0x%08X",
                 count, location, word(location), jit.Regs()[2], GuestStringValue(host, jit.Regs()[2]).c_str(), node);
            for (uint32_t i = 0; node && node != sentinel && i < 8; ++i) {
                const uint32_t wrapper = word(node + 16);
                const uint32_t child = word(wrapper + 20);
                LOGI("ResourceLogicalLocation child #%u node=0x%08X wrapper=0x%08X child=0x%08X vtable=0x%08X",
                     i, node, wrapper, child, word(child));
                node = word(node);
            }
        }
    });
    auto register_startup_probe = [&](const char* thunk_name, const char* label) {
        auto calls = std::make_shared<std::atomic<uint32_t>>(0);
        RegisterThunk(thunk_name, [calls, label](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            const uint32_t count = ++*calls;
            if (count > 64) return;
            const uint32_t state = jit.Regs()[0];
            if (strcmp(label, "luaSave") == 0 || strcmp(label, "luaCreate") == 0) {
                const uint32_t top = state ? host.MemoryRead32(state + 8u) : 0;
                const uint32_t value = top >= 8u ? host.MemoryRead32(top - 8u) : 0;
                const uint32_t type = top >= 4u ? host.MemoryRead32(top - 4u) & 0xFu : 0;
                const uint32_t length = type == 4u && value ? host.MemoryRead32(value + 12u) : 0;
                const char* path = length && length < 512u
                    ? reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), value + 16u)) : nullptr;
                LOGI("%s entry #%u state=0x%08X top=0x%08X argType=%u arg='%.*s'",
                     label, count, state, top, type, path ? static_cast<int>(length) : 0,
                     path ? path : "");
            } else {
                LOGI("%s entry #%u state=0x%08X", label, count, state);
            }
        });
    };
    register_startup_probe("telltale_log_lua_scene_add", "luaSceneAdd");
    register_startup_probe("telltale_log_lua_scene_open", "luaSceneOpen");
    register_startup_probe("telltale_log_lua_load_script", "luaLoadScript");
    register_startup_probe("telltale_log_resource_set_exists", "luaResourceSetExists");
    register_startup_probe("telltale_log_resource_exists", "luaResourceExists");
    register_startup_probe("telltale_log_resource_set_enable", "luaResourceSetEnable");
    register_startup_probe("telltale_log_resource_set_default_location", "luaResourceSetDefaultLocation");
    register_startup_probe("telltale_log_lua_get_preferences", "luaGetPreferences");
    register_startup_probe("telltale_log_lua_random_seed", "luaRandomSeed");
    register_startup_probe("telltale_log_lua_start_external", "luaStartExternalPlatforms");
    register_startup_probe("telltale_log_lua_property_set", "luaPropertySet");
    register_startup_probe("telltale_log_lua_property_exists", "luaPropertyExists");
    register_startup_probe("telltale_log_lua_save", "luaSave");
    register_startup_probe("telltale_log_lua_create", "luaCreate");
    register_startup_probe("telltale_log_lua_user_signed_in", "luaPlatformIsUserSignedIn");
    RegisterThunk("telltale_log_minecraft_signedin_result", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        LOGI("MCSM PlatformIsUserSignedIn result=%u", jit.Regs()[0]);
    });
    RegisterThunk("telltale_log_minecraft_quicksave", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        LOGI("MCSM QuickSave handle=0x%08X object=0x%08X symbol=0x%08X%08X",
             handle, handle ? host.MemoryRead32(handle + 0x1C) : 0,
             handle ? host.MemoryRead32(handle + 0x14) : 0,
             handle ? host.MemoryRead32(handle + 0x10) : 0);
    });
    register_startup_probe("telltale_log_resource_resolve_url", "luaResourceResolveURLToConcrete");
    register_startup_probe("telltale_log_resource_resolve_address", "luaResourceResolveAddressToConcreteLocationID");
    register_startup_probe("telltale_log_resource_address_name", "luaResourceAddressGetResourceName");
    register_startup_probe("telltale_log_resource_create_archive", "luaResourceCreateConcreteArchiveLocation");
    register_startup_probe("telltale_log_resource_patch_apply", "ResourcePatchSet::Apply");
    RegisterThunk("telltale_log_metastream_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            LOGI("MetaStream::Open #%u stream=0x%08X address=0x%08X path='%s' mode=%u params=0x%08X",
                 count, jit.Regs()[0], jit.Regs()[1],
                 GuestStringValue(host, jit.Regs()[1]).c_str(), jit.Regs()[2], jit.Regs()[3]);
        }
    });
    RegisterThunk("telltale_log_metastream_attach", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const auto word = [&host](uint32_t addr) -> uint32_t {
                return addr && static_cast<uint64_t>(addr) + 4 <= host.GetGuestMemorySize()
                    ? host.MemoryRead32(addr) : 0;
            };
            const uint32_t meta = jit.Regs()[0];
            const uint32_t holder = jit.Regs()[1];
            const uint32_t data_stream = word(holder);
            const uint32_t resource = word(meta + 8);
            LOGI("MetaStream::Attach #%u meta=0x%08X holder=0x%08X data=0x%08X mode=%u "
                 "resource=0x%08X type=%u symbol=0x%08X%08X parent=0x%08X "
                 "dsVt=0x%08X dsFd=0x%08X dsBase=0x%08X dsSize=0x%08X",
                 count, meta, holder, data_stream, jit.Regs()[2], resource, word(resource),
                 word(resource + 12), word(resource + 8), word(resource + 16), word(data_stream),
                 word(data_stream + 44), word(data_stream + 48), word(data_stream + 56));
        }
    });
    RegisterThunk("telltale_log_metastream_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const auto word = [&host](uint32_t addr) -> uint32_t {
                return addr && static_cast<uint64_t>(addr) + 4 <= host.GetGuestMemorySize()
                    ? host.MemoryRead32(addr) : 0;
            };
            const auto byte = [&host](uint32_t addr) -> uint32_t {
                return addr < host.GetGuestMemorySize() ? host.MemoryRead8(addr) : 0;
            };
            const uint32_t meta = jit.Regs()[0];
            const uint32_t depth = word(meta + 12);
            const uint32_t sections = word(meta + 20);
            const uint32_t section_index = depth && depth <= 4 && sections
                ? word(sections + 2328u * (depth - 1) + 2320) : 0;
            const uint32_t section = depth && depth <= 4 && sections && section_index < 4
                ? sections + 2328u * (depth - 1) + 576u * section_index : 0;
            const uint32_t buffer_pos = word(section + 56);
            const uint32_t buffer_size = word(section + 60);
            const uint32_t at_pos = buffer_pos < buffer_size ? section + 64 + buffer_pos : 0;
            LOGI("MetaStream::ReadData #%u meta=0x%08X want=%u pos=%u size=%u section=%u data=0x%08X "
                 "buf=%u/%u at=%02X%02X%02X%02X",
                 count, meta, jit.Regs()[2],
                 word(section + 24), word(section + 16), section_index, word(section),
                 buffer_pos, buffer_size, byte(at_pos), byte(at_pos + 1), byte(at_pos + 2), byte(at_pos + 3));
        }
    });
    RegisterThunk("telltale_log_posix_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const uint32_t stream = jit.Regs()[0];
            const uint32_t op = jit.Regs()[1];
            LOGI("DataStreamFile_Posix::Read #%u stream=0x%08X fd=%d base=0x%08X size=0x%08X "
                 "op=0x%08X offset=0x%08X count=%u buf=0x%08X",
                 count, stream, static_cast<int32_t>(host.MemoryRead32(stream + 44)),
                 host.MemoryRead32(stream + 48), host.MemoryRead32(stream + 56), op,
                 op ? host.MemoryRead32(op + 8) : 0, op ? host.MemoryRead32(op + 4) : 0,
                 op ? host.MemoryRead32(op) : 0);
        }
    });
    RegisterThunk("telltale_log_resource_address_ctor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const std::string path = GuestStringValue(host, jit.Regs()[1]);
            const uint64_t crc = GuestCRC64(host, path);
            if (crc && !path.empty()) {
                std::lock_guard<std::mutex> lock(g_resource_name_mutex);
                g_resource_names[crc] = path;
            }
            LOGI("ResourceAddress::Ctor #%u out=0x%08X path='%s' crc=0x%08X%08X",
                 count, jit.Regs()[0], path.c_str(),
                 static_cast<uint32_t>(crc >> 32), static_cast<uint32_t>(crc));
        }
    });
    RegisterThunk("telltale_log_meta_load", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const uint32_t info = jit.Regs()[3];
            const uint64_t symbol = static_cast<uint64_t>(host.MemoryRead32(info + 8)) |
                                     (static_cast<uint64_t>(host.MemoryRead32(info + 12)) << 32);
            std::string name;
            {
                std::lock_guard<std::mutex> lock(g_resource_name_mutex);
                const auto it = g_resource_names.find(symbol);
                if (it != g_resource_names.end()) name = it->second;
            }
            LOGI("Meta::MetaOperation_Load #%u object=0x%08X class=0x%08X info=0x%08X mode=%u "
                 "symbol=0x%08X%08X name='%s' location=0x%08X stream=0x%08X output=0x%08X",
                 count, jit.Regs()[0], jit.Regs()[1], info, info ? host.MemoryRead32(info) : 0,
                 static_cast<uint32_t>(symbol >> 32), static_cast<uint32_t>(symbol), name.c_str(),
                 info ? host.MemoryRead32(info + 16) : 0, info ? host.MemoryRead32(info + 20) : 0,
                 info ? host.MemoryRead32(info + 28) : 0);
        }
    });
    RegisterThunk("telltale_log_handle_info_ctor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const uint32_t address = jit.Regs()[1];
            const uint64_t symbol = static_cast<uint64_t>(address ? host.MemoryRead32(address + 8) : 0) |
                                     (static_cast<uint64_t>(address ? host.MemoryRead32(address + 12) : 0) << 32);
            std::string name;
            {
                std::lock_guard<std::mutex> lock(g_resource_name_mutex);
                const auto it = g_resource_names.find(symbol);
                if (it != g_resource_names.end()) name = it->second;
            }
            LOGI("HandleObjectInfo::Ctor #%u info=0x%08X address=0x%08X type=%u symbol=0x%08X%08X name='%s' "
                 "class=0x%08X object=0x%08X lr=0x%08X",
                 count, jit.Regs()[0], address, address ? host.MemoryRead32(address) : 0,
                 static_cast<uint32_t>(symbol >> 32), static_cast<uint32_t>(symbol), name.c_str(),
                 jit.Regs()[2], jit.Regs()[3], jit.Regs()[14]);
        }
    });
    RegisterThunk("telltale_log_handle_base_set_object", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const uint32_t address = jit.Regs()[1];
            const uint64_t symbol = static_cast<uint64_t>(address ? host.MemoryRead32(address + 8) : 0) |
                                     (static_cast<uint64_t>(address ? host.MemoryRead32(address + 12) : 0) << 32);
            LOGI("HandleBase::SetObject #%u handle=0x%08X address=0x%08X type=%u symbol=0x%08X%08X "
                 "class=0x%08X lr=0x%08X",
                 count, jit.Regs()[0], address, address ? host.MemoryRead32(address) : 0,
                 static_cast<uint32_t>(symbol >> 32), static_cast<uint32_t>(symbol), jit.Regs()[2], jit.Regs()[14]);
        }
    });
    RegisterThunk("telltale_log_async_thread", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 64) LOGI("AsyncStreamManager::_RequestThreadFunc entry #%u this=0x%08X arg=0x%08X", count,
                              jit.Regs()[0], jit.Regs()[1]);
    });
    RegisterThunk("telltale_log_async_request", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t request = jit.Regs()[1];
        if (count <= 64) {
            LOGI("AsyncStreamManager::_DoRequest entry #%u manager=0x%08X request=0x%08X type=%u stream=0x%08X stream2=0x%08X",
                 count, jit.Regs()[0], request, request ? host.MemoryRead32(request + 24) : 0,
                 request ? host.MemoryRead32(request + 36) : 0, request ? host.MemoryRead32(request + 40) : 0);
        }
    });
    RegisterThunk("telltale_log_async_finish", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t request = jit.Regs()[1];
        if (count <= 64) {
            LOGI("AsyncStreamManager::_FinishRequest entry #%u manager=0x%08X request=0x%08X ok=%u resultLo=0x%08X",
                 count, jit.Regs()[0], request, jit.Regs()[2], request ? host.MemoryRead32(request + 128) : 0);
        }
    });
    RegisterThunk("telltale_log_data_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t stream = jit.Regs()[0];
        const uint32_t op = jit.Regs()[1];
        if (count <= 64) {
            LOGI("DataStreamFile_Android::Read entry #%u stream=0x%08X op=0x%08X buf=0x%08X count=%u offset=0x%08X",
                 count, stream, op, op ? host.MemoryRead32(op) : 0, op ? host.MemoryRead32(op + 4) : 0,
                 op ? host.MemoryRead32(op + 8) : 0);
        }
    });
    RegisterThunk("telltale_log_async_load_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t ptr = jit.Regs()[1];
        if (count <= 64) {
            LOGI("AsyncLoadManager::Wait entry #%u manager=0x%08X handlePtr=0x%08X info=0x%08X async=0x%08X",
                 count, jit.Regs()[0], ptr, ptr ? host.MemoryRead32(ptr) : 0,
                 ptr && host.MemoryRead32(ptr) ? host.MemoryRead32(host.MemoryRead32(ptr) + 80) : 0);
        }
    });
    RegisterThunk("telltale_log_android_heap_alloc_aligned", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 64) LOGI("AndroidHeap::AllocAligned entry #%u heap=%d size=%u align=%d", count,
                              jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });
    RegisterThunk("telltale_log_android_heap_free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t pointer = jit.Regs()[1];
        if (count <= 64) LOGI("AndroidHeap::Free entry #%u heap=0x%08X pointer=0x%08X", count,
                              jit.Regs()[0], pointer);
    });
    RegisterThunk("telltale_log_cache_copy_directory", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 32) {
            LOGI("ResourceConcreteLocation_CacheDirectory::_CopyDirectory entry #%u this=0x%08X source=0x%08X destination=0x%08X entries=%u",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 jit.Regs()[0] ? host.MemoryRead32(jit.Regs()[0] + 84) : 0);
        }
    });
    RegisterThunk("telltale_log_memory_stream_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t stream = jit.Regs()[0];
        const uint32_t op = jit.Regs()[1];
        if (count <= 128) {
            LOGI("DataStreamMemory::Write entry #%u stream=0x%08X type=%u chunk=%u offsetLo=0x%08X count=%u",
                 count, stream, stream ? host.MemoryRead32(stream + 52) : 0,
                 stream ? host.MemoryRead32(stream + 56) : 0,
                 op ? host.MemoryRead32(op + 8) : 0, op ? host.MemoryRead32(op + 4) : 0);
        }
    });
    RegisterThunk("telltale_log_pool_initialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t pool = jit.Regs()[0];
        const uint32_t elements = jit.Regs()[1];
        const uint32_t element_size = pool ? host.MemoryRead32(pool + 8) : 0;
        const uint64_t bytes = static_cast<uint64_t>(elements) * element_size;
        if (bytes >= 65536 && count <= 256) {
            LOGI("Pool::Initialize large #%u pool=0x%08X elements=%u elementSize=%u bytes=%llu heapType=%d",
                 count, pool, elements, element_size,
                 static_cast<unsigned long long>(bytes),
                 pool ? static_cast<int32_t>(host.MemoryRead32(pool + 12)) : 0);
        }
    });
    RegisterThunk("telltale_log_gpool_alloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        static std::atomic<uint32_t> expansion_logs{0};
        static std::atomic<uint32_t> twelve_logs{0};
        const uint32_t count = ++calls;
        const uint32_t gpool = jit.Regs()[0];
        const uint32_t element_size = gpool ? host.MemoryRead32(gpool + 24) : 0;
        const uint32_t head_raw = gpool ? host.MemoryRead32(gpool + 20) : 0;
        const uint32_t head = head_raw & ~1u;
        const int32_t free_count = head ? static_cast<int32_t>(host.MemoryRead32(head + 24)) : 0;
        const bool log_expansion = free_count <= 1 && expansion_logs.fetch_add(1) < 128;
        const bool log_twelve = element_size == 12 && free_count <= 1 && twelve_logs.fetch_add(1) < 128;
        if (count <= 256 || log_expansion || log_twelve || (count % 100000u) == 0) {
            const uint32_t sp = jit.Regs()[13];
            const uint32_t list_caller = static_cast<uint64_t>(sp) + 16 <= host.GetGuestMemorySize()
                ? host.MemoryRead32(sp + 12) : 0;
            const uint32_t list_count = static_cast<uint64_t>(sp) + 28 <= host.GetGuestMemorySize()
                ? host.MemoryRead32(sp + 24) : 0;
            const uint32_t list_owner = static_cast<uint64_t>(sp) + 72 <= host.GetGuestMemorySize()
                ? host.MemoryRead32(sp + 68) : 0;
            const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
            LOGI("GPool::Alloc #%u this=0x%08X request=%u tag='%s' caller=0x%08X listCaller=0x%08X listCount=%u listOwner=0x%08X head=0x%08X free=%d elementSize=%u initial=%u grow=%u heapType=%d",
                 count, gpool, jit.Regs()[1], tag ? tag : "", jit.Regs()[14], list_caller, list_count, list_owner,
                 head_raw, free_count, element_size,
                 gpool ? host.MemoryRead32(gpool + 28) : 0,
                 gpool ? host.MemoryRead32(gpool + 32) : 0,
                 gpool ? static_cast<int32_t>(host.MemoryRead32(gpool + 36)) : 0);
        }
    });
    RegisterThunk("telltale_log_gpool_ctor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 128) {
            const uint32_t sp = jit.Regs()[13];
            LOGI("GPool::GPool #%u this=0x%08X global=%u name=0x%08X elementSize=%u initial=%u grow=%u heapType=%d",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3],
                 static_cast<uint64_t>(sp) + 12 <= host.GetGuestMemorySize()
                     ? host.MemoryRead32(sp) : 0,
                 static_cast<uint64_t>(sp) + 12 <= host.GetGuestMemorySize()
                     ? host.MemoryRead32(sp + 4) : 0,
                 static_cast<uint64_t>(sp) + 12 <= host.GetGuestMemorySize()
                     ? static_cast<int32_t>(host.MemoryRead32(sp + 8)) : 0);
        }
    });
    RegisterThunk("telltale_log_handle_set_object", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t info = jit.Regs()[0];
        if (count <= 64) {
            LOGI("HandleObjectInfo::SetHandleObjectPointer #%u info=0x%08X old=0x%08X new=0x%08X ra=0x%08X%08X location=0x%08X class=0x%08X flags=0x%08X",
                 count, info, info ? host.MemoryRead32(info + 28) : 0, jit.Regs()[1],
                 info ? host.MemoryRead32(info + 20) : 0, info ? host.MemoryRead32(info + 16) : 0,
                 info ? host.MemoryRead32(info + 24) : 0,
                 info ? host.MemoryRead32(info + 32) : 0,
                 info ? host.MemoryRead32(info + 36) : 0);
        }
    });
    RegisterThunk("telltale_log_propertyset_serialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 16) {
            LOGI("PropertySet::MetaOperation_SerializeAsync #%u this=0x%08X info=0x%08X class=0x%08X member=0x%08X",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
        }
    });
    RegisterThunk("telltale_log_propertylist_serialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 16) {
            const uint32_t member = jit.Regs()[3];
            LOGI("List<PropertySet>::MetaOperation_SerializeAsync #%u list=0x%08X info=0x%08X class=0x%08X member=0x%08X words=%08X/%08X/%08X/%08X/%08X/%08X/%08X",
                 count, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], member,
                 member ? host.MemoryRead32(member) : 0, member ? host.MemoryRead32(member + 4) : 0,
                 member ? host.MemoryRead32(member + 8) : 0, member ? host.MemoryRead32(member + 12) : 0,
                 member ? host.MemoryRead32(member + 16) : 0, member ? host.MemoryRead32(member + 20) : 0,
                 member ? host.MemoryRead32(member + 24) : 0);
        }
    });
    RegisterThunk("telltale_log_propertylist_count", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        const uint32_t sp = jit.Regs()[13];
        const uint32_t list_count = static_cast<uint64_t>(sp) + 12 <= host.GetGuestMemorySize()
            ? host.MemoryRead32(sp + 8) : 0;
        if (count <= 32 || list_count > 1000) {
            const auto word = [&host](uint32_t addr) -> uint32_t {
                return addr && static_cast<uint64_t>(addr) + 4 <= host.GetGuestMemorySize()
                    ? host.MemoryRead32(addr) : 0;
            };
            const auto byte = [&host](uint32_t addr) -> uint32_t {
                return addr < host.GetGuestMemorySize() ? host.MemoryRead8(addr) : 0;
            };
            const uint32_t stream = jit.Regs()[5];
            const uint32_t resource = word(stream + 8);
            const uint32_t depth = word(stream + 12);
            const uint32_t sections = word(stream + 20);
            const uint32_t section_index = depth && depth <= 4 && sections
                ? word(sections + 2328u * (depth - 1) + 2320) : 0;
            const uint32_t section = depth && depth <= 4 && sections && section_index < 4
                ? sections + 2328u * (depth - 1) + 576u * section_index : 0;
            const uint32_t data_stream = word(section);
            const uint64_t stream_pos = static_cast<uint64_t>(word(section + 24)) |
                                         (static_cast<uint64_t>(word(section + 28)) << 32);
            const uint64_t stream_size = static_cast<uint64_t>(word(section + 16)) |
                                          (static_cast<uint64_t>(word(section + 20)) << 32);
            const uint32_t buffer_pos = word(section + 56);
            const uint32_t buffer_size = word(section + 60);
            const uint32_t res_type = word(resource);
            const uint32_t res_symbol_lo = word(resource + 8);
            const uint32_t res_symbol_hi = word(resource + 12);
            const uint32_t res_parent = word(resource + 16);
            const uint32_t before_pos = buffer_pos >= 4 ? section + 64 + buffer_pos - 4 : 0;
            LOGI("List<PropertySet> serialized count #%u value=%u (0x%08X) list=0x%08X "
                 "meta=0x%08X mode=%u depth=%u sections=0x%08X section=%u data=0x%08X "
                 "pos=%llu size=%llu buf=%u/%u before=%02X%02X%02X%02X "
                 "resource=0x%08X type=%u symbol=0x%08X%08X parent=0x%08X "
                 "dsVt=0x%08X ds40=0x%08X ds48=0x%08X ds60=0x%08X ds68=0x%08X",
                 count, list_count, list_count, jit.Regs()[7], stream, word(stream + 28), depth, sections,
                 section_index, data_stream,
                 static_cast<unsigned long long>(stream_pos), static_cast<unsigned long long>(stream_size),
                 buffer_pos, buffer_size, byte(before_pos), byte(before_pos + 1), byte(before_pos + 2), byte(before_pos + 3),
                 resource, res_type, res_symbol_hi, res_symbol_lo, res_parent,
                 word(data_stream), word(data_stream + 40), word(data_stream + 48),
                 word(data_stream + 60), word(data_stream + 68));
        }
    });
    RegisterThunk("telltale_log_handle_property_string", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const uint32_t stream = jit.Regs()[1];
            LOGI("Handle<PropertySet> resource string #%u path='%s' stream=0x%08X mode=%u",
                 count, GuestStringValue(host, jit.Regs()[0]).c_str(), stream,
                 stream ? host.MemoryRead32(stream + 28) : 0);
        }
    });
    RegisterThunk("telltale_log_handle_property_symbol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> calls{0};
        const uint32_t count = ++calls;
        if (count <= 256) {
            const uint32_t symbol = jit.Regs()[0];
            const uint64_t value = static_cast<uint64_t>(symbol ? host.MemoryRead32(symbol) : 0) |
                                    (static_cast<uint64_t>(symbol ? host.MemoryRead32(symbol + 4) : 0) << 32);
            std::string name;
            {
                std::lock_guard<std::mutex> lock(g_resource_name_mutex);
                const auto it = g_resource_names.find(value);
                if (it != g_resource_names.end()) name = it->second;
            }
            LOGI("Handle<PropertySet> resource symbol #%u symbol=0x%08X%08X name='%s' stream=0x%08X mode=%u",
                 count, static_cast<uint32_t>(value >> 32), static_cast<uint32_t>(value), name.c_str(),
                 jit.Regs()[1], jit.Regs()[1] ? host.MemoryRead32(jit.Regs()[1] + 28) : 0);
        }
    });

    // Asset override: see InstallAssetOverrideHook below. R1 is the archive-relative
    // entry name; returning ip=0 makes the veneer return NULL, so the engine's own
    // "not in the archive" path takes over and opens the plain file instead.
    RegisterThunk("asset_override_archive_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[12] = HasAssetOverride(name) ? 0u : g_asset_override_real_fn;
    });
}

// ---------------------------------------------------------------------------
// Loading modified assets from <externalFilesDir>/...
//
// Engines of this era resolve a file through a chain: archive -> optional second
// archive -> plain fopen(rootDir + path). Making the first archive report "not
// found" for any file the user dropped into the override root turns that existing
// fallback into a full mod mechanism, with no archive-format code and no risk to
// the normal path. Point InstallAssetOverrideHook at the guest's archive-open PLT
// slot; everything below is engine-agnostic.
// ---------------------------------------------------------------------------

static std::string g_override_root;   // e.g. /sdcard/Android/data/<pkg>/files/
static bool g_override_enabled = false;

void SetAssetOverrideRoot(const std::string& root) {
    g_override_root = root;
    if (!g_override_root.empty() && g_override_root.back() != '/') g_override_root += '/';
    struct stat st;
    g_override_enabled = !g_override_root.empty() &&
                         stat(g_override_root.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    LOGI("Asset override root: '%s' (%s)", g_override_root.c_str(), g_override_enabled ? "active" : "inactive");
}

bool HasAssetOverride(const char* entry_name) {
    if (!g_override_enabled || !entry_name) return false;
    // Entry names carry the archive layout, e.g. "assets/data/textures/x.bin" or
    // "<expansion-prefix>/assets/data/textures/x.bin"; the override root mirrors
    // everything below "assets/". Adjust this split if the guest archives differ.
    const char* rel = strstr(entry_name, "assets/");
    if (!rel) return false;
    rel += 7;
    if (!*rel) return false;
    std::string path = g_override_root + rel;
    if (access(path.c_str(), R_OK) != 0) return false;
    LOGI("Asset override: '%s' -> '%s'", entry_name, path.c_str());
    return true;
}

void InstallTelltaleCurrentDirectoryFix(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    auto install = [&](const char* symbol, const char* thunk_name) -> bool {
        const uint32_t target = host.FindSymbol(symbol);
        if (!target || (target & 1)) return false;
        const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress(thunk_name);
        const uint32_t svc = host.MemoryRead32(hook);
        if ((svc & 0xFF000000) != 0xEF000000) return false;

        const uint32_t veneer = host.GuestAlloc(32, 4);
        if (!veneer) return false;
        host.MemoryWrite32(veneer + 0, svc);
        host.MemoryWrite32(veneer + 4, host.MemoryRead32(target));
        host.MemoryWrite32(veneer + 8, host.MemoryRead32(target + 4));
        host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
        host.MemoryWrite32(veneer + 16, target + 8);
        host.MemoryWrite32(target + 0, 0xE51FF004);
        host.MemoryWrite32(target + 4, veneer);
        host.InvalidateGuestCode(veneer, 20);
        host.InvalidateGuestCode(target, 8);
        host.AddExecutableRange(veneer, 20);
        LOGI("Installed Telltale hook '%s' at 0x%08X", thunk_name, target);
        return true;
    };

    const bool execute_hook = install("_ZN13ScriptManager7ExecuteERK6String", "telltale_fix_current_directory_script");
    const bool load_hook = install("luaL_loadstring", "telltale_fix_lua_source");
    installed = execute_hook && load_hook;
    if (!installed) LOGE("Unable to install complete Telltale Lua source repair");
}

void InstallTelltaleRenderFrameProbe(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    const uint32_t target = host.FindSymbol("_ZN10GameRender11RenderFrameEv");
    if (!target || (target & 1)) return;
    if (host.MemoryRead32(target) != 0xE92D4FF0 || host.MemoryRead32(target + 4) != 0xED2D8B02) {
        LOGE("RenderFrame probe refused unexpected prologue at 0x%08X", target);
        return;
    }

    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_render_frame");
    const uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) return;

    const uint32_t veneer = host.GuestAlloc(32, 4);
    if (!veneer) return;
    host.MemoryWrite32(veneer + 0, svc);
    host.MemoryWrite32(veneer + 4, host.MemoryRead32(target));
    host.MemoryWrite32(veneer + 8, host.MemoryRead32(target + 4));
    host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 16, target + 8);
    host.MemoryWrite32(target + 0, 0xE51FF004);
    host.MemoryWrite32(target + 4, veneer);
    host.InvalidateGuestCode(veneer, 20);
    host.InvalidateGuestCode(target, 8);
    host.AddExecutableRange(veneer, 20);
    installed = true;
    LOGI("Installed RenderFrame probe at 0x%08X (veneer 0x%08X)", target, veneer);
}

void InstallTelltaleRenderExecuteProbe(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    const uint32_t target = host.FindSymbol("_ZN17RenderThreadFrame20Execute_DefaultFrameEv");
    if (!target || (target & 1)) return;
    if (host.MemoryRead32(target) != 0xE92D4038 || host.MemoryRead32(target + 4) != 0xE1A04000) {
        LOGE("Render execute probe refused unexpected prologue at 0x%08X", target);
        return;
    }

    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_render_execute");
    const uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) return;

    const uint32_t veneer = host.GuestAlloc(32, 4);
    if (!veneer) return;
    host.MemoryWrite32(veneer + 0, svc);
    host.MemoryWrite32(veneer + 4, host.MemoryRead32(target));
    host.MemoryWrite32(veneer + 8, host.MemoryRead32(target + 4));
    host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 16, target + 8);
    host.MemoryWrite32(target + 0, 0xE51FF004);
    host.MemoryWrite32(target + 4, veneer);
    host.InvalidateGuestCode(veneer, 20);
    host.InvalidateGuestCode(target, 8);
    host.AddExecutableRange(veneer, 20);
    installed = true;
    LOGI("Installed RenderThreadFrame execute probe at 0x%08X (veneer 0x%08X)", target, veneer);
}

void InstallTelltaleSceneProbes(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    auto install = [&](const char* symbol, const char* thunk_name, uint32_t first, uint32_t second) {
        const uint32_t target = host.FindSymbol(symbol);
        if (!target || (target & 1)) return false;
        if (host.MemoryRead32(target) != first || host.MemoryRead32(target + 4) != second) {
            LOGE("Scene probe refused unexpected prologue for '%s' at 0x%08X", symbol, target);
            return false;
        }
        const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress(thunk_name);
        const uint32_t svc = host.MemoryRead32(hook);
        if ((svc & 0xFF000000) != 0xEF000000) return false;

        const uint32_t veneer = host.GuestAlloc(32, 4);
        if (!veneer) return false;
        host.MemoryWrite32(veneer + 0, svc);
        host.MemoryWrite32(veneer + 4, first);
        host.MemoryWrite32(veneer + 8, second);
        host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
        host.MemoryWrite32(veneer + 16, target + 8);
        host.MemoryWrite32(target + 0, 0xE51FF004);
        host.MemoryWrite32(target + 4, veneer);
        host.InvalidateGuestCode(veneer, 20);
        host.InvalidateGuestCode(target, 8);
        host.AddExecutableRange(veneer, 20);
        LOGI("Installed scene probe '%s' at 0x%08X (veneer 0x%08X)", symbol, target, veneer);
        return true;
    };

    const bool add = install("_ZN5Scene8AddSceneERK15ResourceAddressRK6String",
                             "telltale_log_scene_add", 0xE92D43F0, 0xE1A07001);
    const bool open = install("_ZN5Scene9OpenSceneERK15ResourceAddressRK6String",
                              "telltale_log_scene_open", 0xE92D41F0, 0xE1A05001);
    installed = add && open;
    if (!installed) LOGE("Unable to install complete Telltale scene probes");
}

void InstallTelltaleDoLoadProbe(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    const uint32_t target = host.FindSymbol("_ZN13ScriptManager6DoLoadERK6String");
    if (!target || (target & 1)) return;
    if (host.MemoryRead32(target) != 0xE92D4FF0 || host.MemoryRead32(target + 4) != 0xE24DD024) {
        LOGE("DoLoad probe refused unexpected prologue at 0x%08X", target);
        return;
    }
    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_doload");
    const uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) return;

    const uint32_t veneer = host.GuestAlloc(32, 4);
    if (!veneer) return;
    host.MemoryWrite32(veneer + 0, svc);
    host.MemoryWrite32(veneer + 4, host.MemoryRead32(target));
    host.MemoryWrite32(veneer + 8, host.MemoryRead32(target + 4));
    host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 16, target + 8);
    host.MemoryWrite32(target + 0, 0xE51FF004);
    host.MemoryWrite32(target + 4, veneer);
    host.InvalidateGuestCode(veneer, 20);
    host.InvalidateGuestCode(target, 8);
    host.AddExecutableRange(veneer, 20);

    const uint32_t load_result_site = target + 0x30;
    if (host.MemoryRead32(load_result_site) != 0xE2501000 || host.MemoryRead32(load_result_site + 4) != 0x1A000042) {
        LOGE("DoLoad LoadResource probe refused unexpected branch at 0x%08X", load_result_site);
        return;
    }
    const uint32_t load_result_hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_loadresource_result");
    const uint32_t load_result_svc = host.MemoryRead32(load_result_hook);
    if ((load_result_svc & 0xFF000000) != 0xEF000000) return;
    const uint32_t load_result_veneer = host.GuestAlloc(32, 4);
    if (!load_result_veneer) return;
    host.MemoryWrite32(load_result_veneer + 0, load_result_svc);
    host.MemoryWrite32(load_result_veneer + 4, 0xE2501000); // subs r1, r0, #0
    host.MemoryWrite32(load_result_veneer + 8, 0x0A000001); // beq fall-through path
    host.MemoryWrite32(load_result_veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(load_result_veneer + 16, target + 0x144); // original BNE target
    host.MemoryWrite32(load_result_veneer + 20, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(load_result_veneer + 24, target + 0x38); // fall-through after original BNE
    host.MemoryWrite32(load_result_site, 0xE51FF004);
    host.MemoryWrite32(load_result_site + 4, load_result_veneer);
    host.InvalidateGuestCode(load_result_veneer, 28);
    host.InvalidateGuestCode(load_result_site, 8);
    host.AddExecutableRange(load_result_veneer, 28);

    const uint32_t call_result_site = target + 0x44;
    if (host.MemoryRead32(call_result_site) != 0xE2508000 || host.MemoryRead32(call_result_site + 4) != 0x0A00002C) {
        LOGE("DoLoad TTPCall probe refused unexpected branch at 0x%08X", call_result_site);
        return;
    }
    const uint32_t call_result_hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_ttpcall_result");
    const uint32_t call_result_svc = host.MemoryRead32(call_result_hook);
    if ((call_result_svc & 0xFF000000) != 0xEF000000) return;
    const uint32_t call_result_veneer = host.GuestAlloc(32, 4);
    if (!call_result_veneer) return;
    host.MemoryWrite32(call_result_veneer + 0, call_result_svc);
    host.MemoryWrite32(call_result_veneer + 4, 0xE2508000); // subs r8, r0, #0
    host.MemoryWrite32(call_result_veneer + 8, 0x0A000001); // beq original error path
    host.MemoryWrite32(call_result_veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(call_result_veneer + 16, target + 0x4C); // original success path
    host.MemoryWrite32(call_result_veneer + 20, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(call_result_veneer + 24, target + 0x100); // original BEQ target
    host.MemoryWrite32(call_result_site, 0xE51FF004);
    host.MemoryWrite32(call_result_site + 4, call_result_veneer);
    host.InvalidateGuestCode(call_result_veneer, 28);
    host.InvalidateGuestCode(call_result_site, 8);
    host.AddExecutableRange(call_result_veneer, 28);

    const uint32_t result_site = target + 0x138;
    if (host.MemoryRead32(result_site) != 0xE1A00008 || host.MemoryRead32(result_site + 4) != 0xE28DD024) {
        LOGE("DoLoad result probe refused unexpected epilogue at 0x%08X", result_site);
        return;
    }
    const uint32_t result_hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_doload_result");
    const uint32_t result_svc = host.MemoryRead32(result_hook);
    if ((result_svc & 0xFF000000) != 0xEF000000) return;
    const uint32_t result_veneer = host.GuestAlloc(32, 4);
    if (!result_veneer) return;
    host.MemoryWrite32(result_veneer + 0, 0xE1A00008); // mov r0, r8: DoLoad result
    host.MemoryWrite32(result_veneer + 4, 0xE1A01007); // mov r1, r7: DoLoad String object
    host.MemoryWrite32(result_veneer + 8, result_svc);
    host.MemoryWrite32(result_veneer + 12, 0xE28DD024); // add sp, sp, #0x24
    host.MemoryWrite32(result_veneer + 16, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(result_veneer + 20, target + 0x140); // original pop {r4-r11,pc}
    host.MemoryWrite32(result_site, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(result_site + 4, result_veneer);
    host.InvalidateGuestCode(result_veneer, 24);
    host.InvalidateGuestCode(result_site, 8);
    host.AddExecutableRange(result_veneer, 24);
    installed = true;
    LOGI("Installed DoLoad probe at 0x%08X (result veneer 0x%08X)", target, result_veneer);
}

void InstallTelltaleTTPCallErrorProbe(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    const uint32_t target = host.FindSymbol("_ZN13ScriptManager7TTPCallEP9lua_Stateii");
    if (!target || (target & 1)) return;
    const uint32_t site = target + 0x34;
    if (host.MemoryRead32(site) != 0xEBFFFFF0 || host.MemoryRead32(site + 4) != 0xE1A00006) {
        LOGE("TTPCall error probe refused unexpected call site at 0x%08X", site);
        return;
    }
    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_ttpcall_error");
    const uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) return;
    const uint32_t veneer = host.GuestAlloc(32, 4);
    if (!veneer) return;
    host.MemoryWrite32(veneer + 0, svc);
    host.MemoryWrite32(veneer + 4, 0xE1A00006); // mov r0, r6: original Error argument
    host.MemoryWrite32(veneer + 8, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 12, target + 0x3C); // original lua_settop setup
    host.MemoryWrite32(site, 0xE51FF004);
    host.MemoryWrite32(site + 4, veneer);
    host.InvalidateGuestCode(veneer, 16);
    host.InvalidateGuestCode(site, 8);
    host.AddExecutableRange(veneer, 16);
    installed = true;
    LOGI("Installed TTPCall error probe at 0x%08X (veneer 0x%08X)", site, veneer);
}

void InstallTelltaleArchiveProbe(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    const uint32_t target = host.FindSymbol("_ZN23ResourceLocationFactory15CreateTTArchiveERK6SymbolRK3PtrI10DataStreamEb");
    if (!target || (target & 1)) return;
    if (host.MemoryRead32(target) != 0xE92D41F0 || host.MemoryRead32(target + 4) != 0xE1A04000) {
        LOGE("Archive probe refused unexpected prologue at 0x%08X", target);
        return;
    }
    const uint32_t site = target + 0x28;
    if (host.MemoryRead32(site) != 0xE1A00004 || host.MemoryRead32(site + 4) != 0xE28DD008) {
        LOGE("Archive probe refused unexpected epilogue at 0x%08X", site);
        return;
    }
    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_ttarchive_result");
    const uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) return;
    const uint32_t veneer = host.GuestAlloc(32, 4);
    if (!veneer) return;
    host.MemoryWrite32(veneer + 0, 0xE1A00004); // mov r0, r4: output pointer
    host.MemoryWrite32(veneer + 4, svc);
    host.MemoryWrite32(veneer + 8, 0xE28DD008); // add sp, sp, #8
    host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 16, target + 0x30); // original pop {r4-r8,pc}
    host.MemoryWrite32(site, 0xE51FF004);
    host.MemoryWrite32(site + 4, veneer);
    host.InvalidateGuestCode(veneer, 20);
    host.InvalidateGuestCode(site, 8);
    host.AddExecutableRange(veneer, 20);
    installed = true;
    LOGI("Installed archive result probe at 0x%08X (veneer 0x%08X)", target, veneer);
}

void InstallTelltaleStartupProbes(DynarmicHost& host) {
    static bool installed = false;
    if (installed) return;

    auto install = [&](const char* symbol, const char* thunk_name, uint32_t first, uint32_t second) {
        const uint32_t target = host.FindSymbol(symbol);
        if (!target || (target & 1)) return false;
        if (host.MemoryRead32(target) != first || host.MemoryRead32(target + 4) != second) {
            LOGE("Startup probe refused unexpected prologue for '%s' at 0x%08X", symbol, target);
            return false;
        }
        const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress(thunk_name);
        const uint32_t svc = host.MemoryRead32(hook);
        if ((svc & 0xFF000000) != 0xEF000000) return false;

        const uint32_t veneer = host.GuestAlloc(32, 4);
        if (!veneer) return false;
        host.MemoryWrite32(veneer + 0, svc);
        host.MemoryWrite32(veneer + 4, first);
        host.MemoryWrite32(veneer + 8, second);
        host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc, [pc, #-4]
        host.MemoryWrite32(veneer + 16, target + 8);
        host.MemoryWrite32(target + 0, 0xE51FF004);
        host.MemoryWrite32(target + 4, veneer);
        host.InvalidateGuestCode(veneer, 20);
        host.InvalidateGuestCode(target, 8);
        host.AddExecutableRange(veneer, 20);
        LOGI("Installed startup probe '%s' at 0x%08X (veneer 0x%08X)", symbol, target, veneer);
        return true;
    };

    const bool scene_add = install("_Z11luaSceneAddP9lua_State", "telltale_log_lua_scene_add",
                                   0xE92D4FF0, 0xE24DD03C);
    const bool scene_open = install("_Z12luaSceneOpenP9lua_State", "telltale_log_lua_scene_open",
                                    0xE92D43F0, 0xE24DD04C);
    const bool load_script = install("_Z13luaLoadScriptP9lua_State", "telltale_log_lua_load_script",
                                     0xE92D4070, 0xE1A04000);
    const bool resource_set_exists = install("_Z20luaResourceSetExistsP9lua_State", "telltale_log_resource_set_exists",
                                             0xE92D4030, 0xE24DD014);
    const bool resource_exists = install("_Z17luaResourceExistsP9lua_State", "telltale_log_resource_exists",
                                         0xE92D40F0, 0xE1A04000);
    const bool resource_set_enable = install("_Z20luaResourceSetEnableP9lua_State", "telltale_log_resource_set_enable",
                                              0xE92D40F0, 0xE24DD014);
    const bool resource_set_default = install("_Z29luaResourceSetDefaultLocationP9lua_State",
                                               "telltale_log_resource_set_default_location",
                                               0xE92D40F0, 0xE1A04000);
    const bool get_preferences = install("_Z17luaGetPreferencesP9lua_State", "telltale_log_lua_get_preferences",
                                         0xE92D4010, 0xE1A04000);
    const bool random_seed = install("_Z13luaRandomSeedP9lua_State", "telltale_log_lua_random_seed",
                                     0xE92D4038, 0xE1A04000);
    const bool start_external = install("_Z25luaStartExternalPlatformsP9lua_State", "telltale_log_lua_start_external",
                                        0xE92D4010, 0xE1A04000);
    const bool property_set = install("_Z14luaPropertySetP9lua_State", "telltale_log_lua_property_set",
                                      0xE92D4070, 0xE24DD010);
    const bool property_exists = install("_Z17luaPropertyExistsP9lua_State", "telltale_log_lua_property_exists",
                                         0xE92D40F0, 0xE24DD014);
    const bool lua_save = install("_Z7luaSaveP9lua_State", "telltale_log_lua_save",
                                  0xE92D40F0, 0xE24DD014);
    const bool lua_create = install("_Z9luaCreateP9lua_State", "telltale_log_lua_create",
                                    0xE92D4FF0, 0xE1A06000);
    const bool user_signed_in = install("_Z25luaPlatformIsUserSignedInP9lua_State", "telltale_log_lua_user_signed_in",
                                        0xE92D4010, 0xE1A04000);
    const bool mount_directory = install("_Z18T3_MOUNT_DIRECTORYPKcS0_", "telltale_log_mount_directory",
                                         0xE92D4FF0, 0xE24DD094);
    const bool resource_directory_create = install("_ZN17ResourceDirectory6CreateERK6Stringb",
                                                   "telltale_log_resource_directory_create",
                                                   0xE92D41F0, 0xE24DD020);
    const bool resource_location_directory = install("_ZN23ResourceLocationFactory15CreateDirectoryERK6SymbolRK3PtrI17ResourceDirectoryE",
                                                      "telltale_log_resource_location_directory",
                                                      0xE92D40F8, 0xE1A04000);
    const bool concrete_get_resources = install("_ZN24ResourceConcreteLocation12GetResourcesER3MapI6Symbol15ResourceAddressSt4lessIS1_EEPK10StringMask",
                                                 "telltale_log_concrete_get_resources", 0xE92D4FF0, 0xE1A0A000);
    const bool concrete_ptr_get_resources = install("_ZN24ResourceConcreteLocation12GetResourcesER3MapI6Symbol3PtrIS_ESt4lessIS1_EEPK10StringMask",
                                                    "telltale_log_concrete_ptr_get_resources", 0xE92D4FF0, 0xE1A0B000);
    const bool directory_get_resources = install("_ZN34ResourceConcreteLocation_Directory12GetResourcesER3SetI6SymbolSt4lessIS1_EEPK10StringMask",
                                                  "telltale_log_directory_get_resources", 0xE92D4FF0, 0xE24DD03C);
    const bool bundle_get_resources = install("_ZN31ResourceConcreteLocation_Bundle12GetResourcesER3SetI6SymbolSt4lessIS1_EEPK10StringMask",
                                               "telltale_log_bundle_get_resources", 0xE92D4FF0, 0xE1A07001);
    const bool logical_get_resources = install("_ZN23ResourceLogicalLocation12GetResourcesER3MapI6Symbol15ResourceAddressSt4lessIS1_EEPK10StringMask",
                                               "telltale_log_logical_get_resources", 0xE92D41F0, 0xE280801C);
    const bool logical_set_get_resources = install("_ZN23ResourceLogicalLocation12GetResourcesER3SetI6SymbolSt4lessIS1_EEPK10StringMask",
                                                   "telltale_log_logical_get_resources", 0xE92D41F0, 0xE280801C);
    const bool ttarchive_get_resources = install("_ZN10TTArchive212GetResourcesER3SetI6SymbolSt4lessIS1_EEPK10StringMask",
                                                 "telltale_log_ttarchive_get_resources", 0xE2523000, 0xE92D43F0);
    const bool resource_resolve_url = install("_Z31luaResourceResolveURLToConcreteP9lua_State",
                                              "telltale_log_resource_resolve_url",
                                              0xE92D40F0, 0xE1A04000);
    const bool resource_resolve_address = install("_Z45luaResourceResolveAddressToConcreteLocationIDP9lua_State",
                                                   "telltale_log_resource_resolve_address",
                                                   0xE92D43F0, 0xE1A04000);
    const bool resource_address_name = install("_Z33luaResourceAddressGetResourceNameP9lua_State",
                                               "telltale_log_resource_address_name",
                                               0xE92D41F0, 0xE1A04000);
    const bool resource_create_archive = install("_Z40luaResourceCreateConcreteArchiveLocationP9lua_State",
                                                  "telltale_log_resource_create_archive",
                                                  0xE92D43F0, 0xE24DD034);
    const bool resource_patch_apply = install("_ZN16ResourcePatchSet5ApplyEbb", "telltale_log_resource_patch_apply",
                                               0xE92D4FF0, 0xE24DD094);
    const bool meta_open = install("_ZN10MetaStream4OpenERK21ResourceAddressString14MetaStreamModeRK16MetaStreamParams",
                                   "telltale_log_metastream_open", 0xE92D43F0, 0xE1A06000);
    const bool meta_attach = install("_ZN10MetaStream6AttachERK3PtrI10DataStreamE14MetaStreamModeRK16MetaStreamParams",
                                     "telltale_log_metastream_attach", 0xE92D4FF0, 0xE591C000);
    const bool meta_read = install("_ZN10MetaStream8ReadDataEPvj", "telltale_log_metastream_read",
                                   0xE590C00C, 0xE3003918);
    const bool posix_read = install("_ZN20DataStreamFile_Posix4ReadER12DataStreamOp", "telltale_log_posix_read",
                                    0xE92D43F8, 0xE1A05000);
    const bool resource_address_ctor = install("_ZN15ResourceAddressC1ERK6String", "telltale_log_resource_address_ctor",
                                                0xE92D4030, 0xE1A04000);
    const bool meta_load = install("_ZN4Meta18MetaOperation_LoadEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS0_",
                                   "telltale_log_meta_load", 0xE92D4FF0, 0xE24DD064);
    const bool handle_info_ctor = install("_ZN16HandleObjectInfoC2ERK15ResourceAddressPK20MetaClassDescriptionPv",
                                          "telltale_log_handle_info_ctor", 0xE92D43F0, 0xE1A05001);
    const bool async_thread = install("_ZN18AsyncStreamManager18_RequestThreadFuncEPv", "telltale_log_async_thread",
                                      0xE92D4FF8, 0xE1A05000);
    const bool async_request = install("_ZN18AsyncStreamManager10_DoRequestER18AsyncStreamRequest", "telltale_log_async_request",
                                       0xE92D4FF0, 0xE24DD04C);
    const bool async_finish = install("_ZN18AsyncStreamManager14_FinishRequestER18AsyncStreamRequestby", "telltale_log_async_finish",
                                      0xE92D4FF0, 0xE24DD04C);
    const bool data_read = install("_ZN22DataStreamFile_Android4ReadER12DataStreamOp", "telltale_log_data_read",
                                   0xE92D43F8, 0xE1A05000);
    const bool async_load_wait = install("_ZN16AsyncLoadManager4WaitE3PtrI16HandleObjectInfoE", "telltale_log_async_load_wait",
                                         0xE92D40F8, 0xE5913000);
    const bool android_heap_alloc_aligned = install("_ZN11AndroidHeap12AllocAlignedE8HeapTypeii",
                                                    "telltale_log_android_heap_alloc_aligned",
                                                    0xE92D47F0, 0xE1A05002);
    const bool android_heap_free = install("_ZN11AndroidHeap4FreeEPv", "telltale_log_android_heap_free",
                                           0xE92D4010, 0xE1A04001);
    const bool cache_copy = install("_ZN39ResourceConcreteLocation_CacheDirectory14_CopyDirectoryEP17ResourceDirectoryS1_",
                                    "telltale_log_cache_copy_directory", 0xE92D4FF0, 0xE5904058);
    const bool memory_stream_write = install("_ZN16DataStreamMemory5WriteER12DataStreamOp",
                                             "telltale_log_memory_stream_write", 0xE1C120D8, 0xE92D4FF0);
    const bool pool_initialize = install("_ZN4Pool10InitializeEi", "telltale_log_pool_initialize",
                                         0xE92D4070, 0xE1A04000);
    const bool gpool_alloc = install("_ZN5GPool5AllocEjPKc", "telltale_log_gpool_alloc",
                                     0xE92D47F0, 0xE2806010);
    const bool gpool_ctor = install("_ZN5GPoolC2EbPKciii8HeapType", "telltale_log_gpool_ctor",
                                    0xE92D4FF0, 0xE24DD00C);
    const bool handle_set_object = install("_ZN16HandleObjectInfo22SetHandleObjectPointerEPv",
                                           "telltale_log_handle_set_object", 0xE92D40F8, 0xE590601C);
    const bool propertyset_serialize = install("_ZN11PropertySet28MetaOperation_SerializeAsyncEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS0_",
                                                "telltale_log_propertyset_serialize", 0xE92D4FF0, 0xE24DD0C4);
    const bool propertylist_serialize = install("_ZN4ListI6HandleI11PropertySetEE28MetaOperation_SerializeAsyncEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS4_",
                                                "telltale_log_propertylist_serialize", 0xE92D4FF0, 0xE1A07000);
    auto install_mcsm_save_probe = [&](const char* symbol, uint32_t offset,
                                       uint32_t first, uint32_t second, const char* thunk_name) {
        const uint32_t target = host.FindSymbol(symbol);
        const uint32_t site = target + offset;
        if (!target || (target & 1u) || host.MemoryRead32(site) != first ||
            host.MemoryRead32(site + 4u) != second) return;
        const uint32_t thunk = host.GetThunkManager().GetOrCreateThunkAddress(thunk_name);
        const uint32_t svc = host.MemoryRead32(thunk);
        if ((svc & 0xFF000000u) != 0xEF000000u) return;
        const uint32_t veneer = host.GuestAlloc(20, 4);
        if (!veneer) return;
        host.MemoryWrite32(veneer, svc);
        host.MemoryWrite32(veneer + 4u, first);
        host.MemoryWrite32(veneer + 8u, second);
        host.MemoryWrite32(veneer + 12u, 0xE51FF004u);
        host.MemoryWrite32(veneer + 16u, site + 8u);
        host.MemoryWrite32(site, 0xE51FF004u);
        host.MemoryWrite32(site + 4u, veneer);
        host.InvalidateGuestCode(veneer, 20);
        host.InvalidateGuestCode(site, 8);
        host.AddExecutableRange(veneer, 20);
        LOGI("Installed MCSM save diagnostic probe '%s' at 0x%08X", symbol, site);
    };
    install_mcsm_save_probe("_Z25luaPlatformIsUserSignedInP9lua_State", 0x30u,
                            0xE1A01000u, 0xE1A00004u, "telltale_log_minecraft_signedin_result");
    install_mcsm_save_probe("_ZN16HandleObjectInfo9QuickSaveEv", 0x10u,
                            0xE24DD018u, 0xE590601Cu, "telltale_log_minecraft_quicksave");
    bool propertylist_count_hook = false;
    bool handle_property_string_hook = false;
    bool handle_property_symbol_hook = false;
    bool handle_base_set_object_hook = false;
    bool project_pref_enum_hook = false;
    bool mask_compare_hook = false;
    bool mask_compare_call_hook = false;
    const uint32_t list_target = host.FindSymbol("_ZN4ListI6HandleI11PropertySetEE28MetaOperation_SerializeAsyncEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS4_");
    if (list_target && !(list_target & 1)) {
        const uint32_t site = list_target + 0x48;
        const uint32_t original_call = host.MemoryRead32(site);
        const uint32_t original_next = host.MemoryRead32(site + 4);
        if (original_call == 0xE12FFF33 && original_next == 0xE5953000) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_propertylist_count");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(32, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, original_call);
                    host.MemoryWrite32(veneer + 4, svc);
                    host.MemoryWrite32(veneer + 8, original_next);
                    host.MemoryWrite32(veneer + 12, 0xE51FF004);
                    host.MemoryWrite32(veneer + 16, site + 8);
                    host.MemoryWrite32(site, 0xE51FF004);
                    host.MemoryWrite32(site + 4, veneer);
                    host.InvalidateGuestCode(veneer, 20);
                    host.InvalidateGuestCode(site, 8);
                    host.AddExecutableRange(veneer, 20);
                    propertylist_count_hook = true;
                    LOGI("Installed PropertySet list-count hook at 0x%08X (veneer 0x%08X)", site, veneer);
                }
            }
        } else {
            LOGE("PropertySet list-count hook refused unexpected site at 0x%08X: 0x%08X 0x%08X",
                 site, original_call, original_next);
        }
    }
    const uint32_t handle_target = host.FindSymbol("_ZN6HandleI11PropertySetE28MetaOperation_SerializeAsyncEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS2_");
    if (false && handle_target && !(handle_target & 1)) {
        const uint32_t site = handle_target + 0x110;
        const uint32_t original_call = host.MemoryRead32(site);
        const uint32_t original_next = host.MemoryRead32(site + 4);
        if (original_call == 0xE12FFF33 && original_next == 0xE59D3004) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_handle_property_string");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(48, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, 0xE92D0030); // push {r4,r5}
                    host.MemoryWrite32(veneer + 4, 0xE1A04001); // mov r4,r1: String object
                    host.MemoryWrite32(veneer + 8, 0xE1A05000); // mov r5,r0: MetaStream
                    host.MemoryWrite32(veneer + 12, original_call); // blx r3
                    host.MemoryWrite32(veneer + 16, 0xE1A00004); // mov r0,r4
                    host.MemoryWrite32(veneer + 20, 0xE1A01005); // mov r1,r5
                    host.MemoryWrite32(veneer + 24, svc);
                    host.MemoryWrite32(veneer + 28, 0xE8BD0030); // pop {r4,r5}
                    host.MemoryWrite32(veneer + 32, 0xE51FF004); // ldr pc, [pc, #-4]
                    host.MemoryWrite32(veneer + 36, site + 4);
                    host.MemoryWrite32(site, 0xE51FF004);
                    host.MemoryWrite32(site + 4, veneer);
                    host.InvalidateGuestCode(veneer, 40);
                    host.InvalidateGuestCode(site, 8);
                    host.AddExecutableRange(veneer, 40);
                    handle_property_string_hook = true;
                    LOGI("Installed Handle<PropertySet> resource-string hook at 0x%08X (veneer 0x%08X)", site, veneer);
                }
            }
        } else {
            LOGE("Handle<PropertySet> resource-string hook refused unexpected site at 0x%08X: 0x%08X 0x%08X",
                 site, original_call, original_next);
        }
        const uint32_t symbol_site = handle_target + 0x78;
        const uint32_t symbol_call = host.MemoryRead32(symbol_site);
        const uint32_t symbol_next = host.MemoryRead32(symbol_site + 4);
        if (symbol_call == 0xE12FFF33 && symbol_next == 0xE1CD20D8) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_handle_property_symbol");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(48, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, 0xE92D0030); // push {r4,r5}
                    host.MemoryWrite32(veneer + 4, 0xE1A04001); // mov r4,r1: Symbol object
                    host.MemoryWrite32(veneer + 8, 0xE1A05000); // mov r5,r0: MetaStream
                    host.MemoryWrite32(veneer + 12, symbol_call); // blx r3
                    host.MemoryWrite32(veneer + 16, 0xE1A00004); // mov r0,r4
                    host.MemoryWrite32(veneer + 20, 0xE1A01005); // mov r1,r5
                    host.MemoryWrite32(veneer + 24, svc);
                    host.MemoryWrite32(veneer + 28, 0xE8BD0030); // pop {r4,r5}
                    host.MemoryWrite32(veneer + 32, 0xE51FF004); // ldr pc, [pc, #-4]
                    host.MemoryWrite32(veneer + 36, symbol_site + 4);
                    host.MemoryWrite32(symbol_site, 0xE51FF004);
                    host.MemoryWrite32(symbol_site + 4, veneer);
                    host.InvalidateGuestCode(veneer, 40);
                    host.InvalidateGuestCode(symbol_site, 8);
                    host.AddExecutableRange(veneer, 40);
                    handle_property_symbol_hook = true;
                    LOGI("Installed Handle<PropertySet> resource-symbol hook at 0x%08X (veneer 0x%08X)", symbol_site, veneer);
                }
            }
        } else {
            LOGE("Handle<PropertySet> resource-symbol hook refused unexpected site at 0x%08X: 0x%08X 0x%08X",
                 symbol_site, symbol_call, symbol_next);
        }
    }
    const uint32_t base_set_object = host.FindSymbol("_ZN10HandleBase9SetObjectERK15ResourceAddressPK20MetaClassDescription");
    const uint32_t singleton = host.FindSymbol("_ZN21HandleObjectInfoCache11smSingletonE");
    if (false && base_set_object && !(base_set_object & 1) && singleton) {
        const uint32_t original_first = host.MemoryRead32(base_set_object);
        const uint32_t original_second = host.MemoryRead32(base_set_object + 4);
        const uint32_t original_third = host.MemoryRead32(base_set_object + 8);
        if (original_first == 0xE59FC078 && original_second == 0xE92D4030 && original_third == 0xE1A0E001) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_handle_base_set_object");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(32, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, svc);
                    host.MemoryWrite32(veneer + 4, 0xE92D4030); // push {r4,r5,lr}
                    host.MemoryWrite32(veneer + 8, 0xE1A0E001); // mov lr,r1
                    host.MemoryWrite32(veneer + 12, 0xE59FC008); // ldr ip,[pc,#8]
                    host.MemoryWrite32(veneer + 16, 0xE51FF004); // ldr pc,[pc,#-4]
                    host.MemoryWrite32(veneer + 20, base_set_object + 16);
                    host.MemoryWrite32(veneer + 24, 0);
                    host.MemoryWrite32(veneer + 28, singleton);
                    host.MemoryWrite32(base_set_object, 0xE51FF004);
                    host.MemoryWrite32(base_set_object + 4, veneer);
                    host.InvalidateGuestCode(veneer, 32);
                    host.InvalidateGuestCode(base_set_object, 8);
                    host.AddExecutableRange(veneer, 32);
                    handle_base_set_object_hook = true;
                    LOGI("Installed HandleBase::SetObject hook at 0x%08X (veneer 0x%08X)", base_set_object, veneer);
                }
            }
        } else {
            LOGE("HandleBase::SetObject hook refused unexpected prologue at 0x%08X: 0x%08X 0x%08X 0x%08X",
                 base_set_object, original_first, original_second, original_third);
        }
    }
    const uint32_t project_prefs = host.FindSymbol("_ZN10GameEngine16OpenProjectPrefsEv");
    // Temporarily disable this call-site probe; OpenProjectPrefs stays untouched.
    if (false && project_prefs && !(project_prefs & 1)) {
        const uint32_t site = project_prefs + 0x160;
        const uint32_t original_call = host.MemoryRead32(site);
        const uint32_t original_next = host.MemoryRead32(site + 4);
        if (original_call == 0xE12FFF33 && original_next == 0xE59D5080) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_project_pref_enum");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(20, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, svc);
                    host.MemoryWrite32(veneer + 4, original_call);
                    host.MemoryWrite32(veneer + 8, 0xE51FF004); // ldr pc, [pc, #-4]
                    host.MemoryWrite32(veneer + 12, site + 4);
                    host.MemoryWrite32(site, 0xE51FF004);
                    host.MemoryWrite32(site + 4, veneer);
                    host.InvalidateGuestCode(veneer, 16);
                    host.InvalidateGuestCode(site, 8);
                    host.AddExecutableRange(veneer, 16);
                    project_pref_enum_hook = true;
                    LOGI("Installed OpenProjectPrefs enumeration hook at 0x%08X (veneer 0x%08X)", site, veneer);
                }
            }
        } else {
            LOGE("OpenProjectPrefs enumeration hook refused unexpected site at 0x%08X: 0x%08X 0x%08X",
                 site, original_call, original_next);
        }
    }
    const uint32_t mask_target = host.FindSymbol("_ZN10StringMask11MaskCompareEPKcS1_S1_NS_8MaskModeE");
    const ElfLoader* game_engine = host.FindModule("libGameEngine.so");
    if (false && mask_target && !(mask_target & 1) && game_engine) {
        const uint32_t original_first = host.MemoryRead32(mask_target);
        const uint32_t original_second = host.MemoryRead32(mask_target + 4);
        if (original_first == 0xE92D4FF0 && original_second == 0xE59F4420) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_mask_compare");
            const uint32_t svc = host.MemoryRead32(hook);
            if ((svc & 0xFF000000) == 0xEF000000) {
                const uint32_t veneer = host.GuestAlloc(32, 4);
                if (veneer) {
                    host.MemoryWrite32(veneer + 0, svc);
                    host.MemoryWrite32(veneer + 4, original_first);
                    host.MemoryWrite32(veneer + 8, 0xE59F4008); // ldr r4,[pc,#8]
                    host.MemoryWrite32(veneer + 12, 0xE51FF004); // ldr pc,[pc,#-4]
                    host.MemoryWrite32(veneer + 16, mask_target + 12);
                    host.MemoryWrite32(veneer + 20, 0);
                    host.MemoryWrite32(veneer + 24, game_engine->GetBaseAddress() + 0x1085214);
                    host.MemoryWrite32(mask_target, 0xE51FF004);
                    host.MemoryWrite32(mask_target + 4, veneer);
                    host.InvalidateGuestCode(veneer, 28);
                    host.InvalidateGuestCode(mask_target, 8);
                    host.AddExecutableRange(veneer, 28);
                    mask_compare_hook = true;
                    LOGI("Installed StringMask::MaskCompare entry hook at 0x%08X (veneer 0x%08X)", mask_target, veneer);
                }
            }
        } else {
            LOGE("StringMask::MaskCompare entry hook refused unexpected prologue at 0x%08X: 0x%08X 0x%08X",
                 mask_target, original_first, original_second);
        }
    }
    const uint32_t mask_call_owner = host.FindSymbol("_ZN10TTArchive213_GetResourcesEP3SetI6SymbolSt4lessIS1_EEPS0_I6StringS2_IS6_EEPK10StringMask");
    // Temporarily disable this call-site probe; the real MaskCompare stays untouched.
    if (false && mask_call_owner && !(mask_call_owner & 1) && mask_target && !(mask_target & 1)) {
        const uint32_t site = mask_call_owner + 0x180;
        const uint32_t original_call = host.MemoryRead32(site);
        const uint32_t original_next = host.MemoryRead32(site + 4);
        if (original_call == 0xEBF88399 && original_next == 0xE3500000) {
            const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("telltale_log_mask_compare");
            const uint32_t svc = host.MemoryRead32(hook);
            const uint32_t veneer = host.GuestAlloc(64, 4);
            const int64_t branch_delta = static_cast<int64_t>(veneer) - static_cast<int64_t>(site + 8);
            if ((svc & 0xFF000000) == 0xEF000000 && veneer &&
                branch_delta >= -(1LL << 25) && branch_delta < (1LL << 25) && (branch_delta & 3) == 0) {
                host.MemoryWrite32(veneer + 0, 0xE92D4070); // push {r4,r5,r6,lr}
                host.MemoryWrite32(veneer + 4, 0xE1A04000); // mov r4,r0: mask
                host.MemoryWrite32(veneer + 8, 0xE1A05001); // mov r5,r1: candidate
                host.MemoryWrite32(veneer + 12, 0xE59FC01C); // ldr ip,[pc,#28]
                host.MemoryWrite32(veneer + 16, 0xE12FFF3C); // blx ip
                host.MemoryWrite32(veneer + 20, 0xE1A06000); // mov r6,r0: result
                host.MemoryWrite32(veneer + 24, 0xE1A00004); // mov r0,r4
                host.MemoryWrite32(veneer + 28, 0xE1A01005); // mov r1,r5
                host.MemoryWrite32(veneer + 32, 0xE1A02006); // mov r2,r6
                host.MemoryWrite32(veneer + 36, svc);
                host.MemoryWrite32(veneer + 40, 0xE1A00006); // mov r0,r6
                host.MemoryWrite32(veneer + 44, 0xE8BD8070); // pop {r4,r5,r6,pc}
                host.MemoryWrite32(veneer + 48, mask_target);
                host.MemoryWrite32(site, 0xEB000000u | (static_cast<uint32_t>(branch_delta >> 2) & 0x00FFFFFFu));
                host.InvalidateGuestCode(veneer, 52);
                host.InvalidateGuestCode(site, 4);
                host.AddExecutableRange(veneer, 52);
                mask_compare_call_hook = true;
                LOGI("Installed StringMask::MaskCompare call hook at 0x%08X (veneer 0x%08X)", site, veneer);
            } else {
                LOGE("StringMask::MaskCompare call hook refused branch range at 0x%08X", site);
            }
        } else {
            LOGE("StringMask::MaskCompare call hook refused unexpected site at 0x%08X: 0x%08X 0x%08X",
                 site, original_call, original_next);
        }
    }
    installed = scene_add && scene_open && load_script && resource_set_exists && resource_exists &&
                resource_set_enable && resource_set_default && get_preferences && random_seed &&
                start_external && property_set && property_exists && mount_directory &&
                resource_directory_create && resource_location_directory && concrete_get_resources && concrete_ptr_get_resources &&
                directory_get_resources && bundle_get_resources && logical_get_resources && logical_set_get_resources &&
                ttarchive_get_resources && resource_resolve_url &&
                resource_resolve_address && resource_address_name && resource_create_archive &&
                resource_patch_apply && meta_open && meta_attach && meta_read && posix_read && resource_address_ctor &&
                meta_load && handle_info_ctor && async_thread && async_request && async_finish && data_read && async_load_wait &&
                android_heap_alloc_aligned && android_heap_free && cache_copy && memory_stream_write &&
                pool_initialize && gpool_alloc && gpool_ctor && handle_set_object && propertyset_serialize &&
                propertylist_serialize && propertylist_count_hook;
    if (!installed) LOGE("Unable to install complete Telltale startup probes");
}

void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol) {
    if (!g_override_enabled || !plt_slot || !real_symbol) return;

    static bool s_installed = false;
    if (s_installed) return;

    g_asset_override_real_fn = host.FindSymbol(real_symbol);
    if (!g_asset_override_real_fn) {
        LOGE("InstallAssetOverrideHook: '%s' not found in the guest", real_symbol);
        return;
    }

    uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("asset_override_archive_open");
    uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) {
        LOGE("InstallAssetOverrideHook: unexpected trampoline at 0x%08X", hook);
        return;
    }

    // ARM veneer: run the hook, then either tail-call the real archive-open (ip != 0)
    // or return NULL. BX reaches the whole address space and handles the Thumb bit,
    // so unlike a B-based trampoline there is no +-32 MB limit.
    uint32_t veneer = host.GuestAlloc(32, 4);
    host.MemoryWrite32(veneer + 0,  svc);         // svc  #id
    host.MemoryWrite32(veneer + 4,  0xE35C0000);  // cmp  ip, #0
    host.MemoryWrite32(veneer + 8,  0x112FFF1C);  // bxne ip
    host.MemoryWrite32(veneer + 12, 0xE3A00000);  // mov  r0, #0
    host.MemoryWrite32(veneer + 16, 0xE12FFF1E);  // bx   lr
    host.InvalidateGuestCode(veneer, 32);

    host.MemoryWrite32(plt_slot + 0, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.MemoryWrite32(plt_slot + 4, veneer);
    host.InvalidateGuestCode(plt_slot, 12);
    // The veneer is executable guest code living in the heap, so it must be
    // exempt from runaway-PC containment.
    host.AddExecutableRange(veneer, 32);

    s_installed = true;
    LOGI("Installed asset-override hook on '%s' (plt 0x%08X, veneer 0x%08X)",
         real_symbol, plt_slot, veneer);
}

bool InstallMCSMHideBorderOverride(DynarmicHost& host) {
    constexpr const char* kVignettePaths[] = {
        "files/Net/ui_vignette1.d3dtx",
        "files/Net/ui_vignette2.d3dtx",
    };
    constexpr const char* kVignetteResourceNames[] = {
        "ui_vignette1.d3dtx",
        "ui_vignette2.d3dtx",
    };
    ApkEntry* overrides[2] = {
        FindApkEntry(kVignettePaths[0]),
        FindApkEntry(kVignettePaths[1]),
    };
    if (!overrides[0] && !overrides[1]) {
        LOGI("MCSM hide-border texture split not indexed; keeping original vignette textures.");
        return true;
    }
    if (!overrides[0] || !overrides[1]) {
        LOGE("MCSM hide-border split must include both vignette texture resources.");
        return false;
    }
    constexpr uint8_t kD3DTXMagic[] = {'5', 'V', 'S', 'M'};
    for (size_t i = 0; i < std::size(overrides); ++i) {
        uint8_t magic[sizeof(kD3DTXMagic)]{};
        if (overrides[i]->file_size != 131339 ||
            pread(overrides[i]->apk_fd, magic, sizeof(magic), overrides[i]->data_offset) !=
                static_cast<ssize_t>(sizeof(magic)) ||
            memcmp(magic, kD3DTXMagic, sizeof(kD3DTXMagic)) != 0) {
            LOGE("MCSM hide-border texture %s is not the expected MCSM 1.37 D3DTX asset.",
                 kVignetteResourceNames[i]);
            return false;
        }
    }

    constexpr char kResourceLookupSymbol[] = "_ZN10TTArchive213_FindResourceERK6Symbol";
    constexpr char kCRC64Symbol[] = "_Z21CRC64_CaseInsensitiveyPKc";
    constexpr char kThunkName[] = "mcsm_hide_border_find_vignette_textures";
    ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* lookup_symbol = engine ? engine->GetExportedSymbol(kResourceLookupSymbol) : nullptr;
    const ElfSymbol* crc_symbol = engine ? engine->GetExportedSymbol(kCRC64Symbol) : nullptr;
    if (!lookup_symbol || lookup_symbol->type != STT_FUNC || (lookup_symbol->value & 1u) ||
        !crc_symbol || crc_symbol->type != STT_FUNC || !crc_symbol->value) {
        LOGE("MCSM hide-border override refused: required GameEngine exports are unavailable.");
        return false;
    }

    const uint32_t target = lookup_symbol->value;
    constexpr uint32_t kLookupPrologue0 = 0xE92D40F0u;
    constexpr uint32_t kLookupPrologue1 = 0xE24DD00Cu;
    if (host.MemoryRead32(target) != kLookupPrologue0 ||
        host.MemoryRead32(target + 4u) != kLookupPrologue1) {
        LOGE("MCSM hide-border override refused unexpected TTArchive2 lookup prologue at 0x%08X.", target);
        return false;
    }

    uint64_t vignette_hashes[2]{};
    for (size_t i = 0; i < std::size(vignette_hashes); ++i) {
        const size_t name_size = strlen(kVignetteResourceNames[i]) + 1;
        const uint32_t name_address = host.GuestAlloc(name_size, 1);
        if (!name_address) {
            LOGE("MCSM hide-border override could not allocate resource name %s.",
                 kVignetteResourceNames[i]);
            return false;
        }
        for (size_t j = 0; j < name_size; ++j) {
            host.MemoryWrite8(name_address + static_cast<uint32_t>(j),
                              static_cast<uint8_t>(kVignetteResourceNames[i][j]));
        }
        const uint32_t hash_low = host.RunFunction(crc_symbol->value, {0, 0, name_address});
        vignette_hashes[i] = (static_cast<uint64_t>(host.GetResultHigh()) << 32) | hash_low;
        host.GuestFree(name_address);
        if (!vignette_hashes[i]) {
            LOGE("MCSM hide-border override could not hash resource name %s.",
                 kVignetteResourceNames[i]);
            return false;
        }
    }
    if (vignette_hashes[0] == vignette_hashes[1]) {
        LOGE("MCSM hide-border texture resource hashes unexpectedly collided.");
        return false;
    }

    const uint32_t thunk = host.GetThunkManager().RegisterThunk(
        kThunkName, [vignette_hash_a = vignette_hashes[0], vignette_hash_b = vignette_hashes[1],
                     continuation = target + 8u](Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
            const uint32_t symbol_address = jit.Regs()[1];
            const bool valid_symbol = GuestRangeValid(runtime.GetGuestMemorySize(), symbol_address, 8);
            const uint64_t value = valid_symbol ? runtime.MemoryRead64(symbol_address) : 0;
            jit.Regs()[12] = (value == vignette_hash_a || value == vignette_hash_b) ? 0u : continuation;
        });
    const uint32_t svc = thunk ? host.MemoryRead32(thunk) : 0;
    if (!thunk || (svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("MCSM hide-border override could not register its guest lookup hook.");
        return false;
    }

    const uint32_t veneer = host.GuestAlloc(36, alignof(uint32_t));
    if (!veneer) {
        LOGE("MCSM hide-border override could not allocate its lookup veneer.");
        return false;
    }
    host.MemoryWrite32(veneer + 0u, svc);
    host.MemoryWrite32(veneer + 4u, 0xE35C0000u);
    host.MemoryWrite32(veneer + 8u, 0x1A000001u);
    host.MemoryWrite32(veneer + 12u, 0xE3A00000u);
    host.MemoryWrite32(veneer + 16u, 0xE12FFF1Eu);
    host.MemoryWrite32(veneer + 20u, kLookupPrologue0);
    host.MemoryWrite32(veneer + 24u, kLookupPrologue1);
    host.MemoryWrite32(veneer + 28u, 0xE51FF004u);
    host.MemoryWrite32(veneer + 32u, target + 8u);
    host.MemoryWrite32(target, 0xE51FF004u);
    host.MemoryWrite32(target + 4u, veneer);
    host.InvalidateGuestCode(veneer, 36);
    host.InvalidateGuestCode(target, 8);
    host.AddExecutableRange(veneer, 36);
    LOGI("Installed MCSM hide-border texture hooks: hashes=%08X%08X,%08X%08X lookup=0x%08X veneer=0x%08X",
         static_cast<uint32_t>(vignette_hashes[0] >> 32), static_cast<uint32_t>(vignette_hashes[0]),
         static_cast<uint32_t>(vignette_hashes[1] >> 32), static_cast<uint32_t>(vignette_hashes[1]),
         target, veneer);
    return true;
}

bool InstallMCSMAppFilesUserLocation(DynarmicHost& host) {
    const uint32_t update = host.FindSymbol("_ZN16Platform_Android6UpdateEv");
    const uint32_t complete = host.FindSymbol("_ZN16Platform_Android21OnPermRequestCompleteEib");
    if (!update || !complete || (update & 1u) || (complete & 1u) ||
        host.MemoryRead32(update) != 0xE92D43F0u ||
        host.MemoryRead32(update + 4u) != 0xE1A04000u) {
        LOGE("MCSM app-files user location refused unexpected Platform_Android symbols or prologue");
        return false;
    }

    const uint32_t done = host.GuestAlloc(1, 1);
    const uint32_t veneer = host.GuestAlloc(88, 4);
    if (!done || !veneer) {
        LOGE("MCSM app-files user location could not allocate guest trampoline");
        return false;
    }
    host.MemoryWrite8(done, 0);
    uint32_t probe_instruction = 0xE1A00000u;
#if ARM32_BRIDGE_ENABLE_TELLTALE_DIAGNOSTIC_PROBES
    const uint32_t probe = host.GetThunkManager().RegisterThunk(
        "mcsm_user_location_update_probe", [done](Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
            static unsigned count = 0;
            if (count++ >= 16) return;
            const uint32_t platform = jit.Regs()[0];
            LOGI("MCSM user location update #%u: platform=0x%08X lazy=0x%08X pending=%u available=%u done=%u",
                 count, platform, runtime.MemoryRead32(platform + 0x14u),
                 runtime.MemoryRead8(platform + 0x11u), runtime.MemoryRead8(platform + 0x12u),
                 runtime.MemoryRead8(done));
        });
    probe_instruction = host.MemoryRead32(probe);
#endif

    // This engine initializes <User> as a lazy location. On current Android,
    // the app-specific external files directory is writable without an OS
    // storage permission, so no permission callback binds the lazy location.
    // Complete that internal initialization after the lazy object exists.
    const uint32_t code[] = {
        probe_instruction,
        0xE92D500Fu, 0xE59F303Cu, 0xE5D32000u, 0xE3520000u,
        0x1A000008u, 0xE5902014u, 0xE3520000u, 0x0A000005u,
        0xE3A02001u, 0xE5C32000u, 0xE3A01002u, 0xE3A02001u,
        0xE59FC014u, 0xE12FFF3Cu, 0xE8BD500Fu, 0xE92D43F0u,
        0xE1A04000u, 0xE59FF004u,
        done, complete, update + 8u,
    };
    static_assert(sizeof(code) == 88);
    for (size_t i = 0; i < std::size(code); ++i)
        host.MemoryWrite32(veneer + static_cast<uint32_t>(i * 4), code[i]);
    host.MemoryWrite32(update, 0xE51FF004u);
    host.MemoryWrite32(update + 4u, veneer);
    host.InvalidateGuestCode(veneer, sizeof(code));
    host.InvalidateGuestCode(update, 8);
    host.AddExecutableRange(veneer, sizeof(code));
    LOGI("Installed MCSM app-files user location: update=0x%08X callback=0x%08X veneer=0x%08X",
         update, complete, veneer);
    return true;
}

bool InstallMCSMEpisodeDirectory(DynarmicHost& host, const std::string& files_dir) {
    bool has_episode_description = false;
    for (int i = 0; i < g_num_apk_entries; ++i) {
        const char* name = g_apk_entries[i].name;
        if (strncmp(name, "assets/telltale/files/Net/_resdesc_50_Minecraft10", 49) == 0) {
            has_episode_description = true;
            break;
        }
    }
    if (!has_episode_description) return true;

    const uint32_t construct = host.FindSymbol(
        "_ZN14ResourceFramer46ConstructResourceSystemFromGameDataDirectoriesEv");
    const uint32_t string_ctor = host.FindSymbol("_ZN6StringC2EPKc");
    const uint32_t directory_create = host.FindSymbol("_ZN17ResourceDirectory6CreateERK6Stringb");
    const uint32_t framer_get = host.FindSymbol("_ZN14ResourceFramer3GetEv");
    const uint32_t set_insert = host.FindSymbol(
        "_ZNSt8_Rb_treeI3PtrI17ResourceDirectoryES2_St9_IdentityIS2_ESt4lessIS2_E12StdAllocatorIS2_EE16_M_insert_uniqueIRKS2_EESt4pairISt17_Rb_tree_iteratorIS2_EbEOT_");
    if (!construct || !string_ctor || !directory_create || !framer_get || !set_insert ||
        (construct & 1u) || host.MemoryRead32(construct) != 0xE92D4FF0u ||
        host.MemoryRead32(construct + 4u) != 0xE24DD0D4u) {
        LOGE("MCSM episode directory refused unexpected ResourceFramer symbols or prologue");
        return false;
    }

    const std::string directory = files_dir + "/Net/";
    const uint32_t directory_ptr = host.GuestAlloc(directory.size() + 1, 1);
    const uint32_t veneer = host.GuestAlloc(128, 4);
    if (!directory_ptr || !veneer) {
        LOGE("MCSM episode directory could not allocate guest trampoline");
        return false;
    }
    for (size_t i = 0; i < directory.size(); ++i) host.MemoryWrite8(directory_ptr + i, directory[i]);
    host.MemoryWrite8(directory_ptr + directory.size(), 0);

    // Add the packaged Net directory to ResourceFramer's source set immediately
    // before it scans resource descriptions. The normal descriptor scripts then
    // register only episode sets whose split APK is present.
    const uint32_t code[] = {
        0xE92D500Fu, 0xE24DD010u, 0xE1A0000Du, 0xE59F1058u,
        0xE59FC058u, 0xE12FFF3Cu, 0xE28D0004u, 0xE1A0100Du,
        0xE3A02000u, 0xE59FC048u, 0xE12FFF3Cu, 0xE59D3004u,
        0xE3530000u, 0x0A000006u, 0xE59FC038u, 0xE12FFF3Cu,
        0xE2801004u, 0xE28D0008u, 0xE28D2004u, 0xE59FC028u,
        0xE12FFF3Cu, 0xE28DD010u, 0xE8BD500Fu, 0xE92D4FF0u,
        0xE24DD0D4u, 0xE51FF004u,
        construct + 8u, directory_ptr, string_ctor, directory_create,
        framer_get, set_insert,
    };
    static_assert(sizeof(code) == 128);
    for (size_t i = 0; i < std::size(code); ++i)
        host.MemoryWrite32(veneer + static_cast<uint32_t>(i * 4), code[i]);
    host.MemoryWrite32(construct, 0xE51FF004u);
    host.MemoryWrite32(construct + 4u, veneer);
    host.InvalidateGuestCode(veneer, sizeof(code));
    host.InvalidateGuestCode(construct, 8);
    host.AddExecutableRange(veneer, sizeof(code));
    LOGI("Installed MCSM episode directory: '%s' framer=0x%08X veneer=0x%08X",
         directory.c_str(), construct, veneer);
    return true;
}
