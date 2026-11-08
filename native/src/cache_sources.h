#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>

struct CacheMember {
    const char* asset;
    uint64_t size;
    uint32_t crc32;
    const char* sha256;
    unsigned owner; // BASE=0, EP2..EP5=1..4, optional hide-border=5, Russian text=6.
};

struct CacheApkInput {
    const char* path;
    int owner; // Trusted ApplicationInfo role: BASE0, cache-only EP2..Russian1..6, ordinary/W=-1.
};

// Bootstrap-only role-aware preparation. Strict IndexApks stays unchanged.
// Bad cache-member metadata rejects its whole P owner; valid E can replace it.
// A malformed BASE/ordinary ZIP envelope remains an APK error, not missing cache.
int PrepareCacheApks(const CacheApkInput* apks, size_t apk_count,
                     const CacheMember* members, size_t count,
                     const std::atomic<bool>* cancelled = nullptr);

using CacheVerifier = bool (*)(int fd, const CacheMember& member, void* context);

// Bootstrap only, after IndexApks and before guest execution. Member strings
// remain alive until the next successful IndexApks; release manifests are static.
// The verifier must
// hash the entire held FD, reject concurrent mutation, and never reopen its path.
int SelectCacheSources(const CacheMember* members, size_t count,
                       const char* files_dir, const char* obb_dir, bool hide_border,
                       CacheVerifier verify, void* context,
                       const std::atomic<bool>* cancelled = nullptr);
// Bootstrap lock only, before guest admission; clears all index/owner FDs and state.
void DiscardCacheSources();
int CacheOwnerSource(unsigned owner); // 0=unavailable, 1=packaged, 2=external.

struct CacheAssetRegion {
    int fd = -1; // Independent real FD; the caller owns it after success.
    off_t offset = 0, length = 0;
    bool external = false;
    char owner[384]{};
};

// Exact lowercase Android asset names only. 0=ordinary asset, 1=selected cache,
// -1=rejected cache. Rejected cache must not fall through to AssetManager.
int OpenCacheAssetRegion(const char* name, CacheAssetRegion& region);
bool CacheAssetDirectory(const char* name, std::vector<std::string>& names);
