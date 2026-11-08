#pragma once
#include "cache_sources.h"
#include <jni.h>
#include <mutex>
#include <string>
#include <vector>

namespace cache_bootstrap {
enum Result : int { Prepared = 0, Cancelled = 1, InputError = 2, RequiredCacheUnavailable = 3 };
struct Snapshot {
    jobject context = nullptr; // Borrowed; activated job retains its global ref for the process.
    std::string package, files, obb;
    std::vector<std::string> apks, split_names;
    std::vector<int> roles;
};

// The UI uses only Begin/Cancel/Activate/OwnerSource. Run and Release are worker-only.
// All index mutation and guest initialization share this bootstrap mutex.
std::mutex& LoadMutex();
jlong Begin(JNIEnv* env, jobject context, const char* expected_package);
int Run(JNIEnv* env, jlong token, bool hide_border, const CacheMember* members, size_t count);
void Cancel(jlong token);
bool Activate(jlong token);
void Release(JNIEnv* env, jlong token);
bool Admitted();
int OwnerSource(unsigned owner); // Fast ACTIVE snapshot, never Ensure/hash/index.
bool CopyActiveSnapshot(Snapshot& snapshot); // Caller holds LoadMutex; no recursive load lock.
bool ValidateSnapshot(JNIEnv* env, const Snapshot& snapshot);
// Diagnostic-only worker callback; no control lock or recursive load lock, never affects job result.
void ObservePrivateMetadataPreparation(JNIEnv* env, jobject context, const char* package, jlong token) noexcept;
}
