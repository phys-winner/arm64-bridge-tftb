#include "cache_bootstrap.h"
#include "cache_verify_jni.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <memory>
#include <unordered_map>
#include <unistd.h>

namespace cache_bootstrap {
namespace {
enum class Phase { New, Running, Prepared, Failed, Activated };
struct Job {
    jlong token = 0;
    jobject context = nullptr;
    std::string package;
    std::atomic<bool> cancelled{false};
    Phase phase = Phase::New; // Protected by control_mutex.
    Snapshot snapshot;
    std::array<int, 7> owners{};
};
std::mutex control_mutex, load_mutex;
std::unordered_map<jlong, std::shared_ptr<Job>> jobs;
std::shared_ptr<Job> current;
jlong next_token = 1, indexed_token = 0; // indexed_token is protected by load_mutex.
std::atomic<bool> admitted{false};

struct Frame {
    JNIEnv* env;
    bool pushed = false;
    explicit Frame(JNIEnv* e) : env(e) { pushed = env->PushLocalFrame(32) == JNI_OK; }
    ~Frame() {
        // ReadSnapshot rejects entry exceptions; any pending exception here is ours.
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (pushed) env->PopLocalFrame(nullptr);
    }
};

bool String(JNIEnv* env, jstring value, std::string& out) {
    if (!value || env->ExceptionCheck()) return false;
    const jsize length = env->GetStringUTFLength(value);
    if (env->ExceptionCheck() || length <= 0 || length > 8192) return false;
    const char* text = env->GetStringUTFChars(value, nullptr);
    struct Utf {
        JNIEnv* env; jstring value; const char* text;
        ~Utf() { if (text) env->ReleaseStringUTFChars(value, text); }
    } utf{env, value, text};
    if (!text || env->ExceptionCheck()) return false;
    out.assign(text, static_cast<size_t>(length));
    return out.find('\0') == std::string::npos;
}

bool Absolute(const std::string& path) { return !path.empty() && path.front() == '/'; }
int Role(const std::string& name) {
    constexpr const char* names[] = {"split_episode_02", "split_episode_03", "split_episode_04", "split_episode_05", "split_hide_border", "split_russian"};
    for (int i = 0; i < 6; ++i) if (name == names[i]) return i + 1;
    return -1; // Includes independent widescreen and ordinary unknown splits.
}

bool Directory(JNIEnv* env, jobject context, jclass klass, const char* name,
               const char* signature, bool files, std::string& out) {
    jmethodID getter = env->GetMethodID(klass, name, signature);
    if (!getter || env->ExceptionCheck()) return false;
    jobject file = files ? env->CallObjectMethod(context, getter, nullptr) : env->CallObjectMethod(context, getter);
    if (env->ExceptionCheck()) return false;
    if (!file) { out.clear(); return true; }
    jclass file_class = env->GetObjectClass(file);
    if (!file_class || env->ExceptionCheck()) return false;
    jmethodID absolute = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
    if (!absolute || env->ExceptionCheck()) return false;
    auto path = static_cast<jstring>(env->CallObjectMethod(file, absolute));
    return !env->ExceptionCheck() && String(env, path, out) && Absolute(out);
}

bool ReadSnapshot(JNIEnv* env, jobject context, const std::string& package, Snapshot& out) {
    if (!env || !context || package.empty() || env->ExceptionCheck()) return false;
    Frame frame(env);
    if (!frame.pushed) return false;
    jclass klass = env->GetObjectClass(context);
    if (!klass || env->ExceptionCheck()) return false;
    jmethodID package_name = env->GetMethodID(klass, "getPackageName", "()Ljava/lang/String;");
    if (!package_name || env->ExceptionCheck()) return false;
    auto name = static_cast<jstring>(env->CallObjectMethod(context, package_name));
    std::string observed;
    if (env->ExceptionCheck() || !String(env, name, observed) || observed != package) return false;
    jmethodID application = env->GetMethodID(klass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (!application || env->ExceptionCheck()) return false;
    jobject info = env->CallObjectMethod(context, application);
    if (!info || env->ExceptionCheck()) return false;
    jclass info_class = env->GetObjectClass(info);
    if (!info_class || env->ExceptionCheck()) return false;
    jfieldID uid_field = env->GetFieldID(info_class, "uid", "I");
    if (!uid_field || env->ExceptionCheck()) return false;
    const jint uid = env->GetIntField(info, uid_field);
    if (env->ExceptionCheck() || uid < 0 || static_cast<uid_t>(uid) != getuid()) return false;
    auto field = [&](const char* key, const char* signature) -> jobject {
        jfieldID id = env->GetFieldID(info_class, key, signature);
        if (!id || env->ExceptionCheck()) return nullptr;
        return env->GetObjectField(info, id);
    };
    if (!String(env, static_cast<jstring>(field("packageName", "Ljava/lang/String;")), observed) || observed != package) return false;
    std::string base;
    if (!String(env, static_cast<jstring>(field("sourceDir", "Ljava/lang/String;")), base) || !Absolute(base)) return false;
    auto names = static_cast<jobjectArray>(field("splitNames", "[Ljava/lang/String;"));
    if (env->ExceptionCheck()) return false;
    auto paths = static_cast<jobjectArray>(field("splitSourceDirs", "[Ljava/lang/String;"));
    if (env->ExceptionCheck() || (!names != !paths)) return false;
    const jsize length = names ? env->GetArrayLength(names) : 0;
    if (env->ExceptionCheck() || length < 0 || length > 63) return false;
    if (paths && (env->GetArrayLength(paths) != length || env->ExceptionCheck())) return false;
    out.context = context; out.package = package;
    out.apks = {std::move(base)}; out.split_names = {""}; out.roles = {0};
    for (jsize i = 0; i < length; ++i) {
        auto split_name = static_cast<jstring>(env->GetObjectArrayElement(names, i));
        std::string split, path;
        if (env->ExceptionCheck() || !String(env, split_name, split)) return false;
        auto split_path = static_cast<jstring>(env->GetObjectArrayElement(paths, i));
        if (env->ExceptionCheck() || !String(env, split_path, path) || !Absolute(path)) return false;
        if (std::find(out.split_names.begin(), out.split_names.end(), split) != out.split_names.end() ||
            std::find(out.apks.begin(), out.apks.end(), path) != out.apks.end()) return false;
        out.roles.push_back(Role(split)); out.split_names.push_back(std::move(split)); out.apks.push_back(std::move(path));
        env->DeleteLocalRef(split_name); env->DeleteLocalRef(split_path);
    }
    if (!Directory(env, context, klass, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;", true, out.files) ||
        !Directory(env, context, klass, "getObbDir", "()Ljava/io/File;", false, out.obb)) return false;
    return !out.files.empty(); // SAVE needs the actual app-specific root; never redirect to private/shared cache.
}

bool IsCurrent(const std::shared_ptr<Job>& job) {
    std::lock_guard<std::mutex> lock(control_mutex);
    return current == job && !job->cancelled.load(std::memory_order_relaxed);
}
}

std::mutex& LoadMutex() { return load_mutex; }
bool Admitted() { return admitted.load(std::memory_order_acquire); }

jlong Begin(JNIEnv* env, jobject context, const char* expected_package) {
    if (!env || !context || !expected_package || !*expected_package || env->ExceptionCheck()) return 0;
    jobject retained = env->NewGlobalRef(context);
    if (!retained) return 0;
    jlong token = 0;
    try {
        auto job = std::make_shared<Job>();
        job->context = retained; job->package = expected_package;
        std::lock_guard<std::mutex> lock(control_mutex);
        if ((!current || current->phase != Phase::Activated) && jobs.size() < 64 &&
            next_token < std::numeric_limits<jlong>::max()) {
            job->token = next_token;
            jobs.emplace(next_token, job);
            if (current) current->cancelled.store(true, std::memory_order_relaxed);
            current = std::move(job); token = next_token++;
            admitted.store(false, std::memory_order_release);
        }
    } catch (...) { token = 0; }
    if (!token) env->DeleteGlobalRef(retained);
    return token;
}

int Run(JNIEnv* env, jlong token, bool hide_border, const CacheMember* members, size_t count) {
    std::shared_ptr<Job> job;
    {
        std::lock_guard<std::mutex> lock(control_mutex);
        auto found = jobs.find(token);
        if (found == jobs.end() || found->second != current || found->second->phase != Phase::New ||
            found->second->cancelled.load(std::memory_order_relaxed)) return Cancelled;
        job = found->second; job->phase = Phase::Running;
    }
    // ponytail: one bootstrap/index, serialize workers; per-runtime indexes if multiple runtimes are ever needed.
    std::lock_guard<std::mutex> load(load_mutex);
    int result = Cancelled;
    if (IsCurrent(job)) {
        DiscardCacheSources(); indexed_token = token;
        result = InputError;
        try {
            Snapshot snapshot;
            if (ReadSnapshot(env, job->context, job->package, snapshot) && IsCurrent(job)) {
                ObservePrivateMetadataPreparation(env, job->context, job->package.c_str(), token);
                std::vector<CacheApkInput> inputs;
                inputs.reserve(snapshot.apks.size());
                for (size_t i = 0; i < snapshot.apks.size(); ++i)
                    inputs.push_back({snapshot.apks[i].c_str(), snapshot.roles[i]});
                CacheVerifyContext verifier{env, &job->cancelled};
                const bool hide = hide_border && std::find(snapshot.roles.begin(), snapshot.roles.end(), 5) != snapshot.roles.end();
                if (PrepareCacheApks(inputs.data(), inputs.size(), members, count, &job->cancelled) == 0) {
                    result = RequiredCacheUnavailable;
                    if (SelectCacheSources(members, count, snapshot.files.c_str(), snapshot.obb.c_str(), hide,
                                           VerifyCacheFd, &verifier, &job->cancelled) == 0) {
                        std::lock_guard<std::mutex> lock(control_mutex);
                        if (current == job && !job->cancelled.load(std::memory_order_relaxed)) {
                            job->snapshot = std::move(snapshot);
                            for (unsigned i = 0; i < job->owners.size(); ++i) job->owners[i] = CacheOwnerSource(i);
                            job->phase = Phase::Prepared; result = Prepared;
                        }
                    }
                }
            }
        } catch (...) { result = InputError; }
    }
    if (!IsCurrent(job)) result = Cancelled;
    if (result != Prepared && indexed_token == token) { DiscardCacheSources(); indexed_token = 0; }
    if (result != Prepared) {
        std::lock_guard<std::mutex> lock(control_mutex);
        job->phase = Phase::Failed;
    }
    return result;
}

void Cancel(jlong token) {
    std::lock_guard<std::mutex> lock(control_mutex);
    auto found = jobs.find(token);
    if (found != jobs.end() && found->second->phase != Phase::Activated)
        found->second->cancelled.store(true, std::memory_order_relaxed);
}

bool Activate(jlong token) {
    std::lock_guard<std::mutex> lock(control_mutex);
    if (!current || current->token != token || current->phase != Phase::Prepared ||
        current->cancelled.load(std::memory_order_relaxed)) return false;
    current->phase = Phase::Activated;
    admitted.store(true, std::memory_order_release);
    return true;
}

void Release(JNIEnv* env, jlong token) {
    Cancel(token); // Signal before waiting on the long bootstrap lock; never call Release on UI.
    std::lock_guard<std::mutex> load(load_mutex);
    std::shared_ptr<Job> job;
    jobject context = nullptr;
    {
        std::lock_guard<std::mutex> lock(control_mutex);
        auto found = jobs.find(token);
        if (found == jobs.end() || found->second->phase == Phase::Activated) return;
        job = found->second;
        if (current == job) current.reset();
        jobs.erase(found);
        context = job->context; job->context = nullptr;
    }
    if (indexed_token == token) { DiscardCacheSources(); indexed_token = 0; }
    if (context) env->DeleteGlobalRef(context);
}

int OwnerSource(unsigned owner) {
    if (!Admitted()) return 0;
    std::lock_guard<std::mutex> lock(control_mutex);
    return current && current->phase == Phase::Activated && owner < current->owners.size() ? current->owners[owner] : 0;
}

bool CopyActiveSnapshot(Snapshot& snapshot) {
    std::lock_guard<std::mutex> lock(control_mutex);
    if (!current || current->phase != Phase::Activated || !Admitted()) return false;
    snapshot = current->snapshot;
    return true;
}

bool ValidateSnapshot(JNIEnv* env, const Snapshot& snapshot) {
    try {
        Snapshot observed;
        return ReadSnapshot(env, snapshot.context, snapshot.package, observed) && observed.apks == snapshot.apks &&
            observed.split_names == snapshot.split_names && observed.roles == snapshot.roles &&
            observed.files == snapshot.files && observed.obb == snapshot.obb;
    } catch (...) { return false; }
}
}
