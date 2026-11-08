#pragma once
#include "cache_sources.h"
#include <jni.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct CacheVerifyContext {
    JNIEnv* env;
    const std::atomic<bool>* cancelled = nullptr;
};

// opaque is a call-local real-JNI context. The caller owns and retains fd.
// This verifies publication-time bytes; a read-only fd does not freeze the inode.
inline bool VerifyCacheFd(int fd, const CacheMember& member, void* opaque) {
    struct RestoreErrno {
        int value = errno;
        ~RestoreErrno() { errno = value; }
    } restore_errno;
    auto* verification = static_cast<CacheVerifyContext*>(opaque);
    auto cancelled = [&] {
        return verification && verification->cancelled &&
            verification->cancelled->load(std::memory_order_relaxed);
    };
    auto* env = verification ? verification->env : nullptr;
    if (cancelled() || !env || env->ExceptionCheck() || fd < 0 || !member.sha256 ||
        member.size > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) return false;

    auto hex = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<unsigned char, 32> expected{};
    for (size_t i = 0; i < expected.size(); ++i) {
        const int high = hex(member.sha256[i * 2]);
        if (high < 0) return false;
        const int low = hex(member.sha256[i * 2 + 1]);
        if (low < 0) return false;
        expected[i] = static_cast<unsigned char>((high << 4) | low);
    }
    if (member.sha256[64] != '\0') return false;

    const int flags = ::fcntl(fd, F_GETFL);
    struct stat before{};
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || ::fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_size < 0 ||
        static_cast<uint64_t>(before.st_size) != member.size) return false;

    if (env->PushLocalFrame(8) < 0) {
        if (env->ExceptionCheck()) env->ExceptionClear(); // Only this call's new failure.
        return false;
    }
    struct LocalFrame {
        JNIEnv* env;
        ~LocalFrame() {
            // Entry rejected preexisting exceptions; all pending exceptions here are ours.
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->PopLocalFrame(nullptr);
        }
    } frame{env};

    jclass klass = env->FindClass("java/security/MessageDigest");
    if (!klass || env->ExceptionCheck()) return false;
    jmethodID factory = env->GetStaticMethodID(
        klass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!factory || env->ExceptionCheck()) return false;
    jmethodID update = env->GetMethodID(klass, "update", "([BII)V");
    if (!update || env->ExceptionCheck()) return false;
    jmethodID digest = env->GetMethodID(klass, "digest", "()[B");
    if (!digest || env->ExceptionCheck()) return false;
    jstring algorithm = env->NewStringUTF("SHA-256");
    if (!algorithm || env->ExceptionCheck()) return false;
    jobject context = env->CallStaticObjectMethod(klass, factory, algorithm);
    if (!context || env->ExceptionCheck()) return false;
    jbyteArray input = env->NewByteArray(64 * 1024);
    if (!input || env->ExceptionCheck()) return false;

    std::array<jbyte, 64 * 1024> buffer;
    for (uint64_t position = 0; position < member.size;) {
        const size_t requested = static_cast<size_t>(
            std::min<uint64_t>(buffer.size(), member.size - position));
        if (cancelled()) return false;
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), requested, static_cast<off_t>(position));
        } while (count < 0 && errno == EINTR);
        if (count <= 0 || static_cast<size_t>(count) > requested) return false;
        env->SetByteArrayRegion(input, 0, static_cast<jsize>(count), buffer.data());
        if (env->ExceptionCheck()) return false;
        env->CallVoidMethod(context, update, input, static_cast<jint>(0), static_cast<jint>(count));
        if (env->ExceptionCheck()) return false;
        position += static_cast<uint64_t>(count);
    }

    if (cancelled()) return false;
    auto result = static_cast<jbyteArray>(env->CallObjectMethod(context, digest));
    if (!result || env->ExceptionCheck()) return false;
    const jsize result_size = env->GetArrayLength(result);
    if (env->ExceptionCheck() || result_size != 32) return false;
    std::array<jbyte, 32> actual{};
    env->GetByteArrayRegion(result, 0, 32, actual.data());
    if (env->ExceptionCheck()) return false;

    struct stat after{};
    if (::fstat(fd, &after) != 0) return false;
    return !cancelled() && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_mode == after.st_mode && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
        std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}
