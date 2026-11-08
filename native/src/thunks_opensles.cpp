#include "thunks_opensles.h"
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "game_port_config.h"
#include "thunk_types.h"

#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <android/log.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/resource.h>

#define LOG_TAG "Arm32Bridge_Audio"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace {
constexpr size_t BUFFER_QUEUE_COUNT = 128;
constexpr size_t MAX_BUFFER_SIZE = 16384;

struct AudioState {
    std::mutex mutex;
    std::condition_variable cv;
    DynarmicHost* owner = nullptr;
    std::thread thread;
    std::thread::id worker_id;
    bool running = false, ready = false, start_done = false, closing = false;
    bool control = false, in_flight = false, app_paused = false, lifecycle_pending = false;
    std::atomic<uint64_t> wakeups{0};
    std::atomic<bool> accepting{false};
    SLObjectItf engine_object = nullptr, mix_object = nullptr, player_object = nullptr;
    SLEngineItf engine = nullptr;
    SLPlayItf play = nullptr;
    SLAndroidSimpleBufferQueueItf queue = nullptr;
    SLVolumeItf volume = nullptr;
    SLAndroidConfigurationItf config = nullptr;
    uint32_t engine_guest = 0, engine_interface = 0, mix_guest = 0, player_guest = 0;
    uint32_t play_guest = 0, queue_guest = 0, volume_guest = 0, config_guest = 0;
    uint32_t callback = 0, context = 0, completed_index = 0;
    SLuint32 requested_state = SL_PLAYSTATE_STOPPED, channels = 0;
    uint8_t buffers[BUFFER_QUEUE_COUNT][MAX_BUFFER_SIZE]{};
    size_t write_index = 0;
    uint64_t callbacks = 0, enqueues = 0, bytes = 0, nonzero = 0;
    std::unordered_map<std::string, uint32_t> iids;
#ifdef BRIDGE_OPENSL_TEST
    bool fake = false, disable_start = false;
    SLAndroidSimpleBufferQueueState fake_queue{};
    SLuint32 fake_play = SL_PLAYSTATE_STOPPED;
    SLresult fake_error = SL_RESULT_SUCCESS;
    unsigned starts = 0;
#endif
};

AudioState& Audio() {
    // ponytail: one PCM player; process-lifetime synchronization storage avoids cross-TU
    // destructor ordering. Owner shutdown releases all handles and joins the thread.
    static AudioState* state = new AudioState;
    return *state;
}

SLresult QueueState(AudioState& s, SLAndroidSimpleBufferQueueState& state);

void HostBqPlayerCallback(SLAndroidSimpleBufferQueueItf, void* context) {
    auto& state = *static_cast<AudioState*>(context);
    if (state.accepting.load(std::memory_order_acquire)) {
        // Native controls may be waiting for this callback; never wait to acquire its state lock.
        std::unique_lock<std::mutex> lock(state.mutex, std::try_to_lock);
        const uint64_t before = lock.owns_lock() ? state.callbacks : 0;
        state.wakeups.fetch_add(1, std::memory_order_release);
        state.cv.notify_all();
        // Android pulls the next buffer on return; give the dedicated guest worker one bounded refill.
        if (lock.owns_lock() && state.running && state.callback && !state.control && !state.closing) {
            SLAndroidSimpleBufferQueueState queue{};
            if (QueueState(state, queue) == SL_RESULT_SUCCESS && !queue.count &&
                (queue.index != state.completed_index || state.in_flight)) {
                state.cv.wait_for(lock, std::chrono::milliseconds(4), [&] {
                    return state.callbacks != before || !state.running || !state.callback || state.control ||
                           state.closing || !state.accepting.load(std::memory_order_acquire);
                });
            }
        }
    }
}

bool Range(DynarmicHost& host, uint32_t address, size_t size) {
    return GuestRangeValid(host.GetGuestMemorySize(), address, size);
}

bool IIDMatches(DynarmicHost& host, uint32_t address, SLInterfaceID iid) {
    if (Range(host, address, sizeof(*iid)) &&
        memcmp(host.GetGuestMemoryBase() + address, iid, sizeof(*iid)) == 0) return true;
    if (!Range(host, address, 4)) return false;
    address = host.MemoryRead32(address);
    return Range(host, address, sizeof(*iid)) &&
           memcmp(host.GetGuestMemoryBase() + address, iid, sizeof(*iid)) == 0;
}

bool Interfaces(DynarmicHost& host, uint32_t count, uint32_t ids, uint32_t required,
                std::initializer_list<SLInterfaceID> supported) {
    if (count > 16 || !Range(host, ids, count * 4) || !Range(host, required, count * 4)) return false;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t iid = host.MemoryRead32(ids + i * 4);
        if (!Range(host, iid, sizeof(SLInterfaceID_))) return false;
        const bool match = std::any_of(supported.begin(), supported.end(), [&](SLInterfaceID native) {
            return IIDMatches(host, iid, native);
        });
        if (!match && host.MemoryRead32(required + i * 4)) return false;
    }
    return true;
}

uint32_t MakeInterface(DynarmicHost& host,
                       std::initializer_list<std::pair<unsigned, const char*>> methods) {
    const uint32_t table = host.GuestAlloc(64 * 4, 8), object = host.GuestAlloc(8, 8);
    if (!table || !object) { host.GuestFree(table); host.GuestFree(object); return 0; }
    const uint32_t unsupported = host.GetThunkManager().GetOrCreateThunkAddress("SL_Unsupported");
    for (unsigned i = 0; i < 64; ++i) host.MemoryWrite32(table + i * 4, unsupported);
    for (const auto& [slot, name] : methods)
        host.MemoryWrite32(table + slot * 4, host.GetThunkManager().GetOrCreateThunkAddress(name));
    host.MemoryWrite32(object, table);
    return object;
}

void FreeInterface(DynarmicHost& host, uint32_t& object) {
    if (object) { host.GuestFree(host.MemoryRead32(object)); host.GuestFree(object); object = 0; }
}

bool Usable(AudioState& s, DynarmicHost& host) {
    return s.owner == &host && ((!s.closing && !s.control) ||
           (s.in_flight && s.worker_id == std::this_thread::get_id()));
}

bool BeginControl(AudioState& s, std::unique_lock<std::mutex>& lock) {
    if (s.control || (s.in_flight && s.worker_id == std::this_thread::get_id())) return false;
    s.control = true;
    s.cv.wait(lock, [&] { return !s.in_flight; }); // releases mutex; callback may re-enqueue
    return true;
}

SLuint32 EffectiveState(const AudioState& s) {
    return s.app_paused && s.requested_state == SL_PLAYSTATE_PLAYING
        ? SL_PLAYSTATE_PAUSED : s.requested_state;
}

SLresult QueueState(AudioState& s, SLAndroidSimpleBufferQueueState& state) {
#ifdef BRIDGE_OPENSL_TEST
    if (s.fake) { state = s.fake_queue; return s.fake_error; }
#endif
    return s.queue ? (*s.queue)->GetState(s.queue, &state) : SL_RESULT_PRECONDITIONS_VIOLATED;
}

SLresult PlayState(AudioState& s, SLuint32 state) {
#ifdef BRIDGE_OPENSL_TEST
    if (s.fake) { if (!s.fake_error) s.fake_play = state; return s.fake_error; }
#endif
    return s.play ? (*s.play)->SetPlayState(s.play, state) : SL_RESULT_PRECONDITIONS_VIOLATED;
}

bool PlayerReady(const AudioState& s) {
#ifdef BRIDGE_OPENSL_TEST
    if (s.fake) return s.player_guest != 0;
#endif
    return s.play && s.queue;
}

void EndControl(AudioState& s) {
    s.control = false;
    if (s.lifecycle_pending && !s.closing && PlayerReady(s)) {
        const SLresult result = PlayState(s, EffectiveState(s));
        if (result) LOGE("Deferred audio lifecycle state failed: %u", result);
    }
    s.lifecycle_pending = false;
    s.cv.notify_all();
}

void PumpOne(AudioState& s, std::unique_lock<std::mutex>& lock) {
    // Pause stops native consumption, not acknowledgment of buffers already completed.
    // Waiting for PLAYING here can prevent the guest from finishing mixer suspension.
    if (s.closing || s.control || !s.callback || !PlayerReady(s)) return;
    SLAndroidSimpleBufferQueueState state{};
    const SLresult result = QueueState(s, state);
    if (result != SL_RESULT_SUCCESS) {
        LOGE("OpenSL queue state failed in callback pump: %u", result);
        s.running = false;
        return;
    }
    if (state.index == s.completed_index) return;
    if (static_cast<uint32_t>(state.index - s.completed_index) > BUFFER_QUEUE_COUNT) {
        LOGE("OpenSL unsupported-policy: completion index changed without a controlled Clear");
        s.running = false;
        return;
    }
    ++s.completed_index;
    const uint32_t callback = s.callback, context = s.context, queue = s.queue_guest;
    DynarmicHost* host = s.owner;
    s.in_flight = true;
    lock.unlock();
    host->RunFunction(callback, {queue, context});
    lock.lock();
    ++s.callbacks;
    s.in_flight = false;
    s.cv.notify_all();
}

void AudioThreadLoop(DynarmicHost* host) {
    auto& s = Audio();
    bool ready = false;
    try { ready = host->PrepareThreadContext(); }
    catch (...) { LOGE("Audio worker JIT initialization failed"); }
    std::unique_lock<std::mutex> lock(s.mutex);
    s.worker_id = std::this_thread::get_id();
    s.ready = ready;
    s.start_done = true;
    if (!ready) s.running = false;
    s.cv.notify_all();
    if (!ready) return;
    const int priority_result = setpriority(PRIO_PROCESS, 0, -16);
    LOGI("Dedicated audio thread ready (priority result=%d)", priority_result);
    while (s.running) {
        s.cv.wait_for(lock, std::chrono::milliseconds(5), [&] {
            return !s.running || (!s.control && s.callback && s.wakeups.load(std::memory_order_acquire));
        });
        if (!s.running) break;
        if (s.control || !s.callback) continue;
        s.wakeups.exchange(0, std::memory_order_acq_rel);
        // Native index, not wake count, identifies completed buffers. A late notification
        // after Clear sees its reset index and cannot dispatch a stale guest callback.
        for (;;) {
            const uint32_t before = s.completed_index;
            PumpOne(s, lock);
            if (!s.running || before == s.completed_index) break;
        }
    }
    s.ready = false;
    s.cv.notify_all();
    LOGI("Dedicated audio thread stopped");
}

SLresult StartLocked(AudioState& s, DynarmicHost& host, std::unique_lock<std::mutex>& lock) {
#ifdef BRIDGE_OPENSL_TEST
    if (s.disable_start) return SL_RESULT_SUCCESS; // reproduce candidate125 only in test target
#endif
    if (s.thread.joinable()) return s.ready && s.running ? SL_RESULT_SUCCESS : SL_RESULT_RESOURCE_ERROR;
    s.running = true;
    s.start_done = false;
    try { s.thread = std::thread(AudioThreadLoop, &host); }
    catch (...) { s.running = false; return SL_RESULT_RESOURCE_ERROR; }
#ifdef BRIDGE_OPENSL_TEST
    ++s.starts;
#endif
    s.cv.wait(lock, [&] { return s.start_done; });
    return s.ready ? SL_RESULT_SUCCESS : SL_RESULT_RESOURCE_ERROR;
}

void DestroyPlayer(AudioState& s, std::unique_lock<std::mutex>& lock, bool free_guest = true) {
    s.accepting.store(false, std::memory_order_release);
    const SLObjectItf player = s.player_object;
    lock.unlock();
    if (player) (*player)->Destroy(player); // native callback lifetime barrier
    lock.lock();
    s.player_object = nullptr; s.play = nullptr; s.queue = nullptr; s.volume = nullptr; s.config = nullptr;
    s.callback = s.context = s.completed_index = 0;
    s.write_index = 0; s.channels = 0; s.requested_state = SL_PLAYSTATE_STOPPED;
    s.wakeups.store(0, std::memory_order_release);
    if (s.owner && free_guest) {
        for (uint32_t* object : {&s.player_guest, &s.play_guest, &s.queue_guest, &s.volume_guest, &s.config_guest})
            FreeInterface(*s.owner, *object);
    }
#ifdef BRIDGE_OPENSL_TEST
    s.fake = false;
    s.fake_queue = {};
#endif
}

void UnsafeVoidCall(Dynarmic::A32::Jit& jit, const char* operation) {
    LOGE("OpenSL unsupported-policy: %s cannot safely quiesce this callback", operation);
    jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

SLresult RealizePlayer(AudioState& s) {
    if (s.play && s.queue) return SL_RESULT_SUCCESS;
    if (!s.player_object) return SL_RESULT_PRECONDITIONS_VIOLATED;
    SLresult result = (*s.player_object)->Realize(s.player_object, SL_BOOLEAN_FALSE);
    if (result == SL_RESULT_SUCCESS) result = (*s.player_object)->GetInterface(s.player_object, SL_IID_PLAY, &s.play);
    if (result == SL_RESULT_SUCCESS) result = (*s.player_object)->GetInterface(s.player_object, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &s.queue);
    if (result == SL_RESULT_SUCCESS) result = (*s.player_object)->GetInterface(s.player_object, SL_IID_VOLUME, &s.volume);
    if (result == SL_RESULT_SUCCESS) result = (*s.queue)->RegisterCallback(s.queue, HostBqPlayerCallback, &s);
    if (result == SL_RESULT_SUCCESS) {
        s.accepting.store(true, std::memory_order_release);
        LOGI("Host Audio Player realized successfully");
    }
    return result;
}

SLresult Enqueue(AudioState& s, DynarmicHost& host, uint32_t self, uint32_t address, uint32_t size) {
    if (!Usable(s, host) || !PlayerReady(s) || self != s.queue_guest) return SL_RESULT_PRECONDITIONS_VIOLATED;
    const void* input = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, size);
    if (!size || size > MAX_BUFFER_SIZE || !input || !s.channels || size % (s.channels * 2))
        return SL_RESULT_PARAMETER_INVALID;
    SLAndroidSimpleBufferQueueState state{};
    SLresult result = QueueState(s, state);
    if (result != SL_RESULT_SUCCESS) return result;
    if (state.count >= BUFFER_QUEUE_COUNT) return SL_RESULT_BUFFER_INSUFFICIENT;
    auto* target = s.buffers[s.write_index];
    memcpy(target, input, size);
#ifdef BRIDGE_OPENSL_TEST
    if (s.fake) { result = s.fake_error; if (!result) ++s.fake_queue.count; }
    else
#endif
    result = (*s.queue)->Enqueue(s.queue, target, size);
    if (result != SL_RESULT_SUCCESS) return result;
    s.write_index = (s.write_index + 1) % BUFFER_QUEUE_COUNT;
    ++s.enqueues; s.bytes += size;
#if ARM32_BRIDGE_ENABLE_AUDIO_DIAGNOSTICS
    unsigned peak = 0;
    uint32_t hash = 2166136261u;
    for (uint32_t i = 0; i < size; ++i) hash = (hash ^ target[i]) * 16777619u;
    for (uint32_t i = 0; i < size; i += 2) {
        int16_t value; memcpy(&value, target + i, 2);
        peak = std::max(peak, static_cast<unsigned>(value < 0 ? -static_cast<int>(value) : value));
    }
    if (peak) ++s.nonzero;
    if (s.enqueues <= 10 || s.enqueues % 200 == 0) {
        LOGI("SLBufferQueue_Enqueue #%llu: size=%u, pBuffer=0x%08X, idx=%zu", (unsigned long long)s.enqueues, size, address, s.write_index);
        LOGI("Audio proof: callbacks=%llu enqueues=%llu bytes=%llu nonzero=%llu peak=%u hash=%08X",
             (unsigned long long)s.callbacks, (unsigned long long)s.enqueues, (unsigned long long)s.bytes,
             (unsigned long long)s.nonzero, peak, hash);
    }
#endif
    return SL_RESULT_SUCCESS;
}
} // namespace

void ShutdownOpenSLES(DynarmicHost* host) {
    if (!host) return;
    auto& s = Audio();
    std::unique_lock<std::mutex> lock(s.mutex);
    if (s.owner != host) return;
    if (s.worker_id == std::this_thread::get_id()) {
        LOGE("OpenSL unsupported-policy: host destruction on its callback thread");
        std::abort(); // Never unmap a host which is still executing its callback.
    }
    if (s.closing) { s.cv.wait(lock, [&] { return s.owner != host; }); return; }
    s.cv.wait(lock, [&] { return !s.control || s.owner != host; });
    if (s.owner != host) return;
    s.closing = true;
    s.control = true;
    s.running = false;
    s.cv.notify_all();
    s.cv.wait(lock, [&] { return !s.in_flight; });
    lock.unlock();
    if (s.thread.joinable()) s.thread.join();
    lock.lock();
    DestroyPlayer(s, lock);
    const SLObjectItf mix = s.mix_object, engine = s.engine_object;
    lock.unlock();
    if (mix) (*mix)->Destroy(mix);
    if (engine) (*engine)->Destroy(engine);
    lock.lock();
    s.mix_object = nullptr; s.engine_object = nullptr; s.engine = nullptr;
    for (uint32_t* object : {&s.mix_guest, &s.engine_interface, &s.engine_guest}) FreeInterface(*host, *object);
    s.owner = nullptr; s.worker_id = {};
    s.closing = s.control = s.app_paused = s.lifecycle_pending = false;
    s.cv.notify_all();
}

void PauseAudioPlayback(DynarmicHost* host) {
    if (!host) return;
    auto& s = Audio();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.owner) s.owner = host; // Pause can precede FMOD's first player creation.
    if (s.owner != host || s.closing) return;
    s.app_paused = true;
    if (s.control) { s.lifecycle_pending = true; return; }
    if (PlayerReady(s)) {
        const SLresult result = PlayState(s, EffectiveState(s));
        if (result) LOGE("PauseAudioPlayback failed: %u", result);
    }
    s.cv.notify_all();
}

void ResumeAudioPlayback(DynarmicHost* host) {
    auto& s = Audio();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (s.owner != host || s.closing) return;
    s.app_paused = false;
    if (s.control) { s.lifecycle_pending = true; return; }
    if (PlayerReady(s)) {
        const SLresult result = PlayState(s, EffectiveState(s));
        if (result) LOGE("ResumeAudioPlayback failed: %u", result);
    }
    s.cv.notify_all();
}

uint32_t GetOpenSLESInterfacePointer(const std::string& name) {
    auto& s = Audio();
    std::lock_guard<std::mutex> lock(s.mutex);
    const auto it = s.iids.find(name);
    return it == s.iids.end() ? 0 : it->second;
}

void RegisterOpenSLESThunks(ThunkManager& manager, DynarmicHost& host) {
    {
        auto& s = Audio();
        std::lock_guard<std::mutex> lock(s.mutex);
        for (const auto& [name, iid] : std::initializer_list<std::pair<const char*, SLInterfaceID>>{
                 {"SL_IID_ENGINE", SL_IID_ENGINE}, {"SL_IID_ANDROIDSIMPLEBUFFERQUEUE", SL_IID_ANDROIDSIMPLEBUFFERQUEUE},
                 {"SL_IID_ANDROIDCONFIGURATION", SL_IID_ANDROIDCONFIGURATION}, {"SL_IID_PLAY", SL_IID_PLAY},
                 {"SL_IID_VOLUME", SL_IID_VOLUME}, {"SL_IID_OUTPUTMIX", SL_IID_OUTPUTMIX},
                 {"SL_IID_BUFFERQUEUE", SL_IID_BUFFERQUEUE}, {"SL_IID_RECORD", SL_IID_RECORD}}) {
            const uint32_t data = host.GuestAlloc(sizeof(*iid), 4), pointer = host.GuestAlloc(4, 4);
            if (!data || !pointer) { host.GuestFree(data); host.GuestFree(pointer); LOGE("OpenSL IID allocation failed"); continue; }
            memcpy(host.GetGuestMemoryBase() + data, iid, sizeof(*iid));
            host.MemoryWrite32(pointer, data);
            manager.RegisterSymbol(name, pointer);
            if (!s.owner || s.owner == &host) s.iids[name] = pointer;
        }
    }
    manager.RegisterThunk("SL_Unsupported", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        LOGE("OpenSL unsupported-policy: unimplemented interface method");
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });
    manager.RegisterThunk("slCreateEngine", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const uint32_t out = jit.Regs()[0];
        if (!Range(h, out, 4) || !Range(h, jit.Regs()[13], 8)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        if (s.owner && s.owner != &h) { jit.Regs()[0] = SL_RESULT_RESOURCE_ERROR; return; }
        if (s.engine_object || s.control || s.closing) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        if (jit.Regs()[1] || !Interfaces(h, jit.Regs()[3], h.MemoryRead32(jit.Regs()[13]), h.MemoryRead32(jit.Regs()[13] + 4), {SL_IID_ENGINE})) {
            jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return;
        }
        SLObjectItf object = nullptr; SLEngineItf engine = nullptr;
        SLresult result = slCreateEngine(&object, 0, nullptr, 0, nullptr, nullptr);
        if (!result) result = (*object)->Realize(object, SL_BOOLEAN_FALSE);
        if (!result) result = (*object)->GetInterface(object, SL_IID_ENGINE, &engine);
        if (result) { if (object) (*object)->Destroy(object); jit.Regs()[0] = result; return; }
        s.owner = &h; s.engine_object = object; s.engine = engine;
        s.engine_guest = MakeInterface(h, {{0,"SLObject_Realize"},{1,"SLObject_Resume"},{2,"SLObject_GetState"},
            {3,"SLEngine_GetInterface"},{4,"SLObject_RegisterCallback"},{5,"SLObject_AbortAsyncOperation"},{6,"SLObject_Destroy"}});
        s.engine_interface = MakeInterface(h, {{2,"SLEngine_CreateAudioPlayer"},{7,"SLEngine_CreateOutputMix"}});
        if (!s.engine_guest || !s.engine_interface) {
            FreeInterface(h,s.engine_guest); FreeInterface(h,s.engine_interface);
            (*s.engine_object)->Destroy(s.engine_object); s.engine_object = nullptr; s.engine = nullptr;
            jit.Regs()[0] = SL_RESULT_MEMORY_FAILURE; return;
        }
        h.MemoryWrite32(out, s.engine_guest);
        LOGI("slCreateEngine created guest engine 0x%08X", s.engine_guest);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLObject_Realize", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::unique_lock<std::mutex> lock(s.mutex);
        if (!Usable(s,h)) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        if (jit.Regs()[1]) { jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return; }
        const uint32_t self = jit.Regs()[0];
        SLresult result = SL_RESULT_PARAMETER_INVALID;
        if (self && (self == s.engine_guest || self == s.mix_guest)) result = SL_RESULT_SUCCESS;
        if (self && self == s.player_guest) {
            result = RealizePlayer(s);
            if (result) {
                if (!BeginControl(s,lock)) { jit.Regs()[0] = result; return; }
                DestroyPlayer(s,lock,false); EndControl(s);
            }
        }
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLObject_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        LOGE("OpenSL unsupported-policy: asynchronous object resume");
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });
    manager.RegisterThunk("SLObject_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const uint32_t self = jit.Regs()[0], out = jit.Regs()[1];
        if (!Usable(s,h) || !self || (self != s.engine_guest && self != s.mix_guest && self != s.player_guest) || !Range(h,out,4)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        h.MemoryWrite32(out, self == s.player_guest && !PlayerReady(s) ? SL_OBJECT_STATE_UNREALIZED : SL_OBJECT_STATE_REALIZED);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLObject_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        LOGE("OpenSL unsupported-policy: asynchronous object callback");
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });
    manager.RegisterThunk("SLObject_AbortAsyncOperation", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        UnsafeVoidCall(jit, "AbortAsyncOperation");
    });
    manager.RegisterThunk("SLObject_Destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::unique_lock<std::mutex> lock(s.mutex);
        const uint32_t self = jit.Regs()[0];
        if (!Usable(s,h) || !self || (self != s.player_guest && self != s.mix_guest && self != s.engine_guest) || !BeginControl(s,lock)) {
            UnsafeVoidCall(jit,"Destroy"); return;
        }
        const bool engine = self == s.engine_guest, mix = self == s.mix_guest;
        DestroyPlayer(s,lock);
        if (engine || mix) {
            SLObjectItf object = s.mix_object; s.mix_object = nullptr;
            lock.unlock(); if (object) (*object)->Destroy(object); lock.lock();
            FreeInterface(h,s.mix_guest);
        }
        if (engine) {
            SLObjectItf object = s.engine_object; s.engine_object = nullptr; s.engine = nullptr;
            lock.unlock(); if (object) (*object)->Destroy(object); lock.lock();
            FreeInterface(h,s.engine_guest); FreeInterface(h,s.engine_interface);
        }
        EndControl(s);
    });
    manager.RegisterThunk("SLEngine_GetInterface", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || !s.engine_guest || jit.Regs()[0] != s.engine_guest || !Range(h,jit.Regs()[2],4)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        if (!IIDMatches(h,jit.Regs()[1],SL_IID_ENGINE)) { jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return; }
        h.MemoryWrite32(jit.Regs()[2],s.engine_interface); jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLEngine_CreateOutputMix", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || !s.engine || !s.engine_interface || jit.Regs()[0] != s.engine_interface || !Range(h,jit.Regs()[1],4) || !Range(h,jit.Regs()[13],4)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        if (s.mix_object || !Interfaces(h,jit.Regs()[2],jit.Regs()[3],h.MemoryRead32(jit.Regs()[13]),{})) {
            jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return;
        }
        SLObjectItf mix = nullptr;
        SLresult result = (*s.engine)->CreateOutputMix(s.engine,&mix,0,nullptr,nullptr);
        if (!result) result = (*mix)->Realize(mix,SL_BOOLEAN_FALSE);
        if (result) { if (mix) (*mix)->Destroy(mix); jit.Regs()[0] = result; return; }
        s.mix_guest = MakeInterface(h,{{0,"SLObject_Realize"},{2,"SLObject_GetState"},{6,"SLObject_Destroy"}});
        if (!s.mix_guest) { (*mix)->Destroy(mix); jit.Regs()[0] = SL_RESULT_MEMORY_FAILURE; return; }
        s.mix_object = mix; h.MemoryWrite32(jit.Regs()[1],s.mix_guest); jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLEngine_CreateAudioPlayer", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const uint32_t out = jit.Regs()[1], source = jit.Regs()[2], sink = jit.Regs()[3], sp = jit.Regs()[13];
        if (!Usable(s,h) || jit.Regs()[0] != s.engine_interface || !s.mix_object || s.player_guest) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return;
        }
        if (!Range(h,out,4) || !Range(h,source,8) || !Range(h,sink,8) || !Range(h,sp,12)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        const uint32_t locator = h.MemoryRead32(source), format = h.MemoryRead32(source+4), mixloc = h.MemoryRead32(sink);
        if (!Range(h,locator,8) || !Range(h,format,28) || !Range(h,mixloc,8)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        if (!Interfaces(h,h.MemoryRead32(sp),h.MemoryRead32(sp+4),h.MemoryRead32(sp+8),
                        {SL_IID_ANDROIDSIMPLEBUFFERQUEUE,SL_IID_BUFFERQUEUE,SL_IID_PLAY,SL_IID_VOLUME,SL_IID_ANDROIDCONFIGURATION})) {
            jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return;
        }
        const uint32_t locator_type = h.MemoryRead32(locator), capacity = h.MemoryRead32(locator+4);
        SLDataFormat_PCM pcm{}; memcpy(&pcm,h.GetGuestMemoryBase()+format,sizeof(pcm));
        if ((locator_type != SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE && locator_type != SL_DATALOCATOR_BUFFERQUEUE) ||
            !capacity || capacity > BUFFER_QUEUE_COUNT || h.MemoryRead32(mixloc) != SL_DATALOCATOR_OUTPUTMIX ||
            h.MemoryRead32(mixloc+4) != s.mix_guest || pcm.formatType != SL_DATAFORMAT_PCM ||
            (pcm.numChannels != 1 && pcm.numChannels != 2) || pcm.bitsPerSample != 16 || pcm.containerSize != 16 ||
            pcm.endianness != SL_BYTEORDER_LITTLEENDIAN || !pcm.samplesPerSec || pcm.samplesPerSec > 192000000u) {
            jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return;
        }
        // Android also derives AudioTrack notification cadence from this capacity.
        SLDataLocator_AndroidSimpleBufferQueue queue{SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE,capacity};
        SLDataSource native_source{&queue,&pcm};
        SLDataLocator_OutputMix mix{SL_DATALOCATOR_OUTPUTMIX,s.mix_object}; SLDataSink native_sink{&mix,nullptr};
        const SLInterfaceID ids[]{SL_IID_ANDROIDSIMPLEBUFFERQUEUE,SL_IID_PLAY,SL_IID_VOLUME,SL_IID_ANDROIDCONFIGURATION};
        const SLboolean required[]{SL_BOOLEAN_TRUE,SL_BOOLEAN_TRUE,SL_BOOLEAN_TRUE,SL_BOOLEAN_TRUE};
        SLObjectItf player = nullptr; SLAndroidConfigurationItf config = nullptr;
        SLresult result = (*s.engine)->CreateAudioPlayer(s.engine,&player,&native_source,&native_sink,4,ids,required);
        if (!result) result = (*player)->GetInterface(player,SL_IID_ANDROIDCONFIGURATION,&config);
        SLint32 stream = SL_ANDROID_STREAM_MEDIA;
        if (!result) result = (*config)->SetConfiguration(config,SL_ANDROID_KEY_STREAM_TYPE,&stream,sizeof(stream));
        if (result) { if (player) (*player)->Destroy(player); jit.Regs()[0] = result; return; }
        s.player_guest = MakeInterface(h,{{0,"SLObject_Realize"},{2,"SLObject_GetState"},{3,"SLPlayer_GetInterface"},{6,"SLObject_Destroy"}});
        s.config_guest = MakeInterface(h,{{0,"SLConfig_SetConfiguration"},{1,"SLConfig_GetConfiguration"}});
        s.play_guest = MakeInterface(h,{{0,"SLPlay_SetPlayState"},{1,"SLPlay_GetPlayState"}});
        s.queue_guest = MakeInterface(h,{{0,"SLBufferQueue_Enqueue"},{1,"SLBufferQueue_Clear"},{2,"SLBufferQueue_GetState"},{3,"SLBufferQueue_RegisterCallback"}});
        s.volume_guest = MakeInterface(h,{{0,"SLVolume_SetVolumeLevel"}});
        if (!s.player_guest || !s.config_guest || !s.play_guest || !s.queue_guest || !s.volume_guest) {
            (*player)->Destroy(player);
            for (uint32_t* object : {&s.player_guest,&s.config_guest,&s.play_guest,&s.queue_guest,&s.volume_guest}) FreeInterface(h,*object);
            jit.Regs()[0] = SL_RESULT_MEMORY_FAILURE; return;
        }
        s.player_object = player; s.config = config; s.channels = pcm.numChannels;
        s.requested_state = SL_PLAYSTATE_STOPPED; s.completed_index = 0; s.write_index = 0;
        h.MemoryWrite32(out,s.player_guest);
        LOGI("Host Audio Player created: %u channels, %u mHz sampleRate",pcm.numChannels,pcm.samplesPerSec);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLPlayer_GetInterface", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const uint32_t out = jit.Regs()[2], iid = jit.Regs()[1];
        if (!Usable(s,h) || jit.Regs()[0] != s.player_guest || !Range(h,out,4)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        uint32_t object = 0;
        if (IIDMatches(h,iid,SL_IID_ANDROIDCONFIGURATION)) object = s.config_guest;
        else if (!PlayerReady(s)) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        else if (IIDMatches(h,iid,SL_IID_PLAY)) object = s.play_guest;
        else if (IIDMatches(h,iid,SL_IID_ANDROIDSIMPLEBUFFERQUEUE) || IIDMatches(h,iid,SL_IID_BUFFERQUEUE)) object = s.queue_guest;
        else if (IIDMatches(h,iid,SL_IID_VOLUME)) object = s.volume_guest;
        if (!object) { jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return; }
        h.MemoryWrite32(out,object); jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    auto configuration = [](Dynarmic::A32::Jit& jit, DynarmicHost& h, bool get) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || jit.Regs()[0] != s.config_guest || !s.config) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        const uint32_t key = jit.Regs()[1], value = jit.Regs()[2], size_arg = jit.Regs()[3];
        char name[64]{}; bool terminated = false;
        for (unsigned n = 0; n < sizeof(name); ++n) {
            if (!Range(h,key,n+1)) break;
            name[n] = h.MemoryRead8(key+n);
            if (!name[n]) { terminated = true; break; }
        }
        if (!terminated) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        if (strcmp(name,reinterpret_cast<const char*>(SL_ANDROID_KEY_STREAM_TYPE)) &&
            strcmp(name,reinterpret_cast<const char*>(SL_ANDROID_KEY_PERFORMANCE_MODE))) {
            LOGE("OpenSL unsupported-policy: configuration key '%s'",name); jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; return;
        }
        if (get && !Range(h,size_arg,4)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        SLuint32 size = get ? h.MemoryRead32(size_arg) : size_arg;
        if (size != 4 || !Range(h,value,4)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        SLint32 data = get ? 0 : static_cast<int32_t>(h.MemoryRead32(value));
        const auto* native_key = reinterpret_cast<const SLchar*>(name);
        const SLresult result = get ? (*s.config)->GetConfiguration(s.config,native_key,&size,&data)
                                    : (*s.config)->SetConfiguration(s.config,native_key,&data,size);
        if (get) { h.MemoryWrite32(size_arg,size); if (!result) h.MemoryWrite32(value,data); }
        jit.Regs()[0] = result;
    };
    manager.RegisterThunk("SLConfig_SetConfiguration", [configuration](Dynarmic::A32::Jit& jit, DynarmicHost& h) { configuration(jit,h,false); });
    manager.RegisterThunk("SLConfig_GetConfiguration", [configuration](Dynarmic::A32::Jit& jit, DynarmicHost& h) { configuration(jit,h,true); });
    manager.RegisterThunk("SLPlay_SetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const uint32_t state = jit.Regs()[1];
        if (!Usable(s,h) || !PlayerReady(s) || jit.Regs()[0] != s.play_guest) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        if (state < SL_PLAYSTATE_STOPPED || state > SL_PLAYSTATE_PLAYING) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        const uint32_t old = s.requested_state; s.requested_state = state;
        const SLresult result = PlayState(s,EffectiveState(s));
        if (result) s.requested_state = old;
        LOGI("SLPlay_SetPlayState: %u result=%u",state,result);
        SLAndroidSimpleBufferQueueState queue{};
        if (QueueState(s,queue) == SL_RESULT_SUCCESS)
            LOGI("Audio control: requested=%u effective=%u appPaused=%u nativeIndex=%u acknowledged=%u queued=%u",
                 s.requested_state,EffectiveState(s),s.app_paused,queue.index,s.completed_index,queue.count);
        s.cv.notify_all(); jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLPlay_GetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || !PlayerReady(s) || jit.Regs()[0] != s.play_guest || !Range(h,jit.Regs()[1],4)) { jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return; }
        SLuint32 state = EffectiveState(s); SLresult result = SL_RESULT_SUCCESS;
#ifdef BRIDGE_OPENSL_TEST
        if (!s.fake)
#endif
        result = (*s.play)->GetPlayState(s.play,&state);
        if (!result) h.MemoryWrite32(jit.Regs()[1],state); jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLBufferQueue_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::unique_lock<std::mutex> lock(s.mutex);
        const uint32_t callback = jit.Regs()[1], context = jit.Regs()[2];
        if (!Usable(s,h) || !PlayerReady(s) || jit.Regs()[0] != s.queue_guest) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        if (callback && (((callback & 1) == 0 && (callback & 3)) || !h.IsExecutableAddress(callback & ~1u))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        if (!BeginControl(s,lock)) { jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return; }
        SLAndroidSimpleBufferQueueState state{};
        SLresult result = QueueState(s,state);
        if (!result && callback) result = StartLocked(s,h,lock);
        if (!result) {
            s.callback = callback; s.context = context; s.completed_index = state.index;
            s.wakeups.store(0,std::memory_order_release);
            LOGI("SLBufferQueue_RegisterCallback: callback=0x%08X, context=0x%08X",callback,context);
        }
        EndControl(s); jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLBufferQueue_Clear", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::unique_lock<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || !PlayerReady(s) || jit.Regs()[0] != s.queue_guest || !BeginControl(s,lock)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED; return;
        }
        SLresult result;
#ifdef BRIDGE_OPENSL_TEST
        if (s.fake) { result = s.fake_error; if (!result) s.fake_queue = {}; }
        else
#endif
        result = (*s.queue)->Clear(s.queue);
        if (!result) {
            SLAndroidSimpleBufferQueueState state{}; result = QueueState(s,state);
            if (!result) { s.completed_index = state.index; s.write_index = 0; s.wakeups.store(0,std::memory_order_release); }
        }
        EndControl(s); jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLBufferQueue_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        if (!Usable(s,h) || !PlayerReady(s) || jit.Regs()[0] != s.queue_guest || !Range(h,jit.Regs()[1],8)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        SLAndroidSimpleBufferQueueState state{}; const SLresult result = QueueState(s,state);
        if (!result) { h.MemoryWrite32(jit.Regs()[1],state.count); h.MemoryWrite32(jit.Regs()[1]+4,state.index); }
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("SLBufferQueue_Enqueue", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        jit.Regs()[0] = Enqueue(s,h,jit.Regs()[0],jit.Regs()[1],jit.Regs()[2]);
    });
    manager.RegisterThunk("SLVolume_SetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
        const int32_t level = static_cast<int32_t>(jit.Regs()[1]);
        if (!Usable(s,h) || jit.Regs()[0] != s.volume_guest || !s.volume || level < INT16_MIN || level > 0) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID; return;
        }
        jit.Regs()[0] = (*s.volume)->SetVolumeLevel(s.volume,static_cast<SLmillibel>(level));
    });
}

#ifdef BRIDGE_OPENSL_TEST
OpenSLESTestSnapshot OpenSLESTestPrepare(DynarmicHost& host, bool disable_start) {
    auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
    if ((s.owner && s.owner != &host) || s.engine_object || s.player_guest || s.thread.joinable()) return {};
    s.owner = &host; s.fake = true; s.disable_start = disable_start; s.channels = 2;
    s.starts = 0; s.callbacks = s.enqueues = s.bytes = s.nonzero = 0;
    s.fake_error = SL_RESULT_SUCCESS; s.fake_queue = {}; s.fake_play = SL_PLAYSTATE_STOPPED;
    s.player_guest = MakeInterface(host,{{6,"SLObject_Destroy"}});
    s.queue_guest = MakeInterface(host,{{0,"SLBufferQueue_Enqueue"},{1,"SLBufferQueue_Clear"},{2,"SLBufferQueue_GetState"},{3,"SLBufferQueue_RegisterCallback"}});
    s.play_guest = MakeInterface(host,{{0,"SLPlay_SetPlayState"},{1,"SLPlay_GetPlayState"}});
    s.accepting.store(true,std::memory_order_release);
    return {s.player_guest,s.queue_guest,s.play_guest,s.starts,s.callbacks,s.enqueues,s.fake_play,0,s.control,s.app_paused};
}
bool OpenSLESTestComplete(bool late_only) {
    auto& s = Audio();
    uint64_t before;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        if (!s.fake && !late_only) return false;
        if (!late_only) {
            if (!s.fake_queue.count) return false;
            --s.fake_queue.count; ++s.fake_queue.index;
        }
        before = s.callbacks;
    }
    HostBqPlayerCallback(nullptr,&s);
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.callbacks != before;
}
void OpenSLESTestError(uint32_t error) {
    auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex); s.fake_error = error;
}
OpenSLESTestSnapshot OpenSLESTestInspect() {
    auto& s = Audio(); std::lock_guard<std::mutex> lock(s.mutex);
    uint32_t hash = 2166136261u;
    for (const auto& buffer : s.buffers) for (uint8_t byte : buffer) hash = (hash ^ byte) * 16777619u;
    return {s.player_guest,s.queue_guest,s.play_guest,s.starts,s.callbacks,s.enqueues,s.fake_play,hash,s.control,s.app_paused};
}
#endif
