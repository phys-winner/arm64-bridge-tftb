#include "cache_read_diag.h"
#include "cache_sources.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "guest_qsort_image.h"
#include "thunks_opensles.h"
#include "telltale_addcallback_fastpath.h"
#include "telltale_propertyset_fastpath.h"
#include "telltale_fps.h"
#include "presentation_pacer.h"
#include "elf_loader.h"
#include "game_port_config.h"
#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <EGL/egl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>

#include <algorithm>
#include <array>
#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <limits>

static bool FpsLuaCheck(DynarmicHost& host);

#if defined(ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE
bool InstallTFTBWidescreenOverride(DynarmicHost& runtime, bool enabled);
#endif

// Small instruction fixtures deliberately exercise the production SVC/BLX path.
static void Load(std::vector<uint32_t>& code, unsigned reg, uint32_t value) {
    code.push_back(0xE3000000u | (reg << 12) | ((value & 0xF000u) << 4) | (value & 0xFFFu)); // movw
    value >>= 16;
    code.push_back(0xE3400000u | (reg << 12) | ((value & 0xF000u) << 4) | (value & 0xFFFu)); // movt
}

static void Call(std::vector<uint32_t>& code, uint32_t target) {
    Load(code, 12, target);
    code.push_back(0xE12FFF3C); // blx ip
}

template<typename T>
static uint32_t Install(DynarmicHost& host, const std::vector<T>& code) {
    const uint32_t address = host.GuestAlloc(code.size() * sizeof(T), 4);
    assert(address);
    memcpy(host.GetGuestMemoryBase() + address, code.data(), code.size() * sizeof(T));
    host.AddExecutableRange(address, code.size() * sizeof(T));
    host.InvalidateGuestCode(address, code.size() * sizeof(T));
    return address;
}

static void ThumbCall(std::vector<uint16_t>& code, uint32_t target) {
    if (code.size() % 2) code.push_back(0xBF00); // align literal PC
    code.insert(code.end(), {0x4C00, 0xE001, static_cast<uint16_t>(target),
                             static_cast<uint16_t>(target >> 16), 0x47A0, 0xBF00}); // ldr r4; b; literal; blx r4
}

static bool FmodCallbackCheck(DynarmicHost& host) {
    Dynarmic::A32::Jit* outer = nullptr;
    Dynarmic::A32::Jit* callback = nullptr;
    uint32_t thread_errno = 0;
    unsigned calls = 0, mode = 0;
    const uint32_t probe = host.GetThunkManager().RegisterThunk("__fmod_sync_probe", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        assert(active.IsJitRunning() && (jit.Regs()[13] & 7) == 0);
        assert(jit.Regs()[0] == 0xA0 && jit.Regs()[1] == 0xB0);
        assert(jit.Regs()[2] == 0x87654321 && jit.Regs()[3] == 0x12345678);
        if (outer) {
            assert(&jit != outer && active.CurrentGuestErrnoAddress() == thread_errno);
            if (callback) assert(callback == &jit);
            callback = &jit;
            active.MemoryWrite32(thread_errno, 17);
        }
        if (mode) {
            assert(active.MemoryRead32(jit.Regs()[13]) == 0x55667788);
            assert(active.MemoryRead32(jit.Regs()[13] + 4) == 0x10203040);
            assert(active.MemoryRead32(jit.Regs()[13] + 8) == 0xC0);
            assert(active.MemoryRead32(jit.Regs()[13] + 12) == 37);
            jit.Regs()[0] = 37; jit.Regs()[1] = 0;
        } else {
            jit.Regs()[0] = 0x87654321; jit.Regs()[1] = 0x12345678;
        }
        ++calls;
    });
    const std::vector<uint32_t> size_args{0xA0,0xB0,0x87654321,0x12345678};
    bool completed = false;
    assert(host.RunSynchronousCallback(probe,size_args,&completed) == 0x1234567887654321ull && completed);
    const uint32_t entry = host.GetThunkManager().RegisterThunk("__fmod_sync_outer", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        outer = &jit; thread_errno = active.CurrentGuestErrnoAddress(); assert(thread_errno);
        const auto registers = jit.Regs(); const auto extended = jit.ExtRegs();
        const auto cpsr = jit.Cpsr(); const auto fpscr = jit.Fpscr();
        const uint32_t previous_high = active.GetResultHigh();
        bool done = false;
        assert(active.RunSynchronousCallback(probe,size_args,&done) == 0x1234567887654321ull && done);
        mode = 1; done = false;
        assert(active.RunSynchronousCallback(probe,{0xA0,0xB0,0x87654321,0x12345678,0x55667788,0x10203040,0xC0,37},&done) == 37 && done);
        assert(jit.Regs() == registers && jit.ExtRegs() == extended && jit.Cpsr() == cpsr && jit.Fpscr() == fpscr);
        assert(active.GetResultHigh() == previous_high && active.CurrentGuestErrnoAddress() == thread_errno && active.MemoryRead32(thread_errno) == 17);
        outer = nullptr; jit.Regs()[0] = 90; jit.Regs()[1] = 0xABCD;
    });
    assert(host.RunFunction(entry,{1,2,3,4},&completed) == 90 && completed && !host.IsJitRunning());
    assert(calls == 3 && host.GetResultHigh() == 0xABCD);
    puts("FMOD synchronous callback checks OK: separate cached JIT, 64-bit result, AAPCS stack, outer CPU state and same-thread errno");
    return true;
}

static bool AudioRefillAckCheck(DynarmicHost& host) {
    using namespace std::chrono_literals;
    const auto player = OpenSLESTestPrepare(host, false);
    assert(player.queue && player.play);
    auto& manager = host.GetThunkManager();
    const uint32_t reg = manager.GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback");
    const uint32_t enqueue = manager.GetOrCreateThunkAddress("SLBufferQueue_Enqueue");
    const uint32_t play = manager.GetOrCreateThunkAddress("SLPlay_SetPlayState");
    const uint32_t clear = manager.GetOrCreateThunkAddress("SLBufferQueue_Clear");
    const uint32_t pcm = host.GuestAlloc(16, 8);
    assert(pcm); memset(host.GetGuestMemoryBase() + pcm, 0x19, 16);
    const auto caller = std::this_thread::get_id();
    std::atomic<bool> hold{false}, entered{false}, release{false};
    const uint32_t delay = manager.RegisterThunk("__audio_refill_delay", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        assert(std::this_thread::get_id() != caller && jit.Regs()[0] == player.queue);
        if (hold) {
            entered = true;
            const auto end = std::chrono::steady_clock::now() + 2s;
            while (!release && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(100us);
            assert(release);
        }
        std::this_thread::sleep_for(1ms); // Model guest work before its replacement PCM is ready.
        jit.Regs()[1] = pcm; jit.Regs()[2] = 16;
    });
    std::vector<uint32_t> code{0xE92D4010};
    Call(code, delay); Call(code, enqueue);
    code.insert(code.end(), {0xE8BD4010, 0xE12FFF1E});
    const uint32_t callback = Install(host, code);
    assert(host.RunFunction(reg, {player.queue, callback, 0}) == SL_RESULT_SUCCESS);
    assert(host.RunFunction(enqueue, {player.queue, pcm, 16}) == SL_RESULT_SUCCESS);
    assert(host.RunFunction(play, {player.play, SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    auto wait = [&](uint64_t count) {
        const auto end = std::chrono::steady_clock::now() + 2s;
        while (OpenSLESTestInspect().callbacks < count && std::chrono::steady_clock::now() < end)
            std::this_thread::sleep_for(100us);
        return OpenSLESTestInspect().callbacks >= count;
    };
    OpenSLESTestComplete(); assert(wait(1)); // Warm the callback's JIT before the measured pulls.
    unsigned acknowledged = 0;
    constexpr unsigned pulls = 8;
    for (unsigned i = 0; i < pulls; ++i) {
        if (OpenSLESTestComplete()) ++acknowledged;
        assert(wait(i + 2));
    }
    const auto preack_begin = std::chrono::steady_clock::now();
    const bool preack = OpenSLESTestComplete(true); // Worker already acknowledged and refilled it.
    const auto preack_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - preack_begin).count();
    assert(host.RunFunction(enqueue, {player.queue, pcm, 16}) == SL_RESULT_SUCCESS);
    const auto nonempty_begin = std::chrono::steady_clock::now();
    OpenSLESTestComplete(); // Two queued buffers leave one ready for Android's next pull.
    const auto nonempty_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - nonempty_begin).count();
    assert(wait(pulls + 2));
    assert(host.RunFunction(clear, {player.queue}) == SL_RESULT_SUCCESS);
    const auto clear_begin = std::chrono::steady_clock::now();
    const bool clear_ack = OpenSLESTestComplete(true); // Empty after Clear, with no new completion.
    const auto clear_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - clear_begin).count();
    std::this_thread::sleep_for(10ms);
    assert(OpenSLESTestInspect().callbacks == pulls + 2);
    assert(host.RunFunction(enqueue, {player.queue, pcm, 16}) == SL_RESULT_SUCCESS);
    hold = true;
    const auto begin = std::chrono::steady_clock::now();
    const bool held_ack = OpenSLESTestComplete();
    const auto held_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - begin).count();
    const auto enter_deadline = std::chrono::steady_clock::now() + 1s;
    while (!entered && std::chrono::steady_clock::now() < enter_deadline) std::this_thread::sleep_for(100us);
    release = true;
    assert(entered && wait(pulls + 3));
    assert(OpenSLESTestInspect().enqueues == pulls + 6);
    assert(host.RunFunction(reg, {player.queue, 0, 0}) == SL_RESULT_SUCCESS);
    ShutdownOpenSLES(&host);
    host.GuestFree(pcm);
    const bool passed = acknowledged == pulls && !held_ack && held_us < 100000 &&
                        !preack && preack_us < 3500 && nonempty_us < 3500 && !clear_ack && clear_us < 3500;
    printf("AUDIO_REFILL_ACK_%s acknowledged=%u/%u held_ack=%u held_us=%lld preack_us=%lld nonempty_us=%lld clear_us=%lld; warmed production callback, dedicated guest JIT, eager-pull return, non-empty queue and late notifications without delay, bounded held-callback fallback\n",
           passed ? "PASS" : "FAIL", acknowledged, pulls, held_ack, static_cast<long long>(held_us),
           static_cast<long long>(preack_us), static_cast<long long>(nonempty_us), static_cast<long long>(clear_us));
    fflush(stdout);
    return passed;
}

static bool AudioPumpCheck(DynarmicHost& host, bool no_pump) {
    using namespace std::chrono_literals;
    std::atomic<bool> finished{false};
    std::thread deadline([&] {
        const auto end = std::chrono::steady_clock::now()+20s;
        while (!finished && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(10ms);
        if (!finished) { fputs("Audio regression timed out (possible lifecycle deadlock)\n",stderr); std::_Exit(2); }
    });
    auto& manager = host.GetThunkManager();
    PauseAudioPlayback(&host); // Backgrounding during FMOD startup must be remembered.
    const auto player = OpenSLESTestPrepare(host,no_pump);
    assert(player.player && player.queue && player.play);
    const uint32_t reg = manager.GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback");
    const uint32_t enqueue = manager.GetOrCreateThunkAddress("SLBufferQueue_Enqueue");
    const uint32_t clear = manager.GetOrCreateThunkAddress("SLBufferQueue_Clear");
    const uint32_t play = manager.GetOrCreateThunkAddress("SLPlay_SetPlayState");
    const uint32_t destroy = manager.GetOrCreateThunkAddress("SLObject_Destroy");
    const uint32_t pcm = host.GuestAlloc(32), context = host.GuestAlloc(8);
    assert(pcm && context);
    memset(host.GetGuestMemoryBase()+pcm,0x19,32);
    host.MemoryWrite32(context,0xABCDEFAA);
    const std::thread::id caller_thread = std::this_thread::get_id();
    std::mutex mutex;
    std::condition_variable cv;
    bool hold = false, entered = false;
    std::atomic<unsigned> invocations{0};
    const uint32_t enter = manager.RegisterThunk("__audio_test_enter",[&](Dynarmic::A32::Jit& jit,DynarmicHost& active) {
        assert(&active == &host && active.IsJitRunning() && std::this_thread::get_id() != caller_thread);
        assert(jit.Regs()[0] == player.queue && jit.Regs()[1] == context && host.MemoryRead32(context) == 0xABCDEFAA);
        assert((jit.Regs()[13] & 7) == 0);
        // A different worker must acquire this mutex while the callback is running.
        bool acquired = false;
        std::thread probe([&] {
            std::lock_guard<std::recursive_mutex> host_lock(host.GetMutex());
            std::lock_guard<std::mutex> lock(mutex); acquired = true; cv.notify_all();
        });
        {
            std::unique_lock<std::mutex> lock(mutex);
            assert(cv.wait_for(lock,2s,[&] { return acquired; }));
            entered = true; cv.notify_all();
            assert(cv.wait_for(lock,2s,[&] { return !hold; }));
        }
        probe.join();
        jit.Regs()[1] = pcm; jit.Regs()[2] = 16;
    });
    const uint32_t leave = manager.RegisterThunk("__audio_test_leave",[&](Dynarmic::A32::Jit& jit,DynarmicHost&) {
        assert(jit.Regs()[0] == SL_RESULT_SUCCESS); // callback re-enqueued through the production thunk
        ++invocations;
    });
    std::vector<uint32_t> arm{0xE92D4010};
    Call(arm,enter); Call(arm,enqueue); Call(arm,leave);
    arm.insert(arm.end(),{0xE8BD4010,0xE12FFF1E});
    const uint32_t callback = Install(host,arm);
    std::vector<uint16_t> thumb{0xB510};
    ThumbCall(thumb,enter); ThumbCall(thumb,enqueue); ThumbCall(thumb,leave);
    thumb.push_back(0xBD10);
    const uint32_t thumb_callback = Install(host,thumb) | 1;
    auto wait_callbacks = [&](uint64_t count) {
        const auto deadline = std::chrono::steady_clock::now()+2s;
        while (std::chrono::steady_clock::now() < deadline) {
            if (OpenSLESTestInspect().callbacks >= count) return true;
            std::this_thread::sleep_for(1ms);
        }
        return false;
    };
    auto call = [&](uint32_t function, std::initializer_list<uint32_t> args) {
        return host.RunFunction(function,std::vector<uint32_t>(args));
    };
    assert(call(reg,{player.queue,callback,context}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,callback,context}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PLAYING);
    OpenSLESTestComplete(); OpenSLESTestComplete();
    if (!wait_callbacks(2)) {
        fprintf(stderr,"Audio regression FAILED: two completions did not reach guest refill (candidate125 missing-start reproduction=%d)\n",no_pump);
        ShutdownOpenSLES(&host);
        finished = true; deadline.join();
        return false;
    }
    assert(OpenSLESTestInspect().starts == 1 && invocations == 2 && OpenSLESTestInspect().enqueues == 4);

    PauseAudioPlayback(&host);
    assert(call(play,{player.play,SL_PLAYSTATE_PAUSED}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    OpenSLESTestComplete(); // A buffer completed before pause; its acknowledgment remains valid.
    if (!wait_callbacks(3)) {
        fputs("Audio regression FAILED: real completion acknowledgment withheld while PAUSED\n",stderr);
        ShutdownOpenSLES(&host);
        finished = true; deadline.join();
        return false;
    }
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    // Only the guest's explicit request resumes hardware, after its acknowledgment.
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    assert(call(play,{player.play,SL_PLAYSTATE_STOPPED}) == SL_RESULT_SUCCESS);
    PauseAudioPlayback(&host); ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_STOPPED);
    OpenSLESTestComplete(); assert(wait_callbacks(4));
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_STOPPED);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);

    PauseAudioPlayback(&host);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    OpenSLESTestComplete(true); // notification from an old buffer, after native index reset
    ResumeAudioPlayback(&host); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 4);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(mutex); hold = true; entered = false;
    }
    OpenSLESTestComplete();
    {
        std::unique_lock<std::mutex> lock(mutex); assert(cv.wait_for(lock,2s,[&] { return entered; }));
    }
    PauseAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    std::atomic<bool> unregistered{false};
    std::thread unregister([&] {
        assert(call(reg,{player.queue,0,0}) == SL_RESULT_SUCCESS);
        unregistered = true;
    });
    const auto control_deadline = std::chrono::steady_clock::now()+2s;
    while (!OpenSLESTestInspect().control && std::chrono::steady_clock::now()<control_deadline)
        std::this_thread::sleep_for(1ms);
    assert(OpenSLESTestInspect().control && !unregistered);
    ResumeAudioPlayback(&host);
    assert(!OpenSLESTestInspect().app_paused);
    PauseAudioPlayback(&host);
    assert(OpenSLESTestInspect().app_paused);
    ResumeAudioPlayback(&host);
    assert(!OpenSLESTestInspect().app_paused);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    {
        std::lock_guard<std::mutex> lock(mutex); hold = false; cv.notify_all();
    }
    unregister.join();
    assert(!OpenSLESTestInspect().control);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PLAYING);
    assert(wait_callbacks(5));
    host.MemoryWrite32(context,0xDEADBEEF); // guest may now release its callback context
    OpenSLESTestComplete(); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 5);
    host.MemoryWrite32(context,0xABCDEFAA);
    assert(call(play,{player.play,SL_PLAYSTATE_STOPPED}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,thumb_callback,context}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().starts == 1);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    OpenSLESTestComplete(); assert(wait_callbacks(6));
    assert(invocations == 6);

    const auto before_bad = OpenSLESTestInspect();
    for (const auto& args : std::vector<std::vector<uint32_t>>{
             {player.queue,0,16},{player.queue,UINT32_MAX-1,16},{player.queue,pcm,16388},
             {player.queue,pcm,0},{player.queue,pcm,3},{player.queue+4,pcm,16}})
        assert(host.RunFunction(enqueue,args) != SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,pcm,context}) == SL_RESULT_PARAMETER_INVALID);
    assert(call(reg,{player.queue,callback|2u,context}) == SL_RESULT_PARAMETER_INVALID);
    assert(OpenSLESTestInspect().enqueues == before_bad.enqueues && OpenSLESTestInspect().buffer_hash == before_bad.buffer_hash);
    OpenSLESTestError(SL_RESULT_RESOURCE_ERROR);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_RESOURCE_ERROR);
    assert(OpenSLESTestInspect().enqueues == before_bad.enqueues && OpenSLESTestInspect().buffer_hash == before_bad.buffer_hash);
    OpenSLESTestError(SL_RESULT_SUCCESS);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    for (unsigned i = 0; i < 128; ++i) assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    const auto full = OpenSLESTestInspect();
    memset(host.GetGuestMemoryBase()+pcm,0x55,32);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_BUFFER_INSUFFICIENT);
    assert(OpenSLESTestInspect().enqueues == full.enqueues && OpenSLESTestInspect().buffer_hash == full.buffer_hash);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,0,0}) == SL_RESULT_SUCCESS);
    call(destroy,{player.player});
    OpenSLESTestComplete(true); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 6 && OpenSLESTestInspect().queue == 0);
    ShutdownOpenSLES(&host);
    assert(OpenSLESTestInspect().queue == 0);
    {
        DynarmicHost teardown;
        assert(teardown.Initialize());
        const auto other = OpenSLESTestPrepare(teardown,false);
        const uint32_t idle_callback = Install(teardown,std::vector<uint32_t>{0xE12FFF1E});
        const uint32_t register_other = teardown.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback");
        assert(teardown.RunFunction(register_other,{other.queue,idle_callback,0}) == SL_RESULT_SUCCESS);
        assert(OpenSLESTestInspect().starts == 1);
    } // destructor must stop/join before destroying the guest JIT and memory
    assert(OpenSLESTestInspect().queue == 0);
    puts("Audio pump checks OK: production registration, ARM/Thumb callbacks, exact args/counts, distinct JIT, re-enqueue without host lock, pause/STOPPED, Clear late notification, unregister quiescence, destroy/join, invalid/full/native-error");
    fflush(stdout);
    finished = true; deadline.join();
    return true;
}

static void AeabiMemoryCheck(DynarmicHost& host) {
    const char* names[][3] = {
        {"__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8"},
        {"__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8"},
        {"__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8"},
        {"__aeabi_memclr", "__aeabi_memclr4", "__aeabi_memclr8"}};
    const uint32_t storage = host.GuestAlloc(64, 8); assert(storage);
    auto* bytes = host.GetGuestMemoryBase() + storage;
    for (unsigned op = 0; op < 4; ++op) for (const char* name : names[op]) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
        assert(fn);
        std::vector<uint32_t> code{0xE92D4010}; Call(code, fn);
        code.insert(code.end(), {0xE8BD4010, 0xE3A0005A, 0xE12FFF1E}); // continuation marker, not an AEABI return value
        const uint32_t caller = Install(host, code);
        for (uint32_t n : {0u, 13u}) for (bool reverse : {false, true}) {
            std::array<uint8_t, 64> expected; expected.fill(0xA5);
            for (unsigned i = 8; i < 56; ++i) expected[i] = static_cast<uint8_t>(i * 7 + 3);
            memcpy(bytes, expected.data(), expected.size());
            const uint32_t d = reverse ? 16 : 8, s = op == 0 ? 40 : reverse ? 8 : 16;
            if (op < 2) memmove(expected.data() + d, expected.data() + s, n);
            else memset(expected.data() + d, op == 2 ? 0x5A : 0, n);
            const auto args = op < 2 ? std::vector<uint32_t>{storage+d, storage+s, n} : std::vector<uint32_t>{storage+d, n, 0x15A};
            assert(host.RunFunction(caller, args) == 90 && !host.IsJitRunning());
            assert(memcmp(bytes, expected.data(), expected.size()) == 0);
        }
        assert(host.RunFunction(caller, {0, 0, 0}) == 90);
    }
    host.GuestFree(storage);
    puts("AEABI memory checks OK: 12 variants, byte counts, overlap, fill argument order, canaries, zero count");
}

static void PendingInvalidationCheck(DynarmicHost& host) {
    const uint32_t function = Install(host, std::vector<uint32_t>{0xE3A00001, 0xE12FFF1E}); // mov r0,#1; bx lr
    assert(host.RunFunction(function) == 1);

    host.MemoryWrite32(function, 0xE3A00002); // mov r0,#2
    host.InvalidateGuestCode(function, sizeof(uint32_t));
    assert(host.RunFunction(function) == 2);

    puts("Pending JIT invalidation check OK: modified guest code was recompiled on the next RunFunction");
}

static void SyncAbiCheck(DynarmicHost& host) {
    using namespace std::chrono_literals;
    auto& manager = host.GetThunkManager();
    auto provider = [&](const char* name) {
        const uint32_t address = manager.FindProvider(name, ThunkManager::ProviderKind::Function);
        assert(address);
        return address;
    };
    auto call = [&](uint32_t function, std::initializer_list<uint32_t> args = {}) {
        return host.RunFunction(function, std::vector<uint32_t>(args));
    };

    const uint32_t errno_fn = provider("__errno");
    const uint32_t syscall_fn = provider("syscall");
    const uint32_t ioctl_fn = provider("ioctl");
    const uint32_t sem_init = provider("sem_init");
    const uint32_t sem_destroy = provider("sem_destroy");
    const uint32_t sem_wait = provider("sem_wait");
    const uint32_t sem_trywait = provider("sem_trywait");
    const uint32_t sem_post = provider("sem_post");
    const uint32_t sem_getvalue = provider("sem_getvalue");
    const uint32_t sem_close = provider("sem_close");
    const uint32_t sem_unlink = provider("sem_unlink");
    const uint32_t mutex_init = provider("pthread_mutex_init");
    const uint32_t mutex_destroy = provider("pthread_mutex_destroy");
    const uint32_t mutex_lock = provider("pthread_mutex_lock");
    const uint32_t mutex_unlock = provider("pthread_mutex_unlock");
    const uint32_t cond_init = provider("pthread_cond_init");
    const uint32_t cond_destroy = provider("pthread_cond_destroy");
    const uint32_t cond_timedwait = provider("pthread_cond_timedwait");
    const uint32_t cond_signal = provider("pthread_cond_signal");

    const uint32_t main_errno = call(errno_fn);
    assert(main_errno >= 0x1000 && main_errno < 0x2000 && (main_errno & 3u) == 0);
    assert(call(errno_fn) == main_errno);
    assert(call(syscall_fn, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);

    constexpr uint32_t kBionicSemValueMax = 0x3fffffffu;
    const uint32_t sem = host.GuestAlloc(4, 4);
    const uint32_t max_sem = host.GuestAlloc(4, 4);
    const uint32_t value = host.GuestAlloc(4, 4);
    assert(sem && max_sem && value);
    assert(call(sem_init, {sem, 0, 0}) == 0);
    assert(host.MemoryRead32(main_errno) == ENOSYS); // successful POSIX calls do not clear errno
    assert(call(sem_trywait, {sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == EAGAIN);
    assert(call(sem_post, {sem}) == 0 && call(sem_trywait, {sem}) == 0);
    assert(call(sem_getvalue, {sem, value}) == 0 && host.MemoryRead32(value) == 0);
    assert(call(sem_init, {max_sem, 0, kBionicSemValueMax + 1}) == UINT32_MAX &&
           host.MemoryRead32(main_errno) == EINVAL);
    assert(call(sem_init, {max_sem, 1, 0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);
    assert(call(sem_init, {max_sem, 0, kBionicSemValueMax}) == 0);
    assert(call(sem_post, {max_sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == EOVERFLOW);
    assert(call(sem_getvalue, {max_sem, value}) == 0 && host.MemoryRead32(value) == kBionicSemValueMax);
    assert(call(sem_wait, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == EINVAL);
    assert(call(sem_getvalue, {sem, UINT32_MAX}) == UINT32_MAX && host.MemoryRead32(main_errno) == EFAULT);
    assert(call(sem_close, {sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);
    assert(call(sem_unlink, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);

    // Two guest CPU contexts must expose independent, stable errno cells.
    std::barrier rendezvous(3);
    std::array<uint32_t, 2> thread_errno{};
    std::array<uint32_t, 2> thread_error{};
    std::thread first([&] {
        thread_errno[0] = call(errno_fn);
        rendezvous.arrive_and_wait();
        assert(call(syscall_fn, {0}) == UINT32_MAX);
        thread_error[0] = host.MemoryRead32(thread_errno[0]);
        rendezvous.arrive_and_wait();
    });
    std::thread second([&] {
        thread_errno[1] = call(errno_fn);
        rendezvous.arrive_and_wait();
        assert(call(ioctl_fn, {0, 0, 0}) == UINT32_MAX);
        thread_error[1] = host.MemoryRead32(thread_errno[1]);
        rendezvous.arrive_and_wait();
    });
    host.MemoryWrite32(main_errno, EDOM);
    rendezvous.arrive_and_wait();
    assert(thread_errno[0] && thread_errno[1] && thread_errno[0] != thread_errno[1] &&
           thread_errno[0] != main_errno && thread_errno[1] != main_errno);
    rendezvous.arrive_and_wait();
    first.join();
    second.join();
    assert(thread_error[0] == ENOSYS && thread_error[1] == ENOTTY && host.MemoryRead32(main_errno) == EDOM);

    const uint32_t mutex = host.GuestAlloc(4, 4);
    const uint32_t cond = host.GuestAlloc(4, 4);
    const uint32_t timeout = host.GuestAlloc(8, 4);
    assert(mutex && cond && timeout);
    assert(call(mutex_init, {mutex, 0}) == 0 && call(cond_init, {cond, 0}) == 0);
    host.MemoryWrite32(main_errno, ERANGE);

    auto timed_wait = [&](int32_t seconds, int32_t nanoseconds) {
        host.MemoryWrite32(timeout, static_cast<uint32_t>(seconds));
        host.MemoryWrite32(timeout + 4, static_cast<uint32_t>(nanoseconds));
        assert(call(mutex_lock, {mutex}) == 0);
        const auto start = std::chrono::steady_clock::now();
        const uint32_t result = call(cond_timedwait, {cond, mutex, timeout});
        const auto elapsed = std::chrono::steady_clock::now() - start;
        assert(call(mutex_unlock, {mutex}) == 0);
        return std::pair{result, elapsed};
    };
    auto negative = timed_wait(-1, 0);
    assert(negative.first == ETIMEDOUT && negative.second < 100ms);
    assert(timed_wait(0, -1).first == EINVAL);
    assert(timed_wait(0, 1000000000).first == EINVAL);
    assert(call(mutex_lock, {mutex}) == 0);
    assert(call(cond_timedwait, {cond, mutex, timeout + 1}) == EINVAL);
    assert(call(cond_timedwait, {cond, mutex, UINT32_MAX - 3}) == EINVAL);
    assert(call(mutex_unlock, {mutex}) == 0);

    auto signal_after = [&](uint32_t timeout_address) {
        assert(call(mutex_lock, {mutex}) == 0);
        std::thread signaler([&] {
            assert(call(mutex_lock, {mutex}) == 0);
            assert(call(cond_signal, {cond}) == 0);
            assert(call(mutex_unlock, {mutex}) == 0);
        });
        const uint32_t result = call(cond_timedwait, {cond, mutex, timeout_address});
        assert(call(mutex_unlock, {mutex}) == 0);
        signaler.join();
        return result;
    };
    const auto future = std::chrono::system_clock::now() + 2s;
    const auto future_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(future.time_since_epoch()).count();
    host.MemoryWrite32(timeout, static_cast<uint32_t>(future_ns / 1000000000LL));
    host.MemoryWrite32(timeout + 4, static_cast<uint32_t>(future_ns % 1000000000LL));
    assert(signal_after(timeout) == 0);
    assert(signal_after(0) == 0); // Bionic API 26 treats a null abstime as an indefinite wait.
    assert(host.MemoryRead32(main_errno) == ERANGE); // pthread APIs return errors directly.

    assert(call(cond_destroy, {cond}) == 0 && call(mutex_destroy, {mutex}) == 0);
    assert(call(sem_destroy, {sem}) == 0 && call(sem_destroy, {max_sem}) == 0);
    puts("Sync ABI checks OK: TLS errno isolation, POSIX sem errors/limits, signed ARM32 timespec and cond waits");
    fflush(stdout);
}

static void PropertySetAccelerationCheck(DynarmicHost& host) {
    assert(InstallTelltalePropertySetAddCallbackAcceleration(host));
    assert(InstallTelltaleGetKeyInfoAcceleration(host));

    const uint32_t add_callback =
        host.FindSymbol("_ZN11PropertySet15AddCallbackBaseERK6SymbolP12FunctionBase");
    const uint32_t key_callbacks_destructor =
        host.FindSymbol("_ZN11PropertySet12KeyCallbacksD2Ev");
    const uint32_t get_key_info = host.FindSymbol(
        "_ZN11PropertySet10GetKeyInfoERK6SymbolRPNS_7KeyInfoERPS_NS_15GetKeyInfoFlagsE");
    const uint32_t get_handle_object_pointer = host.FindSymbol(
        "_ZN16HandleObjectInfo22GetHandleObjectPointerEv");
    assert(add_callback && key_callbacks_destructor && get_key_info &&
           get_handle_object_pointer);
    const uint32_t frame_literal = get_handle_object_pointer + 0xF0u;
    const uint32_t frame_got =
        get_handle_object_pointer + 0x10u + 0x00AE0F70u;

    // Four maximum-size indexes exactly fill the aggregate 262144-node cache;
    // building the fifth must evict the first four before allocating. All five
    // PropertySets deliberately share one valid guest list, keeping this
    // black-box budget regression compact in guest memory.
    constexpr uint32_t budget_node_count = 65536;
    constexpr uint32_t budget_set_count = 5;
    constexpr uint32_t budget_node_size = 0x18;
    const uint32_t budget_property_sets =
        host.GuestAlloc(budget_set_count * 0x50u, 8);
    const uint32_t budget_nodes =
        host.GuestAlloc(budget_node_count * budget_node_size, 8);
    const uint32_t budget_symbols = host.GuestAlloc(16, 8);
    const uint32_t budget_callbacks =
        host.GuestAlloc((budget_set_count + 1u) * 8u, 4);
    assert(budget_property_sets && budget_nodes && budget_symbols &&
           budget_callbacks);
    memset(host.GetGuestMemoryBase() + budget_property_sets, 0,
           budget_set_count * 0x50u);
    memset(host.GetGuestMemoryBase() + budget_nodes, 0,
           budget_node_count * budget_node_size);
    memset(host.GetGuestMemoryBase() + budget_callbacks, 0,
           (budget_set_count + 1u) * 8u);

    for (uint32_t i = 0; i < budget_node_count; ++i) {
        const uint32_t node = budget_nodes + i * budget_node_size;
        host.MemoryWrite32(node + 0x00,
                           i ? node - budget_node_size : 0);
        host.MemoryWrite32(node + 0x04,
                           i + 1u < budget_node_count
                               ? node + budget_node_size
                               : 0);
        host.MemoryWrite32(node + 0x08, 0x81000000u + i);
        host.MemoryWrite32(node + 0x0C, 0x1A2B3C4Du);
    }
    const uint32_t budget_tail =
        budget_nodes + (budget_node_count - 1u) * budget_node_size;
    for (uint32_t i = 0; i < budget_set_count; ++i) {
        const uint32_t set = budget_property_sets + i * 0x50u;
        host.MemoryWrite32(set + 0x0C, budget_node_count);
        host.MemoryWrite32(set + 0x10, budget_nodes);
        host.MemoryWrite32(set + 0x14, budget_tail);
    }
    host.MemoryWrite32(budget_symbols, 0x81000000u);
    host.MemoryWrite32(budget_symbols + 4, 0x1A2B3C4Du);
    for (uint32_t i = 0; i < budget_set_count; ++i) {
        const uint32_t set = budget_property_sets + i * 0x50u;
        const uint32_t callback = budget_callbacks + i * 8u;
        assert(host.RunFunction(add_callback,
                                {set, budget_symbols, callback}) == 1);
        assert(host.MemoryRead32(budget_nodes + 0x14) == callback);
    }

    // Position 12345 is not one of a fresh 65536-node generation's six
    // witnesses (0, 65535, 0, 16385, 32770, 49155). If the first index was not
    // evicted, this new key looks like a miss and the fastpath would append.
    // A rebuild instead finds the authoritative existing node.
    constexpr uint32_t budget_changed_position = 12345;
    constexpr uint32_t budget_changed_key_low = 0xF00DBAADu;
    constexpr uint32_t budget_changed_key_high = 0xCAFEBABEu;
    const uint32_t budget_changed_node =
        budget_nodes + budget_changed_position * budget_node_size;
    const uint32_t budget_changed_callback =
        budget_callbacks + budget_set_count * 8u;
    assert(host.MemoryRead32(budget_changed_node + 0x14) == 0);
    host.MemoryWrite32(budget_changed_node + 0x08, budget_changed_key_low);
    host.MemoryWrite32(budget_changed_node + 0x0C, budget_changed_key_high);
    host.MemoryWrite32(budget_symbols + 8, budget_changed_key_low);
    host.MemoryWrite32(budget_symbols + 12, budget_changed_key_high);
    assert(host.RunFunction(add_callback,
                            {budget_property_sets, budget_symbols + 8,
                             budget_changed_callback}) == 1);
    assert(host.MemoryRead32(budget_property_sets + 0x0C) ==
           budget_node_count);
    assert(host.MemoryRead32(budget_property_sets + 0x14) == budget_tail);
    assert(host.MemoryRead32(budget_changed_node + 0x14) ==
           budget_changed_callback);
    assert(host.MemoryRead32(budget_changed_callback + 4) ==
           budget_changed_callback);

    constexpr uint32_t key_low = 0x55667788u;
    constexpr uint32_t key_high = 0x11223344u;
    constexpr uint32_t appended_key_low = 0x89ABCDEFu;
    constexpr uint32_t appended_key_high = 0x01234567u;
    constexpr uint32_t mutated_key_low = 0x10203040u;
    constexpr uint32_t mutated_key_high = 0x50607080u;
    const uint32_t property_set = host.GuestAlloc(0x50, 8);
    const uint32_t symbol = host.GuestAlloc(8, 8);
    const uint32_t appended_symbol = host.GuestAlloc(8, 8);
    const uint32_t key_node = host.GuestAlloc(0x18, 8);
    const uint32_t appended_key_node = host.GuestAlloc(0x18, 8);
    const uint32_t rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t outputs = host.GuestAlloc(8, 4);
    const uint32_t old_callback = host.GuestAlloc(8, 4);
    const uint32_t new_callback = host.GuestAlloc(8, 4);
    const uint32_t appended_old_callback = host.GuestAlloc(8, 4);
    const uint32_t appended_callback = host.GuestAlloc(8, 4);
    const uint32_t rebuilt_callback = host.GuestAlloc(8, 4);
    const uint32_t mutated_callback = host.GuestAlloc(8, 4);
    const uint32_t fallback_callback = host.GuestAlloc(8, 4);
    assert(property_set && symbol && appended_symbol && key_node &&
           appended_key_node && rb_node && outputs && old_callback &&
           new_callback && appended_old_callback && appended_callback &&
           rebuilt_callback && mutated_callback && fallback_callback);
    memset(host.GetGuestMemoryBase() + property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + key_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + appended_key_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + old_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + new_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + appended_old_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + appended_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + rebuilt_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + mutated_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + fallback_callback, 0, 8);
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(appended_symbol, appended_key_low);
    host.MemoryWrite32(appended_symbol + 4, appended_key_high);

    // Synthetic KeyCallbacks list: first invocation must use the native hit.
    host.MemoryWrite32(property_set + 0x0C, 1);
    host.MemoryWrite32(property_set + 0x10, key_node);
    host.MemoryWrite32(property_set + 0x14, key_node);
    host.MemoryWrite32(key_node + 0x08, key_low);
    host.MemoryWrite32(key_node + 0x0C, key_high);
    host.MemoryWrite32(key_node + 0x14, old_callback);
    host.MemoryWrite32(old_callback + 4, old_callback);
    assert(host.RunFunction(add_callback, {property_set, symbol, new_callback}) == 1);
    assert(host.MemoryRead32(key_node + 0x14) == new_callback);
    assert(host.MemoryRead32(old_callback + 4) == new_callback);
    assert(host.MemoryRead32(new_callback + 4) == old_callback);

    // The guest miss path appends a single KeyCallbacks node. Reproduce that
    // exact transition and require the cached native index to incorporate it.
    host.MemoryWrite32(key_node + 0x04, appended_key_node);
    host.MemoryWrite32(appended_key_node + 0x00, key_node);
    host.MemoryWrite32(appended_key_node + 0x08, appended_key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, appended_key_high);
    host.MemoryWrite32(appended_key_node + 0x14, appended_old_callback);
    host.MemoryWrite32(appended_old_callback + 4, appended_old_callback);
    host.MemoryWrite32(property_set + 0x0C, 2);
    host.MemoryWrite32(property_set + 0x14, appended_key_node);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             appended_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == appended_callback);
    assert(host.MemoryRead32(appended_old_callback + 4) == appended_callback);
    assert(host.MemoryRead32(appended_callback + 4) == appended_old_callback);

    // A removal is not the append-only fast transition. Give the surviving
    // node the removed node's key as well: a stale index would then update the
    // detached node, while a correct rebuild follows the authoritative list.
    host.MemoryWrite32(property_set + 0x0C, 1);
    host.MemoryWrite32(property_set + 0x10, appended_key_node);
    host.MemoryWrite32(property_set + 0x14, appended_key_node);
    host.MemoryWrite32(appended_key_node + 0x00, 0);
    host.MemoryWrite32(appended_key_node + 0x04, 0);
    host.MemoryWrite32(appended_key_node + 0x08, key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, key_high);
    assert(host.RunFunction(add_callback,
                            {property_set, symbol,
                             rebuilt_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == rebuilt_callback);
    assert(host.MemoryRead32(appended_callback + 4) == rebuilt_callback);
    assert(host.MemoryRead32(rebuilt_callback + 4) == appended_old_callback);

    // Metadata is unchanged here, so only per-node validation can notice the
    // in-place key mutation and rebuild the small-list index correctly.
    host.MemoryWrite32(appended_key_node + 0x08, mutated_key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, mutated_key_high);
    host.MemoryWrite32(appended_symbol, mutated_key_low);
    host.MemoryWrite32(appended_symbol + 4, mutated_key_high);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             mutated_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == mutated_callback);
    assert(host.MemoryRead32(rebuilt_callback + 4) == mutated_callback);
    assert(host.MemoryRead32(mutated_callback + 4) == appended_old_callback);

    // An inconsistent count deliberately rejects the native scan. The exact
    // ARM32 body must still find the node and preserve the circular list.
    host.MemoryWrite32(property_set + 0x0C, 0);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             fallback_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == fallback_callback);
    assert(host.MemoryRead32(mutated_callback + 4) == fallback_callback);
    assert(host.MemoryRead32(fallback_callback + 4) == appended_old_callback);

    // A large cached generation validates only rotating witnesses. Exercise
    // the lifecycle guarantee that makes an unobserved ABA reuse safe: every
    // real KeyCallbacks removal runs D2, whose hook invalidates all indexes.
    constexpr uint32_t aba_node_count = 10;
    constexpr uint32_t aba_node_size = 0x18;
    const uint32_t aba_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t aba_nodes =
        host.GuestAlloc(aba_node_count * aba_node_size, 8);
    const uint32_t aba_warm_symbol = host.GuestAlloc(8, 8);
    const uint32_t aba_reused_symbol = host.GuestAlloc(8, 8);
    const uint32_t aba_warm_callback = host.GuestAlloc(8, 4);
    const uint32_t aba_reused_callback = host.GuestAlloc(8, 4);
    assert(aba_property_set && aba_nodes && aba_warm_symbol &&
           aba_reused_symbol && aba_warm_callback && aba_reused_callback);
    memset(host.GetGuestMemoryBase() + aba_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + aba_nodes, 0,
           aba_node_count * aba_node_size);
    memset(host.GetGuestMemoryBase() + aba_warm_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + aba_reused_callback, 0, 8);

    for (uint32_t i = 0; i < aba_node_count; ++i) {
        const uint32_t node = aba_nodes + i * aba_node_size;
        host.MemoryWrite32(node + 0x00,
                           i ? node - aba_node_size : 0);
        host.MemoryWrite32(node + 0x04,
                           i + 1u < aba_node_count ? node + aba_node_size : 0);
        host.MemoryWrite32(node + 0x08, 0x71000000u + i);
        host.MemoryWrite32(node + 0x0C, 0x0BAD0000u + i);
    }
    host.MemoryWrite32(aba_property_set + 0x0C, aba_node_count);
    host.MemoryWrite32(aba_property_set + 0x10, aba_nodes);
    host.MemoryWrite32(aba_property_set + 0x14,
                       aba_nodes + (aba_node_count - 1u) * aba_node_size);
    host.MemoryWrite32(aba_warm_symbol, 0x71000000u);
    host.MemoryWrite32(aba_warm_symbol + 4, 0x0BAD0000u);
    assert(host.RunFunction(add_callback,
                            {aba_property_set, aba_warm_symbol,
                             aba_warm_callback}) == 1);
    assert(host.MemoryRead32(aba_nodes + 0x14) == aba_warm_callback);
    assert(host.MemoryRead32(aba_warm_callback + 4) == aba_warm_callback);

    // Position five is deliberately absent from the first six large-list
    // witnesses. Temporarily unlink it without changing count/head/tail, run
    // its real destructor, then reuse the same address and restore the exact
    // link shape with a different key.
    const uint32_t recycled_node = aba_nodes + 5u * aba_node_size;
    const uint32_t recycled_previous = recycled_node - aba_node_size;
    const uint32_t recycled_next = recycled_node + aba_node_size;
    host.MemoryWrite32(recycled_previous + 0x04, recycled_next);
    host.MemoryWrite32(recycled_next + 0x00, recycled_previous);
    host.MemoryWrite32(recycled_node + 0x00, 0);
    host.MemoryWrite32(recycled_node + 0x04, 0);
    assert(host.MemoryRead32(recycled_node + 0x14) == 0);

    bool destructor_abi_checked = false;
    const uint32_t destructor_check = host.GetThunkManager().RegisterThunk(
        "__propertyset_test_check_keycallbacks_d2_abi",
        [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
            assert(&active == &host && active.IsJitRunning());
            assert(jit.Regs()[0] == recycled_node);
            assert((jit.Regs()[13] & 7u) == 0);
            for (uint32_t reg = 4; reg <= 8; ++reg) {
                assert(jit.Regs()[reg] == 0xC0DE0000u + reg);
            }
            destructor_abi_checked = true;
        });
    assert(destructor_check);
    std::vector<uint32_t> destructor_wrapper{0xE92D41F0u};
    Load(destructor_wrapper, 0, recycled_node);
    for (uint32_t reg = 4; reg <= 8; ++reg) {
        Load(destructor_wrapper, reg, 0xC0DE0000u + reg);
    }
    Call(destructor_wrapper, key_callbacks_destructor);
    Call(destructor_wrapper, destructor_check);
    destructor_wrapper.push_back(0xE8BD81F0u);
    assert(host.RunFunction(Install(host, destructor_wrapper)) ==
           recycled_node);
    assert(destructor_abi_checked);

    constexpr uint32_t recycled_key_low = 0xDEADC0DEu;
    constexpr uint32_t recycled_key_high = 0xFEEDBEEFu;
    memset(host.GetGuestMemoryBase() + recycled_node, 0, aba_node_size);
    host.MemoryWrite32(recycled_node + 0x00, recycled_previous);
    host.MemoryWrite32(recycled_node + 0x04, recycled_next);
    host.MemoryWrite32(recycled_node + 0x08, recycled_key_low);
    host.MemoryWrite32(recycled_node + 0x0C, recycled_key_high);
    host.MemoryWrite32(recycled_previous + 0x04, recycled_node);
    host.MemoryWrite32(recycled_next + 0x00, recycled_node);
    host.MemoryWrite32(aba_reused_symbol, recycled_key_low);
    host.MemoryWrite32(aba_reused_symbol + 4, recycled_key_high);
    assert(host.RunFunction(add_callback,
                            {aba_property_set, aba_reused_symbol,
                             aba_reused_callback}) == 1);
    assert(host.MemoryRead32(recycled_node + 0x14) ==
           aba_reused_callback);
    assert(host.MemoryRead32(aba_reused_callback + 4) ==
           aba_reused_callback);

    // Reuse the same allocation as a minimal PropertySet RB tree.
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(rb_node + 0x10, key_low);
    host.MemoryWrite32(rb_node + 0x14, key_high);
    host.MemoryWrite32(property_set + 0x30, rb_node);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 0}) == key_low);
    assert(host.MemoryRead32(outputs) == rb_node);
    assert(host.MemoryRead32(outputs + 4) == property_set);

    // The two output references may legally be the same guest word.  The
    // original stores KeyInfo first and the owning PropertySet second, so the
    // latter must be the final observable value.
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs, 0}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == property_set);

    // The fixed Handle getter literal/GOT words use direct native reads.  An
    // output alias must therefore fail closed to the original ARM32 body,
    // which still performs its legal ordered output stores.  Restore the
    // deliberately overwritten engine words immediately after each call.
    const uint32_t saved_frame_literal = host.MemoryRead32(frame_literal);
    const uint32_t saved_frame_got = host.MemoryRead32(frame_got);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(
               get_key_info,
               {property_set, symbol, frame_literal, outputs + 4, 0}) ==
           key_low);
    assert(host.MemoryRead32(frame_literal) == rb_node);
    assert(host.MemoryRead32(outputs + 4) == property_set);
    host.MemoryWrite32(frame_literal, saved_frame_literal);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, frame_got, 0}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == rb_node);
    assert(host.MemoryRead32(frame_got) == property_set);
    host.MemoryWrite32(frame_got, saved_frame_got);

    // Output references are legal aliases of the input Symbol in the guest
    // ABI. The native snapshot path rejects this case; the displaced ARM32
    // body must still finish safely and preserve its ordered output stores.
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, symbol, symbol + 4, 0}) ==
           key_low);
    assert(host.MemoryRead32(symbol) == rb_node);
    assert(host.MemoryRead32(symbol + 4) == property_set);
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);

    // A local non-empty miss is completed natively and returns null outputs.
    host.MemoryWrite32(symbol, key_low + 1u);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 0}) == key_low + 1u);
    assert(host.MemoryRead32(outputs) == 0 && host.MemoryRead32(outputs + 4) == 0);

    const uint32_t current_frame =
        host.FindSymbol("_ZN16HandleObjectInfo14smCurrentFrameE");
    const uint32_t parent_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t parent_rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t parent_handle = host.GuestAlloc(0x2C, 8);
    assert(current_frame && parent_property_set && parent_rb_node &&
           parent_handle);
    memset(host.GetGuestMemoryBase() + parent_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + parent_rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + parent_handle, 0, 0x2C);

    // Flag 2 follows an already-loaded parent HandleObjectInfo twice before
    // repeating the lookup. Both the result owner and smCurrentFrame write are
    // observable parts of the original ARM32 path.
    constexpr uint32_t parent_frame_marker = 0x13579BDFu;
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(parent_rb_node + 0x10, key_low);
    host.MemoryWrite32(parent_rb_node + 0x14, key_high);
    host.MemoryWrite32(parent_property_set + 0x30, parent_rb_node);
    host.MemoryWrite32(parent_handle + 0x1C, parent_property_set);
    host.MemoryWrite32(parent_handle + 0x28, 0);
    host.MemoryWrite32(property_set + 0x30, 0);
    host.MemoryWrite32(property_set + 0x44, parent_handle);
    host.MemoryWrite32(current_frame, parent_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 2}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == parent_rb_node);
    assert(host.MemoryRead32(outputs + 4) == parent_property_set);
    assert(host.MemoryRead32(parent_handle + 0x28) == parent_frame_marker);

    // An output word may also alias a HandleObjectInfo frame stamp.  All
    // deferred reads and writes must observe the single ordered ARM32 stream;
    // the final KeyInfo store therefore replaces the intermediate stamp.
    constexpr uint32_t parent_alias_frame_marker = 0x89ABCDEFu;
    host.MemoryWrite32(parent_handle + 0x28, 0);
    host.MemoryWrite32(current_frame, parent_alias_frame_marker);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(
               get_key_info,
               {property_set, symbol, parent_handle + 0x28, outputs + 4, 2}) ==
           key_low);
    assert(host.MemoryRead32(parent_handle + 0x28) == parent_rb_node);
    assert(host.MemoryRead32(outputs + 4) == parent_property_set);

    const uint32_t nested_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t nested_rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t nested_list_node = host.GuestAlloc(0x0C, 4);
    const uint32_t nested_handle = host.GuestAlloc(0x2C, 8);
    assert(nested_property_set && nested_rb_node && nested_list_node &&
           nested_handle);
    memset(host.GetGuestMemoryBase() + nested_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + nested_rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + nested_list_node, 0, 0x0C);
    memset(host.GetGuestMemoryBase() + nested_handle, 0, 0x2C);

    // Flag 4 walks the circular nested-PropertySet list, resolves the loaded
    // handle twice and recursively returns the child as the owning set.
    constexpr uint32_t nested_frame_marker = 0x2468ACE0u;
    const uint32_t nested_sentinel = property_set + 0x1C;
    host.MemoryWrite32(nested_rb_node + 0x10, key_low);
    host.MemoryWrite32(nested_rb_node + 0x14, key_high);
    host.MemoryWrite32(nested_property_set + 0x30, nested_rb_node);
    host.MemoryWrite32(nested_handle + 0x1C, nested_property_set);
    host.MemoryWrite32(nested_handle + 0x28, 0);
    host.MemoryWrite32(property_set + 0x1C, nested_list_node);
    host.MemoryWrite32(property_set + 0x20, nested_list_node);
    host.MemoryWrite32(nested_list_node + 0x00, nested_sentinel);
    host.MemoryWrite32(nested_list_node + 0x04, nested_sentinel);
    host.MemoryWrite32(nested_list_node + 0x08, nested_handle);
    host.MemoryWrite32(current_frame, nested_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 4}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == nested_rb_node);
    assert(host.MemoryRead32(outputs + 4) == nested_property_set);
    assert(host.MemoryRead32(nested_handle + 0x28) == nested_frame_marker);

    // More than eight distinct deferred frame stamps promotes the exact
    // latest-value shadow from its tiny inline cache to the flat table.  Every
    // child deliberately misses, so traversal continues across all nodes and
    // the ordered writes are committed only after the full list is validated.
    constexpr uint32_t promotion_child_count = 100;
    const uint32_t promotion_root = host.GuestAlloc(0x50, 8);
    const uint32_t promotion_children =
        host.GuestAlloc(promotion_child_count * 0x50u, 8);
    const uint32_t promotion_nodes =
        host.GuestAlloc(promotion_child_count * 0x0Cu, 4);
    const uint32_t promotion_handles =
        host.GuestAlloc(promotion_child_count * 0x2Cu, 8);
    assert(promotion_root && promotion_children && promotion_nodes &&
           promotion_handles);
    memset(host.GetGuestMemoryBase() + promotion_root, 0, 0x50);
    memset(host.GetGuestMemoryBase() + promotion_children, 0,
           promotion_child_count * 0x50u);
    memset(host.GetGuestMemoryBase() + promotion_nodes, 0,
           promotion_child_count * 0x0Cu);
    memset(host.GetGuestMemoryBase() + promotion_handles, 0,
           promotion_child_count * 0x2Cu);

    const uint32_t promotion_sentinel = promotion_root + 0x1C;
    host.MemoryWrite32(promotion_root + 0x1C, promotion_nodes);
    host.MemoryWrite32(
        promotion_root + 0x20,
        promotion_nodes + (promotion_child_count - 1u) * 0x0Cu);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        const uint32_t child = promotion_children + index * 0x50u;
        const uint32_t child_sentinel = child + 0x1Cu;
        const uint32_t node = promotion_nodes + index * 0x0Cu;
        const uint32_t handle = promotion_handles + index * 0x2Cu;
        host.MemoryWrite32(child + 0x1C, child_sentinel);
        host.MemoryWrite32(child + 0x20, child_sentinel);
        host.MemoryWrite32(node + 0x00,
                           index + 1u < promotion_child_count
                               ? node + 0x0Cu
                               : promotion_sentinel);
        host.MemoryWrite32(node + 0x04,
                           index ? node - 0x0Cu : promotion_sentinel);
        host.MemoryWrite32(node + 0x08, handle);
        host.MemoryWrite32(handle + 0x1C, child);
    }
    constexpr uint32_t promotion_frame_marker = 0x55AA7711u;
    host.MemoryWrite32(current_frame, promotion_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info,
                     {promotion_root, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 &&
           host.MemoryRead32(outputs + 4) == 0);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        assert(host.MemoryRead32(promotion_handles + index * 0x2Cu + 0x28) ==
               promotion_frame_marker);
    }

    // A second promoted call must get a fresh TLS generation and must not see
    // any address/value pair left by the previous lease.  One hundred children
    // also force the ordered log beyond its inline storage.
    constexpr uint32_t promotion_frame_marker_2 = 0xAA558822u;
    host.MemoryWrite32(current_frame, promotion_frame_marker_2);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info,
                     {promotion_root, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 &&
           host.MemoryRead32(outputs + 4) == 0);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        assert(host.MemoryRead32(promotion_handles + index * 0x2Cu + 0x28) ==
               promotion_frame_marker_2);
    }

    // The native flag-4 path also handles a valid empty nested list.
    host.MemoryWrite32(property_set + 0x30, 0);
    host.MemoryWrite32(property_set + 0x1C, property_set + 0x1C);
    host.MemoryWrite32(property_set + 0x20, property_set + 0x1C);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info, {property_set, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 && host.MemoryRead32(outputs + 4) == 0);

    puts("PropertySet acceleration checks OK: callback index generations, "
         "parent/nested traversal, current-frame writes and exact ARM32 fallback");
    fflush(stdout);
}

static bool GuestRangeCheck() {
    struct RangeCase { size_t arena; uint32_t address; size_t length; bool valid; };
    constexpr size_t full_arena = size_t{1} << 32;
    const RangeCase cases[] = {
        {0x1000, 0, 0, true}, {0x1000, 0, 1, false},
        {0x1000, 0x1000, 0, true}, {0x1000, 0x1000, 1, false},
        {0x1000, 0xFFF, 1, true}, {0x1000, 0xFFF, 2, false},
        {0x1000, 0x1001, 0, false},
        {full_arena, UINT32_MAX, 1, true}, {full_arena, UINT32_MAX, 2, false},
        {full_arena, UINT32_MAX, SIZE_MAX, false}, {full_arena, 1, SIZE_MAX, false},
        {0x80000000u, 0x80000000u, 0, true}, {0x80000000u, 0x80000000u, 1, false},
    };
    for (const auto& test : cases) {
        if (GuestRangeValid(test.arena, test.address, test.length) != test.valid) {
            fprintf(stderr, "FAIL guest span: arena=%zu address=%u length=%zu expected=%d\n",
                    test.arena, test.address, test.length, test.valid);
            return false;
        }
    }
    puts("Guest range checks OK: 13 cases, including zero length, arena end and SIZE_MAX overflow");
    return true;
}

static bool EglDestroyFailureCheck(DynarmicHost& host) {
    auto call = [&](const char* name, std::vector<uint32_t> args = {}) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function);
        assert(fn);
        return host.RunFunction(fn, args);
    };
    // Use a real off-screen surface. Current-object queries register the native
    // objects in the production handle tables without a window or game Activity.
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        fprintf(stderr, "FAIL EGL initialization: 0x%x\n", eglGetError());
        return false;
    }
    const EGLint attributes[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
    EGLConfig config{};
    EGLint count = 0;
    assert(eglChooseConfig(display, attributes, &config, 1, &count) && count == 1);
    const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    const EGLint surface_attributes[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
    assert(context != EGL_NO_CONTEXT && surface != EGL_NO_SURFACE);
    assert(eglMakeCurrent(display, surface, surface, context));
    const uint32_t guest_display = call("eglGetCurrentDisplay");
    const uint32_t guest_context = call("eglGetCurrentContext");
    const uint32_t guest_surface = call("eglGetCurrentSurface", {EGL_DRAW});
    assert(guest_display && guest_context && guest_surface);
    assert(call("eglMakeCurrent", {guest_display, 0, 0, 0}) == EGL_TRUE);

    // A bad display must fail without losing either still-live guest handle.
    assert(call("eglDestroyContext", {0, guest_context}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_DISPLAY);
    assert(call("eglDestroySurface", {0, guest_surface}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_DISPLAY);
    const bool context_retry = call("eglDestroyContext", {guest_display, guest_context}) == EGL_TRUE;
    const bool surface_retry = call("eglDestroySurface", {guest_display, guest_surface}) == EGL_TRUE;
    if (!context_retry || !surface_retry) {
        fprintf(stderr, "FAIL EGL destroy retry: context=%d surface=%d\n", context_retry, surface_retry);
        return false;
    }
    assert(call("eglDestroyContext", {guest_display, guest_context}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_CONTEXT);
    assert(call("eglDestroySurface", {guest_display, guest_surface}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_SURFACE);
    assert(call("eglTerminate", {guest_display}) == EGL_TRUE);
    assert(eglReleaseThread());
    puts("EGL destroy checks OK: failed destroy preserves handles, retry succeeds, successful destroy removes handles");
    return true;
}

static bool PthreadOnceCheck(DynarmicHost& host) {
    using namespace std::chrono_literals;
    auto& manager = host.GetThunkManager();
    const uint32_t once = manager.FindProvider("pthread_once", ThunkManager::ProviderKind::Function);
    const uint32_t control = host.GuestAlloc(8, 4), published = control + 4;
    host.MemoryWrite32(control, 0);
    host.MemoryWrite32(published, 0);
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false, release = false, contender = false, returned = false;
    unsigned calls = 0;
    const uint32_t hold = manager.RegisterThunk("__once_test_init", [&](Dynarmic::A32::Jit&, DynarmicHost& runtime) {
        std::unique_lock lock(mutex);
        ++calls;
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&] { return release; });
        runtime.MemoryWrite32(published, 0x12345678);
    });
    std::vector<uint32_t> init_code{0xE92D4010}; // push r4,lr
    Call(init_code, hold);
    init_code.insert(init_code.end(), {0xE3A00077, 0xE8BD8010}); // void initializer leaves arbitrary r0
    const uint32_t init = Install(host, init_code);
    uint32_t results[2]{UINT32_MAX, UINT32_MAX}, seen = 0;
    bool completed[2]{false, false};
    std::thread first([&] { results[0] = host.RunFunction(once, {control, init}, &completed[0]); });
    {
        std::unique_lock lock(mutex);
        if (!cv.wait_for(lock, 2s, [&] { return entered; })) {
            release = true;
            lock.unlock();
            cv.notify_all();
            first.join();
            return false;
        }
    }
    std::thread second([&] {
        { std::lock_guard lock(mutex); contender = true; cv.notify_all(); }
        results[1] = host.RunFunction(once, {control, init}, &completed[1]);
        seen = host.MemoryRead32(published);
        { std::lock_guard lock(mutex); returned = true; cv.notify_all(); }
    });
    bool premature, started;
    {
        std::unique_lock lock(mutex);
        started = cv.wait_for(lock, 2s, [&] { return contender; });
        premature = cv.wait_for(lock, 100ms, [&] { return returned; });
        release = true;
    }
    cv.notify_all();
    first.join();
    second.join();
    const uint32_t state = host.MemoryRead32(control);
    const bool pair = started && !premature && calls == 1 && results[0] == 0 && results[1] == 0 &&
                      completed[0] && completed[1] && seen == 0x12345678 && state == 2;
    printf("PthreadOnce pair: premature=%u calls=%u results=%u,%u state=%u seen=%08X\n",
           premature, calls, results[0], results[1], state, seen);
    host.MemoryWrite32(control, 0);
    std::vector<uint16_t> thumb_init{0xB510};
    ThumbCall(thumb_init, hold);
    thumb_init.insert(thumb_init.end(), {0x2099, 0xBD10});
    const uint32_t thumb = Install(host, thumb_init) | 1;
    std::vector<uint16_t> thumb_call{0xB510};
    ThumbCall(thumb_call, once);
    thumb_call.push_back(0xBD10);
    const uint32_t caller = Install(host, thumb_call) | 1;
    bool thumb_completed = false;
    const uint32_t result = host.RunFunction(caller, {control, thumb}, &thumb_completed);
    const uint32_t repeated = host.RunFunction(caller, {control, thumb});
    const bool interworking = result == 0 && repeated == 0 && thumb_completed &&
                             calls == 2 && host.MemoryRead32(control) == 2;
    printf("PthreadOnce Thumb: result=%u repeated=%u completed=%u calls=%u state=%u\n",
           result, repeated, thumb_completed, calls, host.MemoryRead32(control));
    const uint32_t inner = host.GuestAlloc(8, 4), outer = inner + 4;
    host.MemoryWrite32(inner, 0);
    host.MemoryWrite32(outer, 0);
    uint32_t saved_sp = 0;
    bool preserved = false;
    const uint32_t frame = manager.RegisterThunk("__once_test_frame", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        if (!saved_sp) { saved_sp = jit.Regs()[13]; return; }
        preserved = jit.Regs()[13] == saved_sp && !(saved_sp & 7) && jit.Regs()[4] == 0x5A && jit.Regs()[0] == 0;
    });
    std::vector<uint32_t> nested_init{0xE92D4010, 0xE3A0405A}; // push r4,lr; callee-saved sentinel
    Call(nested_init, frame);
    Load(nested_init, 0, inner);
    Load(nested_init, 1, init);
    Call(nested_init, once);
    Call(nested_init, frame);
    nested_init.push_back(0xE8BD8010);
    bool nested_completed = false;
    const uint32_t nested_result = host.RunFunction(caller, {outer, Install(host, nested_init)}, &nested_completed);
    const bool nested = nested_result == 0 && nested_completed && preserved && calls == 3 &&
                        host.MemoryRead32(inner) == 2 && host.MemoryRead32(outer) == 2;
    printf("PthreadOnce nested: result=%u completed=%u preserved=%u calls=%u states=%u,%u\n",
           nested_result, nested_completed, preserved, calls, host.MemoryRead32(inner), host.MemoryRead32(outer));
    puts(pair && interworking && nested ? "PTHREAD_ONCE_CHECK_PASS" : "PTHREAD_ONCE_CHECK_FAIL");
    return pair && interworking && nested;
}

// Audit-owned proposal: real CPU getters keep their original once controls.
// Fresh outer controls exercise a forced concurrent waiter without resetting
// published guest state or calling a raw CPU initializer a second time.
static bool RealCpuOnceCheck(DynarmicHost& host, char** argv) {
    using namespace std::chrono_literals;
    std::atomic<bool> finished{false};
    std::thread deadline([&] {
        const auto end = std::chrono::steady_clock::now() + 30s;
        while (!finished && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(10ms);
        if (!finished) {
            fputs("REAL_CPU_ONCE_CHECK_TIMEOUT\n", stderr);
            std::_Exit(2);
        }
    });
    const bool ok = [&] {
        FakeJniEnv::Instance().Init(host);
        const char* names[] = {"libfmod.so", "libfmodstudio.so", "libSDL2.so", "libGameEngine.so", "libmain.so"};
        std::vector<std::vector<uint8_t>> files;
        std::vector<GuestModuleImage> images;
        files.reserve(5);
        images.reserve(5);
        for (int i = 0; i < 5; ++i) {
            std::ifstream input(argv[i + 2], std::ios::binary);
            if (!input.good()) { fprintf(stderr, "Cannot read %s\n", argv[i + 2]); return false; }
            files.emplace_back(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
            images.push_back({names[i], files.back().data(), files.back().size()});
        }
        if (!host.LoadModulesFromMemory(images)) return false;
        const ElfLoader* engine = host.FindModule("libGameEngine.so");
        const ElfLoader* fmod = host.FindModule("libfmod.so");
        if (!engine || !fmod) return false;
        const uint32_t eb = engine->GetBaseAddress(), fb = fmod->GetBaseAddress();
        const uint32_t engine_control = eb + 0x1094C08, fmod_control = fb + 0x164A28;
        const uint32_t engine_getter = eb + 0x5A5B44, fmod_getter = fb + 0xF40A4;
        // These anchors bind private initializer/control RVAs to the audited inputs.
        const std::pair<uint32_t, uint32_t> anchors[] = {
            {eb + 0x5A4B44, 0xE59FCF28}, {eb + 0x5A5B58, 0xEBFEBCFD},
            {eb + 0x5A5B6C, 0x00AEF0AC}, {eb + 0x5A5B70, 0xFFFFEFEC},
            {fb + 0xF3754, 0xE59FC878}, {fb + 0xF40B8, 0xEBFC8675},
            {fb + 0xF40CC, 0x0007096C}, {fb + 0xF40D0, 0xFFFFF69C}
        };
        for (const auto& [address, word] : anchors) {
            if (host.MemoryRead32(address) != word) {
                fprintf(stderr, "Real CPU fingerprint mismatch at %08X\n", address);
                return false;
            }
        }
        const char* getters[] = {"android_getCpuFamily", "android_getCpuFeatures", "android_getCpuCount", "android_getCpuIdArm"};
        const uint32_t getter_rvas[] = {0x5A5B14, 0x5A5B44, 0x5A5B78, 0x5A5C38};
        for (unsigned i = 0; i < 4; ++i) if (engine->GetSymbolAddress(getters[i]) != eb + getter_rvas[i]) return false;
        printf("Real CPU constructors begin: bases=%08X,%08X controls=%08X,%08X states=%u,%u\n",
               eb, fb, engine_control, fmod_control, host.MemoryRead32(engine_control), host.MemoryRead32(fmod_control));
        fflush(stdout);
        if (!host.RunModuleInitializers()) return false;
        printf("Real CPU constructors done: states=%u,%u\n",
               host.MemoryRead32(engine_control), host.MemoryRead32(fmod_control));
        fflush(stdout);

        auto& manager = host.GetThunkManager();
        const uint32_t once = manager.FindProvider("pthread_once", ThunkManager::ProviderKind::Function);
        if (!once) return false;
        // A Thumb contender covers interworking while the ARM owner runs a real
        // getter, which may itself enter once through its relocated guest PLT.
        std::vector<uint16_t> thumb_call{0xB510};
        ThumbCall(thumb_call, once);
        thumb_call.push_back(0xBD10);
        const uint32_t caller = Install(host, thumb_call) | 1;
        auto pair = [&](const char* label, uint32_t getter, uint32_t canonical, uint32_t features) {
            const uint32_t cell = host.GuestAlloc(16, 8), output = cell + 8;
            if (!cell) return false;
            host.MemoryWrite32(cell, 0); // Only test-owned once state is initialized.
            host.MemoryWrite64(output, UINT64_MAX);
            std::mutex mutex;
            std::condition_variable cv;
            bool entered = false, release = false, contender = false, returned = false;
            unsigned calls = 0;
            const std::string hold_name = std::string("__once_real_") + label;
            const uint32_t hold = manager.RegisterThunk(hold_name, [&](Dynarmic::A32::Jit&, DynarmicHost&) {
                std::unique_lock lock(mutex);
                ++calls;
                entered = true;
                cv.notify_all();
                cv.wait(lock, [&] { return release; });
            });
            std::vector<uint32_t> code{0xE92D4010};
            Call(code, hold);
            Call(code, getter);
            Load(code, 12, output);
            code.insert(code.end(), {0xE58C0000, 0xE58C1004, 0xE3A00077, 0xE8BD8010});
            const uint32_t init = Install(host, code);
            uint32_t results[2]{UINT32_MAX, UINT32_MAX}, seen_state = UINT32_MAX;
            uint64_t seen = UINT64_MAX;
            bool completed[2]{false, false};
            printf("Real CPU %s pair begin: canonical=%08X state=%u getter=%08X init=%08X outer=%08X\n",
                   label, canonical, host.MemoryRead32(canonical), getter, init, cell);
            fflush(stdout);
            std::thread first([&] { results[0] = host.RunFunction(once, {cell, init}, &completed[0]); });
            {
                std::unique_lock lock(mutex);
                if (!cv.wait_for(lock, 2s, [&] { return entered; })) {
                    release = true;
                    lock.unlock();
                    cv.notify_all();
                    first.join();
                    return false;
                }
            }
            std::thread second([&] {
                { std::lock_guard lock(mutex); contender = true; cv.notify_all(); }
                results[1] = host.RunFunction(caller, {cell, init}, &completed[1]);
                seen_state = host.MemoryRead32(canonical);
                seen = host.MemoryRead64(output);
                { std::lock_guard lock(mutex); returned = true; cv.notify_all(); }
            });
            bool started, premature;
            {
                std::unique_lock lock(mutex);
                started = cv.wait_for(lock, 2s, [&] { return contender; });
                premature = cv.wait_for(lock, 100ms, [&] { return returned; });
                release = true;
            }
            cv.notify_all();
            first.join();
            second.join();
            const uint64_t value = host.MemoryRead64(features);
            const uint32_t state = host.MemoryRead32(cell), canonical_state = host.MemoryRead32(canonical);
            bool repeat_completed = false;
            const uint32_t repeat = host.RunFunction(caller, {cell, init}, &repeat_completed);
            const bool passed = started && !premature && calls == 1 && results[0] == 0 && results[1] == 0 &&
                completed[0] && completed[1] && repeat_completed && repeat == 0 && state == 2 &&
                canonical_state == 2 && seen_state == 2 && seen == value && host.MemoryRead64(output) == value;
            printf("Real CPU %s pair: premature=%u calls=%u results=%u,%u repeat=%u completed=%u,%u,%u states=%u,%u seen=%016llX value=%016llX\n",
                   label, premature, calls, results[0], results[1], repeat, completed[0], completed[1], repeat_completed,
                   state, canonical_state, static_cast<unsigned long long>(seen), static_cast<unsigned long long>(value));
            fflush(stdout);
            return passed;
        };
        if (!pair("engine", engine_getter, engine_control, eb + 0x1094C00)) return false;
        if (!pair("fmod", fmod_getter, fmod_control, fb + 0x164A38)) return false;
        // Check every nonmutating engine caller against its now-published field.
        const uint32_t field_rvas[] = {0x1094C0C, 0x1094C00, 0x1094BF8, 0x1094BF0};
        for (unsigned i = 0; i < 4; ++i) {
            bool completed = false;
            const uint32_t low = host.RunFunction(eb + getter_rvas[i], {}, &completed);
            const uint64_t value = i == 1 ? (uint64_t{host.GetResultHigh()} << 32) | low : low;
            const uint64_t expected = i == 1 ? host.MemoryRead64(eb + field_rvas[i]) : host.MemoryRead32(eb + field_rvas[i]);
            printf("Real CPU %s: completed=%u value=%016llX expected=%016llX state=%u\n",
                   getters[i], completed, static_cast<unsigned long long>(value), static_cast<unsigned long long>(expected),
                   host.MemoryRead32(engine_control));
            if (!completed || value != expected || host.MemoryRead32(engine_control) != 2) return false;
        }
        // android_setCpu takes a different initializer only while the CPU flag
        // is unset. After these queries its refusal path is the safe contract.
        if (host.MemoryRead32(eb + 0x1094BF4) != 1) return false;
        const uint64_t before_features = host.MemoryRead64(eb + 0x1094C00);
        const uint32_t before_count = host.MemoryRead32(eb + 0x1094BF8);
        bool set_completed = false;
        const uint32_t set = host.RunFunction(eb + 0x5A5BA8, {1, 0, 0, 0}, &set_completed);
        printf("Real CPU android_setCpu after publication: completed=%u result=%u state=%u\n",
               set_completed, set, host.MemoryRead32(engine_control));
        return set_completed && set == 0 && host.MemoryRead32(engine_control) == 2 &&
            host.MemoryRead64(eb + 0x1094C00) == before_features && host.MemoryRead32(eb + 0x1094BF8) == before_count;
    }();
    finished = true;
    deadline.join();
    puts(ok ? "REAL_CPU_ONCE_CHECK_PASS" : "REAL_CPU_ONCE_CHECK_FAIL");
    return ok;
}

extern "C" int IndexApk(const char* apk_path);
extern "C" int IndexApks(const char* const* apk_paths, size_t apk_count);
extern "C" int TelltaleWidescreenOverrideEnabled();
extern "C" bool PrivateMetadataContractCheck();

static bool CacheReadDiagCheck() {
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    using namespace cache_diag;
    errno = EINTR;
    RememberFd(7, "APK_VFS", "check.ttarch2", "/check/base.apk", 32, 14);
    const auto original = Fd(7);
    RememberFile(101, 7);
    assert(errno == EINTR && original.generation && !strcmp(original.kind, "APK_VFS"));
    const unsigned before = records;
    FdDelivered(7, original, "pread", 0, 0);
    FdDelivered(7, original, "pread", -1, 0);
    assert(records == before); // EOF, zero length and errors are not delivery.
    FdDelivered(7, original, "pread", 1, 0);
    FdDelivered(7, original, "pread", 10, 1);
    assert(records == before + 1); // Bounded first-positive record, not per-chunk logging.
    FileDelivered(101, "fread", 1);
    assert(records == before + 2);
    Pushback(101, true);
    FileDelivered(101, "getc", 1);
    assert(seen.contains({"UNKNOWN", "", "", "getc"}));
    Pushback(101, false);
    FileDelivered(101, "getc", 1);
    assert(seen.contains({"APK_VFS", "check.ttarch2", "/check/base.apk", "getc"}));
    ForgetFd(7);
    RememberFd(7, "DISK_PATH", "other.ttarch2", "/check/files/other.ttarch2");
    FdDelivered(7, original, "reused_fd", 1);
    FileDelivered(101, "reused_stream", 1);
    assert(seen.contains({"UNKNOWN", "", "", "reused_fd"}));
    assert(seen.contains({"UNKNOWN", "", "", "reused_stream"}));
    ForgetFile(101); // Must not erase the new descriptor's generation.
    assert(Fd(7).generation != original.generation && Fd(7).generation);
    RememberAsset(202, "check.ttarch2");
    RememberFd(8, "APK_ASSET_FD", Asset(202).name.c_str(), "/check/base.apk", 32, 14);
    ForgetAsset(202);
    const auto handed = Fd(8);
    assert(!strcmp(CheckedAssetRange(handed, 4, 0).kind, "UNKNOWN"));
    assert(!strcmp(CheckedAssetRange(handed, 4, 32).kind, "APK_ASSET_FD"));
    assert(!strcmp(CheckedAssetRange(handed, 4, 44).kind, "UNKNOWN"));
    assert(!strcmp(CheckedAssetRange(handed, 1, -1).kind, "UNKNOWN"));
    assert(!strcmp(Fd(8).kind, "APK_ASSET_FD")); // Asset lifetime does not own handed-out fd.
    assert(Text("invalid'quote").empty() && errno == EINTR);
    descriptors.clear(); streams.clear(); assets.clear(); seen.clear(); records = 0;
    for (unsigned i = 0; i < limit; ++i) RememberFd(10000+i, "DISK_PATH", "check.ttarch2", "/check/files/check.ttarch2");
    RememberFd(20000, "DISK_PATH", "check.ttarch2", "/check/files/check.ttarch2");
    assert(descriptors.size() == limit && saturated && !Fd(20000).generation);
    descriptors.clear(); seen.clear(); records = 0; saturated = false;
    assert(PrivateMetadataContractCheck());
    puts("CACHE_READ_DIAG_CHECK_PASS: positive-only, dedup, errno, pushback, fd reuse, asset handoff, bounded saturation");
    return true;
#else
    return false;
#endif
}

static bool OpenSLQueueCapacityCheck(DynarmicHost& host) {
    std::vector<uint32_t> allocated;
    auto data = [&](std::initializer_list<uint32_t> values) {
        const uint32_t p = host.GuestAlloc(values.size() * 4, 4);
        assert(p); allocated.push_back(p);
        unsigned offset = 0;
        for (uint32_t value : values) { host.MemoryWrite32(p + offset, value); offset += 4; }
        return p;
    };
    auto call = [&](const char* name, std::initializer_list<uint32_t> args) {
        const uint32_t fn = host.GetThunkManager().GetOrCreateThunkAddress(name);
        assert(fn); bool completed = false;
        const uint32_t value = host.RunFunction(fn, std::vector<uint32_t>(args), &completed);
        assert(completed); return value;
    };
    const uint32_t out = data({0, 0});
    assert(call("slCreateEngine", {out, 0, 0, 0, 0, 0}) == SL_RESULT_SUCCESS);
    const uint32_t engine = host.MemoryRead32(out);
    assert(call("SLEngine_GetInterface", {engine, GetOpenSLESInterfacePointer("SL_IID_ENGINE"), out}) == SL_RESULT_SUCCESS);
    const uint32_t engine_interface = host.MemoryRead32(out);
    assert(call("SLEngine_CreateOutputMix", {engine_interface, out, 0, 0, 0}) == SL_RESULT_SUCCESS);
    const uint32_t mix = host.MemoryRead32(out);
    constexpr uint32_t capacity = 2;
    const uint32_t locator = data({SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE, capacity});
    const uint32_t format = data({SL_DATAFORMAT_PCM, 2, 24000000, 16, 16,
                                  SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT, SL_BYTEORDER_LITTLEENDIAN});
    const uint32_t source = data({locator, format});
    const uint32_t sink = data({data({SL_DATALOCATOR_OUTPUTMIX, mix}), 0});
    assert(call("SLEngine_CreateAudioPlayer", {engine_interface, out, source, sink, 0, 0, 0}) == SL_RESULT_SUCCESS);
    const uint32_t player = host.MemoryRead32(out);
    assert(call("SLObject_Realize", {player, 0}) == SL_RESULT_SUCCESS);
    assert(call("SLPlayer_GetInterface", {player, GetOpenSLESInterfacePointer("SL_IID_ANDROIDSIMPLEBUFFERQUEUE"), out}) == SL_RESULT_SUCCESS);
    const uint32_t queue = host.MemoryRead32(out), pcm = data({0x12345678, 0x9ABCDEF0});
    for (unsigned i = 0; i < capacity; ++i)
        assert(call("SLBufferQueue_Enqueue", {queue, pcm, 8}) == SL_RESULT_SUCCESS);
    const uint32_t extra = call("SLBufferQueue_Enqueue", {queue, pcm, 8});
    assert(call("SLBufferQueue_GetState", {queue, out}) == SL_RESULT_SUCCESS);
    const uint32_t count = host.MemoryRead32(out), index = host.MemoryRead32(out + 4);
    fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d native_destroy_begin\n", getpid());
    call("SLObject_Destroy", {engine});
    ShutdownOpenSLES(&host);
    fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d native_destroyed\n", getpid());
    for (uint32_t p : allocated) host.GuestFree(p);
    const bool passed = extra == SL_RESULT_BUFFER_INSUFFICIENT && count == capacity && index == 0;
    printf("OPENSL_CAPACITY_%s requested=%u queued=%u extra_result=%u index=%u; real production thunks, stopped player, no audio playback, destroyed handles\n",
           passed ? "PASS" : "FAIL", capacity, count, extra, index);
    fflush(stdout);
    return passed;
}

static bool VfsFileCheck(DynarmicHost& host, const char* archive, const char* basename = "contract.bin") {
    assert(IndexApk(archive) == 0);
    char temporary[] = "/data/local/tmp/tftb-vfs-XXXXXX";
    const char* root = ::mkdtemp(temporary);
    assert(root);
    printf("VFS_TEMP_ROOT=%s\n",root); fflush(stdout);
    const std::string files = std::string(root) + "/files", net = files + "/Net";
    assert(::mkdir(files.c_str(), 0700) == 0 && ::mkdir(net.c_str(), 0700) == 0);
    const std::string path = net + "/" + basename, only = files + "/OnlyPkg/marker.bin";
    FILE* disk = ::fopen(path.c_str(), "wb");
    assert(disk && ::fwrite("external-longer", 1, 15, disk) == 15 && ::fclose(disk) == 0);
    auto string = [&](const std::string& text) {
        const uint32_t p = host.GuestAlloc(text.size() + 1, 1);
        assert(p); memcpy(host.GetGuestMemoryBase() + p, text.c_str(), text.size() + 1); return p;
    };
    auto call = [&](const char* name, std::initializer_list<uint32_t> args) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
        assert(fn); bool completed = false;
        const uint32_t value = host.RunFunction(fn, std::vector<uint32_t>(args), &completed);
        assert(completed); return value;
    };
    const uint32_t file = string(path), rb = string("rb"), rw = string("r+"), wb = string("wb");
    const uint32_t buffer = host.GuestAlloc(128, 8), info = host.GuestAlloc(104, 8);
    assert(buffer && info);
    const uint32_t stream = call("fopen", {file, rb}); assert(stream);
    assert(call("stat", {file, info}) == 0 && host.MemoryRead32(info + 48) == 14);
    assert(call("fread", {buffer, 1, 2, stream}) == 2);
    assert(memcmp(host.GetGuestMemoryBase() + buffer, "AP", 2) == 0); // Both-source winner.
    assert(call("fflush", {stream}) == 0); // POSIX active-handle synchronization before raw FD use.
    const uint32_t fd = call("fileno", {stream}); assert(fd != UINT32_MAX);
    assert(call("fstat", {fd, info}) == 0 && host.MemoryRead32(info + 48) == 14);
    assert((host.MemoryRead32(info + 16) & 0777) == 0444);
    assert(call("lseek", {fd, 0, SEEK_CUR}) == 2);
    assert(call("read", {fd, buffer, 2}) == 2 && memcmp(host.GetGuestMemoryBase() + buffer, "K-", 2) == 0);
    assert(call("fseek", {stream, 4, SEEK_SET}) == 0);
    assert(call("fread", {buffer, 1, 2, stream}) == 2 && memcmp(host.GetGuestMemoryBase() + buffer, "01", 2) == 0);
    const uint32_t mapped = call("mmap", {0, 14, 1, 2, fd, 0}); assert(mapped != UINT32_MAX);
    assert(memcmp(host.GetGuestMemoryBase() + mapped, "APK-0123456789", 14) == 0); // Non-page-aligned APK entry.
    assert(call("mmap", {0, 15, 1, 2, fd, 0}) == UINT32_MAX);
    assert(call("fseek", {stream, 20, SEEK_SET}) == 0 && call("ftell", {stream}) == 20);
    assert(call("fread", {buffer, 1, 1, stream}) == 0 && call("feof", {stream}) != 0);
    assert(call("fclose", {stream}) == 0 && call("pread", {fd, buffer, 1, 0}) == UINT32_MAX);

    const uint32_t raw = call("open", {file, O_RDONLY, 0}); assert(raw != UINT32_MAX);
    assert(call("fdopen", {raw, rw}) == 0); // Refusal must retain the descriptor.
    assert(call("pread", {raw, buffer, 3, 0}) == 3 && memcmp(host.GetGuestMemoryBase() + buffer, "APK", 3) == 0);
    const uint32_t wrapped = call("fdopen", {raw, rb}); assert(wrapped);
    assert(call("fileno", {wrapped}) == raw);
    assert(call("fread", {buffer, 1, 3, wrapped}) == 3);
    assert(call("ungetc", {'K', wrapped}) == 'K' && call("fflush", {wrapped}) == 0);
    assert(call("lseek", {raw, 0, SEEK_CUR}) == 2); // Purge ungetc without advancing the shared cursor.
    assert(call("read", {raw, buffer, 1}) == 1 && host.MemoryRead8(buffer) == 'K');
    assert(call("lseek", {raw, 0, SEEK_CUR}) == 3);
    assert(call("fclose", {wrapped}) == 0 && call("pread", {raw, buffer, 1, 0}) == UINT32_MAX);

    const uint32_t writable = call("fopen", {file, rw}); assert(writable);
    assert(call("fread", {buffer, 1, 1, writable}) == 1 && host.MemoryRead8(buffer) == 'e');
    assert(call("fseek", {writable, 0, SEEK_SET}) == 0);
    host.MemoryWrite8(buffer, 'Z'); assert(call("fwrite", {buffer, 1, 1, writable}) == 1);
    assert(call("fclose", {writable}) == 0);
    disk = ::fopen(path.c_str(), "rb"); assert(disk && ::getc(disk) == 'Z' && ::fclose(disk) == 0);
    assert(call("fopen", {string(only), wb}) == 0 && call("access", {string(only), W_OK}) == UINT32_MAX);

    const uint32_t parallel_buffers[] = {host.GuestAlloc(16, 8), host.GuestAlloc(16, 8)};
    assert(parallel_buffers[0] && parallel_buffers[1]);
    std::array<std::array<uint32_t, 64>, 2> parallel_handles{};
    std::barrier start(2);
    auto reader = [&](unsigned slot) {
        start.arrive_and_wait();
        for (unsigned i = 0; i < 64; ++i) {
            const uint32_t file_handle = call("fopen", {file, rb}); assert(file_handle);
            parallel_handles[slot][i] = file_handle;
            assert(call("fread", {parallel_buffers[slot], 1, 2, file_handle}) == 2);
            assert(memcmp(host.GetGuestMemoryBase() + parallel_buffers[slot], "AP", 2) == 0);
            assert(call("fclose", {file_handle}) == 0);
        }
    };
    std::thread first(reader, 0), second(reader, 1);
    first.join(); second.join();
    std::vector<uint32_t> handles(parallel_handles[0].begin(), parallel_handles[0].end());
    handles.insert(handles.end(), parallel_handles[1].begin(), parallel_handles[1].end());
    std::sort(handles.begin(), handles.end());
    assert(std::adjacent_find(handles.begin(), handles.end()) == handles.end());
    const uint32_t reopen = call("fopen", {file, rb}); assert(reopen);
    assert(call("freopen", {file, rb, reopen}) == reopen);
    assert(call("fread", {buffer, 1, 1, reopen}) == 1 && host.MemoryRead8(buffer) == 'A');
    assert(call("fclose", {reopen}) == 0);
    const uint32_t dir = call("opendir", {string(files + "/OnlyPkg")}); assert(dir);
    assert(call("readdir", {dir}) && call("closedir", {dir}) == 0);
    assert(::unlink(path.c_str()) == 0 && ::mkdir(path.c_str(), 0700) == 0);
    const uint32_t merged = call("opendir", {string(net)}); assert(merged);
    unsigned seen = 0;
    while (const uint32_t entry = call("readdir", {merged})) {
        // Android ARM32 dirent: two 64-bit fields, reclen at 16, type at 18, name at 19.
        if (!strcmp(reinterpret_cast<const char*>(host.GetGuestMemoryBase() + entry + 19), basename)) {
            ++seen; assert(host.MemoryRead8(entry + 18) == 8); // Packaged regular file beats external directory.
        }
    }
    assert(seen == 1 && call("closedir", {merged}) == 0);
    assert(::rmdir(path.c_str()) == 0 && ::rmdir(net.c_str()) == 0 && ::rmdir(files.c_str()) == 0 && ::rmdir(root) == 0);
    puts("VFS_FILE_CHECK_PASS: packaged winner, writable disk, FD/FILE cursor and ownership, bounded mmap, EOF, virtual directory, concurrent independent streams");
    return true;
}

// One runnable contract for the shared parser and the actual guest LIBC route.
static bool ApkIndexCheck(DynarmicHost& host, int apk_count, char** apk_paths) {
    auto put = [](std::vector<unsigned char>& bytes, size_t offset, uint32_t value, unsigned width) {
        assert(offset + width <= bytes.size());
        for (unsigned i = 0; i < width; ++i) bytes[offset + i] = static_cast<unsigned char>(value >> (8 * i));
    };
    auto get = [](const std::vector<unsigned char>& bytes, size_t offset) {
        assert(offset + 4 <= bytes.size());
        uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i) value |= static_cast<uint32_t>(bytes[offset + i]) << (8 * i);
        return value;
    };
    auto zip = [&](const std::vector<std::pair<std::string, std::string>>& members,
                   bool descriptor = false, bool signature = true, uint16_t method = 0) {
        std::vector<unsigned char> bytes, directory;
        for (const auto& [name, payload] : members) {
            uint32_t crc = UINT32_MAX;
            for (unsigned char c : payload) {
                crc ^= c;
                for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
            }
            crc ^= UINT32_MAX;
            assert(method == 0 || payload.empty());
            const std::string packed = method == 0 ? payload : std::string("\x03\x00", 2); // Valid raw deflate of empty data.
            const uint16_t version = method == 0 ? 10 : 20, flags = 0x800 | (descriptor ? 8 : 0);
            const size_t local = bytes.size(); bytes.resize(local + 30);
            put(bytes, local, 0x04034b50, 4); put(bytes, local + 4, version, 2);
            put(bytes, local + 6, flags, 2); put(bytes, local + 8, method, 2);
            if (!descriptor) {
                put(bytes, local + 14, crc, 4); put(bytes, local + 18, packed.size(), 4); put(bytes, local + 22, payload.size(), 4);
            }
            put(bytes, local + 26, name.size(), 2);
            bytes.insert(bytes.end(), name.begin(), name.end()); bytes.insert(bytes.end(), packed.begin(), packed.end());
            if (descriptor) {
                const size_t at = bytes.size(); bytes.resize(at + (signature ? 16 : 12));
                if (signature) put(bytes, at, 0x08074b50, 4);
                const size_t fields = at + (signature ? 4 : 0);
                put(bytes, fields, crc, 4); put(bytes, fields + 4, packed.size(), 4); put(bytes, fields + 8, payload.size(), 4);
            }
            const size_t central = directory.size(); directory.resize(central + 46);
            put(directory, central, 0x02014b50, 4); put(directory, central + 4, 20, 2); put(directory, central + 6, version, 2);
            put(directory, central + 8, flags, 2); put(directory, central + 10, method, 2); put(directory, central + 16, crc, 4);
            put(directory, central + 20, packed.size(), 4); put(directory, central + 24, payload.size(), 4);
            put(directory, central + 28, name.size(), 2); put(directory, central + 42, local, 4);
            directory.insert(directory.end(), name.begin(), name.end());
        }
        const size_t cd = bytes.size(); bytes.insert(bytes.end(), directory.begin(), directory.end());
        const size_t end = bytes.size(); bytes.resize(end + 22);
        put(bytes, end, 0x06054b50, 4); put(bytes, end + 8, members.size(), 2); put(bytes, end + 10, members.size(), 2);
        put(bytes, end + 12, directory.size(), 4); put(bytes, end + 16, cd, 4);
        return bytes;
    };
    char temporary[] = "/data/local/tmp/tftb-index-XXXXXX";
    const char* root = ::mkdtemp(temporary); assert(root);
    printf("APK_INDEX_TEMP_ROOT=%s\n",root); fflush(stdout);
    std::vector<std::string> paths;
    auto write = [&](const std::vector<unsigned char>& bytes) {
        const std::string path = std::string(root) + "/" + std::to_string(paths.size()) + ".zip";
        FILE* output = ::fopen(path.c_str(), "wb"); assert(output);
        assert(::fwrite(bytes.data(), 1, bytes.size(), output) == bytes.size() && ::fclose(output) == 0);
        paths.push_back(path); return path;
    };
    auto fd_count = [] {
        DIR* dir = ::opendir("/proc/self/fd"); assert(dir);
        unsigned count = 0;
        while (const dirent* entry = ::readdir(dir)) if (entry->d_name[0] != '.') ++count;
        assert(::closedir(dir) == 0); return count;
    };
    const unsigned initial = fd_count();
    const std::string cache_name = "assets/telltale/files/Net/contract.bin";
    const auto valid = zip({{cache_name, std::string("APK-0123456789", 14)}, {"assets/telltale/files/OnlyPkg/marker.bin", "x"}});
    const std::string valid_path = write(valid), empty_path = write(zip({}));
    assert(IndexApk(empty_path.c_str()) == 0 && !TelltaleWidescreenOverrideEnabled() && fd_count() == initial + 1);
    assert(VfsFileCheck(host, valid_path.c_str()));
    const std::string marker_path = write(zip({{"assets/telltale/widescreen.enable", "1"}}));
    const char* both[] = {valid_path.c_str(), marker_path.c_str()};
    assert(IndexApks(both, 2) == 0 && TelltaleWidescreenOverrideEnabled() && fd_count() == initial + 2);
    auto string = [&](const std::string& text) {
        const uint32_t p = host.GuestAlloc(text.size() + 1, 1); assert(p);
        memcpy(host.GetGuestMemoryBase() + p, text.c_str(), text.size() + 1); return p;
    };
    auto call = [&](const char* name, std::initializer_list<uint32_t> args) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
        assert(fn); bool completed = false;
        const uint32_t result = host.RunFunction(fn, std::vector<uint32_t>(args), &completed); assert(completed); return result;
    };
    const uint32_t file = string("files/Net/contract.bin"), rb = string("rb"), buffer = host.GuestAlloc(32, 8);
    assert(buffer);
    const uint32_t stream = call("fopen", {file, rb}), raw = call("open", {file, O_RDONLY, 0});
    assert(stream && raw != UINT32_MAX && fd_count() == initial + 4);
    const auto single = zip({{cache_name, std::string("APK-0123456789", 14)}});
    const size_t end = single.size() - 22, cd = get(single, end + 16);
    unsigned rejected = 0;
    auto invalid = [&](const std::vector<unsigned char>& bytes) {
        const std::string path = write(bytes);
        const unsigned before = fd_count();
        assert(IndexApk(path.c_str()) != 0 && TelltaleWidescreenOverrideEnabled() && fd_count() == before);
        ++rejected;
    };
    struct Change { size_t offset; uint32_t value; unsigned width; };
    const Change changes[] = {
        {end+4,1,2}, {end+6,1,2}, {end+8,0,2}, {end+10,2,2}, {end+12,1,4}, {end+16,UINT32_MAX,4}, {end+20,1,2},
        {cd,0,4}, {cd+6,45,2}, {cd+8,0x801,2}, {cd+20,13,4}, {cd+24,UINT32_MAX,4}, {cd+28,0,2}, {cd+30,65535,2},
        {cd+34,1,2}, {cd+42,UINT32_MAX,4}, {cd+42,static_cast<uint32_t>(cd-20),4},
        {0,0,4}, {4,20,2}, {6,0x808,2}, {8,8,2}, {14,0,4}, {18,15,4}, {22,15,4}, {26,1,2}, {28,65535,2}, {30,'X',1}
    };
    for (const auto& change : changes) { auto bad = single; put(bad,change.offset,change.value,change.width); invalid(bad); }
    auto bad_name = single; bad_name[30] = bad_name[cd+46] = 0; invalid(bad_name);
    auto compressed_cache = single;
    put(compressed_cache,4,20,2); put(compressed_cache,8,8,2); put(compressed_cache,cd+6,20,2); put(compressed_cache,cd+10,8,2);
    invalid(compressed_cache);
    auto trailing_cd = single; put(trailing_cd,end+8,0,2); put(trailing_cd,end+10,0,2); invalid(trailing_cd);
    invalid(zip({{cache_name,"a"},{cache_name,"b"}}));
    for (uint16_t count : {1,3}) {
        auto count_mismatch = valid; const size_t at = valid.size()-22;
        put(count_mismatch,at+8,count,2); put(count_mismatch,at+10,count,2); invalid(count_mismatch);
    }
    const auto inner = zip({{"assets/telltale/files/Net/inner.bin","x"}});
    const size_t inner_cd = get(inner,inner.size()-22+16);
    auto overlap = zip({{cache_name,std::string(reinterpret_cast<const char*>(inner.data()),inner_cd)}});
    std::vector<unsigned char> inner_directory(inner.begin()+inner_cd,inner.end()-22);
    put(inner_directory,42,30+cache_name.size(),4);
    const size_t overlap_cd = get(overlap,overlap.size()-22+16);
    overlap.insert(overlap.end()-22,inner_directory.begin(),inner_directory.end());
    const size_t overlap_end = overlap.size()-22;
    put(overlap,overlap_end+8,2,2); put(overlap,overlap_end+10,2,2); put(overlap,overlap_end+12,overlap_end-overlap_cd,4);
    invalid(overlap);
    const std::string bad_path = write(std::vector<unsigned char>{1,2,3}), duplicate_path = write(single);
    const char* malformed_set[] = {marker_path.c_str(),bad_path.c_str()};
    const char* duplicate_set[] = {valid_path.c_str(),duplicate_path.c_str()};
    const unsigned before_failed_set = fd_count();
    assert(IndexApks(malformed_set,2) != 0 && IndexApks(duplicate_set,2) != 0);
    assert(TelltaleWidescreenOverrideEnabled() && fd_count() == before_failed_set);
    assert(IndexApks(nullptr,1) != 0 && IndexApks(both,0) != 0 && IndexApks(both,65) != 0);
    const char* null_path[] = {marker_path.c_str(),nullptr}; assert(IndexApks(null_path,2) != 0 && fd_count() == before_failed_set);
    assert(call("pread",{raw,buffer,3,0}) == 3 && memcmp(host.GetGuestMemoryBase()+buffer,"APK",3) == 0);
    assert(call("fread",{buffer,1,2,stream}) == 2 && memcmp(host.GetGuestMemoryBase()+buffer,"AP",2) == 0);
    assert(call("fflush",{stream}) == 0); // Purge buffered data so the post-reindex read uses its real duplicate FD.
    assert(IndexApk(empty_path.c_str()) == 0 && !TelltaleWidescreenOverrideEnabled() && fd_count() == initial + 3);
    assert(call("pread",{raw,buffer,3,0}) == 3 && memcmp(host.GetGuestMemoryBase()+buffer,"APK",3) == 0);
    assert(call("fread",{buffer,1,2,stream}) == 2 && memcmp(host.GetGuestMemoryBase()+buffer,"K-",2) == 0);
    assert(call("fclose",{stream}) == 0 && call("close",{raw}) == 0 && fd_count() == initial + 1);
    assert(IndexApks(malformed_set,2) != 0 && !TelltaleWidescreenOverrideEnabled() && fd_count() == initial + 1);
    const char* partial_entries[] = {valid_path.c_str(),bad_path.c_str()};
    assert(IndexApks(partial_entries,2) != 0 && !TelltaleWidescreenOverrideEnabled() && fd_count() == initial + 1);
    assert(call("fopen",{file,rb}) == 0); // Neither staged marker nor staged cache entry escaped a failed set.
    const std::string files = std::string(root) + "/files", net = files + "/Net", external = net + "/contract.bin";
    assert(::mkdir(files.c_str(),0700) == 0 && ::mkdir(net.c_str(),0700) == 0);
    FILE* disk = ::fopen(external.c_str(),"wb"); assert(disk && ::fwrite("external",1,8,disk) == 8 && ::fclose(disk) == 0);
    const uint32_t disk_stream = call("fopen",{string(external),rb}); assert(disk_stream);
    assert(call("fread",{buffer,1,8,disk_stream}) == 8 && memcmp(host.GetGuestMemoryBase()+buffer,"external",8) == 0);
    assert(call("fclose",{disk_stream}) == 0 && ::unlink(external.c_str()) == 0);
    assert(::rmdir(net.c_str()) == 0 && ::rmdir(files.c_str()) == 0);
    auto comment = zip({}); put(comment,20,22,2); comment.resize(44); put(comment,22,0x06054b50,4);
    const std::string comment_path = write(comment), noncache_path = write(zip({{"plain-resource", "x"}}));
    auto misleading = single; put(misleading,end+20,22,2);
    const size_t fake_end = misleading.size(); misleading.resize(fake_end+22);
    put(misleading,fake_end,0x06054b50,4); put(misleading,fake_end+8,1,2); put(misleading,fake_end+10,1,2);
    put(misleading,fake_end+12,46,4); put(misleading,fake_end+16,fake_end-46,4);
    const std::string false_cd_comment_path = write(misleading);
    // A false EOCD can even parse a real member before failing its CD tail: rollback before retry is required.
    put(misleading,fake_end+12,fake_end-cd,4); put(misleading,fake_end+16,cd,4);
    const std::string partial_cd_comment_path = write(misleading);
    assert(IndexApk(false_cd_comment_path.c_str()) == 0 && IndexApk(partial_cd_comment_path.c_str()) == 0);
    const uint32_t comment_stream = call("fopen",{file,rb}); assert(comment_stream);
    assert(call("fread",{buffer,1,3,comment_stream}) == 3 && memcmp(host.GetGuestMemoryBase()+buffer,"APK",3) == 0);
    assert(call("fclose",{comment_stream}) == 0);
    const std::string deflated_path = write(zip({{"classes.dex", ""}},true,true,8));
    const std::string generic_a = write(zip({{"assets/Telltale/override.bin","A"}})), generic_b = write(zip({{"assets/Telltale/override.bin","B"}}));
    const char* generic_set[] = {generic_a.c_str(),generic_b.c_str()};
    assert(IndexApks(generic_set,2) == 0 && fd_count() == initial + 2);
    const uint32_t generic = call("fopen",{string("assets/Telltale/override.bin"),rb}); assert(generic);
    assert(call("fread",{buffer,1,1,generic}) == 1 && host.MemoryRead8(buffer) == 'B'); assert(call("fclose",{generic}) == 0);
    for (bool signature : {false,true}) {
        auto described = zip({{cache_name,std::string("APK-0123456789",14)}},true,signature);
        const size_t dcd = get(described,described.size()-22+16), dd = dcd-(signature?16:12);
        auto corrupt = described; corrupt[dd+(signature?4:0)] ^= 1;
        const std::string described_path = write(described), corrupt_path = write(corrupt);
        assert(IndexApk(described_path.c_str()) == 0 && !TelltaleWidescreenOverrideEnabled());
        const unsigned before = fd_count(); assert(IndexApk(corrupt_path.c_str()) != 0 && fd_count() == before);
        for (unsigned field : {14u,18u,22u}) put(described,field,get(described,dcd+(field==14?16:field==18?20:24)),4);
        assert(IndexApk(write(described).c_str()) == 0); // Match retained APKs with populated bit3 local fields.
    }
    for (bool signature : {false,true}) {
        const auto ambiguous = zip({{cache_name,std::string("\xac\x0a\x7a\xd5",4)}},true,signature);
        const size_t at = get(ambiguous,ambiguous.size()-22+16);
        assert(get(ambiguous,at+16) == 0x08074b50); // Genuine CRC32, also the optional descriptor signature.
        assert(IndexApk(write(ambiguous).c_str()) == 0);
    }
    for (unsigned repeat = 0; repeat < 16; ++repeat) {
        for (const std::string* path : {&empty_path,&marker_path,&comment_path,&false_cd_comment_path,&partial_cd_comment_path,&noncache_path,&deflated_path,&valid_path}) {
            assert(IndexApk(path->c_str()) == 0 && fd_count() == initial + 1);
            assert(TelltaleWidescreenOverrideEnabled() == (path == &marker_path));
        }
    }
    // Same executable/parser/guest thunks, with tiny complete cache owners.
    const std::string files_dir = std::string(root) + "/files", net_dir = files_dir + "/Net";
    const std::string obb_dir = std::string(root) + "/obb";
    assert(::mkdir(files_dir.c_str(),0700) == 0 && ::mkdir(net_dir.c_str(),0700) == 0 && ::mkdir(obb_dir.c_str(),0700) == 0);
    const std::vector<std::pair<std::string,std::string>> cache_payloads = {
        {"assets/telltale/files/base.mft","MFT-BASE"},
        {"assets/telltale/files/Net/base.bin","BASE-0123456789"},
        {"assets/telltale/obb/main.contract.obb","OBB-CONTENTS"},
        {"assets/telltale/files/ep2.mft","MFT-EP02"},
        {"assets/telltale/files/Net/ep2.bin","EP02-0123456789"},
        {"assets/telltale/files/hide.mft","MFT-HIDE"},
    };
    std::array<CacheMember,6> members{};
    std::vector<std::string> external_paths;
    auto external_write = [&](size_t i, const std::string& contents) {
        FILE* f = ::fopen(external_paths[i].c_str(),"wb"); assert(f);
        assert(::fwrite(contents.data(),1,contents.size(),f) == contents.size() && ::fclose(f) == 0);
    };
    for (size_t i = 0; i < members.size(); ++i) {
        const auto& [name,payload] = cache_payloads[i];
        const auto bytes = zip({{name,payload}});
        members[i] = {name.c_str(),payload.size(),get(bytes,get(bytes,bytes.size()-22+16)+16),
                      "0000000000000000000000000000000000000000000000000000000000000000",i < 3 ? 0u : i < 5 ? 1u : 5u};
        external_paths.push_back(name.starts_with("assets/telltale/obb/")
            ? obb_dir + "/" + name.substr(20) : files_dir + "/" + name.substr(22));
        external_write(i,payload);
    }
    struct VerifyContext {
        const std::vector<std::pair<std::string,std::string>>* payloads;
        unsigned calls = 0;
        const char* mutate_path = nullptr;
    } verification{&cache_payloads};
    // Inject a full-byte verifier: tests the selection boundary without pretending
    // this shell executable has a JVM. The real SHA-256 JNI helper needs its app check.
    auto verify = +[](int fd, const CacheMember& member, void* opaque) {
        auto& context = *static_cast<VerifyContext*>(opaque); ++context.calls;
        assert((::fcntl(fd,F_GETFL) & O_ACCMODE) == O_RDONLY && ::lseek(fd,0,SEEK_CUR) == 0);
        for (const auto& [name,payload] : *context.payloads) {
            if (name != member.asset) continue;
            char bytes[32]{};
            const ssize_t got = ::pread(fd,bytes,payload.size()+1,0);
            const bool equal = got == static_cast<ssize_t>(payload.size()) && !memcmp(bytes,payload.data(),payload.size());
            if (equal && context.mutate_path) {
                struct stat metadata{}; assert(::fstat(fd,&metadata) == 0);
                const timespec changed[] = {metadata.st_atim,{metadata.st_mtim.tv_sec+1,metadata.st_mtim.tv_nsec}};
                assert(::utimensat(AT_FDCWD,context.mutate_path,changed,0) == 0);
                context.mutate_path = nullptr;
            }
            return equal;
        }
        return false;
    };
    auto select = [&](bool hide = false) {
        return SelectCacheSources(members.data(),members.size(),files_dir.c_str(),obb_dir.c_str(),hide,verify,&verification);
    };
    auto android = [&](const char* name, std::initializer_list<uint32_t> args) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function, "", "libandroid.so");
        assert(fn); bool completed = false;
        const uint32_t result = host.RunFunction(fn,std::vector<uint32_t>(args),&completed);
        assert(completed); return result;
    };
    const uint32_t asset_name = string("telltale/files/Net/base.bin");
    const uint32_t asset_dir_name = string("telltale/files");
    const uint32_t out_start = host.GuestAlloc(8,4), out_length = out_start + 4;
    assert(out_start);
    // The unit has no JVM. UINT32_MAX is a test-only cache manager token;
    // actual registered ARM32 thunks still run, and no fake pointer reaches NDK.
    auto asset_open = [&](uint32_t name) { return android("AAssetManager_open",{UINT32_MAX,name,1}); };
    auto check_asset = [&](bool external) {
        const unsigned before = fd_count();
        const uint32_t first = asset_open(asset_name), second = asset_open(asset_name);
        assert(first && second && first != second && fd_count() == before + 2);
        const uint32_t length = static_cast<uint32_t>(cache_payloads[1].second.size());
        assert(android("AAsset_getLength",{first}) == length);
        assert(android("AAsset_read",{first,buffer,4}) == 4 && !memcmp(host.GetGuestMemoryBase()+buffer,"BASE",4));
        assert(android("AAsset_read",{second,buffer,2}) == 2 && !memcmp(host.GetGuestMemoryBase()+buffer,"BA",2));
        assert(android("AAsset_seek",{first,static_cast<uint32_t>(-2),SEEK_END}) == length - 2);
        assert(android("AAsset_read",{first,buffer,32}) == 2 && !memcmp(host.GetGuestMemoryBase()+buffer,"89",2));
        assert(android("AAsset_read",{first,buffer,1}) == 0 && android("AAsset_read",{first,0,0}) == 0);
        assert(android("AAsset_seek",{first,1,SEEK_END}) == UINT32_MAX);
        const uint32_t error = call("__errno",{});
        assert(error && host.MemoryRead32(error) == EINVAL);
        assert(android("AAsset_seek",{first,static_cast<uint32_t>(-1),SEEK_SET}) == UINT32_MAX);
        assert(android("AAsset_seek",{first,0,12345}) == UINT32_MAX);
        assert(android("AAsset_seek",{first,0,SEEK_CUR}) == length);
        assert(android("AAsset_read",{second,static_cast<uint32_t>(host.GetGuestMemorySize()-1),2}) == UINT32_MAX);
        assert(host.MemoryRead32(error) == EFAULT && android("AAsset_seek",{second,0,SEEK_CUR}) == 2);
        host.MemoryWrite32(out_start,0x11223344); host.MemoryWrite32(out_length,0x55667788);
        assert(android("AAsset_openFileDescriptor",{first,out_start,static_cast<uint32_t>(host.GetGuestMemorySize()-2)}) == UINT32_MAX);
        assert(fd_count() == before + 2 && host.MemoryRead32(error) == EFAULT && host.MemoryRead32(out_start) == 0x11223344);
        assert(android("AAsset_openFileDescriptor",{first,0,out_length}) == UINT32_MAX && fd_count() == before + 2);
        const uint32_t handed = android("AAsset_openFileDescriptor",{first,out_start,out_length});
        const uint32_t offset = host.MemoryRead32(out_start);
        assert(handed != UINT32_MAX && fd_count() == before + 3 && host.MemoryRead32(out_length) == length);
        assert(external ? offset == 0 : offset > 0);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        assert(!strcmp(cache_diag::Asset(first).kind,external ? "EXTERNAL_CACHE_ASSET" : "APK_ASSET"));
        assert(!strcmp(cache_diag::Fd(handed).kind,external ? "EXTERNAL_CACHE_FD" : "APK_ASSET_FD"));
        assert(!strcmp(cache_diag::CheckedAssetRange(cache_diag::Fd(handed),1,offset+length).kind,"UNKNOWN"));
#endif
        android("AAsset_close",{first}); android("AAsset_close",{first});
        assert(android("AAsset_read",{first,buffer,1}) == UINT32_MAX && host.MemoryRead32(error) == EBADF);
        assert(call("pread",{handed,buffer,length,offset}) == length && !memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),length));
        assert(android("AAsset_seek",{second,0,SEEK_SET}) == 0 && android("AAsset_read",{second,buffer,32}) == length);
        android("AAsset_close",{second}); assert(call("close",{handed}) == 0 && fd_count() == before);
        const uint32_t obb = asset_open(string("telltale/obb/main.contract.obb"));
        assert(obb && android("AAsset_read",{obb,buffer,32}) == cache_payloads[2].second.size());
        assert(!memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[2].second.data(),cache_payloads[2].second.size()));
        android("AAsset_close",{obb});
        assert(!asset_open(string("telltale/files/hide.mft")) && !asset_open(string("telltale/files/unknown.mft")));
        assert(!asset_open(string("fonts/ordinary.ttf"))); // Cache-only test token never calls NDK.
        assert(!android("AAssetManager_open",{0,asset_name,1}) && !android("AAssetManager_open",{UINT32_MAX,asset_name,4}));
        const uint32_t dir = android("AAssetManager_openDir",{UINT32_MAX,asset_dir_name}); assert(dir);
        for (const char* expected : {"base.mft","ep2.mft"}) {
            const uint32_t leaf = android("AAssetDir_getNextFileName",{dir});
            assert(leaf && !strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase()+leaf),expected));
        }
        assert(!android("AAssetDir_getNextFileName",{dir}));
        android("AAssetDir_rewind",{dir});
        const uint32_t leaf = android("AAssetDir_getNextFileName",{dir});
        assert(leaf && !strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase()+leaf),"base.mft"));
        android("AAssetDir_close",{dir});
        assert(!android("AAssetDir_getNextFileName",{dir}));
        const uint32_t empty = android("AAssetManager_openDir",{UINT32_MAX,string("telltale/files/Unknown")});
        assert(empty && !android("AAssetDir_getNextFileName",{empty})); android("AAssetDir_close",{empty});
        assert(fd_count() == before);
    };
    auto packaged_with_extra = cache_payloads;
    packaged_with_extra.push_back({"assets/telltale/files/Net/unknown.bin","unowned"});
    packaged_with_extra.push_back({"assets/telltale/files/unknown.mft","unowned"});
    const std::string full_owner_path = write(zip(packaged_with_extra));
    const char* complete_owners[] = {full_owner_path.c_str(),marker_path.c_str()};
    assert(IndexApks(complete_owners,2) == 0 && select() == 0 && verification.calls == 0);
    assert(CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 1 && CacheOwnerSource(5) == 0 && TelltaleWidescreenOverrideEnabled());
    check_asset(false);
    std::vector<std::string> names;
    assert(CacheAssetDirectory("telltale/files",names) && names == std::vector<std::string>({"base.mft","ep2.mft"}));
    assert(CacheAssetDirectory("telltale/files/Net",names) && names == std::vector<std::string>({"base.bin","ep2.bin"}));
    assert(!CacheAssetDirectory("telltale/files-other",names));
    assert(CacheAssetDirectory("telltale/files/Unknown",names) && names.empty());
    CacheAssetRegion region;
    assert(OpenCacheAssetRegion("telltale/files/hide.mft",region) == -1);
    assert(OpenCacheAssetRegion("telltale/files/unknown.bin",region) == -1);
    assert(OpenCacheAssetRegion("telltale/files/main.contract.obb",region) == -1);
    assert(OpenCacheAssetRegion("telltale/obb/unknown/main.contract.obb",region) == -1);
    assert(OpenCacheAssetRegion("fonts/ordinary.ttf",region) == 0);
    assert(OpenCacheAssetRegion("telltale/files/Net/base.bin",region) == 1 && !region.external && region.offset > 0);
    char selected_bytes[32]{};
    assert(::pread(region.fd,selected_bytes,region.length,region.offset) == region.length && !memcmp(selected_bytes,cache_payloads[1].second.data(),region.length));
    assert(::close(region.fd) == 0);
    // A complete packaged cohort never scans a corrupt external candidate.
    std::string damaged = cache_payloads[1].second; damaged.back() ^= 1; external_write(1,damaged);
    assert(IndexApks(complete_owners,2) == 0 && select(true) == 0 && verification.calls == 0 && CacheOwnerSource(5) == 1);
    external_write(1,cache_payloads[1].second);

    // Missing packaged BASE member forces the entire external cohort, including its OBB.
    const std::string partial_owner_path = write(zip({cache_payloads[0],cache_payloads[3]}));
    const char* partial_owners[] = {partial_owner_path.c_str(),marker_path.c_str()};
    assert(IndexApks(partial_owners,2) == 0 && select() == 0 && verification.calls == 5);
    assert(CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 2 && TelltaleWidescreenOverrideEnabled());
    assert(fd_count() == initial + 7);
    check_asset(true);
    assert(OpenCacheAssetRegion("telltale/obb/main.contract.obb",region) == 1 && region.external && region.offset == 0);
    assert(::close(region.fd) == 0);
    const uint32_t chosen_file = string(external_paths[1]), chosen_mft = string(external_paths[3]);
    const uint32_t live_file = call("fopen",{chosen_file,rb}), live_fd = call("open",{chosen_file,O_RDONLY,0});
    assert(live_file && live_fd != UINT32_MAX);
    assert(OpenCacheAssetRegion("telltale/files/Net/base.bin",region) == 1 && region.external && region.offset == 0);
    const uint32_t live_asset = asset_open(asset_name);
    const uint32_t live_asset_fd = android("AAsset_openFileDescriptor",{live_asset,out_start,out_length});
    const uint32_t live_dir = android("AAssetManager_openDir",{UINT32_MAX,asset_dir_name});
    assert(live_asset && live_asset_fd != UINT32_MAX && live_dir);
    const std::string held_name = external_paths[1] + ".held";
    assert(::rename(external_paths[1].c_str(),held_name.c_str()) == 0); external_write(1,damaged);
    assert(call("pread",{live_fd,buffer,14,0}) == 14 && !memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),14));
    assert(::pread(region.fd,selected_bytes,region.length,0) == region.length && !memcmp(selected_bytes,cache_payloads[1].second.data(),region.length));
    assert(android("AAsset_read",{live_asset,buffer,32}) == cache_payloads[1].second.size());
    assert(!memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),cache_payloads[1].second.size()));
    assert(IndexApk(empty_path.c_str()) == 0); // Published owner handles close; caller duplicates survive.
    assert(android("AAsset_seek",{live_asset,0,SEEK_SET}) == 0);
    assert(android("AAsset_read",{live_asset,buffer,32}) == cache_payloads[1].second.size());
    assert(!memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),cache_payloads[1].second.size()));
    assert(call("pread",{live_asset_fd,buffer,15,0}) == 15 && !memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),15));
    const uint32_t old_leaf = android("AAssetDir_getNextFileName",{live_dir});
    assert(old_leaf && !strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase()+old_leaf),"base.mft"));
    android("AAssetDir_close",{live_dir}); android("AAsset_close",{live_asset});
    assert(call("close",{live_asset_fd}) == 0);
    assert(call("fread",{buffer,1,14,live_file}) == 14 && !memcmp(host.GetGuestMemoryBase()+buffer,cache_payloads[1].second.data(),14));
    assert(call("close",{live_fd}) == 0 && call("fclose",{live_file}) == 0 && ::close(region.fd) == 0 && fd_count() == initial + 1);
    assert(::unlink(external_paths[1].c_str()) == 0 && ::rename(held_name.c_str(),external_paths[1].c_str()) == 0);

    // An otherwise valid external EP2 with a same-size/same-header corrupt tail
    // is unavailable as a whole; its still-present MFT cannot leak through disk.
    damaged = cache_payloads[4].second; damaged.back() ^= 1; external_write(4,damaged);
    std::vector<std::pair<std::string,std::string>> partial_episode(cache_payloads.begin(),cache_payloads.begin()+4);
    const std::string partial_episode_path = write(zip(partial_episode));
    assert(IndexApk(partial_episode_path.c_str()) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 0);
    assert(call("fopen",{chosen_mft,rb}) == 0 && call("open",{chosen_mft,O_RDONLY,0}) == UINT32_MAX);
    assert(call("stat",{chosen_mft,buffer}) == UINT32_MAX && call("access",{chosen_mft,R_OK}) == UINT32_MAX);
    assert(call("open",{string(files_dir+"/Net/../ep2.mft"),O_RDONLY,0}) == UINT32_MAX);
    const std::string relative_escape = files_dir + "/../../" + std::string(strrchr(root,'/')+1) + "/files/ep2.mft";
    assert(call("open",{string(relative_escape),O_RDONLY,0}) == UINT32_MAX && call("fopen",{string(relative_escape),rb}) == 0);
    assert(OpenCacheAssetRegion("telltale/files/ep2.mft",region) == -1);
    assert(!asset_open(string("telltale/files/ep2.mft")) && !asset_open(string("telltale/files/Net/ep2.bin")));
    const uint32_t withheld = android("AAssetManager_openDir",{UINT32_MAX,asset_dir_name}); assert(withheld);
    const uint32_t available = android("AAssetDir_getNextFileName",{withheld});
    assert(available && !strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase()+available),"base.mft"));
    assert(!android("AAssetDir_getNextFileName",{withheld})); android("AAssetDir_close",{withheld});
    assert(CacheAssetDirectory("telltale/files",names) && names == std::vector<std::string>({"base.mft"}));
    const uint32_t dir = call("opendir",{string(files_dir)}); assert(dir);
    unsigned base_seen = 0, rejected_seen = 0;
    while (const uint32_t item = call("readdir",{dir})) {
        const dirent* entry = reinterpret_cast<const dirent*>(host.GetGuestMemoryBase()+item);
        base_seen += !strcmp(entry->d_name,"base.mft");
        rejected_seen += !strcmp(entry->d_name,"ep2.mft") || !strcmp(entry->d_name,"hide.mft");
    }
    assert(base_seen == 1 && rejected_seen == 0 && call("closedir",{dir}) == 0);
    assert(call("open",{chosen_file,O_WRONLY|O_TRUNC,0600}) == UINT32_MAX && call("fopen",{chosen_file,string("wb")}) == 0);
    const std::string stray = net_dir + "/unknown.bin", user_save = files_dir + "/user.save";
    for (const std::string* path : {&stray,&user_save}) {
        FILE* file = ::fopen(path->c_str(),"wb"); assert(file && ::fwrite("user",1,4,file) == 4 && ::fclose(file) == 0);
    }
    assert(call("open",{string(stray),O_RDONLY,0}) == UINT32_MAX);
    const uint32_t ordinary = call("fopen",{string(user_save),rb}); assert(ordinary);
    assert(call("fread",{buffer,1,4,ordinary}) == 4 && !memcmp(host.GetGuestMemoryBase()+buffer,"user",4));
    assert(call("fclose",{ordinary}) == 0 && call("remove",{string(user_save)}) == 0 && ::unlink(stray.c_str()) == 0);
    assert(call("remove",{chosen_file}) == UINT32_MAX);
    assert(call("rename",{chosen_file,string(files_dir+"/unmanaged.bin")}) == UINT32_MAX);
    assert(call("rename",{string(files_dir+"/unmanaged.bin"),chosen_file}) == UINT32_MAX);
    external_write(4,cache_payloads[4].second);

    // Metadata mismatch and splitting one owner over APKs both reject packaged
    // backfill; complete external ownership still works.
    auto wrong_crc = cache_payloads; wrong_crc[1].second.back() ^= 1;
    const std::string wrong_crc_path = write(zip(wrong_crc));
    assert(IndexApk(wrong_crc_path.c_str()) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 1);
    const std::string a = write(zip({cache_payloads[0],cache_payloads[1]})), b = write(zip({cache_payloads[2]}));
    const char* divided[] = {a.c_str(),b.c_str()};
    assert(IndexApks(divided,2) == 0 && select() == 0 && CacheOwnerSource(0) == 2);

    // Required BASE failure, per-file symlink, parent symlink, FIFO, and mutation
    // during verification all fail before publication without leaking held FDs.
    assert(::unlink(external_paths[2].c_str()) == 0);
    assert(IndexApk(empty_path.c_str()) == 0 && select() == -1 && CacheOwnerSource(0) == 0 && fd_count() == initial + 1);
    external_write(2,cache_payloads[2].second);
    assert(::unlink(external_paths[1].c_str()) == 0 && ::symlink(external_paths[0].c_str(),external_paths[1].c_str()) == 0);
    assert(IndexApk(empty_path.c_str()) == 0 && select() == -1 && fd_count() == initial + 1);
    assert(::unlink(external_paths[1].c_str()) == 0);
    if (::mkfifo(external_paths[1].c_str(),0600) == 0) {
        assert(IndexApk(empty_path.c_str()) == 0 && select() == -1 && fd_count() == initial + 1);
        assert(::unlink(external_paths[1].c_str()) == 0);
        puts("CACHE_OWNER_FIFO_PASS: nonblocking open, reject non-regular file");
    } else {
        const int failure = errno;
        assert(failure == EACCES || failure == EPERM);
        printf("CACHE_OWNER_FIFO_NOT_RUN: device creation denied errno=%d\n",failure);
    }
    external_write(1,cache_payloads[1].second);
    const std::string net_hold = files_dir + "/Net.held";
    assert(::rename(net_dir.c_str(),net_hold.c_str()) == 0 && ::symlink(net_hold.c_str(),net_dir.c_str()) == 0);
    assert(IndexApk(empty_path.c_str()) == 0 && select() == -1 && fd_count() == initial + 1);
    assert(::unlink(net_dir.c_str()) == 0 && ::rename(net_hold.c_str(),net_dir.c_str()) == 0);
    verification.mutate_path = external_paths[0].c_str();
    assert(IndexApk(empty_path.c_str()) == 0 && select() == -1 && !verification.mutate_path && fd_count() == initial + 1);
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
        assert(IndexApks(partial_owners,2) == 0 && select() == 0 && fd_count() == initial + 7);
        assert(IndexApk(empty_path.c_str()) == 0 && fd_count() == initial + 1);
    }
    // Role-aware preparation reuses the same parser, with strict ordinary APK
    // framing and a whole-owner poison that no later carrier can resurrect.
    const std::string trusted_base = write(zip({cache_payloads[0],cache_payloads[1],cache_payloads[2],
                                               {"assets/Telltale/ordinary.bin","ordinary"}}));
    const std::string trusted_episode = write(zip({cache_payloads[3],cache_payloads[4]}));
    const std::string trusted_hide = write(zip({cache_payloads[5]}));
    const CacheApkInput trusted[] = {{trusted_base.c_str(),0},{trusted_episode.c_str(),1},
                                    {trusted_hide.c_str(),5},{marker_path.c_str(),-1}};
    auto prepare = [&](const CacheApkInput* inputs, size_t size) {
        return PrepareCacheApks(inputs,size,members.data(),members.size());
    };
    assert(prepare(trusted,4) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 1 && CacheOwnerSource(5) == 0);
    assert(TelltaleWidescreenOverrideEnabled());
    assert(prepare(trusted,4) == 0 && select(true) == 0 && CacheOwnerSource(5) == 1);
    const uint32_t ordinary_stream = call("fopen",{string("assets/Telltale/ordinary.bin"),rb}); assert(ordinary_stream);
    assert(call("fread",{buffer,1,8,ordinary_stream}) == 8 && !memcmp(host.GetGuestMemoryBase()+buffer,"ordinary",8));
    assert(call("fclose",{ordinary_stream}) == 0);
    auto compressed = zip({{cache_payloads[0].first,""}},false,true,8);
    const std::string compressed_cache_path = write(compressed);
    assert(IndexApk(compressed_cache_path.c_str()) != 0); // Public strict API stays strict.
    const CacheApkInput compressed_input[] = {{compressed_cache_path.c_str(),0},{trusted_episode.c_str(),1},{marker_path.c_str(),-1}};
    assert(prepare(compressed_input,3) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 1);
    auto bad_local = zip({cache_payloads[0],cache_payloads[1],cache_payloads[2],{"assets/Telltale/ordinary.bin","ordinary"}});
    bad_local[14] ^= 1;
    const std::string bad_local_path = write(bad_local);
    const CacheApkInput metadata_input[] = {{bad_local_path.c_str(),0},{trusted_episode.c_str(),1}};
    assert(IndexApk(bad_local_path.c_str()) != 0 && prepare(metadata_input,2) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 1);
    const uint32_t retained_generic = call("fopen",{string("assets/Telltale/ordinary.bin"),rb}); assert(retained_generic);
    assert(call("fread",{buffer,1,8,retained_generic}) == 8 && !memcmp(host.GetGuestMemoryBase()+buffer,"ordinary",8));
    assert(call("fclose",{retained_generic}) == 0);
    const std::string duplicate_cache = write(zip({cache_payloads[0],cache_payloads[1],cache_payloads[2],cache_payloads[0]}));
    const CacheApkInput duplicate_input[] = {{duplicate_cache.c_str(),0},{trusted_episode.c_str(),1}};
    assert(prepare(duplicate_input,2) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 1);
    const std::string foreign = write(zip({cache_payloads[0]}));
    const CacheApkInput foreign_input[] = {{trusted_base.c_str(),0},{trusted_episode.c_str(),1},{foreign.c_str(),1}};
    assert(prepare(foreign_input,3) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && CacheOwnerSource(1) == 2);
    const CacheApkInput resurrect[] = {{bad_local_path.c_str(),0},{trusted_base.c_str(),0},{trusted_episode.c_str(),1}};
    assert(prepare(resurrect,3) == 0 && select() == 0 && CacheOwnerSource(0) == 2);
    // False EOCDs must roll back staged entry/name/poison/marker state before retry.
    auto known_comment = zip({cache_payloads[0],cache_payloads[1],cache_payloads[2]});
    const size_t known_end = known_comment.size()-22, known_cd = get(known_comment,known_end+16);
    put(known_comment,known_end+20,22,2);
    const size_t fake_known_end = known_comment.size(); known_comment.resize(fake_known_end+22);
    put(known_comment,fake_known_end,0x06054b50,4);
    put(known_comment,fake_known_end+8,3,2); put(known_comment,fake_known_end+10,3,2);
    put(known_comment,fake_known_end+12,fake_known_end-known_cd,4); put(known_comment,fake_known_end+16,known_cd,4);
    const std::string known_comment_path = write(known_comment);
    const CacheApkInput misleading_input[] = {{known_comment_path.c_str(),0},{trusted_episode.c_str(),1}};
    assert(prepare(misleading_input,2) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 1);
    // Also exercise a fully framed soft-rejected false directory, not just failed CD tail.
    auto poisoned_comment = zip({cache_payloads[0],cache_payloads[1],cache_payloads[2]});
    const size_t poison_end = poisoned_comment.size()-22, poison_cd = get(poisoned_comment,poison_end+16);
    const size_t false_cd = poisoned_comment.size();
    const size_t first_record = 46 + cache_payloads[0].first.size();
    std::vector<unsigned char> false_record(poisoned_comment.begin()+poison_cd,poisoned_comment.begin()+poison_cd+first_record);
    put(false_record,16,get(false_record,16)^1,4);
    poisoned_comment.insert(poisoned_comment.end(),false_record.begin(),false_record.end());
    const size_t false_end = poisoned_comment.size(); poisoned_comment.resize(false_end+22);
    put(poisoned_comment,poison_end+20,poisoned_comment.size()-poison_end-22,2);
    put(poisoned_comment,false_end,0x06054b50,4); put(poisoned_comment,false_end+8,1,2); put(poisoned_comment,false_end+10,1,2);
    put(poisoned_comment,false_end+12,first_record,4); put(poisoned_comment,false_end+16,false_cd,4);
    const std::string poison_comment_path = write(poisoned_comment);
    const CacheApkInput poison_input[] = {{poison_comment_path.c_str(),0},{trusted_episode.c_str(),1}};
    assert(prepare(poison_input,2) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 1);
    const CacheApkInput absent_optional[] = {{trusted_base.c_str(),0},{bad_path.c_str(),1},{marker_path.c_str(),-1}};
    assert(prepare(absent_optional,3) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 2 && TelltaleWidescreenOverrideEnabled());
    const unsigned selected_fds = fd_count();
    const CacheApkInput bad_base[] = {{bad_path.c_str(),0}};
    const CacheApkInput bad_ordinary[] = {{bad_path.c_str(),-1}};
    assert(prepare(bad_base,1) != 0 && prepare(bad_ordinary,1) != 0 && fd_count() == selected_fds && CacheOwnerSource(0) == 1 && TelltaleWidescreenOverrideEnabled());
    auto unsafe_extent = zip({cache_payloads[0]});
    const size_t unsafe_cd = get(unsafe_extent,unsafe_extent.size()-22+16);
    put(unsafe_extent,unsafe_cd+42,unsafe_cd,4);
    const std::string unsafe_path = write(unsafe_extent);
    const CacheApkInput unsafe_base[] = {{unsafe_path.c_str(),0}};
    assert(prepare(unsafe_base,1) != 0 && fd_count() == selected_fds && CacheOwnerSource(0) == 1);
    put(unsafe_extent,unsafe_cd+8,0x801,2); // Bad compatibility must not hide the unsafe physical offset.
    const std::string unsafe_flags_path = write(unsafe_extent);
    const CacheApkInput unsafe_flags_base[] = {{unsafe_flags_path.c_str(),0}};
    assert(prepare(unsafe_flags_base,1) != 0 && fd_count() == selected_fds && CacheOwnerSource(0) == 1);
    auto hidden_overlap = zip({cache_payloads[0],cache_payloads[1]});
    const size_t hidden_overlap_cd = get(hidden_overlap,hidden_overlap.size()-22+16);
    const size_t overlap_second = hidden_overlap_cd + 46 + cache_payloads[0].first.size();
    put(hidden_overlap,hidden_overlap_cd+8,0x801,2); // Reject first cache metadata softly.
    put(hidden_overlap,overlap_second+42,0,4); // Second physical record overlaps first.
    const std::string hidden_overlap_path = write(hidden_overlap);
    const CacheApkInput hidden_overlap_input[] = {{hidden_overlap_path.c_str(),0}};
    assert(prepare(hidden_overlap_input,1) != 0 && fd_count() == selected_fds && CacheOwnerSource(0) == 1);
    auto bad_noncache = zip({{"assets/Telltale/ordinary.bin","ordinary"},cache_payloads[0]});
    bad_noncache[14] ^= 1;
    const std::string bad_noncache_path = write(bad_noncache);
    const CacheApkInput bad_noncache_input[] = {{bad_noncache_path.c_str(),0}};
    assert(prepare(bad_noncache_input,1) != 0 && fd_count() == selected_fds && CacheOwnerSource(0) == 1);
    // A rejected optional owner is completely unavailable when E fails; BASE failure
    // and cancellation both fail before selection publication, without FD leaks.
    external_write(4,std::string(cache_payloads[4].second.size(),'x'));
    assert(prepare(absent_optional,3) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && CacheOwnerSource(1) == 0);
    CacheAssetRegion absent_region;
    assert(OpenCacheAssetRegion("telltale/files/ep2.mft",absent_region) == -1);
    external_write(4,cache_payloads[4].second);
    assert(::unlink(external_paths[2].c_str()) == 0);
    assert(prepare(compressed_input,3) == 0);
    const unsigned failed_selection_fds = fd_count();
    assert(select() == -1 && CacheOwnerSource(0) == 0 && fd_count() == failed_selection_fds);
    external_write(2,cache_payloads[2].second);
    std::atomic<bool> cancelled{true};
    assert(IndexApk(empty_path.c_str()) == 0);
    const unsigned before_cancel = fd_count();
    assert(PrepareCacheApks(trusted,4,members.data(),members.size(),&cancelled) == -1 && errno == ECANCELED && fd_count() == before_cancel);
    assert(SelectCacheSources(members.data(),members.size(),files_dir.c_str(),obb_dir.c_str(),false,verify,&verification,&cancelled) == -1 && errno == ECANCELED && fd_count() == before_cancel && CacheOwnerSource(0) == 0);
    cancelled.store(false);
    struct CancelVerify { decltype(verify) check; VerifyContext* context; std::atomic<bool>* cancelled; } cancel_verify{verify,&verification,&cancelled};
    auto verify_then_cancel = +[](int fd,const CacheMember& member,void* opaque) {
        auto& context = *static_cast<CancelVerify*>(opaque);
        if (member.owner == 1) { context.cancelled->store(true); return false; }
        return context.check(fd,member,context.context);
    };
    assert(SelectCacheSources(members.data(),members.size(),files_dir.c_str(),obb_dir.c_str(),false,verify_then_cancel,&cancel_verify,&cancelled) == -1 && errno == ECANCELED && CacheOwnerSource(0) == 0 && fd_count() == before_cancel);
    cancelled.store(false);
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
        assert(prepare(compressed_input,3) == 0 && select() == 0 && CacheOwnerSource(0) == 2 && fd_count() == initial + 6);
        assert(prepare(trusted,4) == 0 && select() == 0 && CacheOwnerSource(0) == 1 && fd_count() == initial + 4);
    }
    assert(IndexApk(empty_path.c_str()) == 0);
    puts("CACHE_PREPARE_CHECK_PASS: trusted whole owners; compressed/local metadata/duplicates/foreign role; no resurrection; optional quarantine; required noncache/extent strict; failed required E; cancellation including optional verify; transactional FD/marker/EOCD rollback");

    for (const std::string& path : external_paths) assert(::unlink(path.c_str()) == 0);
    assert(::rmdir(net_dir.c_str()) == 0 && ::rmdir(files_dir.c_str()) == 0 && ::rmdir(obb_dir.c_str()) == 0);
    puts("AASSET_CACHE_CHECK_PASS: registered guest thunks; P/E full bytes and OBB; independent cursors; EOF/seek bounds; guest errno/ranges; handed FD and held pathname/index lifetime; owner-filtered directories/rewind; native pointers never fabricated; shell test-only manager token (real JVM manager/ordinary fallback NOT_RUN)");
    puts("CACHE_OWNER_CHECK_PASS: whole packaged/external owners; OBB+MFT; optional rejection; full-byte verifier; held-FD replacement/lifetime; VFS read/stat/access/directory; asset region/directory; symlink/mutation; FD counts; hide opt-in; widescreen independent");
    if (apk_count) {
        assert(IndexApks(apk_paths,static_cast<size_t>(apk_count)) == 0 && fd_count() == initial + apk_count);
        printf("APK_INDEX_INSTALLED_SET_PASS: apks=%d widescreen=%d\n",apk_count,TelltaleWidescreenOverrideEnabled());
    }
    assert(IndexApk(empty_path.c_str()) == 0 && fd_count() == initial + 1);
    for (const std::string& path : paths) assert(::unlink(path.c_str()) == 0);
    assert(::rmdir(root) == 0);
    printf("APK_INDEX_CHECK_PASS: rejected=%u; empty/noncache/marker/comment; deflate/descriptor; transactional set; FD counts; generic override; live guest FILE/FD; external fopen\n",rejected);
    return true;
}

static bool FpsLuaCheck(DynarmicHost& host) {
    assert(!InstallTelltaleFpsBinding(host, {})); // No engine: refuse before any collection write.
    const uint32_t callback = RegisterTelltaleFpsSetter(host);
    const uint32_t state = host.GuestAlloc(20, 4), coroutine = host.GuestAlloc(20, 4);
    const uint32_t ci = host.GuestAlloc(4, 4), function = host.GuestAlloc(24, 4);
    assert(callback && state && coroutine && ci && function);
    int expected = 60;
    const uint32_t before = host.GetThunkManager().RegisterThunk("__fps_before", [](Dynarmic::A32::Jit&, DynarmicHost&) { errno = E2BIG; });
    const uint32_t after = host.GetThunkManager().RegisterThunk("__fps_after", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        assert(jit.Regs()[0] == 0 && errno == E2BIG);
        assert(presentation_pacer::GetMode() == expected);
    });
    std::vector<uint32_t> arm{0xE92D4010};
    Call(arm, before); Call(arm, callback); Call(arm, after);
    arm.insert(arm.end(), {0xE8BD4010, 0xE12FFF1E});
    const uint32_t entry = Install(host, arm);
    std::vector<uint16_t> thumb{0xB510};
    ThumbCall(thumb, before); ThumbCall(thumb, callback); ThumbCall(thumb, after); thumb.push_back(0xBD10);
    const uint32_t thumb_entry = Install(host, thumb) | 1;
    auto init = [&](float value) {
        std::memset(host.GetGuestMemoryBase() + state, 0, 20);
        std::memset(host.GetGuestMemoryBase() + function, 0, 24);
        host.MemoryWrite32(state + 8, function + 16); host.MemoryWrite32(state + 16, ci);
        host.MemoryWrite32(coroutine + 8, function + 16); host.MemoryWrite32(coroutine + 16, ci);
        host.MemoryWrite32(ci, function); host.MemoryWrite32(function, callback);
        host.MemoryWrite32(function + 4, 22); host.MemoryWrite32(function + 12, 3);
        std::memcpy(host.GetGuestMemoryBase() + function + 8, &value, 4);
    };
    auto check = [&](int mode, uint32_t lua_state, uint32_t call_entry) {
        expected = mode; presentation_pacer::SetMode(30);
        std::array<uint8_t, 24> stack{};
        std::memcpy(stack.data(), host.GetGuestMemoryBase() + function, stack.size());
        const uint32_t top = host.MemoryRead32(state + 8);
        bool completed = false;
        assert(host.RunFunction(call_entry, {lua_state}, &completed) == 0 && completed);
        assert(host.MemoryRead32(state + 8) == top);
        assert(!std::memcmp(stack.data(), host.GetGuestMemoryBase() + function, stack.size()));
    };
    for (int mode : {0, 30, 45, 60}) {
        init(static_cast<float>(mode)); check(mode, state, entry); check(mode, coroutine, thumb_entry);
    }
    for (float invalid : {-1.f, 44.5f, std::numeric_limits<float>::infinity(), std::numeric_limits<float>::quiet_NaN()}) {
        init(invalid); check(60, state, entry);
    }
    for (uint32_t tag : {0u, 1u, 4u, 19u}) { init(45); host.MemoryWrite32(function + 12, tag); check(60, state, entry); }
    for (uint32_t top : {function + 8, function + 24}) { init(45); host.MemoryWrite32(state + 8, top); check(60, state, entry); }
    init(45); host.MemoryWrite32(function, callback + 8); check(60, state, entry);
    init(45); host.MemoryWrite32(state + 16, 0); check(60, state, entry);
    init(45); check(60, 0xfffffff0u, entry); check(60, 0, thumb_entry);
    presentation_pacer::SetMode(60);
    puts("FPS_LUA_REAL_ARM_THUMB_SVC_COROUTINE_STACK_ERRNO_ASSERTIONS_PASS");
    return true;
}

int main(int argc, char** argv) {
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
    if (argc == 2 && !strcmp(argv[1], "--private-metadata-only")) return PrivateMetadataContractCheck() ? 0 : 1;
#endif
    if (argc == 2 && !strcmp(argv[1], "--guest-range-only")) return GuestRangeCheck() ? 0 : 1;
    if (argc == 2 && !strcmp(argv[1], "--opensl-capacity-only")) {
        fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d begin\n", getpid());
        bool passed;
        {
            DynarmicHost fixture_host;
            assert(fixture_host.Initialize());
            passed = OpenSLQueueCapacityCheck(fixture_host);
            fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d host_destroy_begin\n", getpid());
        }
        fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d host_destroyed\n", getpid());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        fprintf(stderr, "OPENSL_CAPACITY_STAGE pid=%d quiesced\n", getpid());
        return passed ? 0 : 1;
    }
    DynarmicHost host;
    const bool initialized = host.Initialize();
    assert(initialized);
    if (argc == 2 && !strcmp(argv[1], "--fps-lua-only")) return FpsLuaCheck(host) ? 0 : 1;
    if (argc >= 2 && !strcmp(argv[1], "--apk-index-only")) return ApkIndexCheck(host, argc - 2, argv + 2) ? 0 : 1;
    if (argc == 3 && !strcmp(argv[1], "--cache-read-only")) return CacheReadDiagCheck() && VfsFileCheck(host, argv[2], "contract.ttarch2") ? 0 : 1;
    if (argc == 3 && !strcmp(argv[1], "--vfs-file-only")) return VfsFileCheck(host, argv[2]) ? 0 : 1;
    if (argc == 2 && !strcmp(argv[1], "--pthread-once-only")) return PthreadOnceCheck(host) ? 0 : 1;
    if (argc == 7 && !strcmp(argv[1], "--pthread-once-real-only")) return RealCpuOnceCheck(host, argv) ? 0 : 1;
    bool completed = true;
    host.RunFunction(0, {}, &completed);
    assert(!completed);
#if defined(ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE) && ARM32_BRIDGE_ENABLE_TFTB_WIDESCREEN_OVERRIDE
    if (argc == 7 && (!strcmp(argv[1], "--tftb-widescreen-probe") || !strcmp(argv[1], "--fatal-fetch-probe"))) {
        const bool fatal_fetch = !strcmp(argv[1], "--fatal-fetch-probe");
        if (!fatal_fetch) {
            assert(InstallTFTBWidescreenOverride(host, false));
            assert(!InstallTFTBWidescreenOverride(host, true)); // absent engine fails closed
        }
        const char* names[] = {"libfmod.so", "libfmodstudio.so", "libSDL2.so", "libGameEngine.so", "libmain.so"};
        std::vector<std::vector<uint8_t>> files;
        std::vector<GuestModuleImage> images;
        for (int i = 2; i < argc; ++i) {
            std::ifstream input(argv[i], std::ios::binary);
            assert(input.good());
            files.emplace_back(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
            images.push_back({names[i - 2], files.back().data(), files.back().size()});
        }
        assert(host.LoadModulesFromMemory(images));
        if (fatal_fetch) {
            const uint32_t bad = host.GuestAlloc(64, 4);
            host.MemoryWrite32(bad, 0x13579BDF);
            std::vector<uint32_t> code{0xE92D4002}; // push r1,lr
            Call(code, bad);
            const uint32_t entry = Install(host, code);
            fprintf(stderr, "FATAL_FETCH_PROBE bad=%08X entry=%08X marker=2468ACE0 pid=%d\n", bad, entry, getpid());
            host.RunFunction(entry, {bad, 0x2468ACE0});
            assert(false && "unregistered code fetch must abort");
        }
        const ElfLoader* engine = host.FindModule("libGameEngine.so");
        assert(engine);
        const uint32_t start = engine->GetImageStart(), size = engine->GetImageSize();
        std::vector<uint8_t> before(host.GetGuestMemoryBase() + start, host.GetGuestMemoryBase() + start + size);
        assert(InstallTFTBWidescreenOverride(host, false));
        assert(memcmp(before.data(), host.GetGuestMemoryBase() + start, size) == 0);
        const uint32_t wrapper = engine->GetSymbolAddress("_Z34luaRenderForce_16_by_9_AspectRatioP9lua_State");
        const uint32_t flag = engine->GetSymbolAddress("_ZN12RenderDevice18sbForceAspectRatioE");
        host.MemoryWrite32(wrapper, host.MemoryRead32(wrapper) ^ 1u);
        std::vector<uint8_t> changed(host.GetGuestMemoryBase() + start, host.GetGuestMemoryBase() + start + size);
        assert(!InstallTFTBWidescreenOverride(host, true));
        assert(memcmp(changed.data(), host.GetGuestMemoryBase() + start, size) == 0);
        host.MemoryWrite32(wrapper, host.MemoryRead32(wrapper) ^ 1u);
        host.MemoryWrite8(flag, 0);
        changed.assign(host.GetGuestMemoryBase() + start, host.GetGuestMemoryBase() + start + size);
        assert(!InstallTFTBWidescreenOverride(host, true));
        assert(memcmp(changed.data(), host.GetGuestMemoryBase() + start, size) == 0);
        host.MemoryWrite8(flag, 1);
        assert(InstallTFTBWidescreenOverride(host, true));
        before[wrapper + 36 - start] = 0;
        before[flag - start] = 0;
        assert(memcmp(before.data(), host.GetGuestMemoryBase() + start, size) == 0);
        puts("TFTB_WIDESCREEN_PROBE_PASS: absent marker unchanged; missing engine/code/data refused atomically; exact two writes. No initializers invoked.");
        return 0;
    }
#endif
    if (argc == 2 && (!strcmp(argv[1], "--fatal-guest-probe") || !strcmp(argv[1], "--fatal-abort-probe") ||
                      !strcmp(argv[1], "--fatal-jni-probe") || !strcmp(argv[1], "--fatal-exit-probe"))) {
        fprintf(stderr, "FATAL_PROBE_START %s pid=%d\n", argv[1], getpid());
        if (!strcmp(argv[1], "--fatal-guest-probe")) {
            host.RunFunction(Install(host, std::vector<uint32_t>{0xE7F000F0}));
        } else if (!strcmp(argv[1], "--fatal-jni-probe")) {
            auto& fake = FakeJniEnv::Instance();
            fake.Init(host);
            const uint32_t message = host.GuestAlloc(32, 4);
            memcpy(host.GetGuestMemoryBase() + message, "JNI FATAL PROBE", 16);
            host.RunFunction(host.MemoryRead32(fake.EnvTableGuestAddr() + 72), {fake.EnvTableGuestAddr(), message});
        } else {
            const char* symbol = !strcmp(argv[1], "--fatal-exit-probe") ? "exit" : "abort";
            host.RunFunction(host.GetThunkManager().FindProvider(symbol, ThunkManager::ProviderKind::Function), {7});
        }
        fputs("PROBE_UNEXPECTED_RETURN\n", stderr);
        return 97;
    }
    if (argc == 2 && !strcmp(argv[1], "--fmod-callback-only")) return FmodCallbackCheck(host) ? 0 : 1;
    if (argc == 2 && !strcmp(argv[1], "--audio-refill-only")) return AudioRefillAckCheck(host) ? 0 : 1;
    if (argc == 2 && !strcmp(argv[1], "--egl-destroy-only")) return EglDestroyFailureCheck(host) ? 0 : 1;
    if (argc == 2 && (!strcmp(argv[1],"--audio-only") || !strcmp(argv[1],"--audio-no-pump")))
        return AudioPumpCheck(host,!strcmp(argv[1],"--audio-no-pump")) ? 0 : 1;
    if (!GuestRangeCheck() || !EglDestroyFailureCheck(host)) return 1;
    PendingInvalidationCheck(host);
    AeabiMemoryCheck(host);
    const bool refused_initializers = !host.RunModuleInitializers();
    assert(refused_initializers); // no load-group audit means no initializer execution
    auto& manager = host.GetThunkManager();
    const uint32_t qsort = manager.FindProvider("qsort", ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
    const uint32_t memcmp_fn = manager.FindProvider("memcmp", ThunkManager::ProviderKind::Function);
    assert(qsort && memcmp_fn); // LibcAbiSelfCheck failure prevents these registrations.
    SyncAbiCheck(host);

    bool returned = false, thumb_caller = false, bad_stack = false;
    uint32_t saved_sp = 0;
    size_t comparisons = 0;
    const uint32_t enter = manager.RegisterThunk("__qsort_test_enter", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        assert(active.IsJitRunning());
        saved_sp = jit.Regs()[13];
        assert((saved_sp & 7) == 0);
        for (unsigned i = 4; i <= 11; ++i) jit.Regs()[i] = 0xA000u + i;
        for (unsigned i = 16; i < 32; ++i) jit.ExtRegs()[i] = 0x5A000000u + i;
        if (bad_stack) jit.Regs()[13] += 4;
    });
    const uint32_t leave = manager.RegisterThunk("__qsort_test_leave", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        assert(jit.Regs()[13] == saved_sp);
        assert(bool(jit.Regs()[14] & 1) == thumb_caller);
        for (unsigned i = thumb_caller ? 5 : 4; i <= 11; ++i) assert(jit.Regs()[i] == 0xA000u + i);
        for (unsigned i = 16; i < 32; ++i) assert(jit.ExtRegs()[i] == 0x5A000000u + i);
        returned = true;
    });
    const uint32_t trace = manager.RegisterThunk("__qsort_test_compare", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        assert(active.IsJitRunning() && (jit.Regs()[13] & 7) == 0);
        ++comparisons;
    });

    auto wrapper = [&](uint32_t target) {
        std::vector<uint32_t> code{0xE92D5FF0}; // push r4-r11,ip,lr (40 bytes)
        Call(code, enter);
        Call(code, target);
        Call(code, leave);
        code.insert(code.end(), {0xE8BD5FF0, 0xE3A0005A, 0xE12FFF1E}); // restore; mov r0,#90; bx lr
        return Install(host, code);
    };
    const uint32_t caller = wrapper(qsort);
    std::vector<uint16_t> thumb_code{0xB510}; // push r4,lr
    ThumbCall(thumb_code, enter);
    ThumbCall(thumb_code, qsort);
    ThumbCall(thumb_code, leave);
    thumb_code.insert(thumb_code.end(), {0x205A, 0xBD10}); // movs r0,#90; pop r4,pc
    const uint32_t thumb_wrapper = Install(host, thumb_code) | 1;

    std::vector<uint32_t> compare_code{0xE92D4010}; // push r4,lr
    Call(compare_code, trace);
    compare_code.insert(compare_code.end(), {
        0xE5900000, 0xE5911000, 0xE1500001, // ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1
        0xE3A00000, 0xB3A00102, 0xC3E00102, // 0, INT_MIN if lt, INT_MAX if gt
        0xE8BD4010, 0xE12FFF1E});
    const uint32_t compare = Install(host, compare_code);
    const uint32_t thumb_compare = Install(host, std::vector<uint16_t>{
        0x6800, 0x6809, 0x4288, 0xDB03, 0xDC05, 0x2000, 0x4770, 0xBF00,
        0x2000, 0x43C0, 0x4770, 0x2001, 0x4770, 0xBF00}) | 1;

    const uint32_t storage = host.GuestAlloc(4096, 8), base = storage + 9; // unaligned input plus canaries
    assert(storage);
    auto invoke = [&](uint32_t function, uint32_t address, uint32_t count, uint32_t size, uint32_t cmp, bool success) {
        returned = false;
        thumb_caller = bool(function & 1);
        bool completed = !success;
        const uint32_t result = host.RunFunction(function, {address, count, size, cmp}, &completed);
        assert(completed == success && returned == success && !host.IsJitRunning());
        if (success) assert(result == 90);
        const size_t before_drain = comparisons;
        host.DrainDeferred();
        assert(comparisons == before_drain); // comparator work must never be deferred
    };
    auto numbers = [&](std::vector<int32_t> values, uint32_t cmp, uint32_t function) {
        memset(host.GetGuestMemoryBase() + storage, 0xA5, 4096);
        memcpy(host.GetGuestMemoryBase() + base, values.data(), values.size() * 4);
        invoke(function, base, values.size(), 4, cmp, true);
        std::sort(values.begin(), values.end());
        assert(memcmp(host.GetGuestMemoryBase() + base, values.data(), values.size() * 4) == 0);
        assert(host.MemoryRead8(base - 1) == 0xA5 && host.MemoryRead8(base + values.size() * 4) == 0xA5);
    };
    for (uint32_t function : {caller, thumb_wrapper}) {
        for (uint32_t cmp : {compare, thumb_compare}) {
            numbers({5, -7, 0, 5, INT32_MIN, INT32_MAX, -7, 2}, cmp, function);
            numbers({-4, -3, -2, -1, 0, 1, 2}, cmp, function);
            numbers({9, 8, 7, 6, 5, 4, 3, 2, 1}, cmp, function);
            numbers({7, 7, 7, 7, 7}, cmp, function);
            for (uint32_t count = 2; count < 65; ++count) {
                std::vector<int32_t> values(count);
                for (uint32_t i = 0; i < count; ++i) values[i] = static_cast<int32_t>((i * 1103515245u + count * 12345u) % 37) - 18;
                numbers(values, cmp, function);
            }
        }
    }

    // A guest comparator calls host memcmp and uses its signed result in the guest helper.
    for (uint32_t size : {1u, 3u}) {
        std::vector<uint32_t> code{0xE92D4010};
        Call(code, trace);
        code.push_back(0xE3A02000 | size); // mov r2,#size
        Call(code, memcmp_fn);
        code.insert(code.end(), {0xE8BD4010, 0xE12FFF1E});
        const uint32_t cmp = Install(host, code);
        std::vector<std::vector<uint8_t>> records;
        for (unsigned i = 0; i < 31; ++i) {
            records.emplace_back(size);
            for (uint32_t j = 0; j < size; ++j) records.back()[j] = (i * 17 + j * 7) % 13;
            memcpy(host.GetGuestMemoryBase() + base + i * size, records.back().data(), size);
        }
        host.MemoryWrite8(base - 1, 0xA5);
        host.MemoryWrite8(base + records.size() * size, 0xA5);
        invoke(caller, base, records.size(), size, cmp, true);
        std::sort(records.begin(), records.end());
        for (size_t i = 0; i < records.size(); ++i) assert(memcmp(host.GetGuestMemoryBase() + base + i * size, records[i].data(), size) == 0);
        assert(host.MemoryRead8(base - 1) == 0xA5 && host.MemoryRead8(base + records.size() * size) == 0xA5);
    }

    // Nested qsort stays on the guest stack, sorting a separate array.
    const uint32_t inner = host.GuestAlloc(16, 4);
    const std::array<int32_t, 4> inner_values{8, -2, 8, 1}, inner_sorted{-2, 1, 8, 8};
    memcpy(host.GetGuestMemoryBase() + inner, inner_values.data(), 16);
    std::vector<uint32_t> nested{0xE92D4070, 0xE1A04000, 0xE1A05001}; // push r4-r6,lr; save element pointers
    Load(nested, 0, inner); Load(nested, 1, 4); Load(nested, 2, 4); Load(nested, 3, compare);
    Call(nested, qsort);
    nested.insert(nested.end(), {0xE1A00004, 0xE1A01005});
    Call(nested, compare);
    nested.insert(nested.end(), {0xE8BD4070, 0xE12FFF1E});
    numbers({3, -8, 3, 4, 2}, Install(host, nested), caller);
    assert(memcmp(host.GetGuestMemoryBase() + inner, inner_sorted.data(), 16) == 0);

    // The same helper image works at another guest address (no absolute fixups).
    std::vector<uint8_t> relocated(kGuestQsortCode, kGuestQsortCode + sizeof(kGuestQsortCode));
    const uint32_t second_helper = Install(host, relocated) + kGuestQsortEntryOffset;
    numbers({8, 4, 2, 1, 3, 5, 6, 7}, compare, wrapper(second_helper));

    const size_t before_trivial = comparisons;
    invoke(caller, 0, 0, 0, 0, true);
    invoke(caller, base, 1, 4, compare, true);
    assert(comparisons == before_trivial);
    std::array<uint8_t, 32> unchanged;
    memset(unchanged.data(), 0xA5, unchanged.size());
    memcpy(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size());
    for (const std::array<uint32_t, 4>& args : std::vector<std::array<uint32_t, 4>>{
             {0, 2, 4, compare}, {base, 2, 0, compare}, {base, UINT32_MAX, 16, compare},
             {0xFFFFFFFCu, 2, 4, compare}, {base, 2, 4, 0}, {base, 2, 4, base & ~3u},
             {base, 2, 4, compare | 2u}}) {
        invoke(caller, args[0], args[1], args[2], args[3], false);
        assert(memcmp(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size()) == 0);
    }
    bad_stack = true;
    invoke(caller, base, 2, 4, compare, false);
    bad_stack = false;
    assert(memcmp(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size()) == 0);
    numbers({9, 1, 2, -1}, compare, caller); // input rejection leaves a usable context; CPU faults use the separate fatal probe.
    printf("Guest qsort checks OK: SVC redirect, ARM/Thumb, order/permutation/canaries, host thunk, nested sort, PIC, failure/context; comparisons=%zu\n", comparisons);
    fflush(stdout);

    const uint32_t scan = manager.FindProvider("sscanf", ThunkManager::ProviderKind::Function);
    const uint32_t scan_text = host.GuestAlloc(8192), scan_format = host.GuestAlloc(128), scan_out = host.GuestAlloc(256);
    assert(scan && scan_text && scan_format && scan_out);
    struct ScanCase { const char* format; const char* text; int count; const char* spaces; int value; };
    for (const ScanCase& test : std::vector<ScanCase>{
             {"MemTotal:%[ \t]%d kB", "MemTotal:  6291456 kB\n", 2, "  ", 6291456},
             {"MemFree:%[ \t]%d kB", "MemFree:\t 1234 kB", 2, "\t ", 1234},
             {"MemTotal:%[ \t]%d kB", "MemTotal:  bad", 1, "  ", 0},
             {"MemTotal:%[ \t]%d kB", "MemTotal:7 kB", 0, "", 0},
             {"MemTotal:%[ \t]%d kB", "", EOF, "", 0},
             {"%d", "23", EOF, "", 0}}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), test.text);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), test.format);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, scan_out + 8, scan_out + 128}));
        assert(count == test.count);
        if (count >= 1) assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_out + 8), test.spaces) == 0);
        else assert(host.MemoryRead32(scan_out + 8) == 0xA5A5A5A5);
        assert(host.MemoryRead32(scan_out + 128) == (count >= 2 ? static_cast<uint32_t>(test.value) : 0xA5A5A5A5));
        assert(host.MemoryRead32(scan_out + 4) == 0xA5A5A5A5 && host.MemoryRead32(scan_out + 132) == 0xA5A5A5A5);
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), "MemTotal:  42 kB");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "MemTotal:%[ \t]%d kB");
    const uint32_t invalid_scan = host.RunFunction(scan, {scan_text, scan_format, 0xFFFFFFFFu, scan_out + 128});
    assert(invalid_scan == UINT32_MAX && host.MemoryRead32(scan_out + 128) == 0xA5A5A5A5);
    puts("Meminfo sscanf checks OK: exact formats, two typed outputs, partial/EOF, unsupported format, bounds/canaries");
    fflush(stdout);
    struct UrlCase { const char* format; const char* input; int count; const char* outputs[3]; };
    const uint32_t url_outputs[] = {scan_out + 8, scan_out + 80, scan_out + 160};
    for (const UrlCase& test : std::vector<UrlCase>{
             {"%15[^:]:%[^\n]", "file:assets/game.lua", 2, {"file", "assets/game.lua", ""}},
             {"%15[^\n:]://%[^\n/?]%[^\n]", "https://example.invalid/path?q=1", 3, {"https", "example.invalid", "/path?q=1"}},
             {"%[^\n/?]%[^\n]", "example.invalid/path", 2, {"example.invalid", "/path", ""}},
             {"%15[^\n:]://%[^\n/?]%[^\n]", "http://example.invalid", 2, {"http", "example.invalid", ""}},
             {"%15[^:]:%[^\n]", "abcdefghijklmnop:rest", 1, {"abcdefghijklmno", "", ""}},
             {"%[^\n/?]%[^\n]", "", EOF, {"", "", ""}}}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), test.input);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), test.format);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, url_outputs[0], url_outputs[1], url_outputs[2]}));
        assert(count == test.count);
        for (int i = 0; i < 3; ++i) {
            if (i < count) {
                assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + url_outputs[i]), test.outputs[i]) == 0);
                assert(host.MemoryRead8(url_outputs[i] + strlen(test.outputs[i]) + 1) == 0xA5);
            } else assert(host.MemoryRead32(url_outputs[i]) == 0xA5A5A5A5);
        }
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), "https://example.invalid/p");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "%15[^\n:]://%[^\n/?]%[^\n]");
    const uint32_t bad_third = host.RunFunction(scan, {scan_text, scan_format, url_outputs[0], url_outputs[1], UINT32_MAX});
    assert(bad_third == UINT32_MAX && host.MemoryRead32(url_outputs[0]) == 0xA5A5A5A5 && host.MemoryRead32(url_outputs[1]) == 0xA5A5A5A5);
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "[%*45[0123456789abcdefABCDEF:.]%c");
    for (const char* value : {"[::1]", "example.invalid", ""}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), value);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, url_outputs[0]}));
        const int32_t expected = value[0] == '[' ? 1 : value[0] ? 0 : EOF;
        assert(count == expected && host.MemoryRead8(url_outputs[0] + 1) == 0xA5);
        assert(host.MemoryRead8(url_outputs[0]) == (count == 1 ? ']' : 0xA5)); // %c must not append a NUL
    }
    puts("URL sscanf checks OK: exact scansets, width15, stack output, suppressed IPv6 probe/%c, partial/EOF, bounds/canaries; no network used");
    fflush(stdout);
    const uint32_t print = manager.FindProvider("vsnprintf", ThunkManager::ProviderKind::Function);
    const uint32_t print_format = host.GuestAlloc(128), print_args = host.GuestAlloc(64, 8), print_text = host.GuestAlloc(128), print_out = host.GuestAlloc(256);
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%s:%04x");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_text), "bridge");
    host.MemoryWrite32(print_args, print_text); host.MemoryWrite32(print_args + 4, 42);
    const uint32_t printed = host.RunFunction(print, {print_out, 64, print_format, print_args});
    printf("Guest vsnprintf: count=%u text='%s' (expected 11 'bridge:002a')\n", printed, host.GetGuestMemoryBase() + print_out);
    fflush(stdout);
    assert(printed == 11 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "bridge:002a") == 0);
    const uint32_t measured = host.RunFunction(print, {0, 0, print_format, print_args});
    assert(measured == 11);
    const uint32_t truncated = host.RunFunction(print, {print_out, 8, print_format, print_args});
    assert(truncated == 11 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "bridge:") == 0);
    const uint32_t snprintf_fn = manager.FindProvider("snprintf", ThunkManager::ProviderKind::Function);
    const uint32_t measure_registers = host.RunFunction(snprintf_fn, {0, 0, print_format, print_text, 42});
    assert(measure_registers == 11);
    returned = false; thumb_caller = false;
    const uint32_t aligned_call = host.RunFunction(caller, {base, 2, 4, compare, 0}); // odd stack-word count still needs SP % 8 == 0
    assert(aligned_call == 90 && returned);
    auto print_case = [&](const char* format, const char* expected, uint32_t args) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), format);
        memset(host.GetGuestMemoryBase() + print_out, 0xA5, 256);
        const uint32_t count = host.RunFunction(print, {print_out, 128, print_format, args});
        assert(count == strlen(expected));
        assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), expected) == 0);
        assert(host.MemoryRead8(print_out + strlen(expected) + 1) == 0xA5);
    };
    const double decimal = 1.25;
    uint64_t decimal_bits;
    memcpy(&decimal_bits, &decimal, 8);
    host.MemoryWrite32(print_args, static_cast<uint32_t>(-7));
    host.MemoryWrite32(print_args + 4, 42);
    host.MemoryWrite32(print_args + 8, static_cast<uint32_t>(-3));
    host.MemoryWrite64(print_args + 16, 0x1122334455667788ULL);
    host.MemoryWrite64(print_args + 24, decimal_bits);
    print_case("%+08d|%#x|%ld|%llu|%.2f", "-0000007|0x2a|-3|1234605616436508552|1.25", print_args);
    host.MemoryWrite32(print_args, static_cast<uint32_t>(-8));
    host.MemoryWrite32(print_args + 4, 2);
    host.MemoryWrite64(print_args + 8, decimal_bits);
    print_case("%*.*f", "1.25    ", print_args);
    print_case("%.2f", "1.25", print_args + 4); // absolute va_list alignment, not alignment relative to its start
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%*.*f");
    const uint32_t mixed = host.RunFunction(snprintf_fn, {print_out, 128, print_format, static_cast<uint32_t>(-8), 2, 0,
                                                         static_cast<uint32_t>(decimal_bits), static_cast<uint32_t>(decimal_bits >> 32)});
    assert(mixed == 8 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "1.25    ") == 0);
    host.MemoryWrite32(print_args, print_out + 192); host.MemoryWrite32(print_args + 4, print_text);
    print_case("abc%n:%s", "abc:bridge", print_args);
    assert(host.MemoryRead32(print_out + 192) == 3);
    const uint32_t unterminated = static_cast<uint32_t>(host.GetGuestMemorySize() - 3);
    memcpy(host.GetGuestMemoryBase() + unterminated, "xyz", 3);
    host.MemoryWrite32(print_args, 3); host.MemoryWrite32(print_args + 4, unterminated);
    print_case("%.*s", "xyz", print_args);
    for (const char* unsupported : {"%1$d", "%ls", "%2000000u"}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), unsupported);
        memset(host.GetGuestMemoryBase() + print_out, 0xA5, 256);
        const uint32_t failed = host.RunFunction(print, {print_out, 128, print_format, print_args});
        assert(failed == UINT32_MAX && host.MemoryRead32(print_out) == 0xA5A5A5A5);
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%u");
    const uint32_t bad_va = host.RunFunction(print, {print_out, 128, print_format, 0xFFFFFFFFu});
    assert(bad_va == UINT32_MAX && host.MemoryRead32(print_out) == 0xA5A5A5A5);
    puts("Guest printf checks OK: varargs/GPR/stack alignment, measure/truncate, flags/width/precision, int64/double, bounded strings, %n, typed failures");
    fflush(stdout);
    // Each JIT CPU needs its own exclusive-monitor slot: unrelated LDREX/STREX
    // pairs must survive interleaving on two distinct guest addresses.
    std::barrier rendezvous(2);
    const uint32_t barrier = manager.RegisterThunk("__exclusive_test_barrier", [&](Dynarmic::A32::Jit&, DynarmicHost&) {
        rendezvous.arrive_and_wait();
    });
    std::vector<uint32_t> exclusive_code{0xE92D4070, 0xE1A04000, 0xE1945F9F}; // push; mov r4,r0; ldrex r5,[r4]
    Call(exclusive_code, barrier);
    exclusive_code.insert(exclusive_code.end(), {0xE2855001, 0xE1840F95, 0xE8BD4070, 0xE12FFF1E}); // add; strex r0,r5,[r4]; return
    const uint32_t exclusive_fn = Install(host, exclusive_code), cells = host.GuestAlloc(128, 16);
    host.MemoryWrite32(cells, 10); host.MemoryWrite32(cells + 64, 20);
    uint32_t status[2] = {UINT32_MAX, UINT32_MAX};
    std::thread first([&]() { status[0] = host.RunFunction(exclusive_fn, {cells}); });
    std::thread second([&]() { status[1] = host.RunFunction(exclusive_fn, {cells + 64}); });
    first.join(); second.join();
    printf("Exclusive slots: status=%u,%u values=%u,%u (expected 0,0 and 11,21)\n", status[0], status[1], host.MemoryRead32(cells), host.MemoryRead32(cells + 64));
    fflush(stdout);
    assert(status[0] == 0 && status[1] == 0 && host.MemoryRead32(cells) == 11 && host.MemoryRead32(cells + 64) == 21);
    if (argc > 1) {
        assert(argc == 6);
        const char* names[] = {"libSDL2.so", "libfmod.so", "libfmodstudio.so", "libGameEngine.so", "libmain.so"};
        std::vector<std::vector<uint8_t>> files;
        std::vector<GuestModuleImage> images;
        for (int i = 1; i < argc; ++i) {
            std::ifstream input(argv[i], std::ios::binary);
            assert(input.good());
            files.emplace_back(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
            images.push_back({names[i - 1], files.back().data(), files.back().size()});
        }
        const bool loaded = host.LoadModulesFromMemory(images);
        assert(loaded);

        // Lifecycle hooks are part of the index's compatibility contract. A
        // separate host proves a modified D2 body fails closed without
        // contaminating the host used by the remaining integration checks.
        {
            DynarmicHost fingerprint_host;
            assert(fingerprint_host.Initialize());
            assert(fingerprint_host.LoadModulesFromMemory(images));
            const uint32_t destructor = fingerprint_host.FindSymbol(
                "_ZN11PropertySet12KeyCallbacksD2Ev");
            assert(destructor);
            fingerprint_host.MemoryWrite32(
                destructor, fingerprint_host.MemoryRead32(destructor) ^ 1u);
            fingerprint_host.InvalidateGuestCode(destructor,
                                                  sizeof(uint32_t));
            assert(!InstallTelltalePropertySetAddCallbackAcceleration(
                fingerprint_host));
        }
        puts("KeyCallbacks D2 fingerprint mismatch failed closed in an "
             "isolated host");
        fflush(stdout);

        puts("Actual five-library relocation succeeded; no game initializers invoked");
        fflush(stdout);
        PropertySetAccelerationCheck(host);
        const uint32_t mask_fn = host.FindSymbol("_ZN10StringMask11MaskCompareEPKcS1_S1_NS_8MaskModeE");
        assert(mask_fn);
        const uint32_t mask = host.GuestAlloc(128, 4), name = host.GuestAlloc(128, 4);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + mask), "project_*.prop");
        for (const char* candidate : {"project_general.prop", "project.prop", "project_test.prop", "PROJECT_TEST.PROP", "nothing.prop"}) {
            strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + name), candidate);
            printf("Actual StringMask before: %s\n", candidate);
            fflush(stdout);
            const uint32_t result = host.RunFunction(mask_fn, {mask, name, 0, 0});
            printf("Actual StringMask result: %s -> %u\n", candidate, result);
            fflush(stdout);
            assert(result == (strchr(candidate, '_') != nullptr));
        }
    }
    return AudioPumpCheck(host,false) ? 0 : 1;
}
