#include "presentation_pacer.h"
#include "lua_fps_arg.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <cstring>
#include <future>
#include <thread>

#ifdef NDEBUG
#error This assertion check requires NDEBUG to be undefined.
#endif

using namespace presentation_pacer;
using namespace std::chrono_literals;

static void PeriodCheck(int mode, double hz, double target) {
    const auto expected = std::chrono::ceil<Duration>(std::chrono::duration<double>(1.0 / target));
    assert(FramePeriod(mode, hz) == expected);
    assert(expected > Duration::zero());
}

static void CadenceCheck(int mode, double hz) {
    const Duration p = FramePeriod(mode, hz);
    const TimePoint zero{};
    Deadline d;
    assert(d.Due(zero, p) == zero);
    d.Admit(zero, p);
    for (int i = 1; i <= 20; ++i) {
        const auto slot = zero + p * i;
        assert(d.Due(slot - p / 2, p) == slot); // Early rendering must wait.
        assert(d.Due(slot, p) == slot);
        d.Admit(slot, p);
        assert(d.next == slot + p);
    }
}

static void LuaArgumentCheck() {
    std::array<uint8_t, 512> memory{};
    auto write = [&](uint32_t p, uint32_t v) { std::memcpy(memory.data() + p, &v, 4); };
    constexpr uint32_t state = 32, ci = 80, function = 132, callback = 0x10000;
    auto init = [&](float value) {
        memory.fill(0);
        write(state + 8, function + 16); write(state + 16, ci); write(ci, function);
        write(function, callback); write(function + 4, 22); write(function + 12, 3);
        std::memcpy(memory.data() + function + 8, &value, 4);
    };
    auto decode = [&] { return DecodeTelltaleFpsArg(memory.data(), memory.size(), state, callback); };
    for (float value : {0.f, 30.f, 45.f, 60.f}) {
        init(value); const auto before = memory;
        assert(decode() == static_cast<int>(value)); assert(memory == before);
    }
    for (float value : {-1.f, 44.5f, 120.f, std::numeric_limits<float>::infinity(),
                        std::numeric_limits<float>::quiet_NaN()}) { init(value); assert(decode() == 60); }
    for (uint32_t tag : {0u, 1u, 4u, 19u}) { init(45); write(function + 12, tag); assert(decode() == 60); }
    init(45); write(function + 4, 6); assert(decode() == 60);
    init(45); write(function, callback + 8); assert(decode() == 60);
    for (uint32_t top : {0u, function + 8, function + 24}) { init(45); write(state + 8, top); assert(decode() == 60); }
    for (uint32_t invalid : {0u, 81u, 512u, 0xfffffffcu}) { init(45); write(state + 16, invalid); assert(decode() == 60); }
    init(45); write(ci, 500); assert(decode() == 60);
    init(45); assert(DecodeTelltaleFpsArg(memory.data(), memory.size(), 0xfffffff0u, callback) == 60);
    assert(DecodeTelltaleFpsArg(nullptr, 512, state, callback) == 60);
    assert(DecodeTelltaleFpsArg(memory.data(), memory.size(), state, 0) == 60);
    // A different valid lua_State must work: callbacks can execute on coroutines.
    init(45); write(52 + 8, function + 16); write(52 + 16, ci);
    assert(DecodeTelltaleFpsArg(memory.data(), memory.size(), 52, callback) == 45);
}

static void WakeCheck(int change) {
    SetMode(0); SetRefreshHz(1); SetActive(true); Reset();
    std::promise<void> armed;
    auto ready = armed.get_future();
    auto result = std::async(std::launch::async, [&] {
        errno = EDOM;
        WaitBeforeSwap(9, 10); armed.set_value(); WaitBeforeSwap(9, 10);
        assert(errno == EDOM);
    });
    ready.wait();
    assert(result.wait_for(20ms) == std::future_status::timeout);
    if (change == 0) SetActive(false);
    if (change == 1) Reset();
    if (change == 2) SetMode(60);
    if (change == 3) SetRefreshHz(90);
    assert(result.wait_for(250ms) == std::future_status::ready);
    result.get(); SetActive(false);
}

int main() {
    LuaArgumentCheck();
    for (int mode : {0, 30, 45, 60}) assert(NormalizeMode(mode) == mode);
    for (int mode : {-1, 1, 29, 90, 120}) assert(NormalizeMode(mode) == 60);
    for (double hz : {0.0, -60.0, std::numeric_limits<double>::infinity(),
                      std::numeric_limits<double>::quiet_NaN(), 1e-300, 1e300}) {
        assert(NormalizeRefreshHz(hz) == 60.0);
        PeriodCheck(0, hz, 60.0);
    }
    PeriodCheck(30, 60, 30); PeriodCheck(45, 60, 45);
    PeriodCheck(60, 90, 60); PeriodCheck(0, 90, 90);
    PeriodCheck(45, 30, 30); PeriodCheck(7, 90, 60);
    PeriodCheck(0, 59.94, 59.94); PeriodCheck(60, 59.94, 59.94);
    assert(NormalizeRefreshHz(59.94) == 59.94);
    assert(FramePeriod(0, 59.94) > FramePeriod(0, 60.0));
    for (int mode : {0, 30, 45, 60}) {
        CadenceCheck(mode, 60.0);
        CadenceCheck(mode, 90.0);
    }

    const TimePoint zero{};
    const Duration p = FramePeriod(60, 60);
    const Duration epsilon = Duration{1};
    Deadline late;
    late.Due(zero, p); late.Admit(zero, p);
    assert(late.Due(zero + p + epsilon, p) == zero + p);
    late.Admit(zero + p + epsilon, p);
    assert(late.next == zero + p * 2); // Not now+p or the next future due slot.

    Deadline block;
    block.Due(zero, p); block.Admit(zero, p); // Swap starts at time0.
    const TimePoint returned = zero + p + p / 10; // EGL blocked beyond the due time.
    assert(block.Due(returned, p) <= returned); // Must NOT sleep another period.
    block.Admit(returned, p);
    assert(block.next == zero + p * 2);

    Deadline stall;
    stall.Due(zero, p); stall.Admit(zero, p);
    const TimePoint after_stall = zero + p * 20;
    assert(stall.Due(after_stall, p) == after_stall);
    stall.Admit(after_stall, p);
    assert(stall.Due(after_stall, p) == after_stall + p); // No catch-up burst.

    Deadline oversleep;
    oversleep.Due(zero, p); oversleep.Admit(zero, p);
    oversleep.Admit(zero + p * 4, p);
    assert(oversleep.next == zero + p * 5);
    oversleep.Reset();
    assert(oversleep.Due(zero + p * 9, p) == zero + p * 9);

    // Execute the production disabled gate, reset paths, and one real CV timeout.
    errno = E2BIG; WaitBeforeSwap(1, 2); assert(errno == E2BIG);
    SetMode(0); SetRefreshHz(1000); SetActive(true); Reset();
    const auto begin = Clock::now();
    errno = ERANGE;
    WaitBeforeSwap(1, 2); WaitBeforeSwap(1, 2);
    assert(errno == ERANGE);
    assert(Clock::now() - begin >= FramePeriod(0, 1000));
    SetMode(45); WaitBeforeSwap(1, 2);
    SetRefreshHz(90); WaitBeforeSwap(1, 2);
    WaitBeforeSwap(1, 3); Reset(); WaitBeforeSwap(1, 3);
    SetActive(false); WaitBeforeSwap(1, 3);
    SetActive(true); WaitBeforeSwap(1, 3);
    SetActive(false); SetMode(60); SetRefreshHz(60);
    for (int change : {0, 1, 2, 3}) WakeCheck(change);
    SetMode(60); SetRefreshHz(60); assert(GetMode() == 60);
    std::puts("FPS_PACER_DEADLINE_WAKE_ERRNO_AND_LUA_ARGUMENT_ASSERTIONS_PASS");
}
