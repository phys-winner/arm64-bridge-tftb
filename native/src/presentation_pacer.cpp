#include "presentation_pacer.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cmath>
#include <condition_variable>
#include <mutex>

namespace presentation_pacer {
int NormalizeMode(int mode) noexcept {
    return mode == 0 || mode == 30 || mode == 45 || mode == 60 ? mode : 60;
}

double NormalizeRefreshHz(double hz) noexcept {
    if (!std::isfinite(hz) || hz <= 0.0) return 60.0;
    const double seconds = 1.0 / hz;
    const double tick = std::chrono::duration<double>(Duration{1}).count();
    const double maximum = std::chrono::duration<double>(Duration::max()).count() / 4.0;
    // Reject unrepresentable periods rather than overflow or create a zero wait.
    return std::isfinite(seconds) && seconds >= tick && seconds < maximum ? hz : 60.0;
}

Duration FramePeriod(int mode, double actual_refresh_hz) noexcept {
    mode = NormalizeMode(mode);
    const double hz = NormalizeRefreshHz(actual_refresh_hz);
    const double target = mode == 0 ? hz : std::min(hz, static_cast<double>(mode));
    return std::chrono::ceil<Duration>(std::chrono::duration<double>(1.0 / target));
}

void Deadline::Reset() noexcept { armed = false; }

TimePoint Deadline::Due(TimePoint now, Duration period) noexcept {
    assert(period > Duration::zero());
    // A full missed period rebases once; a slightly late slot stays due NOW.
    if (!armed || (now >= next && now - next >= period)) {
        next = now;
        armed = true;
    }
    return next;
}

void Deadline::Admit(TimePoint now, Duration period) noexcept {
    Due(now, period); // Also accounts for a whole-period OS wait overshoot.
    assert(now >= next);
    if (next > TimePoint::max() - period) Reset();
    else next += period; // BEFORE EGL: blocking swap time counts toward this slot.
}

namespace {
struct State {
    std::mutex mutex;
    std::condition_variable changed;
    int mode = 60;
    double refresh_hz = 60.0;
    bool active = false;
    uint64_t epoch = 1;
};
// One process-lifetime pacer; root must stop callers before library teardown.
State state;

struct ErrnoRestore {
    int saved = errno;
    ~ErrnoRestore() { errno = saved; }
};

struct ThreadSchedule {
    Deadline deadline;
    uint64_t epoch = 0;
    uint32_t display = 0;
    uint32_t surface = 0;
};
// shortcut: one active Surface per thread; retain per-Surface schedules if a second is observed.
thread_local ThreadSchedule local;
} // namespace

void SetMode(int mode) {
    mode = NormalizeMode(mode);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.mode == mode) return;
        state.mode = mode;
        ++state.epoch;
    }
    state.changed.notify_all();
}

int GetMode() {
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.mode;
}

void SetRefreshHz(double hz) {
    hz = NormalizeRefreshHz(hz);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.refresh_hz == hz) return;
        state.refresh_hz = hz;
        ++state.epoch;
    }
    state.changed.notify_all();
}

void SetActive(bool active) {
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.active == active) return;
        state.active = active;
        ++state.epoch;
    }
    state.changed.notify_all();
}

void Reset() {
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        ++state.epoch;
    }
    state.changed.notify_all();
}

void WaitBeforeSwap(uint32_t display, uint32_t surface) {
    ErrnoRestore preserve;
    std::unique_lock<std::mutex> lock(state.mutex);
    for (;;) {
        if (!state.active || !display || !surface) {
            local.deadline.Reset();
            return;
        }
        if (local.epoch != state.epoch || local.display != display || local.surface != surface) {
            local.deadline.Reset();
            local.epoch = state.epoch;
            local.display = display;
            local.surface = surface;
        }
        const Duration period = FramePeriod(state.mode, state.refresh_hz);
        const TimePoint now = Clock::now();
        const TimePoint due = local.deadline.Due(now, period);
        if (now >= due) {
            local.deadline.Admit(now, period);
            return; // unique_lock is destroyed before the caller enters EGL.
        }
        const uint64_t epoch = state.epoch;
        state.changed.wait_until(lock, due, [epoch] { return state.epoch != epoch; });
        // CV releases ONLY our mutex while sleeping; epoch/active are rechecked.
    }
}
} // namespace presentation_pacer
