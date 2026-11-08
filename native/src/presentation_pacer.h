#pragma once

#include <chrono>
#include <cstdint>

namespace presentation_pacer {
using Clock = std::chrono::steady_clock;
using Duration = Clock::duration;
using TimePoint = Clock::time_point;

int NormalizeMode(int mode) noexcept; // 0 = DISPLAY; invalid = 60.
double NormalizeRefreshHz(double hz) noexcept;
Duration FramePeriod(int mode, double actual_refresh_hz) noexcept;

// Pure math used by the real wait and the fake-time assertion check.
struct Deadline {
    TimePoint next{};
    bool armed = false;
    void Reset() noexcept;
    TimePoint Due(TimePoint now, Duration period) noexcept;
    void Admit(TimePoint now, Duration period) noexcept;
};

void SetMode(int mode);
int GetMode();
void SetRefreshHz(double actual_refresh_hz);
// Initially false. Root must keep this false throughout guest loading/JNI_OnLoad.
void SetActive(bool active);
// Surface recreation/context change, including reuse of the same guest IDs.
void Reset();
// Call after releasing registry/load/guest locks, before the real EGL swap.
// This does not skip the caller's EGL operation or retain any EGL handle.
void WaitBeforeSwap(uint32_t guest_display, uint32_t guest_surface);
} // namespace presentation_pacer
