#pragma once
#include <cstdint>
#include <string>

class ThunkManager;
class DynarmicHost;

void RegisterOpenSLESThunks(ThunkManager& manager, DynarmicHost& host);
uint32_t GetOpenSLESInterfacePointer(const std::string& name);
void ShutdownOpenSLES(DynarmicHost* host);
void PauseAudioPlayback(DynarmicHost* host);
void ResumeAudioPlayback(DynarmicHost* host);

#ifdef BRIDGE_OPENSL_TEST
struct OpenSLESTestSnapshot {
    uint32_t player = 0, queue = 0, play = 0;
    unsigned starts = 0;
    uint64_t callbacks = 0, enqueues = 0;
    uint32_t native_state = 0, buffer_hash = 0;
    bool control = false, app_paused = false;
};
OpenSLESTestSnapshot OpenSLESTestPrepare(DynarmicHost& host, bool disable_start);
bool OpenSLESTestComplete(bool late_only = false);
void OpenSLESTestError(uint32_t error);
OpenSLESTestSnapshot OpenSLESTestInspect();
#endif
