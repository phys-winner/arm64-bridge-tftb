#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    // Returns the guest address of this thunk's trampoline.
    uint32_t RegisterThunk(const std::string& name, ThunkHandler handler);
    void RegisterSymbol(const std::string& name, uint32_t address);
    void RegisterDataSymbol(const std::string& name, uint32_t address,
                            const std::vector<std::string>& libraries = {});
    enum class ProviderKind : uint8_t { Function, Object };
    uint32_t FindProvider(const std::string& name, ProviderKind kind,
                          const std::string& version = "", const std::string& library = "") const;
    static bool SupportsLibrary(const std::string& library);
    static bool SupportsVersion(const std::string& library, const std::string& version);

    uint32_t GetOrCreateThunkAddress(const std::string& name);
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);

    const std::unordered_map<std::string, uint32_t>& GetThunkSymbolTable() const {
        return m_symbol_to_address;
    }

    static uint32_t s_screenWidth;
    static uint32_t s_screenHeight;
    // Virtual screen size reported to the guest for UI scaling; 0 = report the real one.
    static uint32_t s_virtualWidth;
    static uint32_t s_virtualHeight;
    static uint32_t s_forced_dpi;
    static uint32_t s_ui_inset;

private:
    void RegisterGLThunks();
    void RegisterLibcThunks();
    DynarmicHost& m_host;
    uint32_t m_next_thunk_addr = 0x00010000; // Base address for thunk trampolines
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    std::unordered_map<std::string, ProviderKind> m_symbol_kinds;
    std::unordered_map<std::string, std::vector<std::string>> m_symbol_libraries;
    std::vector<std::string> m_registration_libraries;
    std::vector<ThunkHandler> m_id_to_handler;
    std::unordered_map<uint32_t, std::string> m_id_to_name;
};

struct GuestThreadWorker {
    uint32_t start_func;
    uint32_t arg;
};

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers();
void AddGuestThreadWorker(uint32_t start_func, uint32_t arg);

// Device probes the guest usually wants (thunk_manager.cpp). Kept generic: no
// game class is consulted, only android.os / Resources / system properties.
std::string QueryDeviceLanguage();
std::string QueryDeviceCountryCode();
uint32_t QueryDeviceDensity();
uint32_t QueryDeviceIsPad();

// Asset overriding from <externalFilesDir>/... (thunks_libc.cpp).
// Technique: the engine's own archive->archive->plain-file lookup chain is left
// alone; the first source is simply made to miss for any file the user dropped
// into the override root, so the engine's existing fallback does the work.
void SetAssetOverrideRoot(const std::string& root);
bool HasAssetOverride(const char* entry_name);
void ClearArm32TmZoneCache(const DynarmicHost* host);
void InstallTelltaleCurrentDirectoryFix(DynarmicHost& host);
bool InstallMCSMEpisodeDirectory(DynarmicHost& host, const std::string& files_dir);
bool InstallMCSMAppFilesUserLocation(DynarmicHost& host);
void InstallTelltaleRenderFrameProbe(DynarmicHost& host);
void InstallTelltaleRenderExecuteProbe(DynarmicHost& host);
void InstallTelltaleSceneProbes(DynarmicHost& host);
void InstallTelltaleDoLoadProbe(DynarmicHost& host);
void InstallTelltaleStartupProbes(DynarmicHost& host);
void InstallTelltaleTTPCallErrorProbe(DynarmicHost& host);
void InstallTelltaleArchiveProbe(DynarmicHost& host);
bool InstallMCSMHideBorderOverride(DynarmicHost& host);
// plt_slot: the guest PLT entry of the archive-open function to divert.
// real_symbol: that same function's name, resolved in the guest for the tail call.
void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol);
