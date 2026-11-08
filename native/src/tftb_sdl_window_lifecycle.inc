#include <condition_variable>

// All methods are protected by the existing presentation mutex. Only the
// established UI looper owns guest Pause/Resume execution; a Window owner can
// publish/retire readiness without recursively entering its running JIT.
struct TftbSdlWindowLifecycle {
    struct Ticket {
        uint64_t epoch = 0;
        uint64_t serial = 0;
        bool foreground = true;
        constexpr explicit operator bool() const { return serial != 0; }
    };
    uint32_t window = 0;
    uint64_t epoch = 0, serial = 0, active_serial = 0;
    // Acknowledge posted native events/tokens, not later PumpEvents consumption.
    bool applied_foreground = true, active = false, stopping = false;

    constexpr void Publish(uint32_t value, bool foreground) {
        if (stopping) return;
        window = value;
        ++epoch;
        applied_foreground = foreground;
    }
    constexpr void Retire() { window = 0; ++epoch; }
    constexpr void Stop() { stopping = true; Retire(); }
    constexpr Ticket Claim(bool foreground) {
        if (stopping || !window || active || applied_foreground == foreground) return {};
        active = true;
        active_serial = ++serial;
        return {epoch, active_serial, foreground};
    }
    constexpr bool Complete(Ticket ticket, bool succeeded) {
        if (!active || ticket.serial != active_serial) return false;
        active = false;
        if (succeeded && !stopping && window && ticket.epoch == epoch)
            applied_foreground = ticket.foreground;
        return true;
    }
};

static TftbSdlWindowLifecycle g_sdl_window_lifecycle;
static std::condition_variable g_sdl_window_idle;
static std::thread::id g_sdl_transition_owner;

static void StopSdlWindowLifecycle() {
    std::lock_guard<std::mutex> lock(g_presentation_mutex);
    g_sdl_window_lifecycle.Stop();
}

static bool InstallTftbSdlWindowLifecycle(DynarmicHost& runtime, bool image_verified) {
    const ElfLoader* sdl = runtime.FindModule("libSDL2.so");
    if (!image_verified || !sdl) return false;
    const ElfSymbol* create = sdl->GetExportedSymbol("Android_CreateWindow");
    const ElfSymbol* destroy = sdl->GetExportedSymbol("Android_DestroyWindow");
    const ElfSymbol* pump = sdl->GetExportedSymbol("Android_PumpEvents");
    const ElfSymbol* window = sdl->GetExportedSymbol("Android_Window");
    constexpr uint32_t kCreateRva = 0x89EE4, kCreateTail = 0xA0;
    constexpr uint32_t kDestroyRva = 0x89FE4, kDestroyGate = 0x20;
    constexpr uint32_t kWindowRva = 0xCDC74, kPausedRva = 0xCDC54;
    const uint64_t base = sdl->GetBaseAddress();
    auto span = [&](uint64_t address, size_t size, uint32_t flags, bool file_backed) {
        if (!size || address < base || address + size > runtime.GetGuestMemorySize()) return false;
        for (const ElfSegment& segment : sdl->GetSegments()) {
            const uint64_t lower = base + segment.vaddr;
            const uint64_t upper = lower + (file_backed ? segment.filesz : segment.memsz);
            if (segment.flags == flags && address >= lower && address + size <= upper) return true;
        }
        return false;
    };
    auto function = [&](const ElfSymbol* symbol, uint32_t rva, uint32_t size) {
        return symbol && symbol->type == STT_FUNC && symbol->size == size &&
            static_cast<uint64_t>(symbol->value) == base + rva + 1 &&
            span(base + rva, size, PF_R | PF_X, true);
    };
    // The trust boundary is the shared complete original-SDL SHA guard installed
    // by the primary-motion repair; these local guards pin both altered seams
    // and the internal Android_Paused-byte derivation in Android_PumpEvents.
    if (!function(create, kCreateRva, 248) || !function(destroy, kDestroyRva, 140) ||
        !function(pump, 0x89838, 204) || !window || window->type != STT_OBJECT ||
        window->size != 4 || static_cast<uint64_t>(window->value) != base + kWindowRva ||
        !span(base + kWindowRva, 4, PF_R | PF_W, false) ||
        !span(base + kPausedRva, 1, PF_R | PF_W, false) ||
        base + kPausedRva > UINT32_MAX ||
        runtime.MemoryRead32(create->value & ~1u) != 0xAF03B5F0u ||
        runtime.MemoryRead32((create->value & ~1u) + kCreateTail) != 0x20006004u ||
        runtime.MemoryRead32((create->value & ~1u) + kCreateTail + 4) != 0xBDF0B001u ||
        runtime.MemoryRead32(destroy->value & ~1u) != 0xAF03B5F0u ||
        runtime.MemoryRead32((destroy->value & ~1u) + kDestroyGate) != 0x68096800u ||
        runtime.MemoryRead32((destroy->value & ~1u) + kDestroyGate + 4) != 0x68086002u ||
        runtime.MemoryRead32(base + 0x89844) != 0x44794926u ||
        runtime.MemoryRead16(base + 0x89848) != 0x7809u ||
        runtime.MemoryRead32(base + 0x898E0) != 0x0004440Au ||
        base + 0x8984A + runtime.MemoryRead32(base + 0x898E0) != base + kPausedRva ||
        runtime.MemoryRead32(window->value) != 0 || runtime.MemoryRead8(base + kPausedRva) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
            "TFTB SDL lifecycle refused: exact Window/paused-byte fingerprint mismatch; no writes.");
        return false;
    }
    const uint32_t window_address = window->value;
    const uint32_t paused_address = static_cast<uint32_t>(base + kPausedRva);
    const uint32_t create_thunk = runtime.GetThunkManager().RegisterThunk("tftb_sdl_window_ready",
        [window_address, paused_address](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            if (jit.Regs()[0] != window_address || !jit.Regs()[4] ||
                host.MemoryRead32(window_address) != jit.Regs()[4] ||
                host.MemoryRead8(paused_address) > 1)
                __android_log_assert(nullptr, LOG_TAG, "TFTB SDL Window publication contract failed");
            {
                std::lock_guard<std::mutex> lock(g_presentation_mutex);
                g_sdl_window_lifecycle.Publish(jit.Regs()[4], host.MemoryRead8(paused_address) == 0);
            }
            NotifyTelltaleUiLifecycle();
        });
    const uint32_t destroy_thunk = runtime.GetThunkManager().RegisterThunk("tftb_sdl_window_retire",
        [window_address](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            if (jit.Regs()[0] != window_address || jit.Regs()[2] != 0 ||
                host.MemoryRead32(window_address) != jit.Regs()[4])
                __android_log_assert(nullptr, LOG_TAG, "TFTB SDL Window retirement contract failed");
            {
                std::unique_lock<std::mutex> lock(g_presentation_mutex);
                if (g_sdl_window_lifecycle.active && g_sdl_transition_owner == std::this_thread::get_id())
                    __android_log_assert(nullptr, LOG_TAG, "TFTB SDL Window destroyed inside lifecycle callback");
                // Pause/Resume post their semaphores; neither waits for this
                // Window-owner thread. Release our mutex while they finish.
                g_sdl_window_idle.wait(lock, [] { return !g_sdl_window_lifecycle.active; });
                g_sdl_window_lifecycle.Retire();
            }
            NotifyTelltaleUiLifecycle();
        });
    const uint32_t create_svc = create_thunk ? runtime.MemoryRead32(create_thunk) : 0;
    const uint32_t destroy_svc = destroy_thunk ? runtime.MemoryRead32(destroy_thunk) : 0;
    if ((create_svc & 0xFF000000u) != 0xEF000000u ||
        (destroy_svc & 0xFF000000u) != 0xEF000000u) return false;
    const uint32_t veneer = runtime.GuestAlloc(48, 4);
    if (!veneer) return false;
    // ARM success tail: original store, readiness SVC, original flag-setting
    // zero result, local-stack release and interworking saved-register return.
    const uint32_t creation[] = {0xE5804000u, create_svc, 0xE3B00000u, 0xE28DD004u, 0xE8BD80F0u};
    // ARM retirement seam: original two GOT loads, retirement SVC BEFORE the
    // null store/semaphore destruction, original remaining loads, Thumb return.
    const uint32_t retirement[] = {0xE5900000u, 0xE5911000u, destroy_svc, 0xE5802000u,
        0xE5910000u, 0xE51FF004u, ((destroy->value & ~1u) + kDestroyGate + 8) | 1u};
    for (size_t i = 0; i < std::size(creation); ++i)
        runtime.MemoryWrite32(veneer + static_cast<uint32_t>(i * 4), creation[i]);
    for (size_t i = 0; i < std::size(retirement); ++i)
        runtime.MemoryWrite32(veneer + 20 + static_cast<uint32_t>(i * 4), retirement[i]);
    runtime.AddExecutableRange(veneer, 48);
    runtime.InvalidateGuestCode(veneer, 48);
    const uint32_t create_site = (create->value & ~1u) + kCreateTail;
    const uint32_t destroy_site = (destroy->value & ~1u) + kDestroyGate;
    runtime.MemoryWrite32(create_site, 0xF000F8DFu); // Thumb ldr.w pc,[pc,#0]; ARM target.
    runtime.MemoryWrite32(create_site + 4, veneer);
    runtime.MemoryWrite32(destroy_site, 0xF000F8DFu);
    runtime.MemoryWrite32(destroy_site + 4, veneer + 20);
    runtime.InvalidateGuestCode(create_site, 8);
    runtime.InvalidateGuestCode(destroy_site, 8);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "TFTB SDL Window lifecycle applied");
    return true;
}

// Invoked only outside an active JIT on the established UI owner. Its state
// mutex is released before any guest/JNI/audio work; retirement can wait for
// the exact finite in-flight transition without freeing its Window/semaphores.
void ApplyPendingSdlWindowLifecycle(JNIEnv* env) {
    if (!env || env->ExceptionCheck() || !cache_bootstrap::Admitted() || g_loading_here ||
        !g_ready.load(std::memory_order_acquire) ||
        !g_host || g_host->IsJitRunning()) return;
    if (!TelltaleUiLifecycleOwner()) { NotifyTelltaleUiLifecycle(); return; }
    TftbSdlWindowLifecycle::Ticket ticket;
    {
        std::lock_guard<std::mutex> lock(g_presentation_mutex);
        ticket = g_sdl_window_lifecycle.Claim(g_presentation_foreground);
        if (ticket) g_sdl_transition_owner = std::this_thread::get_id();
    }
    if (!ticket) return;
    bool completed = false;
    struct Finish {
        TftbSdlWindowLifecycle::Ticket ticket;
        bool& completed;
        ~Finish() {
            {
                std::lock_guard<std::mutex> lock(g_presentation_mutex);
                if (g_sdl_window_lifecycle.Complete(ticket, completed))
                    g_sdl_transition_owner = {};
            }
            g_sdl_window_idle.notify_all();
        }
    } finish{ticket, completed};
    const uint32_t symbol = ticket.foreground ? g_symbols.nativeResume : g_symbols.nativePause;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    // Exact verified native bodies ignore env/class; no Java object is retained.
    g_host->RunFunction(symbol, {fake.EnvTableGuestAddr(), 0}, &completed);
}
