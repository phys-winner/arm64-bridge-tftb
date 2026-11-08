// Optional owner-only probe seam, adapted from the preserved v2 ARM32 helper.
// Its caller must use the exact-SDL SHA guard in tftb_sdl_primary_motion.inc.
// Include after g_host/g_ready and before kSdlMethods, in an explicit probe build.
// Register: {"nativeTouchProbeSnapshot", "()[J", (void*)Native_touchProbeSnapshot}
// Add the matching public static native method to SDLActivity.smali.
// No SDL mutator, native loader, JNI redirect, global reset or event hook is used.
#if defined(BRIDGE_TOUCH_PROBE_TEST) && BRIDGE_TOUCH_PROBE_TEST
struct TouchProbeApiGuard {
    const char* name;
    uint32_t rva;
    size_t count;
    uint8_t bytes[16];
};
#define ApiGuard TouchProbeApiGuard
#include "retained_v2_sdl_api_guards.h"
#undef ApiGuard

static jlongArray Native_touchProbeSnapshot(JNIEnv* env, jclass) {
    auto fail = [&](const char* message) -> jlongArray {
        if (!env->ExceptionCheck()) {
            jclass type = env->FindClass("java/lang/IllegalStateException");
            if (type) env->ThrowNew(type, message);
        }
        return nullptr;
    };
    if (env->ExceptionCheck()) return nullptr;
    if (!g_ready.load(std::memory_order_acquire) || !g_host || g_host->IsJitRunning())
        return fail("NEGATIVE_GUEST_NOT_READY_OR_QUERY_REENTRY");
    DynarmicHost& runtime = *g_host;
    const ElfLoader* sdl = runtime.FindModule("libSDL2.so");
    if (!sdl) return fail("NEGATIVE_GUEST_SDL_MODULE_ABSENT");
    const uint32_t base = sdl->GetBaseAddress();
    std::array<uint32_t, 12> resolved{};
    auto span = [&](uint32_t address, uint32_t size, uint32_t flags) {
        const uint64_t end = static_cast<uint64_t>(address) + size;
        if (!size || end > runtime.GetGuestMemorySize()) return false;
        for (const ElfSegment& segment : sdl->GetSegments()) {
            const uint64_t lower = static_cast<uint64_t>(base) + segment.vaddr;
            if (segment.flags == flags && address >= lower && end <= lower + segment.memsz)
                return true;
        }
        return false;
    };
    for (size_t i = 0; i < resolved.size(); ++i) {
        const auto& guard = api_guards[i];
        const ElfSymbol* symbol = sdl->GetExportedSymbol(guard.name);
        const uint64_t expected = static_cast<uint64_t>(base) + guard.rva;
        if (!symbol || symbol->type != STT_FUNC || symbol->value != expected ||
            !span(symbol->value & ~1u, static_cast<uint32_t>(guard.count), PF_R | PF_X))
            return fail("NEGATIVE_GUEST_SDL_API_ADDRESS_OR_SEGMENT");
        resolved[i] = symbol->value;
        for (size_t j = 0; j < guard.count; ++j)
            if (runtime.MemoryRead8((symbol->value & ~1u) + static_cast<uint32_t>(j)) != guard.bytes[j])
                return fail("NEGATIVE_GUEST_SDL_API_PREIMAGE");
    }
    for (size_t i = 0; i < 6; ++i) {
        const uint64_t slot = static_cast<uint64_t>(base) + dynapi_slots[i];
        if (slot > UINT32_MAX || !span(static_cast<uint32_t>(slot), 4, PF_R | PF_W) ||
            runtime.MemoryRead32(static_cast<uint32_t>(slot)) != resolved[i*2+1])
            return fail("NEGATIVE_GUEST_SDL_DYNAPI_TARGET");
    }
    const uint32_t scratch = runtime.GuestAlloc(16, 8);
    if (!scratch) return fail("NEGATIVE_QUERY_SCRATCH_ALLOCATION");
    struct Scratch {
        DynarmicHost& runtime; uint32_t address;
        ~Scratch() { runtime.GuestFree(address); }
    } allocation{runtime, scratch};
    bool completed = true;
    auto call = [&](size_t index, std::vector<uint32_t> args = {}) {
        if (!completed) return uint32_t{0};
        bool returned = false;
        const uint32_t value = runtime.RunFunction(resolved[index*2], args, &returned);
        completed = returned;
        return value;
    };
    for (uint32_t i = 0; i < 16; ++i) runtime.MemoryWrite8(scratch+i, 0);
    call(5, {scratch});
    if (!completed || runtime.MemoryRead8(scratch) != 2 || runtime.MemoryRead8(scratch+1) != 0 ||
        runtime.MemoryRead8(scratch+2) != 1)
        return fail("NEGATIVE_GUEST_SDL_VERSION_OR_CALL_RETURN");
    const int32_t devices = static_cast<int32_t>(call(1));
    if (!completed || devices < 0 || devices > 16)
        return fail("NEGATIVE_GUEST_TOUCH_DEVICE_BOUND_OR_CALL_RETURN");
    const uint32_t mouse = call(0, {scratch, scratch+4});
    if (!completed) return fail("NEGATIVE_GUEST_MOUSE_QUERY_CALL_RETURN");
    std::vector<jlong> packed{static_cast<jlong>(mouse),
                             static_cast<int32_t>(runtime.MemoryRead32(scratch)),
                             static_cast<int32_t>(runtime.MemoryRead32(scratch+4)), devices};
    packed.reserve(4 + 16*2 + 64*4);
    int total = 0;
    for (int d = 0; d < devices; ++d) {
        if (static_cast<int32_t>(call(1)) != devices || !completed)
            return fail("NEGATIVE_GUEST_TOUCH_DEVICE_CHANGED_DURING_QUERY");
        const uint32_t id_low = call(2, {static_cast<uint32_t>(d)});
        const uint32_t id_high = runtime.GetResultHigh();
        if (!completed) return fail("NEGATIVE_GUEST_TOUCH_DEVICE_CALL_RETURN");
        const uint64_t device = (static_cast<uint64_t>(id_high) << 32) | id_low;
        const int32_t fingers = static_cast<int32_t>(call(3, {id_low, id_high}));
        if (!completed || fingers < 0 || fingers > 64-total)
            return fail("NEGATIVE_GUEST_TOUCH_FINGER_BOUND_OR_CALL_RETURN");
        total += fingers;
        packed.push_back(static_cast<jlong>(device));
        packed.push_back(fingers);
        for (int f = 0; f < fingers; ++f) {
            const uint32_t address = call(4, {id_low, id_high, static_cast<uint32_t>(f)});
            if (!completed || !address || (address & 7u) ||
                static_cast<uint64_t>(address) + 24 > runtime.GetGuestMemorySize())
                return fail("NEGATIVE_GUEST_TOUCH_FINGER_POINTER_OR_CALL_RETURN");
            // Exact original ARM32 SDL_Finger ABI: id64, x/y/pressure float32, stride24.
            packed.push_back(static_cast<jlong>(runtime.MemoryRead64(address)));
            packed.push_back(runtime.MemoryRead32(address+8));
            packed.push_back(runtime.MemoryRead32(address+12));
            packed.push_back(runtime.MemoryRead32(address+16));
        }
        if (static_cast<int32_t>(call(3, {id_low, id_high})) != fingers || !completed)
            return fail("NEGATIVE_GUEST_TOUCH_FINGER_CHANGED_DURING_QUERY");
    }
    if (static_cast<int32_t>(call(1)) != devices || !completed)
        return fail("NEGATIVE_GUEST_TOUCH_DEVICE_CHANGED_AT_QUERY_END");
    jlongArray result = env->NewLongArray(static_cast<jsize>(packed.size()));
    if (result) env->SetLongArrayRegion(result, 0, static_cast<jsize>(packed.size()), packed.data());
    return result;
}
#endif
