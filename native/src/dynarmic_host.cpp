#include "dynarmic_host.h"
#include "elf_loader.h"
#include "game_port_config.h"
#include "thunk_manager.h"
#include "thunks_opensles.h"
#include <cstring>
#include <algorithm>
#include <elf.h>
#include <android/log.h>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define LOG_TAG "Arm32Bridge_Host"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

#define EXIT_TRAP_ARM   0x00000004
#define EXIT_TRAP_THUMB 0x00000008

namespace {
#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS
struct HeapTrace {
    uint64_t total_bytes = 0;
    uint64_t total_capacity = 0;
    uint64_t allocs = 0;
    uint64_t live_bytes = 0;
    uint64_t live_blocks = 0;
    bool first_large_logged = false;
};
std::unordered_map<uint32_t, HeapTrace> g_heap_trace;
#endif

std::string BaseSymbolName(const std::string& name) {
    const size_t version = name.find('@');
    return version == std::string::npos ? name : name.substr(0, version);
}

bool ExportMatchesImport(uint8_t import_type, uint8_t export_type) {
    if (import_type == STT_OBJECT) return export_type == STT_OBJECT;
    if (import_type == STT_FUNC) return export_type == STT_FUNC || export_type == STT_NOTYPE;
    return import_type == STT_NOTYPE &&
           (export_type == STT_FUNC || export_type == STT_OBJECT || export_type == STT_NOTYPE);
}
}

thread_local DynarmicHost::JitContext* DynarmicHost::s_active_context = nullptr;

DynarmicHost::DynarmicHost() = default;

DynarmicHost::~DynarmicHost() {
    ShutdownOpenSLES(this);
    ClearArm32TmZoneCache(this);
    {
        std::lock_guard<std::mutex> lock(m_jit_mutex);
        m_jit_contexts.clear();
    }
    if (m_memory) {
#if defined(_WIN32)
        VirtualFree(m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_memory_size);
#endif
        m_memory = nullptr;
    }
}

// Reserve guest memory. MAP_NORESERVE keeps the 4 GiB reservation virtual: untouched pages
// cost nothing and only written pages are ever committed.
static uint8_t* MapGuestMemory(size_t size) {
#if defined(_WIN32)
    return reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : reinterpret_cast<uint8_t*>(p);
#endif
}

bool DynarmicHost::Initialize() {
    // Mapping the whole 32-bit space lets the JIT emit a single `ldr Wt, [Xfastmem, Waddr, uxtw]`
    // per guest access instead of a call into MemoryRead*/MemoryWrite*.
    m_memory_size = GUEST_ADDRESS_SPACE;
    m_memory = MapGuestMemory(m_memory_size);

    bool fastmem = m_memory != nullptr;
    if (m_memory == nullptr) {
        LOGE("Could not reserve %zu bytes for the guest address space; "
             "falling back to %zu bytes without fastmem.", GUEST_ADDRESS_SPACE, GUEST_FALLBACK_SIZE);
        m_memory_size = GUEST_FALLBACK_SIZE;
        m_memory = MapGuestMemory(m_memory_size);
        if (!m_memory) {
            LOGE("Failed to allocate guest memory (%zu bytes)", m_memory_size);
            m_memory_size = 0;
            return false;
        }
    }

    if (!HeapSelfCheck()) return false;

    // ARM exit trap at 0x00000004: SVC 0 (0xEF000000)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM) = 0xEF000000;

    // Thumb exit trap at 0x00000008: SVC 0 (0xDF00, 0xDF00)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB) = 0xDF00DF00;

    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();

    // SDL, FMOD and the game execute on distinct host threads. Each host thread gets its
    // own Dynarmic CPU context while sharing guest memory and the exclusive monitor.
    m_fastmem = fastmem;
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(kMaxJitContexts);
    GetThreadContext();
    LOGI("Dynarmic Host initialized: %zu bytes guest space, fastmem %s",
         m_memory_size, fastmem ? "ON" : "OFF");
    return true;
}

DynarmicHost::JitContext& DynarmicHost::GetThreadContext() {
    const std::thread::id id = std::this_thread::get_id();
    std::lock_guard<std::mutex> lock(m_jit_mutex);
    auto it = m_jit_contexts.find(id);
    if (it != m_jit_contexts.end()) return *it->second;
    return *m_jit_contexts.emplace(id, CreateJitContext(0)).first->second;
}

std::unique_ptr<DynarmicHost::JitContext> DynarmicHost::CreateJitContext(uint32_t thread_errno) {
    Dynarmic::A32::UserConfig config;
    config.callbacks = this;
    config.global_monitor = m_monitor.get();
    config.processor_id = m_next_processor_id; // Includes the synchronous callback CPUs.
    config.arch_version = Dynarmic::A32::ArchVersion::v7;
    config.enable_cycle_counting = false;
    config.always_little_endian = true;
    config.define_unpredictable_behaviour = true;
    if (m_fastmem) config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);

    auto context = std::make_unique<JitContext>();
    context->owner = this;
    if (!m_monitor || config.processor_id >= kMaxJitContexts ||
        config.processor_id >= m_monitor->GetProcessorCount()) {
        LOGE("Guest CPU context capacity exceeded at slot %zu; execution refused", config.processor_id);
        return context;
    }
    ++m_next_processor_id;
    context->errno_addr = thread_errno ? thread_errno : kGuestTlsBase +
                          static_cast<uint32_t>(config.processor_id) * kGuestTlsStride;
    if (!thread_errno) MemoryWrite32(context->errno_addr, 0);
    context->jit = std::make_unique<Dynarmic::A32::Jit>(config);
    constexpr uint32_t kStackStride = 0x00200000;
    const uint32_t old_top = m_next_stack_top.fetch_sub(kStackStride);
    context->stack_top = old_top > 0x32200000 ? old_top : 0;
    if (!context->stack_top) LOGE("Out of guest thread stack space.");
    LOGI("Created guest CPU context with stack top 0x%08X processor=%zu", context->stack_top, config.processor_id);
    return context;
}

bool DynarmicHost::PrepareThreadContext() {
    JitContext& context = GetThreadContext();
    return context.jit && context.stack_top;
}

bool DynarmicHost::IsJitRunning() const {
    return s_active_context && s_active_context->running;
}

uint32_t DynarmicHost::CurrentGuestErrnoAddress() const {
    return s_active_context && s_active_context->running && s_active_context->owner == this
        ? s_active_context->errno_addr : 0;
}

void DynarmicHost::LogGuestExecution() const {
    // Temporary startup-stall trace: sample atomics, never a running JIT's registers.
    std::lock_guard<std::mutex> lock(m_jit_mutex);
    for (const auto& [id, context] : m_jit_contexts) {
        const uint64_t boundary = context->last_boundary.load(std::memory_order_relaxed);
        if (!boundary) continue;
        const uint32_t svc = static_cast<uint32_t>(boundary >> 32) & 0x7FFFFFFFu;
        LOGI("Guest execution: stack=0x%08X svc=%u thunk=0x%08X LR=0x%08X inHost=%u",
             context->stack_top, svc, svc ? 0x10000 + (svc - 1) * 8 : 0,
             static_cast<uint32_t>(boundary), static_cast<unsigned>(boundary >> 63));
    }
}

uint32_t DynarmicHost::GetResultHigh() const {
    std::lock_guard<std::mutex> lock(m_jit_mutex);
    auto it = m_jit_contexts.find(std::this_thread::get_id());
    return it != m_jit_contexts.end() ? it->second->result_hi : 0;
}

namespace {
constexpr uint32_t kModuleBase = 0x40000000;
constexpr uint32_t kModuleLimit = 0x50000000;
constexpr uint32_t kModuleAlignment = 0x10000;

bool InspectModuleSpan(const uint8_t* data, size_t size, uint32_t& min_vaddr, uint32_t& max_vaddr) {
    if (!data || size < sizeof(Elf32_Ehdr)) return false;
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_machine != EM_ARM || ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
        static_cast<uint64_t>(ehdr->e_phoff) + static_cast<uint64_t>(ehdr->e_phnum) * sizeof(Elf32_Phdr) > size) {
        return false;
    }
    const auto* phdrs = reinterpret_cast<const Elf32_Phdr*>(data + ehdr->e_phoff);
    min_vaddr = UINT32_MAX;
    max_vaddr = 0;
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const auto& ph = phdrs[i];
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_filesz > ph.p_memsz || static_cast<uint64_t>(ph.p_offset) + ph.p_filesz > size ||
            static_cast<uint64_t>(ph.p_vaddr) + ph.p_memsz > UINT32_MAX) return false;
        min_vaddr = std::min(min_vaddr, ph.p_vaddr);
        max_vaddr = std::max(max_vaddr, ph.p_vaddr + ph.p_memsz);
    }
    return min_vaddr != UINT32_MAX && max_vaddr > min_vaddr;
}
}

bool DynarmicHost::LoadModulesFromMemory(const std::vector<GuestModuleImage>& modules) {
    if (modules.empty() || !m_modules.empty()) {
        LOGE("LoadModulesFromMemory requires one non-empty initial module set.");
        return false;
    }

    uint32_t cursor = kModuleBase;
    for (const GuestModuleImage& image : modules) {
        uint32_t min_vaddr = 0, max_vaddr = 0;
        if (image.name.empty() || FindModule(image.name) || !InspectModuleSpan(image.data, image.size, min_vaddr, max_vaddr)) {
            LOGE("Invalid guest module: %s", image.name.c_str());
            return false;
        }
        const uint32_t base = (cursor + kModuleAlignment - 1) & ~(kModuleAlignment - 1);
        const uint64_t end = static_cast<uint64_t>(base) + max_vaddr;
        if (end > std::min(kModuleLimit, kHeapBase)) {
            LOGE("Guest modules exceed reserved module space at %s", image.name.c_str());
            return false;
        }

        auto loader = std::make_unique<ElfLoader>(m_memory, base, m_memory_size);
        if (!loader->LoadFromMemory(image.data, image.size)) {
            LOGE("Failed to load guest module: %s", image.name.c_str());
            return false;
        }
        for (const GuestModule& existing : m_modules) {
            if (loader->GetImageStart() < existing.loader->GetImageEnd() &&
                existing.loader->GetImageStart() < loader->GetImageEnd()) {
                LOGE("Guest module overlap: %s with %s", image.name.c_str(), existing.name.c_str());
                return false;
            }
        }
        LOGI("Guest module %s at 0x%08X..0x%08X", image.name.c_str(),
             loader->GetImageStart(), loader->GetImageEnd());
        cursor = static_cast<uint32_t>((end + kModuleAlignment - 1) & ~(static_cast<uint64_t>(kModuleAlignment) - 1));
        m_modules.push_back({image.name, std::move(loader)});
    }

    bool dependencies_ok = true;
    for (size_t i = 0; i < m_modules.size(); ++i) {
        const auto& module = m_modules[i];
        for (const auto& needed : module.loader->GetNeededLibraries()) {
            const ElfLoader* guest = FindModule(needed);
            LOGI("Dependency module='%s' needed='%s' provider=%s", module.name.c_str(), needed.c_str(),
                 guest ? "guest" : ThunkManager::SupportsLibrary(needed) ? "bridge" : "MISSING");
            if (!guest && !ThunkManager::SupportsLibrary(needed)) dependencies_ok = false;
            for (size_t j = i + 1; j < m_modules.size(); ++j) {
                if (m_modules[j].name == needed) {
                    LOGE("Guest initializer dependency order invalid: %s before %s", module.name.c_str(), needed.c_str());
                    dependencies_ok = false;
                }
            }
        }
    }

    uint32_t guest_ctype_object = 0;
    uint32_t guest_toupper_object = 0;
    uint32_t guest_tolower_object = 0;
    auto resolve_ctype_data = [this, &guest_ctype_object, &guest_toupper_object, &guest_tolower_object](const ElfImport& import) -> uint32_t {
        if (import.type != STT_OBJECT) return 0;
        const std::string base_name = BaseSymbolName(import.name);
        if (base_name == "_ctype_") {
            if (!guest_ctype_object) {
                const uint32_t table = GuestAlloc(384, 16);
                const uint32_t object = GuestAlloc(4, 4);
                if (!table || !object) return 0;
                for (uint32_t i = 0; i < 384; ++i) MemoryWrite8(table + i, 0);
                for (uint32_t c = 0; c < 256; ++c) {
                    const bool space = c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
                    const bool upper = c >= 'A' && c <= 'Z', lower = c >= 'a' && c <= 'z';
                    const bool digit = c >= '0' && c <= '9';
                    const bool hex = digit || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
                    const bool control = c < 32 || c == 127;
                    const bool punct = c >= 33 && c <= 126 && !upper && !lower && !digit;
                    const uint8_t flags = (upper ? 1 : 0) | (lower ? 2 : 0) | (digit ? 4 : 0) |
                        (space ? 8 : 0) | (punct ? 16 : 0) | (control ? 32 : 0) | (hex ? 64 : 0) |
                        (c == ' ' ? 128 : 0);
                    MemoryWrite8(table + 128 + c, flags);
                }
                MemoryWrite32(object, table + 127);
                guest_ctype_object = object;
                m_thunk_manager->RegisterDataSymbol("_ctype_", guest_ctype_object, {"libc.so"});
                LOGI("Provided guest _ctype_ object=0x%08X table=0x%08X", object, table + 127);
            }
            return guest_ctype_object;
        }
        if (base_name == "_toupper_tab_") {
            if (!guest_toupper_object) {
                const uint32_t table = GuestAlloc(384 * sizeof(uint16_t), 16);
                const uint32_t object = GuestAlloc(4, 4);
                if (!table || !object) return 0;
                for (uint32_t c = 0; c < 384; ++c) MemoryWrite16(table + c * 2, 0);
                for (uint32_t c = 0; c < 256; ++c) {
                    uint16_t upper = static_cast<uint16_t>(c);
                    if (c >= 'a' && c <= 'z') upper = static_cast<uint16_t>(c - ('a' - 'A'));
                    MemoryWrite16(table + (128 + c) * 2, upper);
                }
                MemoryWrite16(table + 127 * 2, 0xFFFF); // EOF
                MemoryWrite32(object, table + 127 * 2);
                guest_toupper_object = object;
                m_thunk_manager->RegisterDataSymbol("_toupper_tab_", guest_toupper_object, {"libc.so"});
                LOGI("Provided guest _toupper_tab_ object=0x%08X table=0x%08X", object, table + 127 * 2);
            }
            return guest_toupper_object;
        }
        if (base_name == "_tolower_tab_") {
            if (!guest_tolower_object) {
                const uint32_t table = GuestAlloc(384 * sizeof(uint16_t), 16);
                const uint32_t object = GuestAlloc(4, 4);
                if (!table || !object) return 0;
                for (uint32_t c = 0; c < 384; ++c) MemoryWrite16(table + c * 2, 0);
                for (uint32_t c = 0; c < 256; ++c) {
                    uint16_t lower = static_cast<uint16_t>(c);
                    if (c >= 'A' && c <= 'Z') lower = static_cast<uint16_t>(c + ('a' - 'A'));
                    MemoryWrite16(table + (128 + c) * 2, lower);
                }
                MemoryWrite16(table + 127 * 2, 0xFFFF); // EOF
                MemoryWrite32(object, table + 127 * 2);
                guest_tolower_object = object;
                m_thunk_manager->RegisterDataSymbol("_tolower_tab_", guest_tolower_object, {"libc.so"});
                LOGI("Provided guest _tolower_tab_ object=0x%08X table=0x%08X", object, table + 127 * 2);
            }
            return guest_tolower_object;
        }
        return 0;
    };
    LOGI("Guest resolver scope=global-load-group (supplied module order), exact versions, typed bridge fallback");
    auto resolver = [this, &resolve_ctype_data](const ElfImport& import) -> uint32_t {
        const std::string& name = import.name;
        if ((import.bind != STB_GLOBAL && import.bind != STB_WEAK) ||
            (import.visibility != STV_DEFAULT && import.visibility != STV_PROTECTED) ||
            (import.type != STT_OBJECT && import.type != STT_FUNC && import.type != STT_NOTYPE)) return 0;
        const uint8_t type = import.type == STT_NOTYPE && import.relocation_type == R_ARM_JUMP_SLOT
            ? STT_FUNC : import.type;
        for (const GuestModule& module : m_modules) {
            if (!import.version_library.empty() && module.name != import.version_library) continue;
            if (const ElfSymbol* symbol = module.loader->GetExportedSymbol(name, import.version)) {
                if (ExportMatchesImport(type, symbol->type)) return symbol->value;
                LOGI("Rejected incompatible guest candidate module='%s' name='%s' import-type=%u export-type=%u",
                     module.name.c_str(), name.c_str(), type, symbol->type);
            }
        }
        if (ThunkManager::SupportsVersion(import.version_library, import.version) &&
            (import.version_library.empty() || import.version_library == "libc.so")) resolve_ctype_data(import);
        if (type == STT_FUNC || type == STT_NOTYPE) {
            if (uint32_t provider = m_thunk_manager->FindProvider(name, ThunkManager::ProviderKind::Function,
                                                               import.version, import.version_library)) return provider;
        }
        if (type == STT_OBJECT || type == STT_NOTYPE) {
            if (uint32_t provider = m_thunk_manager->FindProvider(name, ThunkManager::ProviderKind::Object,
                                                               import.version, import.version_library)) return provider;
        }
        return 0; // Unresolved weak imports remain zero; the loader reports every strong failure.
    };
    bool relocated = dependencies_ok;
    for (GuestModule& module : m_modules) {
        if (!module.loader->Relocate(resolver)) {
            LOGE("Failed to relocate guest module: %s", module.name.c_str());
            relocated = false;
        }
    }
    if (!relocated) {
        LOGE("Guest load-group audit FAILED; no initializers may run.");
        return false;
    }
    for (const GuestModule& module : m_modules) {
        for (const ElfSegment& seg : module.loader->GetSegments()) {
            if ((seg.flags & PF_X) != 0) AddExecutableRange(module.loader->GetBaseAddress() + seg.vaddr, seg.memsz);
        }
    }
    m_load_group_ready = true;
    LOGI("Loaded and relocated %zu guest modules.", m_modules.size());
    return true;
}

bool DynarmicHost::RunModuleInitializers() {
    if (!m_load_group_ready) {
        LOGE("Initializers refused: guest load-group audit has not passed.");
        return false;
    }
    for (GuestModule& module : m_modules) {
        if (uint32_t init = module.loader->GetInitFunction()) {
            LOGI("Running DT_INIT for %s at 0x%08X", module.name.c_str(), init);
            bool completed = false;
            RunFunction(init, {}, &completed);
            if (!completed) return false;
        }
        LOGI("Running %zu init-array entries for %s", module.loader->GetInitArray().size(), module.name.c_str());
        for (uint32_t init : module.loader->GetInitArray()) {
            bool completed = false;
            RunFunction(init, {}, &completed);
            if (!completed) return false;
        }
    }
    return true;
}

ElfLoader* DynarmicHost::FindModule(const std::string& name) {
    for (GuestModule& module : m_modules) if (module.name == name) return module.loader.get();
    return nullptr;
}

const ElfLoader* DynarmicHost::FindModule(const std::string& name) const {
    for (const GuestModule& module : m_modules) if (module.name == name) return module.loader.get();
    return nullptr;
}

ElfLoader& DynarmicHost::GetElfLoader() {
    return *m_modules.back().loader;
}

uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    for (const GuestModule& module : m_modules) {
        if (uint32_t addr = module.loader->GetSymbolAddress(name)) return addr;
    }
    return 0;
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args, bool* completed) {
    if (completed) *completed = false;
    JitContext& context = GetThreadContext();
    if (!context.jit || !context.stack_top || !target_pc) return 0;
    if (context.running) {
        std::lock_guard<std::mutex> lock(m_deferred_mutex);
        m_deferred.emplace_back(target_pc, args);
        return 0;
    }
    return static_cast<uint32_t>(ExecuteFunction(context, target_pc, args, completed));
}

uint64_t DynarmicHost::ExecuteFunction(JitContext& context, uint32_t target_pc,
                                     const std::vector<uint32_t>& args, bool* completed) {
    if (completed) *completed = false;
    if (!context.jit || !context.stack_top || !target_pc || context.running) return 0;

    context.running = true;
    JitContext* previous = s_active_context;
    s_active_context = &context;
    struct JitRunningGuard {
        JitContext& context;
        JitContext*& active;
        JitContext* previous;
        ~JitRunningGuard() {
#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
            context.last_boundary.store(0, std::memory_order_relaxed);
#endif
            context.running = false;
            active = previous;
        }
    } running_guard{context, s_active_context, previous};

    Dynarmic::A32::Jit& jit = *context.jit;
    for (size_t i = 0; i < 13; ++i) jit.Regs()[i] = 0;
    for (size_t i = 0; i < args.size() && i < 4; ++i) jit.Regs()[i] = args[i];
    jit.Regs()[13] = context.stack_top;

    if (args.size() > 4) {
        const size_t extra_args = args.size() - 4;
        const uint32_t sp = context.stack_top - static_cast<uint32_t>((extra_args * 4 + 7) & ~size_t{7});
        jit.Regs()[13] = sp;
        for (size_t i = 0; i < extra_args; ++i) MemoryWrite32(sp + static_cast<uint32_t>(i * 4), args[4 + i]);
    }

    const bool is_thumb = (target_pc & 1) != 0;
    jit.Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;
    jit.Regs()[15] = target_pc & ~1u;
    jit.SetCpsr((jit.Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));
    jit.ClearHalt(Dynarmic::HaltReason::UserDefined1);

#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
    context.last_boundary.store(target_pc, std::memory_order_relaxed);
#endif
    Dynarmic::HaltReason hr;
    for (;;) {
        hr = jit.Run();
        if (!Dynarmic::Has(hr, Dynarmic::HaltReason::CacheInvalidation)) break;
        jit.ClearHalt(Dynarmic::HaltReason::CacheInvalidation);
        hr &= ~Dynarmic::HaltReason::CacheInvalidation;
        if (!!hr) break;
    }
    const uint32_t final_pc = jit.Regs()[15];
    context.result_hi = jit.Regs()[1];
    const bool normal_exit = final_pc == EXIT_TRAP_ARM || final_pc == (EXIT_TRAP_ARM + 4) ||
                             final_pc == (EXIT_TRAP_THUMB & ~1u) || final_pc == ((EXIT_TRAP_THUMB & ~1u) + 2);
    if (completed) *completed = normal_exit;
    if (!normal_exit) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
            "Halted with reason 0x%X: RunFunction(0x%08X) PC=0x%08X LR=0x%08X R0=0x%08X SP=0x%08X",
            static_cast<unsigned>(hr), target_pc, final_pc, jit.Regs()[14], jit.Regs()[0], jit.Regs()[13]);
    }
    const uint32_t stack_used = jit.Regs()[13] <= context.stack_top ? context.stack_top - jit.Regs()[13] : UINT32_MAX;
    if (!normal_exit || stack_used > 64) {
        LOGI("RunFunction(0x%08X) halt=0x%X PC=0x%08X LR=0x%08X R0=0x%08X SP=0x%08X top=0x%08X",
             target_pc, static_cast<unsigned>(hr), final_pc, jit.Regs()[14], jit.Regs()[0], jit.Regs()[13], context.stack_top);
    }
    return (static_cast<uint64_t>(context.result_hi) << 32) | jit.Regs()[0];
}

uint64_t DynarmicHost::RunSynchronousCallback(uint32_t pc, const std::vector<uint32_t>& args, bool* completed) {
    if (completed) *completed = false;
    if (s_active_context && s_active_context->running && s_active_context->owner != this) return 0;
    JitContext& primary = GetThreadContext();
    JitContext* context = &primary;
    if (primary.running) {
        // shortcut: one synchronous callback level; extend only for an observed deeper FMOD call.
        if (s_active_context != &primary) return 0;
        std::lock_guard<std::mutex> lock(m_jit_mutex);
        if (!primary.callback) primary.callback = CreateJitContext(primary.errno_addr);
        context = primary.callback.get();
    }
    if (!context->jit || !context->stack_top || context->running) return 0;
    if (context != &primary) context->jit->ClearExclusiveState();
    bool finished = false;
    const uint64_t result = ExecuteFunction(*context, pc, args, &finished);
    if (context != &primary) context->jit->ClearExclusiveState();
    if (completed) *completed = finished;
    return finished ? result : 0;
}

void DynarmicHost::InvalidateGuestCode(uint32_t addr, size_t size) {
    std::lock_guard<std::mutex> lock(m_jit_mutex);
    for (auto& [id, context] : m_jit_contexts) {
        if (context->jit) context->jit->InvalidateCacheRange(addr, size);
        if (context->callback && context->callback->jit) context->callback->jit->InvalidateCacheRange(addr, size);
    }
}

void DynarmicHost::DrainDeferred() {
    if (IsJitRunning()) return;
    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> batch;
    {
        std::lock_guard<std::mutex> lock(m_deferred_mutex);
        batch.swap(m_deferred);
    }
    for (auto& call : batch) RunFunction(call.first, call.second);
}

// -------------------------------------------------------------
// Guest heap
//
// Every block carries a 16-byte header immediately before its payload:
//   [-16] magic  [-12] block base  [-8] capacity  [-4] payload size
// The magic is what makes GuestFree safe: a pointer that does not carry it is
// not ours (module data, an interior pointer, a stack top, something the guest
// invented) and is ignored -- exactly as a no-op free ignored everything.
// Freeing clears the magic, so a double free is ignored too.
//
// A plain bump allocator with an empty GuestFree is the usual first version and
// it is a guaranteed leak: the guest does call free(), nobody listens. Measured
// on a Scaleform title that was ~1 MB/s during gameplay.
// -------------------------------------------------------------
namespace {
constexpr uint32_t kBlockMagic = 0x41524D31; // 'ARM1' - live block
constexpr uint32_t kFreedMagic = 0x41524D46; // 'ARMF' - already on a free list
constexpr uint32_t kHeaderSize = 16;
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    if (size == 0) size = 1;
    if (alignment < 8) alignment = 8;
    // Worst case layout: header, then up to a full alignment step of padding.
    uint64_t need = static_cast<uint64_t>(size) + alignment + kHeaderSize;

    uint32_t base = 0, capacity = 0;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(m_heap_mutex);
        if (need <= kMaxClassSize) {
            int cls = 0;
            while ((1u << (cls + kMinClassShift)) < need) ++cls;
            capacity = 1u << (cls + kMinClassShift);
            auto& fl = m_free_small[cls];
            if (!fl.empty()) { base = fl.back(); fl.pop_back(); recycled = true; }
        } else {
            capacity = static_cast<uint32_t>((need + 15) & ~15ull);
            auto it = m_free_huge.find(capacity);
            if (it != m_free_huge.end() && !it->second.empty()) {
                base = it->second.back();
                it->second.pop_back();
                recycled = true;
            }
        }
        if (!recycled) {
            // Stop before the heap walks into the guest stacks instead of silently
            // handing out addresses that overlap them.
            if (static_cast<uint64_t>(m_heap_current) + capacity > kHeapLimit) {
                const uint32_t pc = s_active_context && s_active_context->jit
                    ? s_active_context->jit->Regs()[15] : 0;
                const uint32_t sp = s_active_context && s_active_context->jit
                    ? s_active_context->jit->Regs()[13] : 0;
                const uint32_t lr = s_active_context && s_active_context->jit
                    ? s_active_context->jit->Regs()[14] : 0;
                const uint32_t thunk_pc = pc & ~7u;
                const char* thunk_name = "";
                if (m_thunk_manager) {
                    for (const auto& [name, address] : m_thunk_manager->GetThunkSymbolTable()) {
                        if (address == thunk_pc) { thunk_name = name.c_str(); break; }
                    }
                }
                LOGE("GuestAlloc out of guest heap: at 0x%08X, want %u, limit 0x%08X pc=0x%08X lr=0x%08X sp=0x%08X thunk='%s' live=%llu blocks=%llu allocs=%llu frees=%llu",
                     m_heap_current, capacity, kHeapLimit, pc, lr, sp, thunk_name,
                     static_cast<unsigned long long>(m_live_bytes),
                     static_cast<unsigned long long>(m_live_blocks),
                     static_cast<unsigned long long>(m_total_allocs),
                     static_cast<unsigned long long>(m_total_frees));
                return 0;
            }
            base = m_heap_current;
            m_heap_current = base + capacity;
        }
        m_live_bytes += size;
        ++m_live_blocks;
        ++m_total_allocs;
#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS
        const uint32_t trace_size = static_cast<uint32_t>(std::min<uint64_t>(size, UINT32_MAX));
        auto& trace = g_heap_trace[trace_size];
        trace.total_bytes += size;
        trace.total_capacity += capacity;
        ++trace.allocs;
        trace.live_bytes += size;
        ++trace.live_blocks;
        if (size >= 65536 && !trace.first_large_logged) {
            const uint32_t pc = s_active_context && s_active_context->jit ? s_active_context->jit->Regs()[15] : 0;
            const uint32_t lr = s_active_context && s_active_context->jit ? s_active_context->jit->Regs()[14] : 0;
            const uint32_t sp = s_active_context && s_active_context->jit ? s_active_context->jit->Regs()[13] : 0;
            const uint32_t stack_lr = sp <= UINT32_MAX - 32 && static_cast<uint64_t>(sp) + 32 <= m_memory_size
                ? MemoryRead32(sp + 28) : 0;
            const uint32_t stack_caller = sp <= UINT32_MAX - 48 && static_cast<uint64_t>(sp) + 48 <= m_memory_size
                ? MemoryRead32(sp + 44) : 0;
            const uint32_t stack_caller2 = sp <= UINT32_MAX - 64 && static_cast<uint64_t>(sp) + 64 <= m_memory_size
                ? MemoryRead32(sp + 60) : 0;
            LOGI("GuestHeap first-large requested=%u pc=0x%08X lr=0x%08X sp=0x%08X stackLR=0x%08X stackCaller=0x%08X stackCaller2=0x%08X",
                 trace_size, pc, lr, sp, stack_lr, stack_caller, stack_caller2);
            trace.first_large_logged = true;
        }
        if ((m_total_allocs & 4095u) == 0) {
            std::vector<std::pair<uint64_t, uint32_t>> top;
            top.reserve(g_heap_trace.size());
            for (const auto& [requested, stats] : g_heap_trace) {
                if (stats.live_bytes) top.emplace_back(stats.live_bytes, requested);
            }
            std::sort(top.rbegin(), top.rend());
            LOGI("GuestHeap milestone allocs=%llu frees=%llu live=%llu blocks=%llu cursor=0x%08X classes=%zu",
                 static_cast<unsigned long long>(m_total_allocs),
                 static_cast<unsigned long long>(m_total_frees),
                 static_cast<unsigned long long>(m_live_bytes),
                 static_cast<unsigned long long>(m_live_blocks), m_heap_current, top.size());
            for (size_t i = 0; i < std::min<size_t>(top.size(), 8); ++i) {
                const auto& stats = g_heap_trace[top[i].second];
                LOGI("GuestHeap live-size #%zu requested=%u bytes=%llu blocks=%llu total=%llu capacity=%llu",
                     i + 1, top[i].second,
                     static_cast<unsigned long long>(stats.live_bytes),
                     static_cast<unsigned long long>(stats.live_blocks),
                     static_cast<unsigned long long>(stats.total_bytes),
                     static_cast<unsigned long long>(stats.total_capacity));
            }
        }
#endif
    }

    uint32_t payload = static_cast<uint32_t>(
        (static_cast<uint64_t>(base) + kHeaderSize + alignment - 1) & ~(static_cast<uint64_t>(alignment) - 1));
    if (recycled && static_cast<uint64_t>(payload) + size <= m_memory_size) {
        // Fresh arena memory has always been zero, and guest code that leaned on
        // that would break in confusing ways the first time it saw a recycled
        // block. Cheap insurance at the observed churn.
        memset(m_memory + payload, 0, size);
    }
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, static_cast<uint32_t>(size));
    return payload;
}

void DynarmicHost::GuestFree(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return;         // cannot be one of ours
    if (MemoryRead32(addr - 16) != kBlockMagic) {
#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS
        static std::atomic<uint32_t> ignored{0};
        const uint32_t count = ++ignored;
        if (count <= 64) {
            LOGI("GuestFree ignored addr=0x%08X magic=0x%08X prev=0x%08X size=0x%08X",
                  addr, MemoryRead32(addr - 16), MemoryRead32(addr - 4), MemoryRead32(addr - 8));
        }
#endif
        return; // foreign pointer, or already freed
    }
    uint32_t base = MemoryRead32(addr - 12);
    uint32_t capacity = MemoryRead32(addr - 8);
    const uint32_t payload_size = MemoryRead32(addr - 4);
    MemoryWrite32(addr - 16, kFreedMagic);
#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    static std::atomic<uint32_t> freed{0};
    const uint32_t count = ++freed;
    if (count <= 64) LOGI("GuestFree released addr=0x%08X base=0x%08X capacity=%u", addr, base, capacity);
#endif

    std::lock_guard<std::mutex> lk(m_heap_mutex);
    m_live_bytes -= std::min<uint64_t>(m_live_bytes, payload_size);
    if (m_live_blocks) --m_live_blocks;
    ++m_total_frees;
#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    auto trace_it = g_heap_trace.find(payload_size);
    if (trace_it != g_heap_trace.end()) {
        trace_it->second.live_bytes -= std::min<uint64_t>(trace_it->second.live_bytes, payload_size);
        if (trace_it->second.live_blocks) --trace_it->second.live_blocks;
    }
#endif
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else {
        m_free_huge[capacity].push_back(base);
    }
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return 0;
    if (MemoryRead32(addr - 16) != kBlockMagic) return 0;
    return MemoryRead32(addr - 4);
}

// Address space for the mmap thunk. Separate from the malloc heap on purpose -- see the
// declaration. No free list: a file mapping is handed to the engine for the life of the
// process, and the mmap thunk reuses an identical (file, offset, length) mapping instead of
// making a second one, which is what keeps a re-opened expansion file from costing the arena
// twice.
uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint32_t aligned = (m_map_current + static_cast<uint32_t>(alignment - 1)) &
                             ~static_cast<uint32_t>(alignment - 1);
    if (static_cast<uint64_t>(aligned) + size > kMapLimit) {
        LOGE("GuestAllocMapping out of mapping space: at 0x%08X, want %zu", aligned, size);
        return 0;
    }
    m_map_current = aligned + static_cast<uint32_t>(size);
    return aligned;
}

// Runs once at startup. A silently wrong allocator corrupts the guest far away
// from the cause, so pay a few microseconds to fail loudly at the source.
bool DynarmicHost::HeapSelfCheck() {
#define HEAP_CHECK(cond) do { if (!(cond)) { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "HeapSelfCheck FAILED: %s", #cond); ok = false; } } while (0)
    bool ok = true;

    uint32_t a = GuestAlloc(100, 8);
    uint32_t b = GuestAlloc(100, 8);
    HEAP_CHECK(a != 0 && b != 0 && a != b);
    HEAP_CHECK((a & 7) == 0 && (b & 7) == 0);
    HEAP_CHECK(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize); // no overlap
    HEAP_CHECK(GuestAllocSize(a) == 100);

    uint32_t aligned = GuestAlloc(64, 0x1000);
    HEAP_CHECK(aligned != 0 && (aligned & 0xFFF) == 0);

    // Freed blocks come back, and the payload is handed over zeroed.
    MemoryWrite32(a, 0xDEADBEEF);
    GuestFree(a);
    HEAP_CHECK(GuestAllocSize(a) == 0);        // magic cleared
    GuestFree(a);                              // double free: must be a no-op
    uint32_t reused = GuestAlloc(100, 8);
    HEAP_CHECK(reused == a);
    HEAP_CHECK(MemoryRead32(reused) == 0);

    // Pointers we did not hand out must be ignored, not recycled.
    GuestFree(0x40000000);
    GuestFree(kHeapBase + 4);
    GuestFree(b + 8);                          // interior pointer
    HEAP_CHECK(GuestAllocSize(b) == 100);      // b survived all of that

    // Large blocks recycle by exact capacity instead of rounding to a power of two.
    uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big != 0 && (big & 0xFFFF) == 0);
    GuestFree(big);
    uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big2 == big);
    GuestFree(big2);

    GuestFree(b);
    GuestFree(reused);
    GuestFree(aligned);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, LOG_TAG,
                       "HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef HEAP_CHECK
    return ok;
}

void DynarmicHost::AddExecutableRange(uint32_t base, uint32_t size) {
    if (!size) return;
    m_code_ranges.emplace_back(base, base + size);
    LOGI("Executable range: 0x%08X..0x%08X", base, base + size);
}

bool DynarmicHost::IsExecutableAddress(uint32_t address) const {
    if (address >= 0x00010000 && address < 0x00020000) return true;
    for (const auto& range : m_code_ranges) {
        if (address >= range.first && address < range.second) return true;
    }
    return false;
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t vaddr) {
    // Runaway PC containment. The arena is zero-filled and zeros decode as a valid
    // `andeq r0,r0,r0`, so a jump through a garbage pointer makes the JIT translate
    // a fresh block every 0x8000 bytes forever: RSS runs away and the LMK kills the
    // process, a symptom that reads exactly like a memory leak. Feed the JIT a
    // fatal diagnostic instead: execution through an unregistered range must stop.
    if (!m_modules.empty() && vaddr >= 0x00010000 && !IsExecutableAddress(vaddr)) {
        // Only this calling thread owns the active JIT. Dump it at the failed
        // translation boundary; never sample another running CPU or relax RX.
        if (s_active_context && s_active_context->owner == this && s_active_context->jit) {
            const auto regs = s_active_context->jit->Regs();
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                "Guest fetch CPU: PC=%08X LR=%08X SP=%08X CPSR=%08X top=%08X",
                regs[15], regs[14], regs[13], s_active_context->jit->Cpsr(), s_active_context->stack_top);
            for (unsigned i = 0; i < 13; i += 4) {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                    "Guest fetch regs r%u: %08X %08X %08X %08X",
                    i, regs[i], regs[i + 1], regs[i + 2], regs[i + 3]);
            }
            for (unsigned i = 0; i < 16; ++i) {
                const uint64_t address = static_cast<uint64_t>(regs[13]) + i * 4;
                if (address + 4 <= m_memory_size) {
                    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Guest fetch stack %08X=%08X",
                        static_cast<uint32_t>(address), MemoryRead32(static_cast<uint32_t>(address)));
                }
            }
        }
        for (unsigned i = 0; i < 4; ++i) {
            const uint64_t address = static_cast<uint64_t>(vaddr) + i * 4;
            if (address + 4 <= m_memory_size) {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Guest fetch data %08X=%08X",
                    static_cast<uint32_t>(address), MemoryRead32(static_cast<uint32_t>(address)));
            }
        }
        __android_log_assert(nullptr, LOG_TAG, "[RUNAWAY] code fetch 0x%08X", vaddr);
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) {
        return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    }
    return std::nullopt;
}

std::uint8_t DynarmicHost::MemoryRead8(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) return m_memory[vaddr];
    return 0;
}

std::uint16_t DynarmicHost::MemoryRead16(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) return *reinterpret_cast<uint16_t*>(m_memory + vaddr);
    return 0;
}

std::uint32_t DynarmicHost::MemoryRead32(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    return 0;
}

std::uint64_t DynarmicHost::MemoryRead64(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) return *reinterpret_cast<uint64_t*>(m_memory + vaddr);
    return 0;
}

void DynarmicHost::MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) m_memory[vaddr] = value;
}

void DynarmicHost::MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) *reinterpret_cast<uint16_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) *reinterpret_cast<uint32_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) *reinterpret_cast<uint64_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) {
    __android_log_assert(nullptr, LOG_TAG, "Interpreter Fallback at 0x%08X (%zu instructions)", pc, num_instructions);
}

void DynarmicHost::CallSVC(std::uint32_t swi) {
    if (!s_active_context) return;
    Dynarmic::A32::Jit& jit = *s_active_context->jit;
    if (swi == 0 || jit.Regs()[15] <= 0x40) {
        jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        return;
    }
#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
    const uint64_t boundary = (static_cast<uint64_t>(swi) << 32) | jit.Regs()[14];
    s_active_context->last_boundary.store(boundary | (1ull << 63), std::memory_order_relaxed);
#endif
    m_thunk_manager->DispatchThunk(swi, jit);
#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
    s_active_context->last_boundary.store(boundary, std::memory_order_relaxed);
#endif
}

void DynarmicHost::ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) {
    __android_log_assert(nullptr, LOG_TAG, "Exception at PC: 0x%08X (type %d)", pc, static_cast<int>(exception));
}

void DynarmicHost::AddTicks(std::uint64_t ticks) {
    if (m_ticks_remaining > ticks) m_ticks_remaining -= ticks;
    else m_ticks_remaining = 0;
}

std::uint64_t DynarmicHost::GetTicksRemaining() {
    return m_ticks_remaining;
}

// STREX: compare-and-set against guest memory. The ExclusiveMonitor already holds its lock
// around this and has verified the reservation, so a plain compare/store is sufficient.
template<typename T>
static bool GuestCompareAndSwap(uint8_t* mem, size_t mem_size, uint32_t vaddr, T value, T expected) {
    if (static_cast<uint64_t>(vaddr) + sizeof(T) > mem_size) return false;
    T* p = reinterpret_cast<T*>(mem + vaddr);
    if (*p != expected) return false;
    *p = value;
    return true;
}

bool DynarmicHost::MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}
