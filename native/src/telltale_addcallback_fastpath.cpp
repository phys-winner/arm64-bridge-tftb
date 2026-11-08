#include "telltale_addcallback_fastpath.h"

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "game_port_config.h"
#include "thunk_manager.h"
#include "thunk_types.h"

#include <android/log.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#define LOG_TAG "Arm32Bridge_PropertySet"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace {

constexpr char kAddCallbackSymbol[] =
    "_ZN11PropertySet15AddCallbackBaseERK6SymbolP12FunctionBase";
constexpr uint32_t kAddCallbackRva = 0x00A8BC08u;
constexpr char kCallbacksBaseAddSymbol[] =
    "_ZN13CallbacksBase15AddCallbackBaseEP12FunctionBase";
constexpr uint32_t kCallbacksBaseAddRva = 0x00C460A0u;
constexpr char kKeyCallbacksConstructorSymbol[] =
    "_ZN11PropertySet12KeyCallbacksC2Ev";
constexpr uint32_t kKeyCallbacksConstructorRva = 0x00A8AEECu;
constexpr char kKeyCallbacksDestructorSymbol[] =
    "_ZN11PropertySet12KeyCallbacksD2Ev";
constexpr uint32_t kKeyCallbacksDestructorRva = 0x00A8AF1Cu;

// libGameEngine.so from the bundled Game of Thrones 1.56 APK. Fingerprint the complete
// 224-byte ARM function, including its cleanup landing pad and literal pool.
// This makes every structure offset and every continuation used below
// fail-closed if a different engine build is loaded.
constexpr std::array<uint32_t, 56> kAddCallbackFingerprint = {
    0xE92D41F0u, 0xE1A05000u, 0xE5904010u, 0xE1A06001u,
    0xE1A07002u, 0xE3540000u, 0x0A00000Cu, 0xE1C100D0u,
    0xE1C420D8u, 0xE1530001u, 0x01520000u, 0x1A000004u,
    0xEA00001Fu, 0xE1C420D8u, 0xE1530001u, 0x01520000u,
    0x0A00001Bu, 0xE5944004u, 0xE3540000u, 0x1AFFFFF8u,
    0xE59F8080u, 0xE3A01018u, 0xE59F207Cu, 0xE79F8008u,
    0xE08F2002u, 0xE1A00008u, 0xEB071275u, 0xE1A04000u,
    0xEBFFFC9Bu, 0xE5953014u, 0xE3A02000u, 0xE5951010u,
    0xE2840008u, 0xE3530000u, 0x15834004u, 0xE1510002u,
    0xE5843000u, 0xE1A01006u, 0xE595300Cu, 0xE5842004u,
    0xE2833001u, 0xE5854014u, 0x05854010u, 0xE585300Cu,
    0xEB070B3Eu, 0xE2840014u, 0xE1A01007u, 0xEB06E8F5u,
    0xE3A00001u, 0xE8BD81F0u, 0xE1A01004u, 0xE1A00008u,
    0xEB0712A8u, 0xFA11C294u, 0x005F0754u, 0x0053413Cu,
};

// The native hit path reproduces this callee directly, so its entire body is
// part of the compatibility contract too. The caller fingerprint alone cannot
// prove that a vendor-patched engine retained the circular-list semantics.
constexpr std::array<uint32_t, 9> kCallbacksBaseAddFingerprint = {
    0xE5903000u, 0xE3530000u, 0x05811004u, 0x15932004u, 0x15812004u,
    0x15831004u, 0xE5801000u, 0xE3A00001u, 0xE12FFF1Eu,
};

// The O(1) index relies on the engine's append-only KeyCallbacks lifecycle:
// AddCallbackBase constructs a node once, and every real node removal invokes
// this destructor before the pool can reuse its address.  Fingerprint both
// lifecycle functions and hook the destructor to invalidate cached generations.
constexpr std::array<uint32_t, 12> kKeyCallbacksConstructorFingerprint = {
    0xE92D4038u, 0xE1A04000u, 0xE3A05000u, 0xE2800008u,
    0xE5845000u, 0xE5845004u, 0xEB070E94u, 0xE5C45010u,
    0xE2840014u, 0xEB06EAF6u, 0xE1A00004u, 0xE8BD8038u,
};
constexpr std::array<uint32_t, 9> kKeyCallbacksDestructorFingerprint = {
    0xE92D4038u, 0xE2805014u, 0xE1A04000u, 0xE1A00005u,
    0xEB06EAFEu, 0xE1A00005u, 0xEB06EB11u, 0xE1A00004u,
    0xE8BD8038u,
};

constexpr uint32_t kPropertySetCountOffset = 0x0Cu;
constexpr uint32_t kPropertySetHeadOffset = 0x10u;
constexpr uint32_t kPropertySetTailOffset = 0x14u;
constexpr uint32_t kKeyCallbacksPreviousOffset = 0x00u;
constexpr uint32_t kKeyCallbacksNextOffset = 0x04u;
constexpr uint32_t kKeyCallbacksKeyOffset = 0x08u;
constexpr uint32_t kKeyCallbacksCallbacksOffset = 0x14u;
constexpr uint32_t kFunctionNextOffset = 0x04u;
constexpr size_t kPropertySetRequiredSize = 0x18u;
constexpr size_t kKeyCallbacksRequiredSize = 0x18u;
constexpr size_t kFunctionRequiredSize = 0x08u;
constexpr uint32_t kMaxCallbackNodes = 65536u;
constexpr size_t kMaxIndexedPropertySets = 8192u;
// Bound aggregate cache growth as well as each individual guest list.  The
// index stores both a compact snapshot and an unordered-map node per callback,
// so a property-set count alone is not a meaningful host-memory limit.
constexpr size_t kMaxIndexedCallbackNodes = 262144u;

bool IsAlignedWord(uint32_t address) {
    return (address & (alignof(uint32_t) - 1u)) == 0;
}

// The SVC handler runs only after every address below has passed a guest-range
// and alignment check.  Accessing the arena directly avoids an out-of-line
// virtual UserCallbacks call for every node in this deliberately hot loop.
// memcpy keeps the access alias-safe and Clang lowers the fixed four-byte copy
// to one AArch64 load/store in optimized builds.
inline uint32_t LoadGuestU32(const uint8_t* memory, uint32_t address) {
    uint32_t value;
    std::memcpy(&value, memory + address, sizeof(value));
    return value;
}

inline void StoreGuestU32(uint8_t* memory, uint32_t address, uint32_t value) {
    std::memcpy(memory + address, &value, sizeof(value));
}

enum class AddCallbackResult {
    Hit,
    Miss,
    Fallback,
};

void RecordAddCallbackDiagnostic(AddCallbackResult result, uint32_t visited) {
#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS
    static std::atomic<uint32_t> calls{0};
    static std::atomic<uint32_t> hits{0};
    static std::atomic<uint32_t> misses{0};
    static std::atomic<uint32_t> fallbacks{0};
    static std::atomic<uint64_t> nodes_visited{0};
    static std::atomic<uint32_t> max_nodes_visited{0};

    if (result == AddCallbackResult::Hit) {
        hits.fetch_add(1, std::memory_order_relaxed);
    } else if (result == AddCallbackResult::Miss) {
        misses.fetch_add(1, std::memory_order_relaxed);
    } else {
        fallbacks.fetch_add(1, std::memory_order_relaxed);
    }
    nodes_visited.fetch_add(visited, std::memory_order_relaxed);
    uint32_t old_max = max_nodes_visited.load(std::memory_order_relaxed);
    while (old_max < visited &&
           !max_nodes_visited.compare_exchange_weak(
               old_max, visited, std::memory_order_relaxed)) {}

    const uint32_t call = calls.fetch_add(1, std::memory_order_relaxed) + 1u;
    if ((call & (call - 1u)) == 0) {
        LOGI("AddCallbackBase calls=%u hit=%u miss=%u fallback=%u "
             "visited=%llu max=%u", call,
             hits.load(std::memory_order_relaxed),
             misses.load(std::memory_order_relaxed),
             fallbacks.load(std::memory_order_relaxed),
             static_cast<unsigned long long>(
                 nodes_visited.load(std::memory_order_relaxed)),
             max_nodes_visited.load(std::memory_order_relaxed));
    }
#else
    (void)result;
    (void)visited;
#endif
}

struct CallbackNodeSnapshot {
    uint32_t address = 0;
    uint64_t key = 0;
};

struct CallbackIndex {
    uint32_t count = 0;
    uint32_t head = 0;
    uint32_t tail = 0;
    size_t next_probe = 0;
    std::vector<CallbackNodeSnapshot> nodes;
    // The value is an index into nodes, not a guest pointer.  This lets a hit
    // validate both neighbouring links before mutating the callback ring.
    std::unordered_map<uint64_t, uint32_t> positions;
};

struct CallbackIndexState {
    std::mutex mutex;
    std::unordered_map<uint32_t, CallbackIndex> property_sets;
    size_t indexed_nodes = 0;
    std::atomic<bool> disabled{false};
};

void ClearCallbackIndexes(CallbackIndexState& state) {
    state.property_sets.clear();
    state.indexed_nodes = 0;
}

void EraseCallbackIndex(CallbackIndexState& state, uint32_t property_set) {
    const auto found = state.property_sets.find(property_set);
    if (found == state.property_sets.end()) return;
    const size_t removed = found->second.nodes.size();
    state.indexed_nodes = removed <= state.indexed_nodes
                              ? state.indexed_nodes - removed
                              : 0;
    state.property_sets.erase(found);
}

bool ReadCallbackNode(const uint8_t* memory, size_t memory_size,
                      uint32_t node, uint32_t& previous, uint32_t& next,
                      uint64_t& key) {
    if (!node || !IsAlignedWord(node) ||
        !GuestRangeValid(memory_size, node, kKeyCallbacksRequiredSize)) {
        return false;
    }
    previous = LoadGuestU32(memory, node + kKeyCallbacksPreviousOffset);
    next = LoadGuestU32(memory, node + kKeyCallbacksNextOffset);
    key = static_cast<uint64_t>(
              LoadGuestU32(memory, node + kKeyCallbacksKeyOffset)) |
          (static_cast<uint64_t>(LoadGuestU32(
               memory, node + kKeyCallbacksKeyOffset + sizeof(uint32_t)))
           << 32u);
    return true;
}

bool BuildCallbackIndex(const uint8_t* memory, size_t memory_size,
                        uint32_t count, uint32_t head, uint32_t tail,
                        CallbackIndex& result, uint32_t& visited) {
    visited = 0;
    if (count > kMaxCallbackNodes) return false;
    if (count == 0) {
        if (head || tail) return false;
        result = CallbackIndex{};
        return true;
    }
    if (!head || !tail) return false;

    CallbackIndex rebuilt;
    rebuilt.count = count;
    rebuilt.head = head;
    rebuilt.tail = tail;
    rebuilt.nodes.reserve(count);
    rebuilt.positions.reserve(count);

    uint32_t node = head;
    uint32_t expected_previous = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t previous = 0;
        uint32_t next = 0;
        uint64_t key = 0;
        if (!ReadCallbackNode(memory, memory_size, node, previous, next, key) ||
            previous != expected_previous) {
            return false;
        }
        ++visited;
        if (!rebuilt.positions.emplace(key, index).second) {
            // AddCallbackBase returns the first matching key, so duplicate keys
            // are outside the invariant required by an O(1) representation.
            return false;
        }
        rebuilt.nodes.push_back({node, key});

        if (index + 1u == count) {
            if (node != tail || next != 0) return false;
        } else if (!next) {
            return false;
        }
        expected_previous = node;
        node = next;
    }
    if (node != 0) return false;
    result = std::move(rebuilt);
    return true;
}

bool ValidateCallbackIndexNode(const uint8_t* memory, size_t memory_size,
                               const CallbackIndex& index, size_t position,
                               bool allow_tail_append = false,
                               uint32_t appended_tail = 0) {
    if (position >= index.nodes.size()) return false;
    const CallbackNodeSnapshot& snapshot = index.nodes[position];
    uint32_t previous = 0;
    uint32_t next = 0;
    uint64_t key = 0;
    if (!ReadCallbackNode(memory, memory_size, snapshot.address,
                          previous, next, key) || key != snapshot.key) {
        return false;
    }
    const uint32_t expected_previous =
        position ? index.nodes[position - 1u].address : 0u;
    uint32_t expected_next = position + 1u < index.nodes.size()
                                 ? index.nodes[position + 1u].address
                                 : 0u;
    if (allow_tail_append && position + 1u == index.nodes.size()) {
        expected_next = appended_tail;
    }
    if (previous != expected_previous || next != expected_next) return false;
    const auto found = index.positions.find(key);
    return found != index.positions.end() && found->second == position;
}

bool ValidateStableCallbackIndex(const uint8_t* memory, size_t memory_size,
                                 CallbackIndex& index) {
    if (index.nodes.size() != index.count ||
        index.positions.size() != index.count) {
        return false;
    }
    if (!index.count) return index.head == 0 && index.tail == 0;
    if (index.nodes.front().address != index.head ||
        index.nodes.back().address != index.tail) {
        return false;
    }

    // Validate every small list and six witnesses from a large one. Legitimate
    // removals clear the cache through the fingerprinted destructor hook;
    // rotating witnesses additionally catch many forms of guest corruption
    // without reinstating O(n) on every lookup.
    const size_t count = index.nodes.size();
    const size_t checks = count <= 8u ? count : 6u;
    for (size_t check = 0; check < checks; ++check) {
        size_t position;
        if (count <= 8u) {
            position = check;
        } else if (check == 0) {
            position = 0;
        } else if (check == 1) {
            position = count - 1u;
        } else {
            position = (index.next_probe + (check - 2u) * (count / 4u + 1u)) % count;
        }
        if (!ValidateCallbackIndexNode(memory, memory_size, index, position)) {
            return false;
        }
    }
    // Advance by one so every interior position is eventually sampled for
    // every list length.  A larger fixed stride can share a divisor with the
    // count and leave some nodes permanently unchecked.
    index.next_probe = count ? (index.next_probe + 1u) % count : 0u;
    return true;
}

bool IncorporateSingleAppend(const uint8_t* memory, size_t memory_size,
                             uint32_t count, uint32_t head, uint32_t tail,
                             CallbackIndex& index) {
    if (count != index.count + 1u || count > kMaxCallbackNodes || !tail) {
        return false;
    }

    uint32_t previous = 0;
    uint32_t next = 0;
    uint64_t key = 0;
    if (!ReadCallbackNode(memory, memory_size, tail, previous, next, key) || next) {
        return false;
    }

    if (index.count == 0) {
        if (head != tail || previous != 0 || index.head || index.tail ||
            !index.nodes.empty() || !index.positions.empty()) {
            return false;
        }
    } else {
        if (head != index.head || tail == index.tail || previous != index.tail ||
            index.nodes.size() != index.count ||
            index.positions.size() != index.count ||
            !ValidateCallbackIndexNode(memory, memory_size, index,
                                       index.nodes.size() - 1u, true, tail)) {
            return false;
        }
        // Check four rotating non-tail witnesses before accepting an O(1)
        // append transition as the complete new list generation.
        const size_t witness_count = index.nodes.size() - 1u;
        const size_t checks = std::min<size_t>(witness_count, 4u);
        for (size_t i = 0; i < checks; ++i) {
            const size_t position =
                (index.next_probe + i * (witness_count / 4u + 1u)) % witness_count;
            if (!ValidateCallbackIndexNode(memory, memory_size, index, position)) {
                return false;
            }
        }
    }
    if (index.positions.find(key) != index.positions.end()) return false;

    index.positions.emplace(key, index.count);
    index.nodes.push_back({tail, key});
    index.count = count;
    index.head = head;
    index.tail = tail;
    index.next_probe = count ? (index.next_probe + 1u) % count : 0u;
    return true;
}

enum class IndexedLookupResult {
    Hit,
    Miss,
    Invalid,
};

IndexedLookupResult LookupIndexedCallbackNode(
    CallbackIndexState& state, const uint8_t* memory, size_t memory_size,
    uint32_t property_set, uint64_t wanted, uint32_t& result_node,
    uint32_t& visited) {
    if (state.disabled.load(std::memory_order_acquire)) {
        return IndexedLookupResult::Invalid;
    }
    const uint32_t count =
        LoadGuestU32(memory, property_set + kPropertySetCountOffset);
    const uint32_t head =
        LoadGuestU32(memory, property_set + kPropertySetHeadOffset);
    const uint32_t tail =
        LoadGuestU32(memory, property_set + kPropertySetTailOffset);

    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.disabled.load(std::memory_order_relaxed)) {
        return IndexedLookupResult::Invalid;
    }
    auto existing = state.property_sets.find(property_set);
    if (existing == state.property_sets.end() &&
        state.property_sets.size() >= kMaxIndexedPropertySets) {
        // Bounded memory is more important than retaining cold indexes.  A
        // later call simply rebuilds from authoritative guest links.
        ClearCallbackIndexes(state);
    }

    auto rebuild = [&]() -> CallbackIndex* {
        // Drop the old generation before allocating its replacement, and
        // enforce the aggregate budget before vector::reserve/map::reserve.
        EraseCallbackIndex(state, property_set);
        if (count > kMaxIndexedCallbackNodes) return nullptr;
        if (state.indexed_nodes > kMaxIndexedCallbackNodes - count) {
            ClearCallbackIndexes(state);
        }

        CallbackIndex fresh;
        uint32_t build_visited = 0;
        if (!BuildCallbackIndex(memory, memory_size, count, head, tail,
                                fresh, build_visited)) {
            return nullptr;
        }
        visited += build_visited;
        auto [position, inserted] =
            state.property_sets.emplace(property_set, std::move(fresh));
        if (!inserted) return nullptr;
        state.indexed_nodes += position->second.nodes.size();
        return &position->second;
    };

    existing = state.property_sets.find(property_set);
    CallbackIndex* index = nullptr;
    if (existing == state.property_sets.end()) {
        index = rebuild();
    } else {
        index = &existing->second;
        const bool stable_metadata = index->count == count &&
                                     index->head == head &&
                                     index->tail == tail;
        if (stable_metadata) {
            if (!ValidateStableCallbackIndex(memory, memory_size, *index)) {
                index = rebuild();
            }
        } else {
            // Rebuilding at the budget boundary keeps accounting exact: the
            // in-place append would otherwise grow nodes before total_nodes.
            if (state.indexed_nodes >= kMaxIndexedCallbackNodes ||
                !IncorporateSingleAppend(memory, memory_size, count, head,
                                         tail, *index)) {
                index = rebuild();
            } else {
                ++state.indexed_nodes;
            }
        }
    }
    if (!index) return IndexedLookupResult::Invalid;

    auto found = index->positions.find(wanted);
    if (found == index->positions.end()) return IndexedLookupResult::Miss;
    if (!ValidateCallbackIndexNode(memory, memory_size, *index, found->second)) {
        index = rebuild();
        if (!index) return IndexedLookupResult::Invalid;
        found = index->positions.find(wanted);
        if (found == index->positions.end()) return IndexedLookupResult::Miss;
        if (!ValidateCallbackIndexNode(memory, memory_size, *index, found->second)) {
            EraseCallbackIndex(state, property_set);
            return IndexedLookupResult::Invalid;
        }
    }
    result_node = index->nodes[found->second].address;
    return IndexedLookupResult::Hit;
}

template <size_t N>
bool MatchesFingerprint(DynarmicHost& host, uint32_t target,
                        const std::array<uint32_t, N>& fingerprint,
                        const char* function_name) {
    for (size_t i = 0; i < fingerprint.size(); ++i) {
        const uint32_t address =
            target + static_cast<uint32_t>(i * sizeof(uint32_t));
        const uint32_t actual = host.MemoryRead32(address);
        if (actual != fingerprint[i]) {
            LOGE("%s acceleration refused: fingerprint mismatch at "
                 "0x%08X (0x%08X != 0x%08X)",
                 function_name, address, actual, fingerprint[i]);
            return false;
        }
    }
    return true;
}

void ResumeOriginalSearch(Dynarmic::A32::Jit& jit, uint32_t target) {
    // The veneer has already executed the original PUSH.  Recreate the three
    // callee-saved argument copies, then resume at the first unpatched load.
    jit.Regs()[5] = jit.Regs()[0];
    jit.Regs()[6] = jit.Regs()[1];
    jit.Regs()[7] = jit.Regs()[2];
    jit.Regs()[12] = target + 0x08u;
}

}  // namespace

bool InstallTelltalePropertySetAddCallbackAcceleration(DynarmicHost& host) {
    ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* symbol = engine ? engine->GetExportedSymbol(kAddCallbackSymbol) : nullptr;
    const ElfSymbol* callbacks_symbol =
        engine ? engine->GetExportedSymbol(kCallbacksBaseAddSymbol) : nullptr;
    const ElfSymbol* constructor_symbol =
        engine ? engine->GetExportedSymbol(kKeyCallbacksConstructorSymbol)
               : nullptr;
    const ElfSymbol* destructor_symbol =
        engine ? engine->GetExportedSymbol(kKeyCallbacksDestructorSymbol)
               : nullptr;
    if (!engine || !symbol || symbol->type != STT_FUNC ||
        symbol->size != sizeof(kAddCallbackFingerprint) || !symbol->value ||
        symbol->value != engine->GetBaseAddress() + kAddCallbackRva ||
        (symbol->value & 3u) || !callbacks_symbol ||
        callbacks_symbol->type != STT_FUNC ||
        callbacks_symbol->size != sizeof(kCallbacksBaseAddFingerprint) ||
        callbacks_symbol->value != engine->GetBaseAddress() + kCallbacksBaseAddRva ||
        (callbacks_symbol->value & 3u) ||
        !constructor_symbol || constructor_symbol->type != STT_FUNC ||
        constructor_symbol->size !=
            sizeof(kKeyCallbacksConstructorFingerprint) ||
        constructor_symbol->value !=
            engine->GetBaseAddress() + kKeyCallbacksConstructorRva ||
        (constructor_symbol->value & 3u) ||
        !destructor_symbol || destructor_symbol->type != STT_FUNC ||
        destructor_symbol->size !=
            sizeof(kKeyCallbacksDestructorFingerprint) ||
        destructor_symbol->value !=
            engine->GetBaseAddress() + kKeyCallbacksDestructorRva ||
        (destructor_symbol->value & 3u) ||
        !GuestRangeValid(host.GetGuestMemorySize(), symbol->value,
                         sizeof(kAddCallbackFingerprint)) ||
        !GuestRangeValid(host.GetGuestMemorySize(), callbacks_symbol->value,
                         sizeof(kCallbacksBaseAddFingerprint)) ||
        !GuestRangeValid(host.GetGuestMemorySize(), constructor_symbol->value,
                         sizeof(kKeyCallbacksConstructorFingerprint)) ||
        !GuestRangeValid(host.GetGuestMemorySize(), destructor_symbol->value,
                         sizeof(kKeyCallbacksDestructorFingerprint))) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: unexpected symbol metadata");
        return false;
    }

    const uint32_t target = symbol->value;
    if (!MatchesFingerprint(host, target, kAddCallbackFingerprint,
                            "PropertySet::AddCallbackBase") ||
        !MatchesFingerprint(host, callbacks_symbol->value,
                            kCallbacksBaseAddFingerprint,
                            "CallbacksBase::AddCallbackBase") ||
        !MatchesFingerprint(host, constructor_symbol->value,
                            kKeyCallbacksConstructorFingerprint,
                            "PropertySet::KeyCallbacks::KeyCallbacks") ||
        !MatchesFingerprint(host, destructor_symbol->value,
                            kKeyCallbacksDestructorFingerprint,
                            "PropertySet::KeyCallbacks::~KeyCallbacks")) {
        return false;
    }

    const auto callback_index = std::make_shared<CallbackIndexState>();
    const uint32_t destructor_thunk = host.GetThunkManager().RegisterThunk(
        "__telltale_invalidate_propertyset_callback_index",
        [callback_index](Dynarmic::A32::Jit&, DynarmicHost&) {
            try {
                std::lock_guard<std::mutex> lock(callback_index->mutex);
                ClearCallbackIndexes(*callback_index);
            } catch (...) {
                // Never unwind through DispatchThunk.  If the host mutex is
                // unusable, permanently fail closed to the exact ARM search.
                callback_index->disabled.store(true,
                                               std::memory_order_release);
            }
        });
    if (!destructor_thunk) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: "
             "destructor invalidation thunk registration failed");
        return false;
    }
    const uint32_t destructor_svc = host.MemoryRead32(destructor_thunk);
    if ((destructor_svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: "
             "invalid destructor thunk trampoline");
        return false;
    }

    const uint32_t thunk = host.GetThunkManager().RegisterThunk(
        "__telltale_native_propertyset_add_callback",
        [target, callback_index](Dynarmic::A32::Jit& jit,
                                 DynarmicHost& runtime) {
            auto& regs = jit.Regs();
            const uint32_t property_set = regs[0];
            const uint32_t key = regs[1];
            const uint32_t callback = regs[2];
            const size_t memory_size = runtime.GetGuestMemorySize();
            uint8_t* const memory = runtime.GetGuestMemoryBase();
            uint32_t visited = 0;

            const auto fallback = [&] {
                RecordAddCallbackDiagnostic(AddCallbackResult::Fallback, visited);
                ResumeOriginalSearch(jit, target);
            };
            if (!IsAlignedWord(property_set) || !IsAlignedWord(key) ||
                !IsAlignedWord(callback) ||
                !GuestRangeValid(memory_size, property_set,
                                 kPropertySetRequiredSize) ||
                !GuestRangeValid(memory_size, key, sizeof(uint64_t)) ||
                !GuestRangeValid(memory_size, callback,
                                 kFunctionRequiredSize)) {
                fallback();
                return;
            }

            const uint32_t key_low = LoadGuestU32(memory, key);
            const uint32_t key_high = LoadGuestU32(memory, key + sizeof(uint32_t));
            const uint64_t wanted = static_cast<uint64_t>(key_low) |
                                    (static_cast<uint64_t>(key_high) << 32u);
            uint32_t node = 0;

#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_INDEX) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_INDEX
            IndexedLookupResult lookup = IndexedLookupResult::Invalid;
            try {
                lookup = LookupIndexedCallbackNode(
                    *callback_index, memory, memory_size, property_set, wanted,
                    node, visited);
            } catch (...) {
                // Guest-controlled list sizes must never let an allocation
                // exception cross the native SVC boundary into Dynarmic.
                try {
                    std::lock_guard<std::mutex> lock(callback_index->mutex);
                    ClearCallbackIndexes(*callback_index);
                } catch (...) {
                    callback_index->disabled.store(true,
                                                   std::memory_order_release);
                }
                fallback();
                return;
            }
            if (lookup == IndexedLookupResult::Invalid) {
                fallback();
                return;
            }
            const bool found_node = lookup == IndexedLookupResult::Hit;
#else
            const uint32_t expected_count =
                LoadGuestU32(memory, property_set + kPropertySetCountOffset);
            node = LoadGuestU32(memory, property_set + kPropertySetHeadOffset);
            while (node) {
                if (!IsAlignedWord(node) ||
                    !GuestRangeValid(memory_size, node,
                                     kKeyCallbacksRequiredSize) ||
                    visited >= expected_count || visited >= kMaxCallbackNodes) {
                    fallback();
                    return;
                }

                const uint32_t node_key_low =
                    LoadGuestU32(memory, node + kKeyCallbacksKeyOffset);
                const uint32_t node_key_high = LoadGuestU32(
                    memory,
                    node + kKeyCallbacksKeyOffset + sizeof(uint32_t));
                if (node_key_low == key_low && node_key_high == key_high) break;

                node = LoadGuestU32(memory, node + kKeyCallbacksNextOffset);
                ++visited;
            }

            if (!node && visited != expected_count) {
                fallback();
                return;
            }
            const bool found_node = node != 0;
#endif

            if (found_node) {
                const uint32_t callbacks = node + kKeyCallbacksCallbacksOffset;
                const uint32_t old_head = LoadGuestU32(memory, callbacks);
                if (old_head &&
                    (!IsAlignedWord(old_head) ||
                     !GuestRangeValid(memory_size, old_head,
                                      kFunctionRequiredSize))) {
                    fallback();
                    return;
                }

                // Exact CallbacksBase::AddCallbackBase behavior: the list is
                // circular and its stored pointer is both head and tail.
                if (old_head) {
                    StoreGuestU32(
                        memory, callback + kFunctionNextOffset,
                        LoadGuestU32(memory, old_head + kFunctionNextOffset));
                    StoreGuestU32(memory, old_head + kFunctionNextOffset,
                                  callback);
                } else {
                    StoreGuestU32(memory, callback + kFunctionNextOffset,
                                  callback);
                }
                StoreGuestU32(memory, callbacks, callback);
                RecordAddCallbackDiagnostic(AddCallbackResult::Hit,
                                            visited + 1u);
                regs[0] = 1u;
                regs[12] = 0u;
                return;
            }

            // The indexed generation proved that this is a miss.  The veneer
            // already created the original stack frame, so jump directly to
            // +0x50: the unchanged allocator/constructor/append block.  On the
            // next call the index accepts only the exact one-node append shape.
            regs[4] = 0u;
            regs[5] = property_set;
            regs[6] = key;
            regs[7] = callback;
            RecordAddCallbackDiagnostic(AddCallbackResult::Miss, visited);
            regs[12] = target + 0x50u;
        });
    if (!thunk) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: thunk registration failed");
        return false;
    }

    const uint32_t svc = host.MemoryRead32(thunk);
    if ((svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: unexpected thunk code");
        return false;
    }

    const uint32_t destructor_veneer =
        host.GuestAlloc(24, alignof(uint32_t));
    if (!destructor_veneer) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: "
             "destructor veneer allocation failed");
        return false;
    }
    host.MemoryWrite32(destructor_veneer + 0x00u,
                       kKeyCallbacksDestructorFingerprint[0]);
    host.MemoryWrite32(destructor_veneer + 0x04u, destructor_svc);
    host.MemoryWrite32(destructor_veneer + 0x08u,
                       kKeyCallbacksDestructorFingerprint[1]);
    host.MemoryWrite32(destructor_veneer + 0x0Cu, 0xE51FF004u);
    host.MemoryWrite32(destructor_veneer + 0x10u,
                       destructor_symbol->value + 8u);
    host.MemoryWrite32(destructor_veneer + 0x14u, 0xE320F000u);
    host.InvalidateGuestCode(destructor_veneer, 24);
    host.AddExecutableRange(destructor_veneer, 24);

    const uint32_t veneer = host.GuestAlloc(24, 4);
    if (!veneer) {
        LOGE("PropertySet::AddCallbackBase acceleration unavailable: veneer allocation failed");
        return false;
    }

    // AAPCS32-compatible entry veneer.  Its first instruction is the exact
    // original prologue, so both continuations see the expected stack frame:
    //   ip == 0: native hit, return true after restoring r4-r8/pc;
    //   ip != 0: tail-branch into the untouched original function body.
    host.MemoryWrite32(veneer + 0x00u, 0xE92D41F0u);  // push {r4-r8,lr}
    host.MemoryWrite32(veneer + 0x04u, svc);
    host.MemoryWrite32(veneer + 0x08u, 0xE35C0000u);  // cmp ip,#0
    host.MemoryWrite32(veneer + 0x0Cu, 0x112FFF1Cu);  // bxne ip
    host.MemoryWrite32(veneer + 0x10u, 0xE3A00001u);  // mov r0,#1
    host.MemoryWrite32(veneer + 0x14u, 0xE8BD81F0u);  // pop {r4-r8,pc}
    host.InvalidateGuestCode(veneer, 24);
    host.AddExecutableRange(veneer, 24);

    // Patch invalidation first. It is benign by itself, and guarantees that
    // once AddCallbackBase starts using the index no removed pool node can
    // survive in a cached generation. Module initializers have not run yet, so
    // no guest thread can observe either two-word rewrite half-complete.
    host.MemoryWrite32(destructor_symbol->value + 4u, destructor_veneer);
    host.MemoryWrite32(destructor_symbol->value, 0xE51FF004u);
    host.InvalidateGuestCode(destructor_symbol->value, 8);

    // The literal jump has no +/-32 MiB limit.
    host.MemoryWrite32(target + 4u, veneer);
    host.MemoryWrite32(target, 0xE51FF004u);  // ldr pc,[pc,#-4]
    host.InvalidateGuestCode(target, 8);

    LOGI("Installed native PropertySet::AddCallbackBase acceleration at "
         "0x%08X -> veneer 0x%08X (destructor invalidation 0x%08X)",
         target, veneer, destructor_symbol->value);
    return true;
}
