#include "telltale_propertyset_fastpath.h"

#include <android/log.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "game_port_config.h"
#include "thunk_manager.h"
#include "thunk_types.h"

#define LOG_TAG "Arm32Bridge_PropertySet"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace {

constexpr char kGetKeyInfoSymbol[] =
    "_ZN11PropertySet10GetKeyInfoERK6SymbolRPNS_7KeyInfoERPS_NS_15GetKeyInfoFlagsE";
constexpr uint32_t kGetKeyInfoRva = 0x00A8F570u;
constexpr char kGetHandleObjectPointerSymbol[] =
    "_ZN16HandleObjectInfo22GetHandleObjectPointerEv";
constexpr uint32_t kGetHandleObjectPointerRva = 0x0058CE30u;
constexpr uint32_t kGetHandleObjectPointerSymbolSize = 0xF4u;
constexpr uint32_t kGetHandleCurrentFrameLiteralOffset = 0xF0u;
constexpr uint32_t kGetHandleCurrentFrameLiteral = 0x00AE0F70u;
constexpr uint32_t kGetHandleCurrentFrameGotRva = 0x0106DDB0u;
constexpr char kHandleCurrentFrameSymbol[] =
    "_ZN16HandleObjectInfo14smCurrentFrameE";
constexpr uint32_t kHandleCurrentFrameRva = 0x010BCAC4u;

// Exact 352-byte ARM-mode body from the supported Game of Thrones
// libGameEngine.so. Checking the whole function (rather than only its prologue)
// makes the layout assumptions below fail closed on any other engine build.
constexpr std::array<uint32_t, 88> kGetKeyInfoFingerprint = {
    0xE92D4FF0u, 0xE24DD00Cu, 0xE1A06000u, 0xE1A07001u, 0xE59DA030u, 0xE1A04002u,
    0xE1A05003u, 0xE3A09000u, 0xE20A8002u, 0xE596E030u, 0xE286B030u, 0xE3DEE001u,
    0x0A000013u, 0xE1C700D0u, 0xE1A0C00Bu, 0xE1CE21D0u, 0xE1530001u, 0x01520000u,
    0x21A0C00Eu, 0x359EE008u, 0x259EE004u, 0xE35E0000u, 0x1AFFFFF7u, 0xE15B000Cu,
    0x0A000007u, 0xE1CC21D0u, 0xE1530001u, 0x01520000u, 0x8A000003u, 0xE584C000u,
    0xE5856000u, 0xE28DD00Cu, 0xE8BD8FF0u, 0xE3580000u, 0xE5849000u, 0x0A000014u,
    0xE5960044u, 0xE3500000u, 0x0A00000Au, 0xEBEBF607u, 0xE3500000u, 0x0A000007u,
    0xE5960044u, 0xE3500000u, 0x0A000002u, 0xEBEBF601u, 0xE1A06000u, 0xEAFFFFD8u,
    0xE5903030u, 0xE7F000F0u, 0xE1A01007u, 0xE1A00006u, 0xEBFFFF7Bu, 0xE5840000u,
    0xE5856000u, 0xE28DD00Cu, 0xE8BD8FF0u, 0xE31A0004u, 0x0A000018u, 0xE5B6801Cu,
    0xE1580006u, 0x0A000015u, 0xE3A09004u, 0xE5980008u, 0xE3500000u, 0x0A00000Eu,
    0xEBEBF5ECu, 0xE3500000u, 0x0A00000Bu, 0xE5980008u, 0xE3500000u, 0x0A000000u,
    0xEBEBF5E6u, 0xE1A03005u, 0xE58D9000u, 0xE1A01007u, 0xE1A02004u, 0xEBFFFFB1u,
    0xE5953000u, 0xE3530000u, 0x1AFFFFCDu, 0xE5988000u, 0xE1580006u, 0x1AFFFFEAu,
    0xE3A03000u, 0xE5843000u, 0xE5853000u, 0xEAFFFFC6u,
};
static_assert(kGetKeyInfoFingerprint.size() * sizeof(uint32_t) == 0x160u);

// Prefix through the non-loading return of
// HandleObjectInfo::GetHandleObjectPointer.  The native implementation below
// handles only the already-loaded and provably-null cases; a handle requiring
// Load() always resumes the complete guest GetKeyInfo body.
constexpr std::array<uint32_t, 20> kGetHandleObjectPointerPrefixFingerprint = {
    0xE59F30E8u, 0xE590C01Cu, 0xE79F3003u, 0xE35C0000u,
    0xE5933000u, 0xE5803028u, 0x0A000001u, 0xE1A0000Cu,
    0xE12FFF1Eu, 0xE92D4030u, 0xE24DD00Cu, 0xE1C041D0u,
    0xE1943005u, 0x0A000002u, 0xE5903024u, 0xE3130A09u,
    0x1A000002u, 0xE1A0000Cu, 0xE28DD00Cu, 0xE8BD8030u,
};

constexpr uint32_t kPropertySetNestedListOffset = 0x1Cu;
constexpr uint32_t kPropertySetNestedListTailOffset = 0x20u;
constexpr uint32_t kPropertySetTreeRootOffset = 0x30u;
constexpr uint32_t kPropertySetParentOffset = 0x44u;
constexpr uint32_t kRbNodeLeftOffset = 0x04u;
constexpr uint32_t kRbNodeRightOffset = 0x08u;
constexpr uint32_t kRbNodeKeyOffset = 0x10u;
constexpr size_t kRbNodeBytesRead = 0x18u;
constexpr size_t kMaxRbDepth = 96;
constexpr size_t kMaxPropertySetDepth = 64;
constexpr size_t kMaxNestedNodes = 65536;
constexpr size_t kDeferredWriteAddressCapacity = 8192;
constexpr size_t kDeferredWriteAddressFixedLimit =
    kDeferredWriteAddressCapacity / 2u;
constexpr size_t kDeferredWriteAddressMaxProbe = 32;
constexpr size_t kDeferredWriteInlineCapacity = 256;
constexpr size_t kDeferredWriteShadowInlineCapacity = 8;
static_assert((kDeferredWriteAddressCapacity &
               (kDeferredWriteAddressCapacity - 1u)) == 0);
constexpr uint32_t kCreateOrParentFlag = 0x02u;
constexpr uint32_t kNestedPropertySetFlag = 0x04u;
constexpr uint32_t kHandleObjectIdOffset = 0x10u;
constexpr uint32_t kHandleObjectPointerOffset = 0x1Cu;
constexpr uint32_t kHandleFlagsOffset = 0x24u;
constexpr uint32_t kHandleLastFrameOffset = 0x28u;
constexpr size_t kHandleRequiredSize = 0x2Cu;
constexpr uint32_t kHandleNeedsLoadMask = 0x9000u;
constexpr uint32_t kNestedNodeNextOffset = 0x00u;
constexpr uint32_t kNestedNodePreviousOffset = 0x04u;
constexpr uint32_t kNestedNodeHandleOffset = 0x08u;
constexpr size_t kNestedNodeRequiredSize = 0x0Cu;

static_assert(kPropertySetNestedListOffset < kPropertySetTreeRootOffset);
static_assert(kPropertySetParentOffset > kPropertySetTreeRootOffset);

bool IsAlignedWord(uint32_t address) {
    return (address & (alignof(uint32_t) - 1u)) == 0;
}

bool IsValidWordRange(size_t memory_size, uint32_t address, size_t size) {
    return IsAlignedWord(address) && GuestRangeValid(memory_size, address, size);
}

// All call sites validate the complete object before reaching these helpers.
// Fixed-size memcpy is alias-safe and becomes a direct AArch64 load/store,
// avoiding a virtual Dynarmic UserCallbacks call at every RB-tree node.
inline uint32_t LoadGuestU32(const uint8_t* memory, uint32_t address) {
    uint32_t value;
    std::memcpy(&value, memory + address, sizeof(value));
    return value;
}

inline void StoreGuestU32(uint8_t* memory, uint32_t address, uint32_t value) {
    std::memcpy(memory + address, &value, sizeof(value));
}

enum class LocalLookupResult {
    Hit,
    Miss,
    Invalid,
};

enum class HandleLookupResult {
    Pointer,
    Null,
    NeedsGuest,
    Invalid,
};

enum class PropertySetSearchResult {
    Handled,
    NeedsGuest,
};

struct DeferredWrite {
    uint32_t address;
    uint32_t value;
};

class DeferredWriteLog {
public:
    bool Empty() const { return size_ == 0; }

    void Push(uint32_t address, uint32_t value) {
        if (size_ < inline_writes_.size()) {
            inline_writes_[size_] = {address, value};
        } else {
            overflow_writes_.push_back({address, value});
        }
        ++size_;
    }

    template <typename Function>
    void ForEach(Function&& function) const {
        const size_t inline_count =
            std::min(size_, inline_writes_.size());
        for (size_t index = 0; index < inline_count; ++index) {
            function(inline_writes_[index]);
        }
        for (const auto& write : overflow_writes_) function(write);
    }

private:
    // No initializer: size_ determines which entries are live, avoiding a
    // memset while keeping the normal 2-4 output writes allocation-free.
    std::array<DeferredWrite, kDeferredWriteInlineCapacity> inline_writes_;
    std::vector<DeferredWrite> overflow_writes_;
    size_t size_ = 0;
};

struct DeferredWriteFlatScratch {
    uint32_t BeginGeneration() {
        ++next_generation;
        if (next_generation == 0) {
            generations.fill(0);
            ++next_generation;
        }
        return next_generation;
    }

    // Thread storage is zero-initialized once. Per-call generations avoid
    // clearing this table during every deep PropertySet traversal.
    std::array<uint32_t, kDeferredWriteAddressCapacity> generations{};
    std::array<uint32_t, kDeferredWriteAddressCapacity> addresses;
    std::array<uint32_t, kDeferredWriteAddressCapacity> values;
    uint32_t next_generation = 0;
    bool in_use = false;
};

DeferredWriteFlatScratch* AcquireDeferredWriteFlatScratch() {
    // TryGetKeyInfo never re-enters the guest: internal parent/nested recursion
    // shares one context, while a NeedsGuest result returns before ARM resumes.
    // Consequently one generation can be leased for the duration of this call.
    static thread_local DeferredWriteFlatScratch scratch;
    if (scratch.in_use) return nullptr;
    scratch.in_use = true;
    return &scratch;
}

struct DeferredWriteShadowUnavailable {};

// Exact latest-value shadow for deferred four-byte writes.  A node-based hash
// dominated B5 profiles, while scanning the complete ordered log made B4
// quadratic.  Real calls normally touch only the two output words and a few
// handle frame stamps, so keep eight *distinct* addresses in a tiny inline
// cache.  The two fixed output words are forwarded directly and never consume
// hash slots.  The ninth distinct handle stamp promotes to a reusable,
// generation-tagged table whose probe count and load are strictly bounded.
class DeferredWriteShadow {
public:
    DeferredWriteShadow() = default;
    ~DeferredWriteShadow() noexcept {
        if (flat_scratch_) flat_scratch_->in_use = false;
    }
    DeferredWriteShadow(const DeferredWriteShadow&) = delete;
    DeferredWriteShadow& operator=(const DeferredWriteShadow&) = delete;
    DeferredWriteShadow(DeferredWriteShadow&&) = delete;
    DeferredWriteShadow& operator=(DeferredWriteShadow&&) = delete;

    void SetOutputAddresses(uint32_t key_info_out, uint32_t owner_out) {
        key_info_out_ = key_info_out;
        owner_out_ = owner_out;
    }

    bool Load(uint32_t address, uint32_t& value) const {
        if (address == key_info_out_ && key_info_written_) {
            value = key_info_value_;
            return true;
        }
        if (address == owner_out_ && owner_written_) {
            value = owner_value_;
            return true;
        }
        // Only handle frame stamps occupy the generic shadow.  Their unsigned
        // address interval is an exact, very cheap negative filter for the
        // property/tree/global reads that dominate deep traversals.
        if (inline_size_ == 0 || address < stamp_min_ || address > stamp_max_) {
            return false;
        }
        if (!flat_scratch_) {
            for (size_t index = inline_size_; index != 0; --index) {
                if (inline_addresses_[index - 1u] == address) {
                    value = inline_values_[index - 1u];
                    return true;
                }
            }
            return false;
        }
        size_t slot = Hash(address);
        for (size_t probe = 0; probe < kDeferredWriteAddressMaxProbe;
             ++probe) {
            if (!Occupied(slot)) return false;
            if (flat_scratch_->addresses[slot] == address) {
                value = flat_scratch_->values[slot];
                return true;
            }
            slot = (slot + 1u) & (kDeferredWriteAddressCapacity - 1u);
        }
        return false;
    }

    void Store(uint32_t address, uint32_t value) {
        bool is_output = false;
        if (address == key_info_out_) {
            key_info_value_ = value;
            key_info_written_ = true;
            is_output = true;
        }
        if (address == owner_out_) {
            owner_value_ = value;
            owner_written_ = true;
            is_output = true;
        }
        if (is_output) return;

        if (inline_size_ == 0) {
            stamp_min_ = address;
            stamp_max_ = address;
        } else {
            stamp_min_ = std::min(stamp_min_, address);
            stamp_max_ = std::max(stamp_max_, address);
        }

        if (!flat_scratch_) {
            for (size_t index = inline_size_; index != 0; --index) {
                if (inline_addresses_[index - 1u] == address) {
                    inline_values_[index - 1u] = value;
                    return;
                }
            }
            if (inline_size_ < kDeferredWriteShadowInlineCapacity) {
                inline_addresses_[inline_size_] = address;
                inline_values_[inline_size_] = value;
                ++inline_size_;
                return;
            }
            PromoteToFlat();
        }
        StoreFlat(address, value);
    }

private:
    void StoreFlat(uint32_t address, uint32_t value) {
        size_t slot = Hash(address);
        for (size_t probe = 0; probe < kDeferredWriteAddressMaxProbe;
             ++probe) {
            if (!Occupied(slot)) {
                if (size_ >= kDeferredWriteAddressFixedLimit) break;
                flat_scratch_->addresses[slot] = address;
                flat_scratch_->values[slot] = value;
                flat_scratch_->generations[slot] = flat_generation_;
                ++size_;
                return;
            }
            if (flat_scratch_->addresses[slot] == address) {
                flat_scratch_->values[slot] = value;
                return;
            }
            slot = (slot + 1u) & (kDeferredWriteAddressCapacity - 1u);
        }

        // Every accepted insertion and lookup is bounded to the same 32-probe
        // window.  An adversarial cluster or >50% load fails closed to the
        // untouched guest body instead of entering an unbounded hash tier.
        throw DeferredWriteShadowUnavailable{};
    }

    void PromoteToFlat() {
        flat_scratch_ = AcquireDeferredWriteFlatScratch();
        if (!flat_scratch_) throw DeferredWriteShadowUnavailable{};
        flat_generation_ = flat_scratch_->BeginGeneration();
        for (size_t index = 0; index < inline_size_; ++index) {
            StoreFlat(inline_addresses_[index], inline_values_[index]);
        }
    }

    static size_t Hash(uint32_t address) {
        // Take high Fibonacci-hash bits.  Masking a 32-bit product's low bits
        // makes regularly spaced guest addresses collide in a power-of-two
        // table.  The high 13 bits address the 8192 reusable slots.
        constexpr unsigned kIndexBits = 13;
        static_assert(kDeferredWriteAddressCapacity ==
                      (size_t{1} << kIndexBits));
        const uint64_t mixed = static_cast<uint64_t>(address >> 2u) *
                               UINT64_C(0x9E3779B97F4A7C15);
        return static_cast<size_t>(mixed >> (64u - kIndexBits));
    }

    bool Occupied(size_t slot) const {
        return flat_scratch_->generations[slot] == flat_generation_;
    }

    // Keep mode/count fields and the common inline cache compact. The much
    // larger flat arrays live in reusable thread storage, shrinking each native
    // call's stack frame and avoiding per-call bitmap initialization.
    DeferredWriteFlatScratch* flat_scratch_ = nullptr;
    uint32_t flat_generation_ = 0;
    size_t inline_size_ = 0;
    size_t size_ = 0;
    uint32_t stamp_min_ = 0;
    uint32_t stamp_max_ = 0;
    uint32_t key_info_out_ = 0;
    uint32_t owner_out_ = 0;
    uint32_t key_info_value_ = 0;
    uint32_t owner_value_ = 0;
    bool key_info_written_ = false;
    bool owner_written_ = false;
    std::array<uint32_t, kDeferredWriteShadowInlineCapacity> inline_addresses_;
    std::array<uint32_t, kDeferredWriteShadowInlineCapacity> inline_values_;
};

struct PropertySetSearchContext {
    uint8_t* memory = nullptr;
    size_t memory_size = 0;
    uint32_t current_frame_address = 0;
    uint32_t current_frame_literal_address = 0;
    uint32_t current_frame_literal = 0;
    uint32_t current_frame_got_address = 0;
    uint32_t symbol = 0;
    uint32_t key_info_out = 0;
    uint32_t owner_out = 0;
    uint32_t result_low = 0;
    uint32_t result_high = 0;
    size_t active_count = 0;
    size_t nested_nodes_seen = 0;
    // Only entries below active_count are read.
    std::array<uint32_t, kMaxPropertySetDepth> active;
    DeferredWriteLog deferred_writes;
    DeferredWriteShadow deferred_write_shadow;
};

struct ActivePropertySetGuard {
    PropertySetSearchContext& context;
    ~ActivePropertySetGuard() { --context.active_count; }
};

bool RangesOverlap(uint32_t first, size_t first_size, uint32_t second,
                   size_t second_size) {
    const uint64_t first_begin = first;
    const uint64_t first_end = first_begin + first_size;
    const uint64_t second_begin = second;
    const uint64_t second_end = second_begin + second_size;
    return first_begin < second_end && second_begin < first_end;
}

inline uint32_t LoadGuestU32View(const PropertySetSearchContext& context,
                                uint32_t address) {
    if (context.deferred_writes.Empty()) {
        return LoadGuestU32(context.memory, address);
    }
    uint32_t value = 0;
    if (context.deferred_write_shadow.Load(address, value)) return value;
    return LoadGuestU32(context.memory, address);
}

inline uint64_t ReadGuestU64View(const PropertySetSearchContext& context,
                                 uint32_t address) {
    return static_cast<uint64_t>(LoadGuestU32View(context, address)) |
           (static_cast<uint64_t>(LoadGuestU32View(
                context, address + sizeof(uint32_t))) << 32u);
}

void DeferGuestWrite(PropertySetSearchContext& context, uint32_t address,
                     uint32_t value) {
    context.deferred_write_shadow.Store(address, value);
    context.deferred_writes.Push(address, value);
}

void DeferOutputPair(PropertySetSearchContext& context, uint32_t key_info,
                     uint32_t owner) {
    // This is the guest's exact STR order, including when both references
    // alias each other or overlap memory read by an outer recursive call.
    DeferGuestWrite(context, context.key_info_out, key_info);
    DeferGuestWrite(context, context.owner_out, owner);
}

LocalLookupResult LookupLocalKey(PropertySetSearchContext& context,
                                 uint32_t property_set) {
    if (!IsValidWordRange(context.memory_size, property_set,
                          kPropertySetParentOffset + sizeof(uint32_t))) {
        return LocalLookupResult::Invalid;
    }

    const uint32_t sentinel = property_set + kPropertySetTreeRootOffset;
    uint32_t node = LoadGuestU32View(context, sentinel) & ~1u;
    const bool tree_was_nonempty = node != 0;
    uint32_t candidate = sentinel;
    uint64_t wanted = 0;
    if (tree_was_nonempty) {
        // The ARM body executes LDRD [symbol] anew for every non-empty
        // PropertySet reached through a parent or nested traversal.
        wanted = ReadGuestU64View(context, context.symbol);
    }

    size_t depth = 0;
    while (node && depth++ < kMaxRbDepth) {
        if (node == sentinel ||
            !IsValidWordRange(context.memory_size, node, kRbNodeBytesRead)) {
            return LocalLookupResult::Invalid;
        }
        const uint64_t key =
            ReadGuestU64View(context, node + kRbNodeKeyOffset);
        if (key >= wanted) {
            candidate = node;
            node = LoadGuestU32View(context, node + kRbNodeLeftOffset);
        } else {
            node = LoadGuestU32View(context, node + kRbNodeRightOffset);
        }
    }
    if (node) return LocalLookupResult::Invalid;

    // LDRD runs for every non-empty lookup and leaves this incidental result in
    // r0:r1 even on a miss.  Preserve it for callers that inspect the ABI noise.
    if (tree_was_nonempty) {
        context.result_low = static_cast<uint32_t>(wanted);
        context.result_high = static_cast<uint32_t>(wanted >> 32u);
    } else {
        context.result_low = property_set;
    }

    if (candidate != sentinel) {
        if (!IsValidWordRange(context.memory_size, candidate, kRbNodeBytesRead)) {
            return LocalLookupResult::Invalid;
        }
        const uint64_t candidate_key =
            ReadGuestU64View(context, candidate + kRbNodeKeyOffset);
        if (candidate_key == wanted) {
            DeferOutputPair(context, candidate, property_set);
            return LocalLookupResult::Hit;
        }
        if (candidate_key < wanted) return LocalLookupResult::Invalid;
    }

    return LocalLookupResult::Miss;
}

HandleLookupResult ResolveLoadedHandle(PropertySetSearchContext& context,
                                       uint32_t handle,
                                       uint32_t& object_pointer) {
    object_pointer = 0;
    if (!handle) return HandleLookupResult::Null;
    if (!IsValidWordRange(context.memory_size, handle, kHandleRequiredSize)) {
        return HandleLookupResult::Invalid;
    }

    // Preserve the getter's ARM load order.  The frame stores are deferred
    // until the complete traversal is known to be native-safe, so any
    // NeedsGuest result can restart the untouched body without duplicate
    // side effects.
    // These three fixed words cannot have a pending native write: output
    // aliases are rejected at entry and every handle-stamp address is checked
    // below before it is deferred.  Bypass the general write shadow for the
    // getter globals that are read once or twice for every traversed handle.
    const uint32_t frame_literal = LoadGuestU32(
        context.memory, context.current_frame_literal_address);
    object_pointer =
        LoadGuestU32View(context, handle + kHandleObjectPointerOffset);
    if (frame_literal != context.current_frame_literal ||
        LoadGuestU32(context.memory, context.current_frame_got_address) !=
            context.current_frame_address) {
        return HandleLookupResult::NeedsGuest;
    }
    const uint32_t current_frame =
        LoadGuestU32(context.memory, context.current_frame_address);
    const uint32_t frame_write_address = handle + kHandleLastFrameOffset;
    if (frame_write_address == context.current_frame_literal_address ||
        frame_write_address == context.current_frame_got_address ||
        frame_write_address == context.current_frame_address) {
        return HandleLookupResult::NeedsGuest;
    }
    DeferGuestWrite(context, frame_write_address, current_frame);
    context.result_low = object_pointer;
    if (object_pointer) return HandleLookupResult::Pointer;

    const uint64_t object_id =
        ReadGuestU64View(context, handle + kHandleObjectIdOffset);
    if (!object_id) return HandleLookupResult::Null;
    const uint32_t flags =
        LoadGuestU32View(context, handle + kHandleFlagsOffset);
    if (!(flags & kHandleNeedsLoadMask)) {
        return HandleLookupResult::Null;
    }
    // Calling HandleObjectInfo::Load from an SVC would re-enter the guest JIT.
    // Resume the untouched ARM32 body instead.
    return HandleLookupResult::NeedsGuest;
}

PropertySetSearchResult SearchPropertySet(PropertySetSearchContext& context,
                                          uint32_t property_set,
                                          uint32_t flags) {
    if (context.active_count >= context.active.size()) {
        return PropertySetSearchResult::NeedsGuest;
    }
    for (size_t i = 0; i < context.active_count; ++i) {
        if (context.active[i] == property_set) {
            return PropertySetSearchResult::NeedsGuest;
        }
    }
    context.active[context.active_count++] = property_set;
    ActivePropertySetGuard active_guard{context};

    const LocalLookupResult local = LookupLocalKey(context, property_set);
    if (local == LocalLookupResult::Invalid) {
        return PropertySetSearchResult::NeedsGuest;
    }
    if (local == LocalLookupResult::Hit) {
        return PropertySetSearchResult::Handled;
    }

    // The original clears *key_info_out immediately after every local miss,
    // before following a parent or traversing nested PropertySets.
    DeferGuestWrite(context, context.key_info_out, 0);

    if (flags & kCreateOrParentFlag) {
        const uint32_t handle = LoadGuestU32View(
            context, property_set + kPropertySetParentOffset);
        uint32_t parent = 0;
        HandleLookupResult first =
            ResolveLoadedHandle(context, handle, parent);
        if (first != HandleLookupResult::Pointer) {
            // A null parent makes the original create a KeyInfo; a loadable
            // parent may call HandleObjectInfo::Load.  Both remain guest work.
            return PropertySetSearchResult::NeedsGuest;
        }
        const uint32_t parent_handle_address =
            property_set + kPropertySetParentOffset;
        const uint32_t second_handle =
            LoadGuestU32View(context, parent_handle_address);
        if (!second_handle) return PropertySetSearchResult::NeedsGuest;
        HandleLookupResult second =
            ResolveLoadedHandle(context, second_handle, parent);
        if (second != HandleLookupResult::Pointer || !parent) {
            return PropertySetSearchResult::NeedsGuest;
        }
        return SearchPropertySet(context, parent, flags);
    }

    if (!(flags & kNestedPropertySetFlag)) {
        DeferOutputPair(context, 0, 0);
        return PropertySetSearchResult::Handled;
    }

    const uint32_t sentinel = property_set + kPropertySetNestedListOffset;
    const uint32_t tail = LoadGuestU32View(
        context, property_set + kPropertySetNestedListTailOffset);
    uint32_t node = LoadGuestU32View(context, sentinel);
    if (node == sentinel) {
        if (tail != sentinel) return PropertySetSearchResult::NeedsGuest;
        DeferOutputPair(context, 0, 0);
        return PropertySetSearchResult::Handled;
    }
    if (!node || tail == sentinel || !tail) {
        return PropertySetSearchResult::NeedsGuest;
    }

    uint32_t expected_previous = sentinel;
    while (node != sentinel) {
        if (++context.nested_nodes_seen > kMaxNestedNodes ||
            !IsValidWordRange(context.memory_size, node,
                              kNestedNodeRequiredSize)) {
            return PropertySetSearchResult::NeedsGuest;
        }
        const uint32_t previous = LoadGuestU32View(
            context, node + kNestedNodePreviousOffset);
        if (previous != expected_previous) {
            return PropertySetSearchResult::NeedsGuest;
        }

        uint32_t handle = LoadGuestU32View(
            context, node + kNestedNodeHandleOffset);
        context.result_low = handle;
        if (handle) {
            uint32_t child = 0;
            const HandleLookupResult first =
                ResolveLoadedHandle(context, handle, child);
            if (first == HandleLookupResult::NeedsGuest ||
                first == HandleLookupResult::Invalid) {
                return PropertySetSearchResult::NeedsGuest;
            }
            if (first == HandleLookupResult::Pointer && child) {
                handle = LoadGuestU32View(
                    context, node + kNestedNodeHandleOffset);
                if (!handle) return PropertySetSearchResult::NeedsGuest;
                const HandleLookupResult second =
                    ResolveLoadedHandle(context, handle, child);
                if (second != HandleLookupResult::Pointer || !child) {
                    return PropertySetSearchResult::NeedsGuest;
                }
                // A recursive AAPCS call receives the Symbol pointer in r1.
                context.result_high = context.symbol;
                if (SearchPropertySet(context, child,
                                      kNestedPropertySetFlag) !=
                    PropertySetSearchResult::Handled) {
                    return PropertySetSearchResult::NeedsGuest;
                }
                if (LoadGuestU32View(context, context.owner_out)) {
                    return PropertySetSearchResult::Handled;
                }
            }
        }

        // The guest loads node->next only after the recursive call returns.
        // Shadow lookup reproduces a pathological alias where an earlier
        // HandleObjectInfo frame stamp changed this link.
        const uint32_t next = LoadGuestU32View(
            context, node + kNestedNodeNextOffset);
        if (!next || (next == sentinel && node != tail)) {
            return PropertySetSearchResult::NeedsGuest;
        }
        expected_previous = node;
        node = next;
    }
    if (expected_previous != tail) {
        return PropertySetSearchResult::NeedsGuest;
    }
    DeferOutputPair(context, 0, 0);
    return PropertySetSearchResult::Handled;
}

// Returns true only when the complete GetKeyInfo operation was performed.
// Lazy handle loading and key creation remain in the exact ARM32 body.
bool TryGetKeyInfo(Dynarmic::A32::Jit& jit, DynarmicHost& host,
                   uint32_t current_frame_address,
                   uint32_t current_frame_literal_address,
                   uint32_t current_frame_got_address) {
    auto& regs = jit.Regs();
    const uint32_t property_set = regs[0];
    const uint32_t symbol = regs[1];
    const uint32_t key_info_out = regs[2];
    const uint32_t owner_out = regs[3];
    const uint32_t stack = regs[13];
    const size_t memory_size = host.GetGuestMemorySize();
    uint8_t* const memory = host.GetGuestMemoryBase();

    if (!IsValidWordRange(memory_size, property_set,
                          kPropertySetParentOffset + sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, symbol, sizeof(uint64_t)) ||
        !IsValidWordRange(memory_size, key_info_out, sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, owner_out, sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, stack, sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, current_frame_address,
                          sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, current_frame_literal_address,
                          sizeof(uint32_t)) ||
        !IsValidWordRange(memory_size, current_frame_got_address,
                          sizeof(uint32_t))) {
        return false;
    }
    if (RangesOverlap(symbol, sizeof(uint64_t), key_info_out,
                      sizeof(uint32_t)) ||
        RangesOverlap(symbol, sizeof(uint64_t), owner_out,
                      sizeof(uint32_t)) ||
        RangesOverlap(current_frame_literal_address, sizeof(uint32_t),
                      key_info_out, sizeof(uint32_t)) ||
        RangesOverlap(current_frame_literal_address, sizeof(uint32_t),
                      owner_out, sizeof(uint32_t)) ||
        RangesOverlap(current_frame_got_address, sizeof(uint32_t),
                      key_info_out, sizeof(uint32_t)) ||
        RangesOverlap(current_frame_got_address, sizeof(uint32_t),
                      owner_out, sizeof(uint32_t)) ||
        RangesOverlap(current_frame_address, sizeof(uint32_t), key_info_out,
                      sizeof(uint32_t)) ||
        RangesOverlap(current_frame_address, sizeof(uint32_t), owner_out,
                      sizeof(uint32_t))) {
        return false;
    }

    PropertySetSearchContext context;
    context.memory = memory;
    context.memory_size = memory_size;
    context.current_frame_address = current_frame_address;
    context.current_frame_literal_address = current_frame_literal_address;
    context.current_frame_literal = kGetHandleCurrentFrameLiteral;
    context.current_frame_got_address = current_frame_got_address;
    context.symbol = symbol;
    context.key_info_out = key_info_out;
    context.owner_out = owner_out;
    context.deferred_write_shadow.SetOutputAddresses(key_info_out, owner_out);
    context.result_low = property_set;
    context.result_high = symbol;
    const uint32_t flags = LoadGuestU32(memory, stack);
    if (SearchPropertySet(context, property_set, flags) !=
        PropertySetSearchResult::Handled) {
        return false;
    }

    context.deferred_writes.ForEach([&](const DeferredWrite& write) {
        StoreGuestU32(memory, write.address, write.value);
    });
    regs[0] = context.result_low;
    regs[1] = context.result_high;
    return true;
}

template <size_t N>
bool MatchesFingerprint(DynarmicHost& host, uint32_t target,
                        const std::array<uint32_t, N>& fingerprint,
                        const char* function_name) {
    for (size_t i = 0; i < fingerprint.size(); ++i) {
        const uint32_t address = target + static_cast<uint32_t>(i * sizeof(uint32_t));
        if (host.MemoryRead32(address) != fingerprint[i]) {
            LOGE("%s acceleration refused: fingerprint mismatch at 0x%08X",
                 function_name, address);
            return false;
        }
    }
    return true;
}

}  // namespace

bool InstallTelltaleGetKeyInfoAcceleration(DynarmicHost& host) {
    ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* symbol =
        engine ? engine->GetExportedSymbol(kGetKeyInfoSymbol) : nullptr;
    const ElfSymbol* handle_symbol =
        engine ? engine->GetExportedSymbol(kGetHandleObjectPointerSymbol)
               : nullptr;
    const ElfSymbol* frame_symbol =
        engine ? engine->GetExportedSymbol(kHandleCurrentFrameSymbol) : nullptr;
    if (!engine || !symbol || symbol->type != STT_FUNC ||
        symbol->size != kGetKeyInfoFingerprint.size() * sizeof(uint32_t) ||
        symbol->value != engine->GetBaseAddress() + kGetKeyInfoRva ||
        (symbol->value & 3u) != 0 || !handle_symbol ||
        handle_symbol->type != STT_FUNC ||
        handle_symbol->size != kGetHandleObjectPointerSymbolSize ||
        handle_symbol->value !=
            engine->GetBaseAddress() + kGetHandleObjectPointerRva ||
        (handle_symbol->value & 3u) != 0 || !frame_symbol ||
        frame_symbol->type != STT_OBJECT ||
        frame_symbol->size != sizeof(uint32_t) ||
        frame_symbol->value !=
            engine->GetBaseAddress() + kHandleCurrentFrameRva ||
        (frame_symbol->value & 3u) != 0) {
        LOGE("GetKeyInfo acceleration unavailable: unexpected symbol metadata");
        return false;
    }

    const uint32_t target = symbol->value;
    const uint32_t handle_literal_address =
        handle_symbol->value + kGetHandleCurrentFrameLiteralOffset;
    const uint64_t handle_got_address_wide =
        static_cast<uint64_t>(handle_symbol->value) + 0x10u +
        kGetHandleCurrentFrameLiteral;
    if (handle_got_address_wide > UINT32_MAX) {
        LOGE("GetKeyInfo acceleration unavailable: handle GOT address overflow");
        return false;
    }
    const uint32_t handle_got_address =
        static_cast<uint32_t>(handle_got_address_wide);
    if (!GuestRangeValid(host.GetGuestMemorySize(), target,
                         kGetKeyInfoFingerprint.size() * sizeof(uint32_t)) ||
        !GuestRangeValid(host.GetGuestMemorySize(), handle_symbol->value,
                         kGetHandleObjectPointerSymbolSize) ||
        !GuestRangeValid(host.GetGuestMemorySize(), frame_symbol->value,
                         sizeof(uint32_t)) ||
        !GuestRangeValid(host.GetGuestMemorySize(), handle_got_address,
                         sizeof(uint32_t)) ||
        !MatchesFingerprint(host, target, kGetKeyInfoFingerprint,
                            "PropertySet::GetKeyInfo") ||
        !MatchesFingerprint(host, handle_symbol->value,
                            kGetHandleObjectPointerPrefixFingerprint,
                            "HandleObjectInfo::GetHandleObjectPointer") ||
        host.MemoryRead32(handle_literal_address) !=
            kGetHandleCurrentFrameLiteral ||
        handle_got_address !=
            engine->GetBaseAddress() + kGetHandleCurrentFrameGotRva ||
        host.MemoryRead32(handle_got_address) != frame_symbol->value) {
        LOGE("GetKeyInfo acceleration unavailable: unexpected current-frame "
             "literal/GOT relationship");
        return false;
    }

    const uint32_t current_frame_address = frame_symbol->value;
    const uint32_t thunk = host.GetThunkManager().RegisterThunk(
        "__telltale_native_propertyset_get_key_info",
        [current_frame_address, handle_literal_address, handle_got_address](
            Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
            bool handled = false;
            try {
                handled = TryGetKeyInfo(
                    jit, runtime, current_frame_address,
                    handle_literal_address, handle_got_address);
            } catch (...) {
                // Traversal is deliberately two-phase: allocation failure can
                // safely restart the untouched ARM body because no deferred
                // guest write has been committed yet.
                handled = false;
            }
            // r12/ip is caller-clobbered and is overwritten by the original
            // function before first use. The veneer consumes it as its branch
            // predicate without disturbing r0-r3, SP, LR, or callee-saved regs.
            jit.Regs()[12] = handled ? 1u : 0u;

#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS
            static std::atomic<uint32_t> calls{0};
            static std::atomic<uint32_t> native_calls{0};
            const uint32_t call = calls.fetch_add(1, std::memory_order_relaxed) + 1;
            if (handled) native_calls.fetch_add(1, std::memory_order_relaxed);
            if ((call & (call - 1u)) == 0) {
                LOGI("GetKeyInfo calls=%u native=%u fallback=%u", call,
                     native_calls.load(std::memory_order_relaxed),
                     call - native_calls.load(std::memory_order_relaxed));
            }
#endif
        });
    if (!thunk) {
        LOGE("GetKeyInfo acceleration unavailable: thunk registration failed");
        return false;
    }
    const uint32_t svc = host.MemoryRead32(thunk);
    if ((svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("GetKeyInfo acceleration unavailable: invalid thunk trampoline");
        return false;
    }

    // ARM-mode veneer:
    //   svc handler               ; r12 = native operation handled
    //   cmp   r12, #0
    //   bxne  lr                  ; fast return, preserving the caller's LR
    //   push  {r4-r11, lr}        ; displaced original prologue
    //   sub   sp, sp, #12
    //   ldr   pc, [pc, #-4]       ; continue at original + 8
    //   .word target + 8
    const uint32_t veneer = host.GuestAlloc(32, alignof(uint32_t));
    if (!veneer) {
        LOGE("GetKeyInfo acceleration unavailable: veneer allocation failed");
        return false;
    }
    host.MemoryWrite32(veneer + 0, svc);
    host.MemoryWrite32(veneer + 4, 0xE35C0000u);   // cmp r12, #0
    host.MemoryWrite32(veneer + 8, 0x112FFF1Eu);   // bxne lr
    host.MemoryWrite32(veneer + 12, kGetKeyInfoFingerprint[0]);
    host.MemoryWrite32(veneer + 16, kGetKeyInfoFingerprint[1]);
    host.MemoryWrite32(veneer + 20, 0xE51FF004u);  // ldr pc, [pc, #-4]
    host.MemoryWrite32(veneer + 24, target + 8u);
    host.MemoryWrite32(veneer + 28, 0xE320F000u);  // nop/padding
    host.InvalidateGuestCode(veneer, 32);
    host.AddExecutableRange(veneer, 32);

    // Installation happens before guest initializers start, so no guest thread
    // can observe the two-word entry rewrite half-complete.
    host.MemoryWrite32(target + 4, veneer);
    host.MemoryWrite32(target, 0xE51FF004u);       // ldr pc, [pc, #-4]
    host.InvalidateGuestCode(target, 8);
    LOGI("Installed native PropertySet::GetKeyInfo acceleration at 0x%08X "
         "(loaded parent/nested traversal, veneer 0x%08X)",
         target, veneer);
    return true;
}
