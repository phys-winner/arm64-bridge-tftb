#pragma once
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

// TFTB's Lua5.2 uses 8-byte TValue, single-precision numbers and 32-bit pointers.
inline int DecodeTelltaleFpsArg(const uint8_t* memory, size_t extent,
                              uint32_t state, uint32_t callback) noexcept {
    auto valid = [extent](uint32_t address, uint64_t size) {
        return address && !(address & 3u) && address <= extent && size <= extent - address;
    };
    auto read = [memory](uint32_t address) {
        uint32_t value;
        std::memcpy(&value, memory + address, sizeof(value));
        return value;
    };
    if (!memory || !callback || !valid(state, 20)) return 60;
    const uint32_t top = read(state + 8), ci = read(state + 16);
    if (!valid(ci, 4)) return 60;
    const uint32_t function = read(ci);
    if (!valid(function, 16) || uint64_t(function) + 16 != top ||
        read(function) != callback || read(function + 4) != 22 ||
        read(function + 12) != 3) return 60;
    float value;
    std::memcpy(&value, memory + function + 8, sizeof(value));
    if (!std::isfinite(value)) return 60;
    return value == 0 || value == 30 || value == 45 || value == 60
        ? static_cast<int>(value) : 60;
}
