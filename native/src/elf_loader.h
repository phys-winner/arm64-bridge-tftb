#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <elf.h>

struct ElfSegment {
    uint32_t vaddr;
    uint32_t memsz;
    uint32_t filesz;
    uint32_t flags;
    uint32_t offset;
};

struct ElfSymbol {
    std::string name;
    uint32_t value = 0;
    uint32_t size = 0;
    uint8_t bind = 0;
    uint8_t type = 0;
    uint16_t shndx = 0;
    uint8_t visibility = 0;
    uint16_t version_index = 0;
    bool version_hidden = false;
    std::string version;
    std::string version_library;
};

struct ElfImport {
    std::string name;
    uint32_t symbol_index;
    uint32_t relocation_type;
    uint32_t target_address;
    uint32_t size;
    uint8_t bind;
    uint8_t type;
    uint8_t visibility = 0;
    uint16_t version_index = 0;
    bool version_hidden = false;
    std::string version;
    std::string version_library;
};

using SymbolResolver = std::function<uint32_t(const ElfImport& import)>;

class ElfLoader {
public:
    ElfLoader(uint8_t* guest_memory_base, uint32_t load_base_addr = 0x40000000,
              size_t guest_memory_size = 0x100000000ULL);
    ~ElfLoader();

    bool Load(const std::string& filepath);
    bool LoadFromMemory(const uint8_t* data, size_t size);
    bool Relocate(const SymbolResolver& resolver);

    uint32_t GetSymbolAddress(const std::string& name) const;
    const ElfSymbol* GetExportedSymbol(const std::string& name, const std::string& version = "") const;
    const std::vector<ElfImport>& GetImports() const { return m_imports; }
    uint32_t GetBaseAddress() const { return m_load_base; }
    uint32_t GetImageStart() const { return m_load_base + m_min_vaddr; }
    uint32_t GetImageSize() const { return m_image_size; }
    uint32_t GetImageEnd() const { return GetImageStart() + m_image_size; }
    uint32_t GetInitFunction() const { return m_init_func ? m_load_base + m_init_func : 0; }
    const std::vector<ElfSegment>& GetSegments() const { return m_segments; }
    const std::vector<uint32_t>& GetInitArray() const { return m_init_array; }
    const std::vector<std::string>& GetNeededLibraries() const { return m_needed_libs; }
    const std::vector<std::string>& GetUndefinedSymbols() const { return m_undefined_symbols; }

private:
    bool ParseHeader(const uint8_t* data, size_t size);
    bool LoadSegments(const uint8_t* data, size_t size);
    bool ParseDynamic(const uint8_t* data, size_t size);
    bool ProcessRelocations(const SymbolResolver& resolver);
    bool ContainsRange(uint64_t vaddr, uint64_t size) const;
    bool ReadString(uint32_t offset, std::string& result) const;
    ElfImport MakeImport(uint32_t symbol_index, const Elf32_Rel& rel) const;

    uint8_t* m_guest_mem;
    uint32_t m_load_base;
    size_t m_guest_memory_size;
    uint32_t m_min_vaddr = 0;
    uint32_t m_image_size = 0;

    std::vector<ElfSegment> m_segments;
    std::vector<ElfSymbol> m_symbols;
    std::unordered_multimap<std::string, size_t> m_exported_symbols;
    std::vector<Elf32_Rel> m_relocations;
    std::vector<ElfImport> m_imports;
    std::vector<std::string> m_undefined_symbols;
    std::vector<std::string> m_needed_libs;
    std::vector<uint32_t> m_init_array;
    uint32_t m_init_array_vaddr = 0;
    uint32_t m_init_array_size = 0;
    uint32_t m_init_func = 0;
    bool m_relocated = false;

    uint32_t m_strtab_vaddr = 0;
    uint32_t m_strtab_size = 0;
};
