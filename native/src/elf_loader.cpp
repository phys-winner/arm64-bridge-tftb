#include "elf_loader.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <unordered_set>
#include <android/log.h>

#define LOG_TAG "Arm32Bridge_Elf"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

ElfLoader::ElfLoader(uint8_t* guest_memory_base, uint32_t load_base_addr, size_t guest_memory_size)
    : m_guest_mem(guest_memory_base), m_load_base(load_base_addr), m_guest_memory_size(guest_memory_size) {}

ElfLoader::~ElfLoader() = default;

bool ElfLoader::Load(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open() || file.tellg() < 0) {
        LOGE("Failed to open ELF file: %s", filepath.c_str());
        return false;
    }
    size_t file_size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(file_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) return false;
    return LoadFromMemory(buffer.data(), buffer.size());
}

bool ElfLoader::LoadFromMemory(const uint8_t* data, size_t size) {
    m_segments.clear();
    m_symbols.clear();
    m_exported_symbols.clear();
    m_relocations.clear();
    m_imports.clear();
    m_undefined_symbols.clear();
    m_needed_libs.clear();
    m_init_array.clear();
    m_min_vaddr = m_image_size = 0;
    m_strtab_vaddr = m_strtab_size = 0;
    m_init_array_vaddr = m_init_array_size = m_init_func = 0;
    m_relocated = false;
    return data && m_guest_mem && ParseHeader(data, size) &&
           LoadSegments(data, size) && ParseDynamic(data, size);
}

bool ElfLoader::ParseHeader(const uint8_t* data, size_t size) {
    if (size < sizeof(Elf32_Ehdr)) return false;
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS32 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT || ehdr->e_version != EV_CURRENT ||
        ehdr->e_machine != EM_ARM || ehdr->e_type != ET_DYN ||
        ehdr->e_ehsize != sizeof(Elf32_Ehdr) ||
        ehdr->e_phentsize != sizeof(Elf32_Phdr) || !ehdr->e_phnum ||
        ehdr->e_phoff % alignof(Elf32_Phdr) ||
        static_cast<uint64_t>(ehdr->e_phoff) + static_cast<uint64_t>(ehdr->e_phnum) * sizeof(Elf32_Phdr) > size) {
        LOGE("Invalid little-endian ARM ET_DYN header/program table.");
        return false;
    }
    return true;
}

bool ElfLoader::LoadSegments(const uint8_t* data, size_t size) {
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);
    const auto* phdrs = reinterpret_cast<const Elf32_Phdr*>(data + ehdr->e_phoff);
    uint32_t min_vaddr = UINT32_MAX, max_vaddr = 0;
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const auto& ph = phdrs[i];
        if (ph.p_type != PT_LOAD) continue;
        const uint64_t end = static_cast<uint64_t>(ph.p_vaddr) + ph.p_memsz;
        if (ph.p_filesz > ph.p_memsz || static_cast<uint64_t>(ph.p_offset) + ph.p_filesz > size ||
            end + m_load_base > m_guest_memory_size || end + m_load_base > UINT32_MAX) {
            LOGE("Invalid PT_LOAD[%u] bounds.", i);
            return false;
        }
        min_vaddr = std::min(min_vaddr, ph.p_vaddr);
        max_vaddr = std::max(max_vaddr, static_cast<uint32_t>(end));
        m_segments.push_back({ph.p_vaddr, ph.p_memsz, ph.p_filesz, ph.p_flags, ph.p_offset});
    }
    if (m_segments.empty() || max_vaddr <= min_vaddr) return false;
    std::sort(m_segments.begin(), m_segments.end(), [](const ElfSegment& a, const ElfSegment& b) {
        return a.vaddr < b.vaddr;
    });
    for (size_t i = 1; i < m_segments.size(); ++i) {
        if (m_segments[i].vaddr < static_cast<uint64_t>(m_segments[i - 1].vaddr) + m_segments[i - 1].memsz) {
            LOGE("Overlapping PT_LOAD segments.");
            return false;
        }
    }
    const uint64_t rounded_end = (static_cast<uint64_t>(max_vaddr) + 0xFFFu) & ~0xFFFull;
    if (rounded_end + m_load_base > m_guest_memory_size || rounded_end + m_load_base > UINT32_MAX) return false;
    m_min_vaddr = min_vaddr;
    m_image_size = static_cast<uint32_t>(rounded_end - min_vaddr);
    for (const auto& seg : m_segments) {
        uint8_t* dest = m_guest_mem + m_load_base + seg.vaddr;
        if (seg.filesz) memcpy(dest, data + seg.offset, seg.filesz);
        if (seg.memsz > seg.filesz) memset(dest + seg.filesz, 0, seg.memsz - seg.filesz);
    }
    LOGI("Loaded %zu segments at 0x%08X..0x%08X", m_segments.size(), GetImageStart(), GetImageEnd());
    return true;
}

bool ElfLoader::ContainsRange(uint64_t vaddr, uint64_t size) const {
    if (vaddr > UINT32_MAX || size > UINT32_MAX || vaddr + size + m_load_base > m_guest_memory_size) return false;
    for (const auto& seg : m_segments) {
        if (vaddr >= seg.vaddr && vaddr + size <= static_cast<uint64_t>(seg.vaddr) + seg.memsz) return true;
    }
    return false;
}

bool ElfLoader::ReadString(uint32_t offset, std::string& result) const {
    if (offset >= m_strtab_size) return false;
    const char* begin = reinterpret_cast<const char*>(m_guest_mem + m_load_base + m_strtab_vaddr + offset);
    const char* end = static_cast<const char*>(memchr(begin, 0, m_strtab_size - offset));
    if (!end) return false;
    result.assign(begin, end);
    return true;
}

bool ElfLoader::ParseDynamic(const uint8_t* data, size_t size) {
    (void)size;
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);
    const auto* phdrs = reinterpret_cast<const Elf32_Phdr*>(data + ehdr->e_phoff);
    const Elf32_Dyn* dyn = nullptr;
    size_t dyn_count = 0;
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const auto& ph = phdrs[i];
        if (ph.p_type != PT_DYNAMIC) continue;
        if (dyn || ph.p_memsz < sizeof(Elf32_Dyn) || ph.p_memsz % sizeof(Elf32_Dyn) ||
            ph.p_vaddr % alignof(Elf32_Dyn) || !ContainsRange(ph.p_vaddr, ph.p_memsz)) return false;
        dyn = reinterpret_cast<const Elf32_Dyn*>(m_guest_mem + m_load_base + ph.p_vaddr);
        dyn_count = ph.p_memsz / sizeof(Elf32_Dyn);
    }
    if (!dyn) return false;
    uint32_t symtab_addr = 0, syment = sizeof(Elf32_Sym), hash_addr = 0, gnu_hash_addr = 0;
    uint32_t rel_addr = 0, rel_size = 0, plt_addr = 0, plt_size = 0, relent = sizeof(Elf32_Rel);
    uint32_t versym_addr = 0, verneed_addr = 0, verneed_count = 0, verdef_addr = 0, verdef_count = 0;
    bool found_null = false, has_rela = false, plt_rel = true;
    std::vector<uint32_t> needed_offsets;
    for (size_t i = 0; i < dyn_count; ++i) {
        const auto& d = dyn[i];
        if (d.d_tag == DT_NULL) { found_null = true; break; }
        switch (d.d_tag) {
            case DT_STRTAB: m_strtab_vaddr = d.d_un.d_ptr; break;
            case DT_STRSZ: m_strtab_size = d.d_un.d_val; break;
            case DT_SYMTAB: symtab_addr = d.d_un.d_ptr; break;
            case DT_SYMENT: syment = d.d_un.d_val; break;
            case DT_HASH: hash_addr = d.d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash_addr = d.d_un.d_ptr; break;
            case DT_REL: rel_addr = d.d_un.d_ptr; break;
            case DT_RELSZ: rel_size = d.d_un.d_val; break;
            case DT_RELENT: relent = d.d_un.d_val; break;
            case DT_JMPREL: plt_addr = d.d_un.d_ptr; break;
            case DT_PLTRELSZ: plt_size = d.d_un.d_val; break;
            case DT_INIT: m_init_func = d.d_un.d_ptr; break;
            case DT_INIT_ARRAY: m_init_array_vaddr = d.d_un.d_ptr; break;
            case DT_INIT_ARRAYSZ: m_init_array_size = d.d_un.d_val; break;
            case DT_NEEDED: needed_offsets.push_back(d.d_un.d_val); break;
            case DT_RELA: case DT_RELASZ: has_rela = true; break;
            case DT_PLTREL: plt_rel = d.d_un.d_val == DT_REL; break;
            case DT_VERSYM: versym_addr = d.d_un.d_ptr; break;
            case DT_VERNEED: verneed_addr = d.d_un.d_ptr; break;
            case DT_VERNEEDNUM: verneed_count = d.d_un.d_val; break;
            case DT_VERDEF: verdef_addr = d.d_un.d_ptr; break;
            case DT_VERDEFNUM: verdef_count = d.d_un.d_val; break;
            default: break;
        }
    }
    if (!found_null || has_rela || !plt_rel || syment != sizeof(Elf32_Sym) || relent != sizeof(Elf32_Rel) ||
        !m_strtab_size || !ContainsRange(m_strtab_vaddr, m_strtab_size) || symtab_addr % alignof(Elf32_Sym)) {
        LOGE("Invalid/unsupported dynamic table (RELA=%d PLT_REL=%d).", has_rela, plt_rel);
        return false;
    }
    for (uint32_t offset : needed_offsets) {
        std::string needed;
        if (!ReadString(offset, needed) || needed.empty()) return false;
        m_needed_libs.push_back(needed);
    }

    // DT_HASH/GNU_HASH define the symbol count; table placement does not.
    uint32_t sym_count = 0;
    if (hash_addr) {
        if (hash_addr % 4 || !ContainsRange(hash_addr, 8)) return false;
        const auto* hash = reinterpret_cast<const uint32_t*>(m_guest_mem + m_load_base + hash_addr);
        if (!ContainsRange(hash_addr, (2ull + hash[0] + hash[1]) * 4)) return false;
        sym_count = hash[1];
    } else if (gnu_hash_addr) {
        if (gnu_hash_addr % 4 || !ContainsRange(gnu_hash_addr, 16)) return false;
        const auto* hash = reinterpret_cast<const uint32_t*>(m_guest_mem + m_load_base + gnu_hash_addr);
        const uint32_t buckets = hash[0], first_symbol = hash[1], bloom_size = hash[2];
        const uint64_t bucket_addr = static_cast<uint64_t>(gnu_hash_addr) + 16 + static_cast<uint64_t>(bloom_size) * 4;
        const uint64_t chain_addr = bucket_addr + static_cast<uint64_t>(buckets) * 4;
        if (!bloom_size || !ContainsRange(gnu_hash_addr, chain_addr - gnu_hash_addr)) return false;
        sym_count = first_symbol;
        for (uint32_t i = 0; i < buckets; ++i) {
            uint32_t index;
            memcpy(&index, m_guest_mem + m_load_base + bucket_addr + i * 4ull, 4);
            if (!index) continue;
            if (index < first_symbol) return false;
            for (;;) {
                const uint64_t addr = chain_addr + static_cast<uint64_t>(index - first_symbol) * 4;
                if (index == UINT32_MAX || !ContainsRange(addr, 4)) return false;
                uint32_t chain;
                memcpy(&chain, m_guest_mem + m_load_base + addr, 4);
                sym_count = std::max(sym_count, ++index);
                if (chain & 1) break;
            }
        }
    }
    if (!sym_count || !ContainsRange(symtab_addr, static_cast<uint64_t>(sym_count) * sizeof(Elf32_Sym)) ||
        (versym_addr && (versym_addr % 2 || !ContainsRange(versym_addr, static_cast<uint64_t>(sym_count) * 2)))) {
        LOGE("Invalid dynamic symbol count/table.");
        return false;
    }

    struct Version { std::string name, library; bool definition; };
    std::unordered_map<uint16_t, Version> versions;
    if ((verneed_addr == 0) != (verneed_count == 0) || (verdef_addr == 0) != (verdef_count == 0)) return false;
    uint64_t cursor = verneed_addr;
    for (uint32_t i = 0; i < verneed_count; ++i) {
        if (cursor % 4 || !ContainsRange(cursor, sizeof(Elf32_Verneed))) return false;
        Elf32_Verneed need;
        memcpy(&need, m_guest_mem + m_load_base + cursor, sizeof(need));
        std::string library;
        if (need.vn_version != 1 || !need.vn_cnt || !need.vn_aux || !ReadString(need.vn_file, library) ||
            std::find(m_needed_libs.begin(), m_needed_libs.end(), library) == m_needed_libs.end()) return false;
        uint64_t aux_addr = cursor + need.vn_aux;
        for (uint16_t j = 0; j < need.vn_cnt; ++j) {
            if (aux_addr % 4 || !ContainsRange(aux_addr, sizeof(Elf32_Vernaux))) return false;
            Elf32_Vernaux aux;
            memcpy(&aux, m_guest_mem + m_load_base + aux_addr, sizeof(aux));
            std::string name;
            const uint16_t index = aux.vna_other & 0x7FFF;
            if (index < 2 || !ReadString(aux.vna_name, name) || name.empty() ||
                !versions.emplace(index, Version{name, library, false}).second) return false;
            if (j + 1 < need.vn_cnt && !aux.vna_next) return false;
            aux_addr += aux.vna_next;
        }
        if (i + 1 < verneed_count && !need.vn_next) return false;
        cursor += need.vn_next;
    }
    cursor = verdef_addr;
    for (uint32_t i = 0; i < verdef_count; ++i) {
        if (cursor % 4 || !ContainsRange(cursor, sizeof(Elf32_Verdef))) return false;
        Elf32_Verdef def;
        memcpy(&def, m_guest_mem + m_load_base + cursor, sizeof(def));
        const uint64_t aux_addr = cursor + def.vd_aux;
        if (def.vd_version != 1 || !def.vd_cnt || !def.vd_aux || aux_addr % 4 ||
            !ContainsRange(aux_addr, sizeof(Elf32_Verdaux))) return false;
        Elf32_Verdaux aux;
        memcpy(&aux, m_guest_mem + m_load_base + aux_addr, sizeof(aux));
        std::string name;
        const uint16_t index = def.vd_ndx & 0x7FFF;
        if (!ReadString(aux.vda_name, name) || name.empty()) return false;
        if (index >= 2 && !versions.emplace(index, Version{name, "", true}).second) return false;
        if (i + 1 < verdef_count && !def.vd_next) return false;
        cursor += def.vd_next;
    }

    const auto* symtab = reinterpret_cast<const Elf32_Sym*>(m_guest_mem + m_load_base + symtab_addr);
    for (uint32_t i = 0; i < sym_count; ++i) {
        const auto& sym = symtab[i];
        ElfSymbol entry;
        if (!ReadString(sym.st_name, entry.name)) return false;
        entry.value = sym.st_shndx == SHN_UNDEF ? 0 : sym.st_value + (sym.st_shndx == SHN_ABS ? 0 : m_load_base);
        entry.size = sym.st_size;
        entry.bind = ELF32_ST_BIND(sym.st_info);
        entry.type = ELF32_ST_TYPE(sym.st_info);
        entry.shndx = sym.st_shndx;
        entry.visibility = sym.st_other & 3u;
        if (versym_addr) {
            uint16_t raw;
            memcpy(&raw, m_guest_mem + m_load_base + versym_addr + i * 2ull, 2);
            entry.version_index = raw & 0x7FFF;
            entry.version_hidden = (raw & 0x8000) != 0;
            if (entry.version_index >= 2) {
                auto version = versions.find(entry.version_index);
                if (version == versions.end() || version->second.definition == (sym.st_shndx == SHN_UNDEF)) return false;
                entry.version = version->second.name;
                entry.version_library = version->second.library;
            }
        }
        m_symbols.push_back(entry);
        if (entry.name.empty()) continue;
        if (sym.st_shndx == SHN_UNDEF) m_undefined_symbols.push_back(entry.name);
        else if ((entry.bind == STB_GLOBAL || entry.bind == STB_WEAK) &&
                 (entry.visibility == STV_DEFAULT || entry.visibility == STV_PROTECTED) &&
                 (!versym_addr || entry.version_index != 0)) {
            m_exported_symbols.emplace(entry.name, i);
        }
    }

    std::unordered_set<uint32_t> relocation_addresses;
    for (const auto& table : {std::pair<uint32_t, uint32_t>{rel_addr, rel_size}, {plt_addr, plt_size}}) {
        if (!table.second) continue;
        if (!table.first || table.first % alignof(Elf32_Rel) || table.second % sizeof(Elf32_Rel) ||
            !ContainsRange(table.first, table.second)) return false;
        const auto* rels = reinterpret_cast<const Elf32_Rel*>(m_guest_mem + m_load_base + table.first);
        for (uint32_t i = 0; i < table.second / sizeof(Elf32_Rel); ++i) {
            // DT_JMPREL may be included in DT_REL. Process that entry once.
            if (!relocation_addresses.insert(table.first + i * sizeof(Elf32_Rel)).second) continue;
            const auto& rel = rels[i];
            if (ELF32_R_TYPE(rel.r_info) == R_ARM_NONE) continue;
            const uint32_t symbol_index = ELF32_R_SYM(rel.r_info);
            if (symbol_index >= m_symbols.size() || rel.r_offset % 4 || !ContainsRange(rel.r_offset, 4)) {
                LOGE("Invalid relocation target/symbol (target=0x%08X symbol=%u).", rel.r_offset, symbol_index);
                return false;
            }
            m_relocations.push_back(rel);
            if (symbol_index && m_symbols[symbol_index].shndx == SHN_UNDEF) m_imports.push_back(MakeImport(symbol_index, rel));
        }
    }
    if (m_init_array_size % 4 || (m_init_array_size &&
        (m_init_array_vaddr % 4 || !ContainsRange(m_init_array_vaddr, m_init_array_size))) ||
        (m_init_func && !ContainsRange(m_init_func & ~1u, 2))) return false;
    LOGI("Parsed %zu exports, %zu undefined symbols, %zu relocation imports, %zu dependencies, %zu versions",
         m_exported_symbols.size(), m_undefined_symbols.size(), m_imports.size(), m_needed_libs.size(), versions.size());
    return true;
}

ElfImport ElfLoader::MakeImport(uint32_t symbol_index, const Elf32_Rel& rel) const {
    const auto& sym = m_symbols[symbol_index];
    ElfImport import;
    import.name = sym.name;
    import.symbol_index = symbol_index;
    import.relocation_type = ELF32_R_TYPE(rel.r_info);
    import.target_address = m_load_base + rel.r_offset;
    import.size = sym.size;
    import.bind = sym.bind;
    import.type = sym.type;
    import.visibility = sym.visibility;
    import.version_index = sym.version_index;
    import.version_hidden = sym.version_hidden;
    import.version = sym.version;
    import.version_library = sym.version_library;
    return import;
}

bool ElfLoader::Relocate(const SymbolResolver& resolver) {
    if (m_relocated) return true;
    return ProcessRelocations(resolver);
}

bool ElfLoader::ProcessRelocations(const SymbolResolver& resolver) {
    bool ok = true;
    size_t missing_strong = 0, weak_zero = 0;
    std::vector<std::pair<uint32_t, uint32_t>> writes;
    for (const auto& rel : m_relocations) {
        const uint32_t type = ELF32_R_TYPE(rel.r_info), symbol_index = ELF32_R_SYM(rel.r_info);
        uint32_t value = 0, addend;
        memcpy(&addend, m_guest_mem + m_load_base + rel.r_offset, 4);
        if (symbol_index) {
            const auto& sym = m_symbols[symbol_index];
            if (sym.shndx != SHN_UNDEF) value = sym.value;
            else {
                const ElfImport import = MakeImport(symbol_index, rel);
                value = resolver(import);
                if (!value && import.bind != STB_WEAK) {
                    LOGE("Unresolved strong import name='%s' type=%u bind=%u visibility=%u version='%s' library='%s' symbol=%u reloc=%u target=0x%08X",
                         import.name.c_str(), import.type, import.bind, import.visibility, import.version.c_str(),
                         import.version_library.c_str(), symbol_index, type, import.target_address);
                    ++missing_strong;
                    ok = false;
                } else if (!value) ++weak_zero;
            }
        }
        switch (type) {
            case R_ARM_RELATIVE:
                if (symbol_index) { ok = false; LOGE("R_ARM_RELATIVE has a symbol."); }
                value = addend + m_load_base;
                break;
            case R_ARM_GLOB_DAT: case R_ARM_JUMP_SLOT: break;
            case R_ARM_ABS32: value += addend; break;
            case R_ARM_REL32: value += addend - (m_load_base + rel.r_offset); break;
            default: LOGE("Unsupported relocation type: %u target=0x%08X", type, m_load_base + rel.r_offset); ok = false; break;
        }
        writes.emplace_back(rel.r_offset, value);
    }
    LOGI("Relocation audit base=0x%08X imports=%zu missing-strong=%zu weak-zero=%zu result=%s",
         m_load_base, m_imports.size(), missing_strong, weak_zero, ok ? "OK" : "FAILED");
    (void)missing_strong;
    (void)weak_zero;
    if (!ok) return false;
    for (const auto& [offset, value] : writes) memcpy(m_guest_mem + m_load_base + offset, &value, 4);
    // Constructor slots must be read after relocation, including imported constructors.
    m_init_array.clear();
    for (uint32_t offset = 0; offset < m_init_array_size; offset += 4) {
        uint32_t init;
        memcpy(&init, m_guest_mem + m_load_base + m_init_array_vaddr + offset, 4);
        if (init && init != UINT32_MAX) m_init_array.push_back(init);
    }
    m_relocated = true;
    return true;
}

uint32_t ElfLoader::GetSymbolAddress(const std::string& name) const {
    const auto* symbol = GetExportedSymbol(name);
    return symbol ? symbol->value : 0;
}

const ElfSymbol* ElfLoader::GetExportedSymbol(const std::string& name, const std::string& version) const {
    const auto range = m_exported_symbols.equal_range(name);
    const ElfSymbol* result = nullptr;
    for (auto it = range.first; it != range.second; ++it) {
        const auto& symbol = m_symbols[it->second];
        if (version.empty() ? symbol.version_hidden : symbol.version != version) continue;
        if (!result || (result->bind == STB_WEAK && symbol.bind == STB_GLOBAL)) result = &symbol;
    }
    return result;
}
