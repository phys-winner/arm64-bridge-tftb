// Build with the recorded Android NDK; run on the explicit Xiaomi test device.
#include "elf_loader.h"
#include <cassert>
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {
constexpr uint32_t base = 0x1000, dynamic_addr = 0x200, hash_addr = 0x400;
constexpr uint32_t str_addr = 0x500, sym_addr = 0x800, rel_addr = 0xA00;
constexpr uint32_t ver_addr = 0xB00, need_addr = 0xC00;

struct Fixture {
    std::vector<uint8_t> file = std::vector<uint8_t>(0x3000);
    std::vector<uint8_t> memory = std::vector<uint8_t>(0x8000, 0xCC);
    std::vector<Elf32_Dyn> dynamic;
    uint32_t string_size = 1;
    template<class T> void put(uint32_t offset, const T& value) {
        assert(offset + sizeof(T) <= file.size());
        memcpy(file.data() + offset, &value, sizeof(T));
    }
    uint32_t text(const char* value) {
        const uint32_t offset = string_size;
        memcpy(file.data() + str_addr + offset, value, strlen(value) + 1);
        string_size += strlen(value) + 1;
        return offset;
    }
    void tag(int32_t type, uint32_t value) {
        Elf32_Dyn entry{}; entry.d_tag = type; entry.d_un.d_val = value;
        dynamic.push_back(entry);
    }
    Fixture(bool gnu_hash = false) {
        Elf32_Ehdr header{};
        memcpy(header.e_ident, ELFMAG, SELFMAG);
        header.e_ident[EI_CLASS] = ELFCLASS32;
        header.e_ident[EI_DATA] = ELFDATA2LSB;
        header.e_ident[EI_VERSION] = EV_CURRENT;
        header.e_version = EV_CURRENT;
        header.e_ehsize = sizeof(header);
        header.e_type = ET_DYN; header.e_machine = EM_ARM;
        header.e_phoff = sizeof(header); header.e_phentsize = sizeof(Elf32_Phdr); header.e_phnum = 2;
        put(0, header);
        const char* names[] = {"", "required", "weak", "call", "hidden", "data", "absolute"};
        for (uint32_t i = 0; i < 7; ++i) {
            Elf32_Sym sym{};
            if (i) {
                sym.st_name = text(names[i]);
                sym.st_info = ELF32_ST_INFO(i == 2 ? STB_WEAK : STB_GLOBAL, i >= 5 ? STT_OBJECT : STT_FUNC);
                sym.st_shndx = i < 3 ? SHN_UNDEF : i == 6 ? SHN_ABS : 1;
                sym.st_value = i < 3 ? 0 : i == 6 ? 0x55 : 0x1100 + (i - 3) * 0x20;
                if (i == 4) sym.st_other = STV_HIDDEN;
            }
            put(sym_addr + i * sizeof(sym), sym);
            put<uint16_t>(ver_addr + i * 2, i == 1 ? 2 : i ? 1 : 0);
        }
        const uint32_t library = text("libc.so"), version = text("LIBC");
        Elf32_Verneed need{}; need.vn_version = 1; need.vn_cnt = 1; need.vn_file = library; need.vn_aux = sizeof(need);
        put(need_addr, need);
        Elf32_Vernaux aux{}; aux.vna_other = 2; aux.vna_name = version;
        put(need_addr + sizeof(need), aux);
        if (gnu_hash) {
            const uint32_t hash[] = {1, 3, 1, 0, 0, 3, 0, 0, 0, 1};
            memcpy(file.data() + hash_addr, hash, sizeof(hash));
        } else {
            const uint32_t hash[] = {1, 7, 0, 0, 0, 0, 0, 0, 0, 0};
            memcpy(file.data() + hash_addr, hash, sizeof(hash));
        }
        const Elf32_Rel rels[] = {
            {0x1400, ELF32_R_INFO(1, R_ARM_GLOB_DAT)},
            {0x1404, ELF32_R_INFO(2, R_ARM_GLOB_DAT)},
            {0x1500, ELF32_R_INFO(0, R_ARM_RELATIVE)},
            {0x1408, ELF32_R_INFO(6, R_ARM_ABS32)},
        };
        memcpy(file.data() + rel_addr, rels, sizeof(rels));
        put<uint32_t>(0x1400, 0xAABBCCDD); put<uint32_t>(0x1404, 99);
        put<uint32_t>(0x1408, 7); put<uint32_t>(0x1500, 0x1100);
        tag(DT_STRTAB, str_addr); tag(DT_STRSZ, string_size);
        tag(DT_SYMTAB, sym_addr); tag(DT_SYMENT, sizeof(Elf32_Sym));
        tag(gnu_hash ? DT_GNU_HASH : DT_HASH, hash_addr);
        tag(DT_REL, rel_addr); tag(DT_RELSZ, sizeof(rels)); tag(DT_RELENT, sizeof(Elf32_Rel));
        tag(DT_VERSYM, ver_addr); tag(DT_VERNEED, need_addr); tag(DT_VERNEEDNUM, 1);
        tag(DT_NEEDED, library); tag(DT_INIT_ARRAY, 0x1500); tag(DT_INIT_ARRAYSZ, 4); tag(DT_NULL, 0);
        finish();
    }
    void finish() {
        memcpy(file.data() + dynamic_addr, dynamic.data(), dynamic.size() * sizeof(Elf32_Dyn));
        Elf32_Phdr load{}; load.p_type = PT_LOAD; load.p_filesz = load.p_memsz = file.size(); load.p_flags = PF_R | PF_W | PF_X;
        put(sizeof(Elf32_Ehdr), load);
        Elf32_Phdr dyn{}; dyn.p_type = PT_DYNAMIC; dyn.p_vaddr = dyn.p_offset = dynamic_addr;
        dyn.p_filesz = dyn.p_memsz = dynamic.size() * sizeof(Elf32_Dyn);
        put(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr), dyn);
    }
    uint32_t word(uint32_t offset) const {
        uint32_t result; memcpy(&result, memory.data() + base + offset, 4); return result;
    }
};
}

int main(int argc, char** argv) {
    // Reject malformed identity fields before copying any segment into guest memory.
    for (int bad = 0; bad < 3; ++bad) {
        Fixture f;
        if (bad == 0) f.file[EI_VERSION] = EV_NONE;
        if (bad == 1) f.put<uint32_t>(offsetof(Elf32_Ehdr, e_version), EV_NONE);
        if (bad == 2) f.put<uint16_t>(offsetof(Elf32_Ehdr, e_ehsize), sizeof(Elf32_Ehdr) - 1);
        ElfLoader loader(f.memory.data(), base, f.memory.size());
        if (loader.LoadFromMemory(f.file.data(), f.file.size())) {
            fprintf(stderr, "FAIL malformed ELF header case %d was accepted\n", bad);
            return 1;
        }
        assert(std::all_of(f.memory.begin(), f.memory.end(), [](uint8_t byte) { return byte == 0xCC; }));
    }
    for (bool gnu : {false, true}) {
        Fixture f(gnu);
        ElfLoader loader(f.memory.data(), base, f.memory.size());
        assert(loader.LoadFromMemory(f.file.data(), f.file.size()));
        const auto& imports = loader.GetImports();
        assert(imports.size() == 2 && imports[0].name == "required" && imports[0].symbol_index == 1);
        assert(imports[0].version == "LIBC" && imports[0].version_index == 2 && imports[0].version_library == "libc.so");
        assert(imports[0].type == STT_FUNC && imports[0].target_address == base + 0x1400);
        assert(imports[1].bind == STB_WEAK && imports[1].version.empty());
        assert(loader.GetSymbolAddress("call") == base + 0x1100);
        assert(!loader.GetExportedSymbol("call", "LIBC") && !loader.GetExportedSymbol("hidden"));
        assert(loader.GetSymbolAddress("absolute") == 0x55);
        unsigned calls = 0;
        assert(!loader.Relocate([&](const ElfImport&) { ++calls; return 0; }));
        assert(calls == 2 && f.word(0x1400) == 0xAABBCCDD && f.word(0x1404) == 99 && f.word(0x1500) == 0x1100);
        assert(loader.Relocate([](const ElfImport& import) { return import.name == "required" ? 0x2001u : 0u; }));
        assert(f.word(0x1400) == 0x2001 && f.word(0x1404) == 0 && f.word(0x1408) == 0x5C);
        assert(loader.GetInitArray() == std::vector<uint32_t>{base + 0x1100});
        assert(loader.Relocate([](const ElfImport&) { assert(false); return 0u; }));
        assert(f.word(0x1500) == base + 0x1100);
    }
    for (int bad = 0; bad < 5; ++bad) {
        Fixture f;
        if (bad == 0) f.put<uint32_t>(sym_addr + sizeof(Elf32_Sym), UINT32_MAX); // string offset
        if (bad == 1) f.put<uint16_t>(ver_addr + 2, 9); // undefined version index
        if (bad == 2) f.put<Elf32_Rel>(rel_addr, {0x4000, ELF32_R_INFO(1, R_ARM_GLOB_DAT)});
        if (bad == 3) { f.dynamic[4].d_tag = DT_RELA; f.finish(); }
        if (bad == 4) f.put<uint32_t>(hash_addr + 4, UINT32_MAX); // count overflow
        ElfLoader loader(f.memory.data(), base, f.memory.size());
        assert(!loader.LoadFromMemory(f.file.data(), f.file.size()));
    }
    // Optional actual immutable guests: parse every image, without executing it.
    std::vector<uint8_t> memory(0x2000000);
    for (int i = 1; i < argc; ++i) {
        ElfLoader loader(memory.data(), 0x10000, memory.size());
        assert(loader.Load(argv[i]));
        printf("guest=%s imports=%zu dependencies=%zu\n", argv[i], loader.GetImports().size(), loader.GetNeededLibraries().size());
    }
    puts("ElfLoader checks OK: header identity, hashes, bounds, type/visibility/version metadata, complete failures, weak zero, constructors");
}
