#include "pe_image.h"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace {

std::string narrow(const char* s) { return s ? std::string(s) : std::string(); }

}

bool PeImage::load(const std::string& path, std::string& error) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) {
        error = "cannot open " + path;
        return false;
    }
    _fseeki64(f, 0, SEEK_END);
    long long size = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (size <= 0 || size > (1ll << 32)) {
        fclose(f);
        error = "bad file size";
        return false;
    }
    bytes_.resize(static_cast<size_t>(size));
    size_t got = fread(bytes_.data(), 1, bytes_.size(), f);
    fclose(f);
    if (got != bytes_.size()) {
        error = "short read";
        return false;
    }
    return parseHeaders(error);
}

bool PeImage::parseHeaders(std::string& error) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes_.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "no MZ";
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes_.size()) {
        error = "bad e_lfanew";
        return false;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes_.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error = "no PE signature";
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        error = "not x86-64";
        return false;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = "not PE32+";
        return false;
    }
    preferredBase_ = nt->OptionalHeader.ImageBase;
    entryRva_ = nt->OptionalHeader.AddressOfEntryPoint;
    sizeOfImage_ = nt->OptionalHeader.SizeOfImage;
    sectionAlignment_ = nt->OptionalHeader.SectionAlignment;

    sections_.clear();
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        SectionInfo s;
        char name[9] = {};
        memcpy(name, sec[i].Name, 8);
        s.name = name;
        s.virtualSize = sec[i].Misc.VirtualSize;
        s.rva = sec[i].VirtualAddress;
        s.rawSize = sec[i].SizeOfRawData;
        s.rawPointer = sec[i].PointerToRawData;
        s.characteristics = sec[i].Characteristics;
        sections_.push_back(s);
    }

    directories_.clear();
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        directories_.emplace_back(nt->OptionalHeader.DataDirectory[i].VirtualAddress,
                                  nt->OptionalHeader.DataDirectory[i].Size);
    }
    return parseFunctions();
}

bool PeImage::parseFunctions() {
    const uint32_t rva = directoryRva(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    const uint32_t size = directorySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    functions_.clear();
    if (!rva || size < 12) return true;
    const uint32_t off = rvaToOffset(rva);
    if (off == 0 || off + size > bytes_.size()) return true;
    const auto* rf = reinterpret_cast<const RUNTIME_FUNCTION*>(bytes_.data() + off);
    const size_t count = size / 12;
    functions_.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        FunctionRange r;
        r.begin = rf[i].BeginAddress;
        r.end = rf[i].EndAddress;
        if (r.end > r.begin) functions_.push_back(r);
    }
    std::sort(functions_.begin(), functions_.end(),
              [](const FunctionRange& a, const FunctionRange& b) { return a.begin < b.begin; });
    return true;
}

uint32_t PeImage::directoryRva(int index) const {
    if (index < 0 || static_cast<size_t>(index) >= directories_.size()) return 0;
    return directories_[index].first;
}

uint32_t PeImage::directorySize(int index) const {
    if (index < 0 || static_cast<size_t>(index) >= directories_.size()) return 0;
    return directories_[index].second;
}

uint32_t PeImage::rvaToOffset(uint32_t rva) const {
    for (const auto& s : sections_) {
        const uint32_t span = std::max(s.virtualSize, s.rawSize);
        if (rva >= s.rva && rva < s.rva + span) {
            if (rva - s.rva >= s.rawSize) return 0;  // inside BSS, no file bytes
            return s.rawPointer + (rva - s.rva);
        }
    }
    return 0;
}

bool PeImage::map(uintptr_t preferredBase, std::string& error) {
    // Reserve the whole image at the preferred base so RVA==VA arithmetic holds.
    size_t reserve = sizeOfImage_;
    void* p = VirtualAlloc(reinterpret_cast<void*>(preferredBase), reserve,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) {
        // Fall back to any address; relocations will fix the image up.
        p = VirtualAlloc(nullptr, reserve, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!p) {
            error = "VirtualAlloc failed";
            return false;
        }
    }
    reservation_ = reinterpret_cast<uintptr_t>(p);
    reservationSize_ = reserve;
    base_ = reservation_;
    delta_ = static_cast<int64_t>(base_) - static_cast<int64_t>(preferredBase_);

    // Headers, then sections.
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes_.data());
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes_.data() + dos->e_lfanew);
    memcpy(reinterpret_cast<void*>(base_), bytes_.data(), nt->OptionalHeader.SizeOfHeaders);
    for (const auto& s : sections_) {
        if (!s.rawSize) continue;
        if (s.rawPointer + s.rawSize > bytes_.size()) {
            error = "section outside file: " + s.name;
            return false;
        }
        memcpy(reinterpret_cast<void*>(base_ + s.rva), bytes_.data() + s.rawPointer, s.rawSize);
    }
    return true;
}

bool PeImage::relocate(std::string& error) {
    const uint32_t relocRva = directoryRva(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const uint32_t relocSize = directorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocRva || !relocSize) return true;
    const uint32_t off = rvaToOffset(relocRva);
    if (!off) {
        error = "bad .reloc rva";
        return false;
    }
    uint32_t p = off;
    const uint32_t end = off + relocSize;
    size_t applied = 0, dir64 = 0, other = 0;
    while (p + 8 <= end && p + 8 <= bytes_.size()) {
        uint32_t page = 0, blockSize = 0;
        memcpy(&page, bytes_.data() + p, 4);
        memcpy(&blockSize, bytes_.data() + p + 4, 4);
        if (blockSize < 8) break;
        const uint32_t n = (blockSize - 8) / 2;
        for (uint32_t i = 0; i < n; ++i) {
            uint16_t entry = 0;
            memcpy(&entry, bytes_.data() + p + 8 + 2 * i, 2);
            const uint32_t type = entry >> 12;
            const uint32_t ofs = entry & 0xFFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            uint8_t* target = reinterpret_cast<uint8_t*>(base_ + page + ofs);
            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t value = 0;
                memcpy(&value, target, 8);
                value += delta_;
                memcpy(target, &value, 8);
                ++dir64;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                uint32_t value = 0;
                memcpy(&value, target, 4);
                value += static_cast<uint32_t>(delta_);
                memcpy(target, &value, 4);
                ++other;
            } else {
                ++other;
            }
            ++applied;
        }
        p += blockSize;
    }
    printf("[map] relocations applied: %zu (dir64=%zu, other=%zu), delta=%lld\n",
           applied, dir64, other, static_cast<long long>(delta_));
    return true;
}

bool PeImage::protectSections(std::string& error) {
    for (const auto& s : sections_) {
        DWORD prot = PAGE_READONLY;
        if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) {
            prot = (s.characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (s.characteristics & IMAGE_SCN_MEM_WRITE) {
            prot = PAGE_READWRITE;
        }
        DWORD old = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(base_ + s.rva),
                            std::max<uint32_t>(s.virtualSize, 1), prot, &old)) {
            error = "VirtualProtect failed for " + s.name;
            return false;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(base_), sizeOfImage_);
    return true;
}

const FunctionRange* PeImage::functionByRva(uint32_t rva) const {
    auto it = std::upper_bound(functions_.begin(), functions_.end(), rva,
                               [](uint32_t value, const FunctionRange& f) { return value < f.begin; });
    if (it == functions_.begin()) return nullptr;
    --it;
    if (rva < it->end) return &*it;
    return nullptr;
}

std::string PeImage::describeAddress(uintptr_t address) const {
    if (!base_ || address < base_ || address >= imageEnd()) {
        char buf[64];
        snprintf(buf, sizeof buf, "outside image (%p)", reinterpret_cast<void*>(address));
        return buf;
    }
    const uint32_t rva = static_cast<uint32_t>(address - base_);
    char buf[128];
    const FunctionRange* fn = functionByRva(rva);
    if (fn) {
        snprintf(buf, sizeof buf, "rva 0x%X (function 0x%X+0x%X)", rva, fn->begin,
                 rva - fn->begin);
    } else {
        snprintf(buf, sizeof buf, "rva 0x%X (no function)", rva);
    }
    return buf;
}
