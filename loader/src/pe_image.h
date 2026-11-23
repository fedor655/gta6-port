#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct SectionInfo {
    std::string name;
    uint32_t rva = 0;
    uint32_t virtualSize = 0;
    uint32_t rawSize = 0;
    uint32_t rawPointer = 0;
    uint32_t characteristics = 0;
};

struct FunctionRange {
    uint32_t begin = 0;
    uint32_t end = 0;
};

class PeImage {
public:
    bool load(const std::string& path, std::string& error);
    bool map(uintptr_t preferredBase, std::string& error);
    bool relocate(std::string& error);
    bool protectSections(std::string& error);

    const FunctionRange* functionByRva(uint32_t rva) const;
    std::string describeAddress(uintptr_t address) const;

    uintptr_t base() const { return base_; }
    uintptr_t imageEnd() const { return base_ + sizeOfImage(); }
    uint32_t entryPoint() const { return entryRva_; }
    uint32_t sizeOfImage() const { return sizeOfImage_; }
    uint64_t preferredImageBase() const { return preferredBase_; }
    uint64_t delta() const { return delta_; }
    bool isMapped() const { return base_ != 0; }

    const std::vector<SectionInfo>& sections() const { return sections_; }
    const std::vector<FunctionRange>& functions() const { return functions_; }
    std::vector<uint8_t>& bytes() { return bytes_; }
    const std::vector<uint8_t>& bytes() const { return bytes_; }

    // Directories (RVAs and sizes), indexed by IMAGE_DIRECTORY_ENTRY_*.
    uint32_t directoryRva(int index) const;
    uint32_t directorySize(int index) const;
    uint32_t rvaToOffset(uint32_t rva) const;

    template <typename T>
    T* atRva(uint32_t rva) { return reinterpret_cast<T*>(base_ + rva); }

private:
    bool parseHeaders(std::string& error);
    bool parseFunctions();

    std::vector<uint8_t> bytes_;
    std::vector<SectionInfo> sections_;
    std::vector<FunctionRange> functions_;
    std::vector<std::pair<uint32_t, uint32_t>> directories_;
    uintptr_t base_ = 0;
    uint64_t preferredBase_ = 0;
    int64_t delta_ = 0;
    uint32_t entryRva_ = 0;
    uint32_t sizeOfImage_ = 0;
    uint32_t sectionAlignment_ = 0;
    uintptr_t reservation_ = 0;
    size_t reservationSize_ = 0;
};
