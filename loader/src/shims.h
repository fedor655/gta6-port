#pragma once

#include <cstdint>
#include <string>
#include <vector>

class PeImage;

enum class BindingKind {
    Real,      // trace thunk: logs the call, then jumps to the real function
    Stub,      // generated thunk that logs and returns 0
    XboxDll,   // Xbox-only DLL that we cannot LoadLibrary; all imports stubbed
    Handler,   // our own implementation (CreateThread and friends)
};

// Hands the main-thread TLS state to the shims so newly created threads get
// the same block installed into their TEB.
void shimSetTlsState(unsigned long slot, void* block, size_t blockSize,
                     const void* templateSrc, size_t templateSize);

struct ImportBinding {
    std::string dll;
    std::string name;
    BindingKind kind = BindingKind::Stub;
    void* target = nullptr;
    uintptr_t iatAddress = 0;
    uint64_t calls = 0;
};

class Imports {
public:
    bool bind(PeImage& image, const std::string& gameDir, bool verbose, std::string& error);
    void printSummary() const;

    const std::vector<ImportBinding>& bindings() const { return bindings_; }
    std::string describeIat(uintptr_t address) const;
    std::string describeTarget(uintptr_t target) const;
    uint64_t totalCalls() const;

private:
    void* makeStub(uint64_t id, const std::string& dll, const std::string& name);
    void* makeTraceStub(uint64_t id, const std::string& dll, const std::string& name,
                        void* realTarget);
    std::vector<ImportBinding> bindings_;
    std::string gameDir_;
};
