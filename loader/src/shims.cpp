#include "shims.h"

#include "pe_image.h"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>

namespace {

const std::set<std::string> kXboxOnlyDlls = {
    "xmem.dll", "xapu.dll", "xg_xs.dll", "AcpHal.dll", "XCRDAPI.dll", "chad.dll",
    "d3d12_xs.dll", "Bink2Scarlett.dll", "amd_fidelityfx_loader_xbox.dll",
    "amd_fidelityfx_upscaler_xbox.dll", "libHttpClient.GDK.dll", "XboxBvhBuilder.dll",
    "GameInput.dll",
};

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return s;
}

std::mutex g_logMutex;
std::vector<std::string>* g_names = nullptr;
uint64_t g_callLimit = 0;
bool g_traceStubs = false;

}  // namespace

extern "C" const char* g_lastShimName = "";
extern "C" uint64_t g_shimCalls = 0;

// Called by every generated stub. `id` indexes the binding table.
extern "C" uint64_t Gta6ShimCall(uint64_t id, uint64_t a, uint64_t b, uint64_t c) {
    ++g_shimCalls;
    auto& names = *g_names;
    if (id >= names.size()) {
        printf("[stub-oor] id=%llu of %zu\n", static_cast<unsigned long long>(id), names.size());
        return 0;
    }
    static uint64_t counter = 0;
    ++counter;
    if (g_callLimit && counter > g_callLimit) {
        fprintf(stderr, "[stub] call limit reached (%llu)\n",
                static_cast<unsigned long long>(g_callLimit));
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), 0x5B0B);
    }
    const std::string& name = names[static_cast<size_t>(id)];
    g_lastShimName = name.c_str();

    printf("[stub] %s(0x%llX, 0x%llX, 0x%llX)\n", name.c_str(),
           static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
           static_cast<unsigned long long>(c));

    // First real shims: the CRT reserves the console's 16 GiB address space
    // through xmem before anything else runs.
    if (name == "xmem.dll!XMemVirtualAlloc") {
        const uint64_t size = b & 0xFFFFFFFFFFFFull;
        const DWORD flags = static_cast<DWORD>(c & 0xFFFFFFFFull);
        DWORD type = flags & (MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN);
        if (!type) type = size >= 0x100000000ull ? MEM_RESERVE : (MEM_COMMIT | MEM_RESERVE);
        // A bare reservation must not be committed: the console's layout asks for
        // tens of GiB and PC commit charge would run out.
        if (size >= 0x100000000ull && !a) type = MEM_RESERVE;
        void* p = VirtualAlloc(reinterpret_cast<void*>(a), static_cast<size_t>(size),
                               type, PAGE_READWRITE);
        if (!p && type != (MEM_COMMIT | MEM_RESERVE)) {
            p = VirtualAlloc(reinterpret_cast<void*>(a), static_cast<size_t>(size),
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        if (!p) {
            p = VirtualAlloc(reinterpret_cast<void*>(a), static_cast<size_t>(size), MEM_RESERVE,
                             PAGE_READWRITE);
        }
        printf("[shim] XMemVirtualAlloc(base=%p, size=0x%llX, flags=0x%lX) -> %p (err=%lu)\n",
               reinterpret_cast<void*>(a), static_cast<unsigned long long>(size),
               static_cast<unsigned long>(flags), p, GetLastError());
        return reinterpret_cast<uint64_t>(p);
    }
    if (name == "xmem.dll!XMemAlloc") {
        const uint64_t size = a ? a : 0x1000;
        void* p = VirtualAlloc(nullptr, static_cast<size_t>(size), MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
        printf("[shim] XMemAlloc(size=0x%llX, attr=0x%llX) -> %p\n",
               static_cast<unsigned long long>(a), static_cast<unsigned long long>(b), p);
        return reinterpret_cast<uint64_t>(p);
    }
    if (name == "xmem.dll!XMemFree" || name == "xmem.dll!XMemVirtualFree") {
        const BOOL ok = VirtualFree(reinterpret_cast<void*>(a), 0, MEM_RELEASE);
        printf("[shim] %s(0x%llX) -> %d\n", name.c_str(),
               static_cast<unsigned long long>(a), ok);
        return ok;
    }
    if (name == "xmem.dll!XMemVirtualFree") {
        BOOL ok = VirtualFree(reinterpret_cast<void*>(a), static_cast<size_t>(b & 0xFFFFFFFFull),
                              static_cast<DWORD>(c & 0xFFFFFFFFull));
        printf("[shim] XMemVirtualFree -> %d\n", ok);
        return ok;
    }
    return 0;
}

void* Imports::makeStub(uint64_t id, const std::string& dll, const std::string& name) {
    static uint8_t* pool = nullptr;
    static size_t used = 0;
    static size_t capacity = 0;
    const size_t stubSize = 40;
    if (!pool) {
        capacity = 0x10000;
        pool = static_cast<uint8_t*>(VirtualAlloc(nullptr, capacity, MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_EXECUTE_READWRITE));
        if (!pool) return nullptr;
        g_names = new std::vector<std::string>();
    }
    if (used + stubSize > capacity) return nullptr;

    uint8_t* p = pool + used;
    used += stubSize;
    // `id` is the binding index, not the stub counter: pad so names[id] is ours.
    if (g_names->size() < id) g_names->resize(static_cast<size_t>(id));
    g_names->push_back(dll + "!" + name);

    // mov rax, rcx ; mov r11, rdx ; mov r9, r8 ; mov rdx, rax ; mov r8, r11
    // mov r10, imm64 ; mov rcx, r10 ; mov rax, Gta6ShimCall ; jmp rax
    // Shuffles (rcx, rdx, r8) into (a, b, c) and passes the binding id in rcx.
    const uint8_t code[40] = {
        0x48, 0x89, 0xC8,
        0x49, 0x89, 0xD3,
        0x4D, 0x89, 0xC1,
        0x48, 0x89, 0xC2,
        0x4D, 0x89, 0xD8,
        0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,
        0x4C, 0x89, 0xD1,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,
    };
    memcpy(p, code, sizeof code);
    memcpy(p + 17, &id, 8);
    void* target = reinterpret_cast<void*>(&Gta6ShimCall);
    memcpy(p + 30, &target, 8);
    if (g_traceStubs) {
        printf("[stub-alloc] %s -> %p (id=%llu)\n", (dll + "!" + name).c_str(), p,
               static_cast<unsigned long long>(id));
    }
    FlushInstructionCache(GetCurrentProcess(), p, stubSize);
    return p;
}

std::string Imports::describeIat(uintptr_t address) const {
    for (const auto& b : bindings_) {
        if (b.iatAddress == address) return b.dll + "!" + b.name;
    }
    return {};
}

std::string Imports::describeTarget(uintptr_t target) const {
    for (const auto& b : bindings_) {
        if (reinterpret_cast<uintptr_t>(b.target) == target) return b.dll + "!" + b.name;
    }
    return {};
}

bool Imports::bind(PeImage& image, const std::string& gameDir, bool verbose, std::string& error) {
    g_traceStubs = verbose;
    gameDir_ = gameDir;
    const uint32_t importRva = image.directoryRva(IMAGE_DIRECTORY_ENTRY_IMPORT);
    const uint32_t importSize = image.directorySize(IMAGE_DIRECTORY_ENTRY_IMPORT);
    (void)importSize;
    if (!importRva) {
        error = "no import directory";
        return false;
    }
    uint32_t off = image.rvaToOffset(importRva);
    if (!off) {
        error = "bad import directory rva";
        return false;
    }
    const uint8_t* data = image.bytes().data();
    std::set<std::string> loadedDlls;
    std::map<std::string, HMODULE> handles;

    while (true) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        memcpy(&desc, data + off, sizeof desc);
        if (!desc.Name && !desc.FirstThunk) break;
        const uint32_t nameOff = image.rvaToOffset(desc.Name);
        const std::string dll = nameOff ? reinterpret_cast<const char*>(data + nameOff) : "?";
        const std::string dllLower = lower(dll);
        const bool xboxOnly = kXboxOnlyDlls.count(dll) > 0;

        HMODULE mod = nullptr;
        if (!xboxOnly) {
            if (handles.count(dllLower)) {
                mod = handles[dllLower];
            } else {
                mod = LoadLibraryA(dll.c_str());
                if (!mod && !gameDir.empty()) {
                    mod = LoadLibraryA((gameDir + "\\" + dll).c_str());
                }
                handles[dllLower] = mod;
            }
        }
        if (mod) loadedDlls.insert(dll);

        uint32_t thunkRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t thunkOff = image.rvaToOffset(thunkRva);
        uint32_t iatRva = desc.FirstThunk;
        while (thunkOff) {
            uint64_t thunk = 0;
            memcpy(&thunk, data + thunkOff, 8);
            if (!thunk) break;
            std::string fn;
            if (thunk & (1ull << 63)) {
                char buf[32];
                snprintf(buf, sizeof buf, "#%llu", static_cast<unsigned long long>(thunk & 0xFFFF));
                fn = buf;
            } else {
                const uint32_t hintOff = image.rvaToOffset(static_cast<uint32_t>(thunk & 0x7FFFFFFF));
                if (hintOff) fn = reinterpret_cast<const char*>(data + hintOff + 2);
            }

            ImportBinding binding;
            binding.dll = dll;
            binding.name = fn;
            binding.iatAddress = image.base() + iatRva;
            void* resolved = nullptr;
            if (mod && !fn.empty() && fn[0] != '#') {
                resolved = reinterpret_cast<void*>(GetProcAddress(mod, fn.c_str()));
            } else if (mod && fn.size() > 1 && fn[0] == '#') {
                resolved = reinterpret_cast<void*>(
                    GetProcAddress(mod, MAKEINTRESOURCEA(static_cast<WORD>(atoi(fn.c_str() + 1)))));
            }
            if (resolved) {
                binding.kind = BindingKind::Real;
                binding.target = resolved;
            } else {
                binding.kind = xboxOnly ? BindingKind::XboxDll : BindingKind::Stub;
                binding.target = makeStub(bindings_.size(), dll, fn);
            }
            if (!binding.target) {
                error = "stub pool exhausted";
                return false;
            }
            memcpy(reinterpret_cast<void*>(image.base() + iatRva), &binding.target, 8);
            if (verbose) {
                printf("[iat] %p %-40s %-48s -> %p %s\n",
                       reinterpret_cast<void*>(binding.iatAddress), dll.c_str(), fn.c_str(),
                       binding.target, binding.kind == BindingKind::Real ? "(real)" : "(stub)");
            }
            bindings_.push_back(binding);
            thunkOff += 8;
            iatRva += 8;
        }
        off += sizeof desc;
    }
    return true;
}

void Imports::printSummary() const {
    std::map<std::string, std::pair<int, int>> stats;  // dll -> {real, stub}
    for (const auto& b : bindings_) {
        auto& s = stats[b.dll];
        if (b.kind == BindingKind::Real) ++s.first; else ++s.second;
    }
    printf("[iat] %zu imports in %zu DLLs\n", bindings_.size(), stats.size());
    for (const auto& [dll, s] : stats) {
        printf("      %-42s real=%-3d stub=%-3d\n", dll.c_str(), s.first, s.second);
    }
}

uint64_t Imports::totalCalls() const {
    uint64_t n = 0;
    for (const auto& b : bindings_) n += b.calls;
    return n;
}
