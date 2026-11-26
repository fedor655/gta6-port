#include "shims.h"

#include "pe_image.h"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <intrin.h>
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

// Per-thread TLS state the loader owns: new threads need the same block setup
// the main thread got, and the image is not a real module, so nobody else
// installs it.
namespace tls_state {
DWORD slot = TLS_OUT_OF_INDEXES;
void* block = nullptr;
size_t blockSize = 0;
const void* templateSrc = nullptr;
size_t templateSize = 0;
bool installed = false;
}

void shimSetTlsState(DWORD slot, void* block, size_t blockSize,
                     const void* templateSrc, size_t templateSize) {
    tls_state::slot = slot;
    tls_state::block = block;
    tls_state::blockSize = blockSize;
    tls_state::templateSrc = templateSrc;
    tls_state::templateSize = templateSize;
    tls_state::installed = true;
}

namespace {

typedef LONG (WINAPI* NtQueryInformationThreadFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationThreadFn getNtQueryInformationThread() {
    static NtQueryInformationThreadFn fn = nullptr;
    if (!fn) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) fn = reinterpret_cast<NtQueryInformationThreadFn>(
            GetProcAddress(ntdll, "NtQueryInformationThread"));
    }
    return fn;
}

// Writes the game's TLS block pointer into a (usually suspended) thread's TEB:
// both the ThreadLocalStoragePointer array at TEB+0x58 and TlsSlots at +0x1480.
bool installTlsInto(HANDLE thread) {
    if (!tls_state::installed || tls_state::slot >= 64) return false;
    auto query = getNtQueryInformationThread();
    if (!query) return false;
    uint8_t info[48] = {};
    // THREAD_BASIC_INFORMATION: ExitStatus, TebBaseAddress, ...
    if (query(thread, 0, info, sizeof info, nullptr) != 0) return false;
    void* teb = *reinterpret_cast<void**>(info + 8);
    if (!teb) return false;
    struct TebLayout {
        uint8_t pad0[0x58];
        void** tlsArray;
        uint8_t pad1[0x1480 - 0x60 - 8];
        void* tlsSlots[64];
    };
    auto* t = reinterpret_cast<TebLayout*>(teb);
    void* block = VirtualAlloc(nullptr, tls_state::blockSize, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    if (!block) return false;
    memcpy(block, tls_state::templateSrc, tls_state::templateSize);
    if (t->tlsArray) t->tlsArray[tls_state::slot] = block;
    t->tlsSlots[tls_state::slot] = block;
    return true;
}

void* g_realCreateThread = nullptr;

}  // namespace

// Real CreateThread replacement: start suspended, install the game's TLS block
// into the new thread's TEB, then resume.
HANDLE WINAPI ShimCreateThread(LPSECURITY_ATTRIBUTES attrs, SIZE_T stackSize,
                               LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags,
                               LPDWORD threadId) {
    void* real = g_realCreateThread;
    if (!real) return nullptr;
    auto create = reinterpret_cast<decltype(&CreateThread)>(real);
    HANDLE h = create(attrs, stackSize, start, param, flags | CREATE_SUSPENDED, threadId);
    if (h) {
        const bool ok = installTlsInto(h);
        printf("[shim] CreateThread(start=%p) tid-stub ok=%d\n", reinterpret_cast<void*>(start),
               ok ? 1 : 0);
        ResumeThread(h);
    } else {
        printf("[shim] CreateThread failed (err=%lu)\n", GetLastError());
    }
    return h;
}

extern "C" const char* g_lastShimName = "";
extern "C" uint64_t g_shimCalls = 0;

// Rate-limited logger used by the trace thunks on real imports.
extern "C" void Gta6ShimLog(uint64_t id) {
    if (!g_names || id >= g_names->size()) return;
    static std::vector<uint64_t>* counts = nullptr;
    if (!counts) counts = new std::vector<uint64_t>(g_names->size(), 0);
    const uint64_t n = ++(*counts)[static_cast<size_t>(id)];
    if (n <= 3) {
        const uintptr_t entryRsp =
            reinterpret_cast<uintptr_t>(_AddressOfReturnAddress()) - 8;
        printf("[call] %s (call #%llu, entry rsp %llX)\n",
               (*g_names)[static_cast<size_t>(id)].c_str(),
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(entryRsp));
    } else if ((n & (n - 1)) != 0) {
        return;
    } else {
        printf("[call] %s (call #%llu)\n", (*g_names)[static_cast<size_t>(id)].c_str(),
               static_cast<unsigned long long>(n));
    }
}

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
        if (!g_names) g_names = new std::vector<std::string>();
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

// Logging thunk for real imports: preserves every register and the stack,
// logs dll!name, then jumps to the real function as if the caller had called
// it directly. Stack arguments stay in place; xmm0-5 are saved around the log.
void* Imports::makeTraceStub(uint64_t id, const std::string& dll, const std::string& name,
                             void* realTarget) {
    static uint8_t* pool = nullptr;
    static size_t used = 0;
    static size_t capacity = 0;
    const size_t stubSize = 136;
    if (!pool) {
        capacity = 0x40000;
        pool = static_cast<uint8_t*>(VirtualAlloc(nullptr, capacity, MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_EXECUTE_READWRITE));
        if (!pool) return nullptr;
    }
    if (used + stubSize > capacity) return nullptr;
    uint8_t* p = pool + used;
    used += stubSize;
    if (!g_names) g_names = new std::vector<std::string>();
    if (g_names->size() < id) g_names->resize(static_cast<size_t>(id));
    g_names->push_back(dll + "!" + name);

    uint8_t code[] = {
        0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,                   // mov r11, real
        0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,             // push rax rcx rdx rbx rbp rsi rdi
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       // push r8..r11
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,       // push r12..r15
        0x48, 0x83, 0xEC, 0x60,                               // sub rsp, 0x60
        0x0F, 0x11, 0x04, 0x24,                               // movups [rsp], xmm0
        0x0F, 0x11, 0x4C, 0x24, 0x10,                         // movups [rsp+0x10], xmm1
        0x0F, 0x11, 0x54, 0x24, 0x20,                         // movups [rsp+0x20], xmm2
        0x0F, 0x11, 0x5C, 0x24, 0x30,                         // movups [rsp+0x30], xmm3
        0x0F, 0x11, 0x64, 0x24, 0x40,                         // movups [rsp+0x40], xmm4
        0x0F, 0x11, 0x6C, 0x24, 0x50,                         // movups [rsp+0x50], xmm5
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,                   // mov rcx, id
        0xE8, 0, 0, 0, 0,                                     // call Gta6ShimLog
        0x0F, 0x10, 0x04, 0x24,                               // movups xmm0, [rsp]
        0x0F, 0x10, 0x4C, 0x24, 0x10,                         // movups xmm1, [rsp+0x10]
        0x0F, 0x10, 0x54, 0x24, 0x20,                         // movups xmm2, [rsp+0x20]
        0x0F, 0x10, 0x5C, 0x24, 0x30,                         // movups xmm3, [rsp+0x30]
        0x0F, 0x10, 0x64, 0x24, 0x40,                         // movups xmm4, [rsp+0x40]
        0x0F, 0x10, 0x6C, 0x24, 0x50,                         // movups xmm5, [rsp+0x50]
        0x48, 0x83, 0xC4, 0x60,                               // add rsp, 0x60
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,       // pop r15..r12
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,       // pop r11..r8
        0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58,             // pop rdi rsi rbp rbx rdx rcx rax
        0x41, 0xFF, 0xE3,                                     // jmp r11
    };
    memcpy(p, code, sizeof code);
    memcpy(p + 2, &realTarget, 8);
    memcpy(p + 68, &id, 8);
    const void* logFn = reinterpret_cast<const void*>(&Gta6ShimLog);
    const size_t callOff = 76;
    int32_t rel = static_cast<int32_t>(reinterpret_cast<const uint8_t*>(logFn) -
                                      (p + callOff + 5));
    memcpy(p + callOff + 1, &rel, 4);
    if (g_traceStubs && id < 2) {
        char hex[512] = {};
        size_t pos = 0;
        for (size_t i = 0; i < 40; ++i) {
            pos += static_cast<size_t>(snprintf(hex + pos, sizeof hex - pos, " %02X", p[i]));
        }
        printf("[thunk] id=%llu at %p:%s\n", static_cast<unsigned long long>(id), p, hex);
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
            // Functions we replace entirely (the shim owns the call).
            const std::string full = dll + "!" + fn;
            if (full == "CreateThread" || full == "api-ms-win-core-processthreads-l1-1-0.dll!CreateThread") {
                g_realCreateThread = resolved;
                binding.kind = BindingKind::Handler;
                binding.target = reinterpret_cast<void*>(&ShimCreateThread);
            } else if (resolved) {
                binding.kind = BindingKind::Real;
                binding.target = makeTraceStub(bindings_.size(), dll, fn, resolved);
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
