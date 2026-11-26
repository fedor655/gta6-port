#include "pe_image.h"
#include "shims.h"

#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

namespace {

PeImage* g_image = nullptr;
uintptr_t g_watchIat = 0;

std::string g_lastStub;

extern "C" const char* g_lastShimName;
extern "C" uint64_t g_shimCalls;

LONG WINAPI faultHandler(EXCEPTION_POINTERS* info) {
    const auto* rec = info->ExceptionRecord;
    const auto* ctx = info->ContextRecord;
    printf("\n[fault] code=0x%08lX rip=%p\n", rec->ExceptionCode,
           reinterpret_cast<void*>(ctx->Rip));
    if (g_image) {
        printf("[fault] %s\n", g_image->describeAddress(ctx->Rip).c_str());
        if (!g_lastStub.empty()) printf("[fault] last stub: %s\n", g_lastStub.c_str());
    }
    printf("[fault] last shim: %s (calls=%llu)\n", g_lastShimName ? g_lastShimName : "?",
           static_cast<unsigned long long>(g_shimCalls));
    if (g_watchIat) {
        const uint64_t slot = *reinterpret_cast<const uint64_t*>(g_watchIat);
        printf("[fault] watch iat=%p value=%p\n", reinterpret_cast<void*>(g_watchIat),
               reinterpret_cast<void*>(slot));
    }
    printf("[fault] rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p rbp=%p rsp=%p\n",
           reinterpret_cast<void*>(ctx->Rax), reinterpret_cast<void*>(ctx->Rbx),
           reinterpret_cast<void*>(ctx->Rcx), reinterpret_cast<void*>(ctx->Rdx),
           reinterpret_cast<void*>(ctx->Rsi), reinterpret_cast<void*>(ctx->Rdi),
           reinterpret_cast<void*>(ctx->Rbp), reinterpret_cast<void*>(ctx->Rsp));
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
        printf("[fault] %s address %p\n",
               rec->ExceptionInformation[0] ? "write to" : "read from",
               reinterpret_cast<void*>(rec->ExceptionInformation[1]));
    }
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

DWORD g_lastException = 0;

bool safeWrite32(uintptr_t address, uint32_t value) {
    __try {
        *reinterpret_cast<uint32_t*>(address) = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_lastException = GetExceptionCode();
        return false;
    }
}

bool setupTls(PeImage& image) {
    const uint32_t tlsRva = image.directoryRva(IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tlsRva) {
        printf("[tls] no TLS directory\n");
        return true;
    }
    auto* tls = image.atRva<IMAGE_TLS_DIRECTORY64>(tlsRva);
    const uintptr_t indexVa = static_cast<uintptr_t>(tls->AddressOfIndex);
    const uintptr_t startVa = static_cast<uintptr_t>(tls->StartAddressOfRawData);
    const uintptr_t endVa = static_cast<uintptr_t>(tls->EndAddressOfRawData);
    (void)startVa;
    (void)endVa;
    printf("[tls] index=%p raw=%p..%p zerofill=%lu\n",
           reinterpret_cast<void*>(tls->AddressOfIndex),
           reinterpret_cast<void*>(tls->StartAddressOfRawData),
           reinterpret_cast<void*>(tls->EndAddressOfRawData),
           static_cast<unsigned long>(tls->SizeOfZeroFill));

    DWORD slot = TlsAlloc();
    printf("[tls] TlsAlloc -> %lu\n", static_cast<unsigned long>(slot));
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(reinterpret_cast<void*>(static_cast<uintptr_t>(indexVa)), &mbi, sizeof mbi);
    printf("[tls] query: base=%p state=0x%lX protect=0x%lX type=0x%lX region=%zu\n",
           mbi.BaseAddress, static_cast<unsigned long>(mbi.State),
           static_cast<unsigned long>(mbi.Protect), static_cast<unsigned long>(mbi.Type),
           static_cast<size_t>(mbi.RegionSize));
    if (slot == TLS_OUT_OF_INDEXES) {
        printf("[tls] TlsAlloc failed\n");
        return true;
    }
    if (!safeWrite32(static_cast<uintptr_t>(indexVa), slot)) {
        printf("[tls] write to index failed, code=0x%08lX\n", g_lastException);
    } else {
        printf("[tls] index stored at %p\n", reinterpret_cast<void*>(static_cast<uintptr_t>(indexVa)));
    }

    const size_t templateSize = static_cast<size_t>(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
    const size_t blockSize = templateSize + tls->SizeOfZeroFill + 64;
    auto* block = static_cast<uint8_t*>(VirtualAlloc(nullptr, blockSize, MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_READWRITE));
    if (!block) return true;
    memcpy(block, reinterpret_cast<void*>(tls->StartAddressOfRawData), templateSize);

    // Two TLS mechanisms exist on Win64: TEB.ThreadLocalStoragePointer (offset
    // 0x58) is what `mov rax, gs:[58h]; mov rbx,[rax+index*8]` uses, and it is
    // the one a module's IMAGE_TLS_DIRECTORY expects. TEB.TlsSlots (0x1480) is
    // the TlsAlloc array. Keep both in sync for the slot we hand out.
    struct TebLayout {
        uint8_t pad0[0x58];
        void** tlsArray;
        uint8_t pad1[0x1480 - 0x60 - 8];
        void* tlsSlots[64];
    };
    auto* teb = reinterpret_cast<TebLayout*>(NtCurrentTeb());
    if (slot < 64) {
        if (teb->tlsArray) teb->tlsArray[slot] = block;
        teb->tlsSlots[slot] = block;
        shimSetTlsState(slot, block, blockSize, reinterpret_cast<const void*>(tls->StartAddressOfRawData),
                        templateSize);
        printf("[tls] slot %lu installed (array %p, block %p)\n",
               static_cast<unsigned long>(slot), static_cast<void*>(teb->tlsArray), block);
    } else {
        printf("[tls] slot %lu >= 64, not installed\n", static_cast<unsigned long>(slot));
    }
    return true;
}

int g_faultLogBudget = 6;

HANDLE g_faultFile = INVALID_HANDLE_VALUE;

void faultLog(const char* fmt, ...) {
    if (g_faultFile == INVALID_HANDLE_VALUE) return;
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof buf - 2, fmt, args);
    va_end(args);
    if (n < 0) return;
    if (n > static_cast<int>(sizeof buf) - 2) n = sizeof buf - 2;
    buf[n++] = '\n';
    DWORD written = 0;
    WriteFile(g_faultFile, buf, static_cast<DWORD>(n), &written, nullptr);
}

LONG CALLBACK firstChanceHandler(EXCEPTION_POINTERS* info) {
    static LONG busy = 0;
    if (InterlockedExchange(&busy, 1)) return EXCEPTION_CONTINUE_SEARCH;
    if (g_faultLogBudget <= 0) {
        busy = 0;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto* rec = info->ExceptionRecord;
    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        rec->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        rec->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    --g_faultLogBudget;
    const auto* ctx = info->ContextRecord;
    char where[160] = "outside image";
    if (g_image) {
        const std::string d = g_image->describeAddress(ctx->Rip);
        strncpy_s(where, sizeof where, d.c_str(), _TRUNCATE);
    }
    unsigned long long arg = 0;
    if (rec->NumberParameters >= 2) arg = rec->ExceptionInformation[1];
    faultLog("[fault] code=0x%08lX rip=%p (%s) nparams=%u p0=%p p1=%p rsp=%p",
             rec->ExceptionCode, reinterpret_cast<void*>(ctx->Rip), where,
             static_cast<unsigned>(rec->NumberParameters),
             rec->NumberParameters ? reinterpret_cast<void*>(rec->ExceptionInformation[0]) : nullptr,
             rec->NumberParameters > 1 ? reinterpret_cast<void*>(rec->ExceptionInformation[1]) : nullptr,
             reinterpret_cast<void*>(ctx->Rsp));
    const uint64_t* stack = reinterpret_cast<const uint64_t*>(ctx->Rsp);
    faultLog("[fault] stack: %llX %llX %llX %llX, last shim %s, calls=%llu",
             static_cast<unsigned long long>(stack[0]),
             static_cast<unsigned long long>(stack[1]),
             static_cast<unsigned long long>(stack[2]),
             static_cast<unsigned long long>(stack[3]),
             g_lastShimName ? g_lastShimName : "?", static_cast<unsigned long long>(g_shimCalls));
    {
        HMODULE mod = nullptr;
        char modName[MAX_PATH] = "?";
        const char* moduleName = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(ctx->Rip), &mod) && mod) {
            GetModuleFileNameA(mod, modName, MAX_PATH);
            moduleName = modName;
            for (const char* s = modName; *s; ++s) if (*s == '\\' || *s == '/') moduleName = s + 1;
        }
        faultLog("[fault] rip module %s, rbp=%p", moduleName, reinterpret_cast<void*>(ctx->Rbp));
    }
    const uint8_t* ripBytes = reinterpret_cast<const uint8_t*>(ctx->Rip);
    char hex[128] = {};
    size_t pos = 0;
    for (int i = -12; i < 12; ++i) {
        pos += static_cast<size_t>(snprintf(hex + pos, sizeof hex - pos, " %02X", ripBytes[i]));
    }
    faultLog("[fault] bytes around rip:%s", hex);
    fflush(stdout);
    busy = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

int runEntry(uintptr_t address) {    auto entry = reinterpret_cast<int (*)()>(address);
    int rc = -1;
    __try {
        rc = entry();
        printf("[run] entry returned %d\n", rc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[run] stopped by SEH, code=0x%08lX\n", GetExceptionCode());
    }
    fflush(stdout);
    return rc;
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const char* exePath = nullptr;
    uint32_t probeRva = 0;
    bool mapOnly = false;
    bool traceIat = false;
    bool doProtect = true;
    bool run = true;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--map-only")) mapOnly = true;
        else if (!strcmp(argv[i], "--trace-iat")) traceIat = true;
        else if (!strcmp(argv[i], "--no-protect")) doProtect = false;
        else if (!strcmp(argv[i], "--no-run")) run = false;
        else if (!strcmp(argv[i], "--probe") && i + 1 < argc) {
            probeRva = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 0));
        }
        else if (!exePath) exePath = argv[i];
    }
    if (!exePath) {
        printf("usage: gta6rt <game_scarlett_master.exe> [--map-only] [--trace-iat] "
               "[--no-protect] [--no-run]\n");
        return 2;
    }

    std::string path = exePath;
    std::string gameDir;
    size_t slash = path.find_last_of("\\/");
    if (slash != std::string::npos) gameDir = path.substr(0, slash);

    PeImage image;
    std::string error;
    if (!image.load(path, error)) {
        printf("[map] load failed: %s\n", error.c_str());
        return 1;
    }
    printf("[map] loaded, sections=%zu, functions=%zu\n", image.sections().size(),
           image.functions().size());
    printf("[map] preferred base %llx, image size %u, entry %x\n",
           static_cast<unsigned long long>(image.preferredImageBase()), image.sizeOfImage(),
           image.entryPoint());

    if (!image.map(static_cast<uintptr_t>(image.preferredImageBase()), error)) {
        printf("[map] map failed: %s\n", error.c_str());
        return 1;
    }
    printf("[map] mapped at %p\n", reinterpret_cast<void*>(image.base()));
    if (!image.relocate(error)) {
        printf("[map] relocate failed: %s\n", error.c_str());
        return 1;
    }

    Imports imports;
    if (!imports.bind(image, gameDir, traceIat, error)) {
        printf("[iat] bind failed: %s\n", error.c_str());
        return 1;
    }
    imports.printSummary();
    {
        int mismatches = 0;
        for (const auto& b : imports.bindings()) {
            const uint64_t actual = *reinterpret_cast<const uint64_t*>(b.iatAddress);
            if (actual != reinterpret_cast<uint64_t>(b.target)) {
                if (mismatches < 5) {
                    printf("[iat-check] %s!%s iat=%p value=%p expected=%p\n", b.dll.c_str(),
                           b.name.c_str(), reinterpret_cast<void*>(b.iatAddress),
                           reinterpret_cast<void*>(actual), b.target);
                }
                ++mismatches;
            }
        }
        printf("[iat-check] %d mismatched slots\n", mismatches);
    }

    if (probeRva) {
        const uint64_t value = *reinterpret_cast<const uint64_t*>(image.base() + probeRva);
        printf("[probe] rva 0x%X -> %p", probeRva, reinterpret_cast<void*>(value));
        const std::string bindingName = imports.describeTarget(static_cast<uintptr_t>(value));
        printf("%s\n", bindingName.empty() ? "" : (" (" + bindingName + ")").c_str());
        MEMORY_BASIC_INFORMATION mbi{};
        VirtualQuery(reinterpret_cast<void*>(value), &mbi, sizeof mbi);
        printf("[probe] region base=%p protect=0x%lX\n", mbi.BaseAddress,
               static_cast<unsigned long>(mbi.Protect));
    }

    if (mapOnly) {
        printf("[map] map-only requested, not protecting or running\n");
        return 0;
    }
    if (doProtect) {
        if (!image.protectSections(error)) {
            printf("[map] protect failed: %s\n", error.c_str());
            return 1;
        }
    }

    setupTls(image);
    g_image = &image;
    g_watchIat = image.base() + 0x6793A58;

    if (!run) return 0;

    auto entry = reinterpret_cast<int (*)()>(image.base() + image.entryPoint());
    printf("[run] calling entry %p ...\n", reinterpret_cast<void*>(entry));
    fflush(stdout);

    g_faultFile = CreateFileA("gta6rt-faults.log", GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    SetUnhandledExceptionFilter(faultHandler);
    AddVectoredExceptionHandler(1, firstChanceHandler);
    runEntry(image.base() + image.entryPoint());
    return 0;
}
