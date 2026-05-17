#include "pch.h"
#include "InstantHookManager.h"
#include "../HookCoreLib/HookCore.h"
#include "HookInterfaces.h"
#include "../../Shared/SharedMacroDef.h"
#include "../../Shared/HookRow.h"
#include "RegistryStore.h"
#include <process.h>
#include <atlbase.h>
#include <algorithm>
#include "../../Shared/LogMacros.h"
#include "UMController.h"

// Helper: create event with security attributes allowing all processes to signal/sync
static HANDLE CreateWorldAccessibleEventW(BOOL bManualReset, BOOL bInitialState, PCWSTR name) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    // Allow everyone access (SYNC | EVENT_MODIFY_STATE | READ_CONTROL)
    if (!SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE)) {
        return NULL;
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = &sd;

    return CreateEventW(&sa, bManualReset, bInitialState, name);
}

// Helper: parse hex address string like "0x418b4" or "418b4"
static DWORD64 ParseAddressText(const wchar_t* input, bool& ok) {
    ok = false;
    if (!input || !input[0]) return 0ULL;
    std::wstring t(input);
    for (auto& c : t) c = towlower(c);
    if (t.rfind(L"0x", 0) == 0) t = t.substr(2);
    if (t.empty()) return 0ULL;
    DWORD64 val = 0ULL;
    for (wchar_t c : t) {
        val <<= 4;
        if (c >= L'0' && c <= L'9') val += c - L'0';
        else if (c >= L'a' && c <= L'f') val += c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') val += c - L'A' + 10;
        else return 0ULL;
    }
    ok = true;
    return val;
}

InstantHookManager::InstantHookManager(IHookServices* services)
    : m_services(services)
{
}

InstantHookManager::~InstantHookManager() {
    StopAll();
}

bool InstantHookManager::AddTarget(const HookTarget& target) {
    ListenerContext* ctx = new ListenerContext;
    ctx->mgr = this;
    ctx->target = target;
    ctx->hLoadNotify = NULL;
    ctx->hHookNotify = NULL;
    ctx->hStopEvent = NULL;
    ctx->hThread = NULL;
    ctx->running = false;
    m_Listeners.push_back(ctx);
    return true;
}

void InstantHookManager::StartAllListeners() {
    for (auto* ctx : m_Listeners) {
        if (ctx->hThread) continue; // Already started

        // Create stop event
        ctx->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ctx->hStopEvent) continue;

        ctx->running = true;
        ctx->hThread = (HANDLE)_beginthreadex(NULL, 0, [](void* lp) -> unsigned {
            ListenerContext* context = static_cast<ListenerContext*>(lp);
            reinterpret_cast<InstantHookManager*>(context->mgr)
                ->ListenerThreadImpl(context);
            return 0;
        }, ctx, 0, NULL);
    }
}

void InstantHookManager::StopAll() {
    for (auto* ctx : m_Listeners) {
        // Signal stop
        if (ctx->hStopEvent) {
            SetEvent(ctx->hStopEvent);
        }
        ctx->running = false;

        // Wait for thread to exit
        if (ctx->hThread) {
            WaitForSingleObject(ctx->hThread, 5000);
            CloseHandle(ctx->hThread);
            ctx->hThread = NULL;
        }

        // Close events
        if (ctx->hStopEvent) {
            CloseHandle(ctx->hStopEvent);
            ctx->hStopEvent = NULL;
        }
        if (ctx->hLoadNotify) {
            CloseHandle(ctx->hLoadNotify);
            ctx->hLoadNotify = NULL;
        }
        if (ctx->hHookNotify) {
            CloseHandle(ctx->hHookNotify);
            ctx->hHookNotify = NULL;
        }

        delete ctx;
    }
    m_Listeners.clear();
}

void InstantHookManager::StopByProcessHash(unsigned long long processFnvHash) {
    std::vector<ListenerContext*> toRemove;

    for (auto* ctx : m_Listeners) {
        if (ctx->target.processFnvHash == processFnvHash) {
            // Signal stop
            if (ctx->hStopEvent) {
                SetEvent(ctx->hStopEvent);
            }
            ctx->running = false;

            // Wait for thread to exit
            if (ctx->hThread) {
                WaitForSingleObject(ctx->hThread, 5000);
                CloseHandle(ctx->hThread);
                ctx->hThread = NULL;
            }

            // Close events
            if (ctx->hStopEvent) {
                CloseHandle(ctx->hStopEvent);
                ctx->hStopEvent = NULL;
            }
            if (ctx->hLoadNotify) {
                CloseHandle(ctx->hLoadNotify);
                ctx->hLoadNotify = NULL;
            }
            if (ctx->hHookNotify) {
                CloseHandle(ctx->hHookNotify);
                ctx->hHookNotify = NULL;
            }

            toRemove.push_back(ctx);
        }
    }

    // Remove from list
    for (auto* ctx : toRemove) {
        m_Listeners.erase(std::remove(m_Listeners.begin(), m_Listeners.end(), ctx), m_Listeners.end());
        delete ctx;
    }
}

bool InstantHookManager::HasListenerForHash(unsigned long long processFnvHash) const {
    for (const auto* ctx : m_Listeners) {
        if (ctx->target.processFnvHash == processFnvHash && ctx->running) {
            return true;
        }
    }
    return false;
}

std::vector<unsigned long long> InstantHookManager::GetActiveProcessHashes() const {
    std::vector<unsigned long long> hashes;
    for (const auto* ctx : m_Listeners) {
        if (ctx->running) {
            hashes.push_back(ctx->target.processFnvHash);
        }
    }
    return hashes;
}

void InstantHookManager::ListenerThreadImpl(ListenerContext* ctx) {
    // construct event names (only once)
    WCHAR loadEventName[MAX_PATH];
    WCHAR hookEventName[MAX_PATH];
    swprintf_s(loadEventName, UM_LOAD_NOTIFY_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash);
    swprintf_s(hookEventName, UM_HOOK_NOTIFY_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash);

    // Create/open events once at startup
    ctx->hLoadNotify = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, loadEventName);
    if (ctx->hLoadNotify) {
        ResetEvent(ctx->hLoadNotify);
    } else {
        ctx->hLoadNotify = CreateWorldAccessibleEventW(FALSE, FALSE, loadEventName);
        if (!ctx->hLoadNotify) {
            LOG_CTRL_INSHOOK(L"failed to create event=%s, Error=0x%x\n", loadEventName, GetLastError());
            ctx->running = false;
            return;
        }
    }

    ctx->hHookNotify = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, hookEventName);
    if (ctx->hHookNotify) {
        ResetEvent(ctx->hHookNotify);
    } else {
        ctx->hHookNotify = CreateWorldAccessibleEventW(TRUE, FALSE, hookEventName);
        if (!ctx->hHookNotify) {
            LOG_CTRL_INSHOOK(L"failed to create event=%s, Error=0x%x\n", hookEventName, GetLastError());
            CloseHandle(ctx->hLoadNotify);
            ctx->hLoadNotify = NULL;
            ctx->running = false;
            return;
        }
    }

    // Main loop: wait for event and perform hook, then loop back for next instance
    while (ctx->running) {
        // Reset events for next iteration
        ResetEvent(ctx->hLoadNotify);
        ResetEvent(ctx->hHookNotify);

        // Wait for either LoadNotify event or stop event
        HANDLE handles[2] = { ctx->hLoadNotify, ctx->hStopEvent };
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0 + 1) {
            // Stop event signaled
            LOG_CTRL_INSHOOK(L"Stop event signaled, exiting listener thread for hash=%llx\n", ctx->target.processFnvHash);
            break;
        }

        if (waitResult != WAIT_OBJECT_0) {
            LOG_CTRL_INSHOOK(L"WaitForMultipleObjects failed, exiting listener thread\n");
            break;
        }

        // target dll is already loaded, we can apply hook now
        DWORD pid = 0;
        // Read hook event file to get PID
        WCHAR hookEventPath[MAX_PATH];
        swprintf_s(hookEventPath, L"C:\\users\\public\\hookevent.%016llx.%016llx",
            ctx->target.processFnvHash, ctx->target.dllFnvHash);

        FILE* hookEventFile = NULL;
        _wfopen_s(&hookEventFile, hookEventPath, L"rt");
        if (hookEventFile) {
            if (fscanf_s(hookEventFile, "%u", &pid) == 1) {
                LOG_CTRL_INSHOOK(L"Hook event file: PID=%u, processHash=%llu, dllHash=%llu\n",
                    pid, ctx->target.processFnvHash, ctx->target.dllFnvHash);
            }
            fclose(hookEventFile);
        }

        if (pid == 0) {
            LOG_CTRL_INSHOOK(L"failed to get PID from hook event file\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // inject hook code DLL
        if (!m_services->InjectTrampoline(pid, ctx->target.dllPath.c_str())) {
            // we signal HookNotify event even we failed to inject hook code dll, because we don't want
            // handler in umhh.dll keep stucking there
            LOG_CTRL_INSHOOK(L"failed to inject hook code dll\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // wait for hook dll to load
        DWORD64 hookDllBase = 0;
        int retries = 50; // 5 seconds max

        // Extract filename from dllPath
        const wchar_t* dllFileName = wcsrchr(ctx->target.dllPath.c_str(), L'\\');
        if (dllFileName) {
            dllFileName++; // Skip the backslash
        } else {
            dllFileName = ctx->target.dllPath.c_str(); // Use full path if no backslash
        }

        while (retries-- > 0) {
            if (m_services->GetModuleBase(pid, dllFileName, &hookDllBase) && hookDllBase != 0) {
                break;
            }
            Sleep(100);
        }

        if (hookDllBase == 0) {
            LOG_CTRL_INSHOOK(L"failed to get hook code dll base\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // get module base
        DWORD64 moduleBase = 0;
        if (!m_services->GetModuleBase(pid, ctx->target.module.c_str(), &moduleBase) || moduleBase == 0) {
            LOG_CTRL_INSHOOK(L"failed to get target module base\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // parse offset
        bool ok = false;
        DWORD64 offset = ParseAddressText(ctx->target.offset.c_str(), ok);
        if (!ok) {
            LOG_CTRL_INSHOOK(L"failed to parse target offset\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // verify export
        DWORD hookCodeOffset = 0;
        CT2A exportNameA(ctx->target.exportName.c_str());
        if (!m_services->CheckExportFromFile(ctx->target.dllPath.c_str(), exportNameA, &hookCodeOffset)) {
            LOG_CTRL_INSHOOK(L"failed to get target export function=%s of target dll%s\n",
                ctx->target.exportName.c_str(), ctx->target.dllPath.c_str());
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // allocate hook ID
        int hookId = -1;
        static LONG g_HookIdLock = 0;
        while (InterlockedExchange(&g_HookIdLock, 1) != 0) Sleep(1);
        static DWORD64 g_HookIdBitfield[4] = { 0 };
        for (int i = 0; i < 4; ++i) {
            if (g_HookIdBitfield[i] != ~0ULL) {
                for (int bit = 0; bit < 64; ++bit) {
                    if (!_bittest((LONG*)&g_HookIdBitfield[i], bit)) {
                        _bittestandset((LONG*)&g_HookIdBitfield[i], bit);
                        hookId = i * 64 + bit;
                        break;
                    }
                }
                if (hookId != -1) break;
            }
        }
        InterlockedExchange(&g_HookIdLock, 0);

        if (hookId == -1) {
            LOG_CTRL_INSHOOK(L"there is no enough hookid\n");
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // execute hook
        DWORD oriLen = 0;
        PVOID trampoline = nullptr;
        PVOID oriAsmAddr = nullptr;
        DWORD64 targetAddress = moduleBase + offset;
        DWORD64 hookFunctionAddress = hookDllBase + hookCodeOffset;
        HookCore::SetHookServices(m_services);
        if (!HookCore::ApplyHook(pid, targetAddress, m_services, hookFunctionAddress, hookId, &oriLen, &trampoline, &oriAsmAddr)) {
            // release hook ID
            _bittestandreset((LONG*)&g_HookIdBitfield[hookId / 64], hookId % 64);
            LOG_CTRL_INSHOOK(L"ApplyHook failed for pid=%u\n", pid);
            SetEvent(ctx->hHookNotify);
            continue;  // Continue to next iteration
        }

        // Persist hook info to registry so HookUI can display it
        FILETIME createTime = {0}, exitTime, kernelTime, userTime;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
                HookRow row;
                row.id = hookId;
                row.address = targetAddress;
                row.module = ctx->target.module;
                row.expFunc = ctx->target.exportName;
                row.ori_asm_code_addr = (unsigned long long)oriAsmAddr;
                row.ori_asm_code_len = oriLen;
                row.trampoline_pit = (unsigned long long)trampoline;

                std::vector<HookRow> rows;
                rows.push_back(row);

                if (!m_services->SaveProcHookList(pid, createTime.dwHighDateTime, createTime.dwLowDateTime, rows)) {
                    LOG_CTRL_INSHOOK(L"failed to persist hook info to registry for pid=%u, hookId=%d\n", pid, hookId);
                } else {
                    LOG_CTRL_INSHOOK(L"hook info persisted to registry: pid=%u, hookId=%d, address=0x%llx\n", pid, hookId, targetAddress);
                }
            }
            CloseHandle(hProc);
        } else {
            LOG_CTRL_INSHOOK(L"failed to open process for GetProcessTimes: pid=%u, Error=0x%x\n", pid, GetLastError());
        }

        // Signal HookNotify so handler code in UMHH.dll can continue
        SetEvent(ctx->hHookNotify);
        LOG_CTRL_INSHOOK(L"Instant hook completed for pid=%u, waiting for next instance...\n", pid);
        // Loop back and wait for next LoadNotify event
    }

    // Cleanup on exit
    if (ctx->hLoadNotify) {
        CloseHandle(ctx->hLoadNotify);
        ctx->hLoadNotify = NULL;
    }
    if (ctx->hHookNotify) {
        CloseHandle(ctx->hHookNotify);
        ctx->hHookNotify = NULL;
    }
    ctx->running = false;
}

// parse .hookseq file
bool InstantHookManager::ParseHookSeqFile(const wchar_t* filePath, std::vector<HookTarget>& outTargets) {
    FILE* f = NULL;
    _wfopen_s(&f,filePath, L"rt, ccs=UNICODE");
    if (!f) return false;

    wchar_t lineBuf[MAX_PATH * 2];
    HookTarget target;
    bool inHook = false;
    bool hasModule = false, hasOffset = false, hasDllPath = false, hasExport = false;

    while (fgetws(lineBuf, MAX_PATH * 2, f)) {
        wchar_t* p = lineBuf;
        // skip tab and whitespace
        while (*p == L' ' || *p == L'\t') p++;
        // trim new line marker
        size_t len = wcslen(p);
        while (len > 0 && (p[len - 1] == L'\n' || p[len - 1] == L'\r' || p[len - 1] == L' ' || p[len - 1] == L'\t')) {
            p[--len] = L'\0';
        }

        if (p[0] == L'[' && wcsncmp(p + 1, L"hook]", 5) == 0) {
            if (inHook && hasModule && hasOffset && hasDllPath && hasExport) {
                outTargets.push_back(target);
            }
            memset(&target, 0, sizeof(target));
            inHook = true;
            hasModule = hasOffset = hasDllPath = hasExport = false;
            continue;
        }

        if (!inHook) continue;

        wchar_t* eq = wcschr(p, L'=');
        if (!eq) continue;
        *eq = L'\0';
        wchar_t* key = p;
        wchar_t* val = eq + 1;
        // trim key
        size_t keyLen = wcslen(key);
        while (keyLen > 0 && (key[keyLen - 1] == L' ' || key[keyLen - 1] == L'\t')) keyLen--;
        key[keyLen] = L'\0';
        // trim val
        while (*val == L' ' || *val == L'\t') val++;

        if (wcscmp(key, L"module") == 0) {
            target.module = val;
            hasModule = true;
        }
        else if (wcscmp(key, L"offset") == 0) {
            target.offset = std::wstring(val);
            hasOffset = true;
        }
        else if (wcscmp(key, L"dllPath") == 0) {
            target.dllPath = val;
            hasDllPath = true;
        }
        else if (wcscmp(key, L"export") == 0) {
            target.exportName = val;
            hasExport = true;
        }
    }

    if (inHook && hasModule && hasOffset && hasDllPath && hasExport) {
        outTargets.push_back(target);
    }

    fclose(f);
    return !outTargets.empty();
}

unsigned long long InstantHookManager::ComputeFnvHash(const wchar_t* str) {
    const unsigned long long FNV_prime = 1099511628211ULL;
    unsigned long long hash = 14695981039346656037ULL;
    const wchar_t* p = str;
    while (*p) {
        wchar_t c = *p++;
        // convert to lowercase
        if (c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
        BYTE bLow = (BYTE)(c & 0xFF);
        BYTE bHigh = (BYTE)((c >> 8) & 0xFF);
        hash ^= (unsigned long long)bLow;
        hash *= FNV_prime;
        hash ^= (unsigned long long)bHigh;
        hash *= FNV_prime;
    }
    return hash;
}
