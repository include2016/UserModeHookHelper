#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "../../Shared/HookServices.h"

class InstantHookManager {
public:
    struct HookTarget {
        DWORD targetPid;
        std::wstring processNtPath;
        unsigned long long processFnvHash;
        unsigned long long dllFnvHash;
        unsigned long long offset;           // target offset for hooking
        std::wstring dllPath;             // hook code dll path
        std::wstring exportName;          // the export function of hook code dll
        std::wstring script;              // Lua mode: script file path
        std::wstring handler;             // Lua mode: handler function name
        std::wstring module;              // target module (the dll that will be monitored)
        std::wstring offsetStr;           // offset string (e.g. "0x220b0")
        std::wstring hookSeqPath;         // path to .hookseq file (for persistence)
    };

    struct PatchEntry {
        std::wstring module;
        std::wstring offsetStr;
        std::wstring patchHex;            // hex byte sequence (e.g. "31C0C3")
    };

    InstantHookManager(IHookServices* services);
    ~InstantHookManager();

    // add an instant hook target
    bool AddTarget(const HookTarget& target);

    // start all listen threads for target dll monitoring
    void StartAllListeners();

    // stop all monitoring threads
    void StopAll();

    // Stop listeners for a specific process hash
    void StopByProcessHash(unsigned long long processFnvHash);

    // Stop listeners for a specific process hash and mode (isPatch=true: patch only, false: hook only)
    void StopByProcessHashAndMode(unsigned long long processFnvHash, bool isPatch);

    // Check if we have active listeners for a process hash
    bool HasListenerForHash(unsigned long long processFnvHash) const;

    // Get all active process hashes
    std::vector<unsigned long long> GetActiveProcessHashes() const;


    static unsigned long long ComputeFnvHash(const wchar_t* str);

    static bool ParseHookSeqFile(const wchar_t* filePath, std::vector<HookTarget>& outTargets);

    // Parse .patchseq file into PatchEntry list
    static bool ParsePatchSeqFile(const wchar_t* filePath, std::vector<PatchEntry>& outEntries);

    // Convert .patchseq to .hookseq file, returns the output .hookseq path
    static bool ConvertPatchSeqToHookSeq(const wchar_t* patchSeqPath, std::wstring& outHookSeqPath);

    // Convert hex string to byte vector. Supports formats:
    //   31C0C3 | \x31\xC0\xC3 | 0x31,0xC0,0xC3 | 31 C0 C3 | 0x31 0xC0 0xC3
    // On invalid format, returns empty and sets outError if provided.
    static std::vector<BYTE> HexToBytes(const std::wstring& hex, std::wstring* outError = nullptr);

private:
    // Per-PID hook ID allocator: each PID gets its own 256-bit bitfield
    struct PerPidHookIdPool {
        DWORD64 bitfield[4] = { 0 };  // 256 bits hook IDs 0..255
    };

    std::unordered_map<DWORD, PerPidHookIdPool> m_PidHookIdPools;
    LONG m_HookIdLock = 0;

    int  AllocHookId(DWORD pid);
    void ReleaseHookId(DWORD pid, int hookId);
    void ReleaseAllHookIdsForPid(DWORD pid);
    void CleanupDeadPidPools();

    struct ListenerContext {
        InstantHookManager* mgr;
        HookTarget target;
        bool isPatchMode;      // true if this listener is for patch mode (patch. prefix)
        HANDLE hLoadNotify;   // LoadNotify.<pFnv>.<dllFnv>
        HANDLE hHookNotify;   // HookNotify.<pFnv>.<dllFnv>
        HANDLE hStopEvent;    // Event to signal thread to stop
        HANDLE hThread;        // Thread handle (owned by context now)
        volatile bool running;
    };

    void ListenerThreadImpl(ListenerContext* ctx);

    std::vector<ListenerContext*> m_Listeners;
    IHookServices* m_services;
};
