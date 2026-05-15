#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "../../Shared/HookServices.h"

class InstantHookManager {
public:
    struct HookTarget {
        DWORD targetPid;
        std::wstring processNtPath;
        unsigned long long processFnvHash;
        unsigned long long dllFnvHash;
        std::wstring dllPath;             // hook code dll path
        std::wstring exportName;          // the export function of hook code dll
        std::wstring module;              // target module (the dll that will be monitored)
        std::wstring offset;              // offset of target address for target dll base
    };

    InstantHookManager(IHookServices* services);
    ~InstantHookManager();

    // add an instant hook target
    bool AddTarget(const HookTarget& target);

    // start all listen threads for target dll monitoring
    void StartAllListeners();

    // stop all monitoring threads
    void StopAll();

    
    static unsigned long long ComputeFnvHash(const wchar_t* str);

    static bool ParseHookSeqFile(const wchar_t* filePath, std::vector<HookTarget>& outTargets);

private:
    struct ListenerContext {
        InstantHookManager* mgr;
        HookTarget target;
        HANDLE hLoadNotify;   // LoadNotify.<pFnv>.<dllFnv>
        HANDLE hHookNotify;   // HookNotify.<pFnv>.<dllFnv>
    };

    void ListenerThreadImpl(ListenerContext* ctx);

    std::vector<ListenerContext*> m_Listeners;
    IHookServices* m_services;
};