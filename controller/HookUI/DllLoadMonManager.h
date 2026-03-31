// DllLoadMonManager.h - Manages DllLoadMon shared memory and LdrLoadDll hooking
#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include "../../Shared/HookServices.h"
#include "../../Shared/DllLoadMonShared.h"
#include "../HookCoreLib/HookCore.h"

class DllLoadMonManager {
public:
    explicit DllLoadMonManager(IHookServices* services);
    ~DllLoadMonManager();

    // Register a module to watch for a specific process
    bool RegisterModuleWatch(DWORD pid, const wchar_t* moduleName);
    
    // Unregister all watches for a process
    void UnregisterModuleWatch(DWORD pid);
    
    // Cleanup all resources
    void Cleanup();

private:
    // Create shared memory and setup DllLoadMon for a process
    bool SetupDllLoadMon(DWORD pid);
    
    // Inject DllLoadMon.dll and hook LdrLoadDll
    bool InstallLdrLoadDllHook(DWORD pid);
    
    // Calculate LdrLoadDll return offset using MD5 of ntdll.dll
    DWORD64 CalculateNtdllLdrLoadDllRetOffset(DWORD pid, bool is64Bit);

    // Per-process state
    std::map<DWORD, std::vector<std::wstring>> m_WatchedModules;  // PID -> module names
    std::map<DWORD, HANDLE> m_WatchFileMappings;                   // PID -> file mapping handle
    
    // Synchronization events (kept alive for signal)
    std::map<DWORD, HANDLE> m_LoadEvents;      // Global\DelayHook_Load_{PID}
    std::map<DWORD, HANDLE> m_ReleaseEvents;   // Global\DelayHook_Release_{PID}
    
    // Hook services interface for process utilities
    IHookServices* m_services;
};
