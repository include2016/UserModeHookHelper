// DllLoadMon.h - DLL Load Monitor Hook Code Provider
// Rev6: This module ONLY provides hook logic code via DllLoadMonHook export function
// Injection is handled by UMController using HookCore::ApplyHook

#pragma once

#include <Windows.h>

#ifdef DLLLOADMON_EXPORTS
#define DLLLOADMON_API extern "C" __declspec(dllexport)
#else
#define DLLLOADMON_API extern "C" __declspec(dllimport)
#endif

// Shared data structure for communication between UMController and DllLoadMon hook
// This structure is allocated in the target process by UMController
struct DllLoadMonSharedData {
    HANDLE hLoadEvent;          // Load notification event (DllLoadMon -> UMController)
    HANDLE hReleaseEvent;       // Release wait event (UMController -> DllLoadMon)
    WCHAR* pModuleBaseList;     // Array of module base addresses being watched
    CHAR* pModuleNameList;      // Array of module names (without .dll extension)
    DWORD dwWatchCount;         // Number of modules in watch list
    SRWLOCK WatchListLock;      // SRW lock for thread-safe access to watch list
};

// Hook callback function type definition
// Parameters passed by UMController during injection
typedef void (*PFN_DllLoadMonHook)(
    PVOID ModuleBase,      // Base address of the module being loaded (RDI points here)
    HANDLE hEventLoad,     // Load notification event (DllLoadMon -> UMController)
    HANDLE hEventRelease,  // Release wait event (UMController -> DllLoadMon)
    PVOID WatchList        // Watch list (shared memory or global variable)
);

// Export function: Provides hook logic code
// This is the ONLY function UMController needs to call via GetProcAddress
DLLLOADMON_API
void DllLoadMonHook(
    PVOID ModuleBase,
    HANDLE hEventLoad,
    HANDLE hEventRelease,
    PVOID WatchList
);

// Optional initialization function (if global state setup is needed)
// May be used to initialize shared memory or global variables
DLLLOADMON_API
NTSTATUS DllLoadMon_Initialize(
    HANDLE hEventLoad,
    HANDLE hEventRelease
);
