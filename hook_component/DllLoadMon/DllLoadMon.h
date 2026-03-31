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
#define MAX_WATCHED_MODULES 0x100
#define MAX_MODULE_NAME_LEN MAX_PATH
// Shared data structure for communication between UMController and DllLoadMon hook
// This structure is stored in a memory-mapped file (not target process memory)
// Maximum 256 DLL names, each up to 256 WCHARs (no .dll extension)
#pragma once

#include <Windows.h>
#include "../../Shared/DllLoadMonShared.h"

#ifdef DLLLOADMON_EXPORTS
#define DLLLOADMON_API extern "C" __declspec(dllexport)
#else
#define DLLLOADMON_API extern "C" __declspec(dllimport)
#endif


// Hook callback function type definition
// Parameters: RCX=ModuleBase, RDX/R8/R9 unused, RSP=stack pointer for PROLOG
// In LdrLoadDll return context: RDI points to PUNICODE_STRING of DLL name
typedef void (*PFN_DllLoadMonHook)(
    PVOID ModuleBase,      // Base address of the module being loaded (RDI points here)
    HANDLE hEventLoad,     // Load notification event (DllLoadMon -> UMController)
    HANDLE hEventRelease,  // Release wait event (UMController -> DllLoadMon)
    PVOID WatchList        // Watch list (shared memory or global variable)
);

// Export function: Provides hook logic code for X64
// Called at LdrLoadDll return address with RDI pointing to PUNICODE_STRING
DLLLOADMON_API
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp);

// Export function: Provides hook logic code for Win32
// Called at LdrLoadDll return address with EDI pointing to PUNICODE_STRING
DLLLOADMON_API
VOID DllLoadMonHook_Win32(ULONG esp);



// UMController helper functions for managing watch list via memory-mapped file
// These functions are called by UMController to set up the shared data

/**
 * Create memory-mapped file and populate watch list
 * Called by UMController before injecting DllLoadMon
 * 
 * @param pid Target process ID
 * @param moduleNames List of DLL names to watch (without .dll extension)
 * @param phFileMapping Output: handle to file mapping object (must be kept open)
 * @param ppSharedData Output: pointer to shared data (optional, can be NULL)
 * @return TRUE on success, FALSE on failure
 */
DLLLOADMON_API
BOOL DllLoadMon_CreateWatchList(
    DWORD pid,
    const std::vector<std::wstring>& moduleNames,
    HANDLE* phFileMapping,
    DllLoadMonSharedData** ppSharedData
);

/**
 * Cleanup memory-mapped file resources
 * Called by UMController when watch is no longer needed
 * 
 * @param hFileMapping File mapping handle to close
 */
DLLLOADMON_API
VOID DllLoadMon_CleanupWatchList(HANDLE hFileMapping);
