// DllLoadMonShared.h - Shared data structures between UMController and DllLoadMon
// This header defines the communication structures used via memory-mapped files

#pragma once

#include <Windows.h>

// Maximum limits for watch list
#define DLM_MAX_WATCHED_MODULES 0x100
#define DLM_MAX_MODULE_NAME_LEN MAX_PATH

// Shared data structure for communication between UMController and DllLoadMon hook
// This structure is stored in a memory-mapped file accessible by both processes
// Maximum 256 DLL names, each up to 256 WCHARs (no .dll extension)
struct DllLoadMonSharedData {
    HANDLE hLoadEvent;          // Load notification event (DllLoadMon -> UMController)
	HANDLE hReleaseEvent;       // Release wait event (UMController -> DllLoadMon)
	HANDLE hDataAccessEvent;       // Release wait event (UMController -> DllLoadMon)
    DWORD dwWatchCount;         // Number of modules in watch list
    volatile LONG WatchListLock;// Spin lock flag for synchronization (0=unlocked, 1=locked)
    WCHAR ModuleNames[DLM_MAX_WATCHED_MODULES][DLM_MAX_MODULE_NAME_LEN]; // DLL name array (Unicode, without .dll extension)
    DWORD ModuleCount;
};
