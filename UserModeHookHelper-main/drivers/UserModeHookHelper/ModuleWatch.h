// ModuleWatch.h
// Module load watch management for delayed hook support
#ifndef MODULE_WATCH_H
#define MODULE_WATCH_H

#include "Common.h"

// Initialize module watch subsystem
NTSTATUS ModuleWatch_Init(VOID);

// Cleanup module watch subsystem
VOID ModuleWatch_Uninit(VOID);

// Register a module watch request for a specific process
NTSTATUS ModuleWatch_Register(DWORD ProcessId, PCUNICODE_STRING ModuleName);

// Unregister module watch requests
NTSTATUS ModuleWatch_Unregister(DWORD ProcessId, PCUNICODE_STRING ModuleName);

// Unregister all module watches for a process (called on process exit)
VOID ModuleWatch_UnregisterByProcess(PEPROCESS Process);

// Check if a loaded image matches any watched modules and notify user-mode
NTSTATUS ModuleWatch_CheckAndNotify(
    PUNICODE_STRING FullImageName,
    PEPROCESS Process,
    PIMAGE_INFO ImageInfo
);

#endif // MODULE_WATCH_H
