// ModuleWatch.c
// Module load watch management for delayed hook support
#include "ModuleWatch.h"
#include "FltCommPort.h"
#include "StrLib.h"
#include "DriverCtx.h"
#include "Trace.h"
#include "Common.h"

// Watch entry structure
typedef struct _MODULE_WATCH_ENTRY {
    LIST_ENTRY ListEntry;
    DWORD ProcessId;
    PEPROCESS Process;        // Referenced process object
    UNICODE_STRING ModuleName; // Module name to watch (allocated from pool)
    ULONGLONG ModuleBase;     // Base address once loaded
    BOOLEAN Notified;         // Whether we've already notified user-mode
} MODULE_WATCH_ENTRY, *PMODULE_WATCH_ENTRY;

// Global watch list and lock
static LIST_ENTRY g_WatchList;
static ERESOURCE g_WatchLock;
static BOOLEAN g_Initialized = FALSE;

NTSTATUS ModuleWatch_Init(VOID)
{
    NTSTATUS status;
    
    if (g_Initialized) return STATUS_ALREADY_INITIALIZED;
    
    InitializeListHead(&g_WatchList);
    
    status = ExInitializeResourceLite(&g_WatchLock);
    if (!NT_SUCCESS(status)) {
        Log(L"ModuleWatch_Init: Failed to initialize resource, 0x%x\n", status);
        return status;
    }
    
    g_Initialized = TRUE;
    Log(L"ModuleWatch subsystem initialized\n");
    return STATUS_SUCCESS;
}

VOID ModuleWatch_Uninit(VOID)
{
    if (!g_Initialized) return;
    
    // Clean up all watch entries
    ExAcquireResourceExclusiveLite(&g_WatchLock, TRUE);
    
    PLIST_ENTRY entry = g_WatchList.Flink;
    while (entry != &g_WatchList) {
        PMODULE_WATCH_ENTRY watch = CONTAINING_RECORD(entry, MODULE_WATCH_ENTRY, ListEntry);
        entry = entry->Flink;
        
        RemoveTailList(&g_WatchList);
        
        if (watch->Process) {
            ObDereferenceObject(watch->Process);
        }
        
        if (watch->ModuleName.Buffer) {
            ExFreePool(watch->ModuleName.Buffer);
        }
        
        ExFreePool(watch);
    }
    
    ExDeleteResourceLite(&g_WatchLock);
    g_Initialized = FALSE;
    
    Log(L"ModuleWatch subsystem uninitialized\n");
}

NTSTATUS ModuleWatch_Register(DWORD ProcessId, PCUNICODE_STRING ModuleName)
{
    if (!g_Initialized) return STATUS_NOT_INITIALIZED;
    if (!ModuleName || ModuleName->Length == 0) return STATUS_INVALID_PARAMETER;
    
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    
    // Lookup process
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status) || process == NULL) {
        Log(L"ModuleWatch_Register: Failed to lookup process %lu, 0x%x\n", ProcessId, status);
        return status;
    }
    
    // Allocate watch entry
    PMODULE_WATCH_ENTRY watch = (PMODULE_WATCH_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx, sizeof(MODULE_WATCH_ENTRY), tag_module_watch);
    
    if (!watch) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Allocate and copy module name
    USHORT nameSize = ModuleName->Length + sizeof(WCHAR); // Extra for safety
    watch->ModuleName.Buffer = (PWCH)ExAllocatePoolZero(
        NonPagedPoolNx, nameSize, tag_module_watch);
    
    if (!watch->ModuleName.Buffer) {
        ExFreePool(watch);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // I don't know why RtlCopyUnicodeString doesn't work, so I just use memcpy
    // RtlCopyUnicodeString(&watch->ModuleName, ModuleName);
	memcpy_s(watch->ModuleName.Buffer, ModuleName->MaximumLength, ModuleName->Buffer, ModuleName->MaximumLength);
	watch->ModuleName.Length = ModuleName->Length;
	watch->ModuleName.MaximumLength = ModuleName->MaximumLength;

	watch->ProcessId = ProcessId;
    watch->Process = process; // Take reference
    watch->ModuleBase = 0;
    watch->Notified = FALSE;
    
    // Add to watch list
    ExAcquireResourceExclusiveLite(&g_WatchLock, TRUE);
    InsertTailList(&g_WatchList, &watch->ListEntry);
    ExReleaseResourceLite(&g_WatchLock);
    
    Log(L"ModuleWatch: Registered watch for PID %lu, module %wZ\n", ProcessId, ModuleName);
    return STATUS_SUCCESS;
}

NTSTATUS ModuleWatch_Unregister(DWORD ProcessId, PCUNICODE_STRING ModuleName)
{
    if (!g_Initialized) return STATUS_NOT_INITIALIZED;
    
    ExAcquireResourceExclusiveLite(&g_WatchLock, TRUE);
    
    PLIST_ENTRY entry = g_WatchList.Flink;
    while (entry != &g_WatchList) {
        PMODULE_WATCH_ENTRY watch = CONTAINING_RECORD(entry, MODULE_WATCH_ENTRY, ListEntry);
        entry = entry->Flink;
        
        if (watch->ProcessId == ProcessId) {
            BOOLEAN match = FALSE;
            
            if (ModuleName && ModuleName->Length > 0) {
                // Match specific module
                if (RtlCompareUnicodeString(&watch->ModuleName, ModuleName, TRUE) == 0) {
                    match = TRUE;
                }
            } else {
                // Remove all watches for this PID
                match = TRUE;
            }
            
            if (match) {
                RemoveEntryList(&watch->ListEntry);
                
                if (watch->Process) {
                    ObDereferenceObject(watch->Process);
                }
                
                if (watch->ModuleName.Buffer) {
                    ExFreePool(watch->ModuleName.Buffer);
                }
                
                ExFreePool(watch);
                
                Log(L"ModuleWatch: Unregistered watch for PID %lu\n", ProcessId);
            }
        }
    }
    
    ExReleaseResourceLite(&g_WatchLock);
    return STATUS_SUCCESS;
}

VOID ModuleWatch_UnregisterByProcess(PEPROCESS Process)
{
    if (!g_Initialized || !Process) return;
    
    DWORD pid = (DWORD)(ULONG_PTR)PsGetProcessId(Process);
    ModuleWatch_Unregister(pid, NULL);
}

// Helper to check if module name matches (case-insensitive, base name only)
static BOOLEAN IsMatchingModule(PUNICODE_STRING FullImageName, PUNICODE_STRING WatchName)
{
	// Log(L"currDllName: %wZ\ttarDllName: %wZ\n", FullImageName, WatchName);
    if (!FullImageName || !WatchName || FullImageName->Length == 0 || WatchName->Length == 0) {
        return FALSE;
    }
    
    // Extract base name from full path
    PWCH buffer = FullImageName->Buffer;
    USHORT chars = FullImageName->Length / sizeof(WCHAR);
    PWCH last = buffer + chars - 1;
    
    // Walk backward to find last separator
    while (last >= buffer && *last != L'\\' && *last != L'/') {
        --last;
    }
    
    PWCH baseName = (last >= buffer && (*last == L'\\' || *last == L'/')) ? (last + 1) : buffer;
    USHORT baseChars = (USHORT)((buffer + chars) - baseName);
    
    // Create temporary UNICODE_STRING for comparison
    UNICODE_STRING base;
    base.Buffer = baseName;
    base.Length = baseChars * sizeof(WCHAR);
    base.MaximumLength = base.Length;
    
    // Compare case-insensitively
    return (RtlCompareUnicodeString(&base, WatchName, TRUE) == 0);
}

NTSTATUS ModuleWatch_CheckAndNotify(
    PUNICODE_STRING FullImageName,
    PEPROCESS Process,
    PIMAGE_INFO ImageInfo
)
{
    if (!g_Initialized || !FullImageName || !Process) {
        return STATUS_SUCCESS; // Not an error, just nothing to do
    }
    
    DWORD pid = (DWORD)(ULONG_PTR)PsGetProcessId(Process);
    ULONGLONG base = (ULONGLONG)ImageInfo->ImageBase;
    
    ExAcquireResourceSharedLite(&g_WatchLock, TRUE);
    
    PLIST_ENTRY entry = g_WatchList.Flink;
    while (entry != &g_WatchList) {
        PMODULE_WATCH_ENTRY watch = CONTAINING_RECORD(entry, MODULE_WATCH_ENTRY, ListEntry);
        entry = entry->Flink;
        
        // Check if this watch is for our process and hasn't been notified yet
        if (watch->ProcessId == pid && !watch->Notified && watch->Process == Process) {
            // Check if the loaded module matches
            if (IsMatchingModule(FullImageName, &watch->ModuleName)) {
                // Update watch entry
                watch->ModuleBase = base;
                watch->Notified = TRUE;
                
                // Notify user-mode
                ULONG notified = 0;
                NTSTATUS status = Comm_BroadcastModuleLoad(
                    pid,
                    FullImageName,
                    base,
                    &notified
                );
                
                if (!NT_SUCCESS(status)) {
                    Log(L"ModuleWatch: Failed to broadcast module load notification, 0x%x\n", status);
                } else {
                    Log(L"ModuleWatch: Notified user-mode of module load: PID %lu, %wZ, base 0x%p\n", 
                        pid, FullImageName, (PVOID)base);
                }
                
                // Remove watch entry after notification (one-time notification)
                // We need to release the lock first
                ExReleaseResourceLite(&g_WatchLock);
                
                // Remove the entry
                ExAcquireResourceExclusiveLite(&g_WatchLock, TRUE);
                RemoveEntryList(&watch->ListEntry);
                
                if (watch->Process) {
                    ObDereferenceObject(watch->Process);
                }
                
                if (watch->ModuleName.Buffer) {
                    ExFreePool(watch->ModuleName.Buffer);
                }
                
                ExFreePool(watch);
                ExReleaseResourceLite(&g_WatchLock);
                
                // Re-acquire shared lock to continue iteration
                ExAcquireResourceSharedLite(&g_WatchLock, TRUE);
                entry = g_WatchList.Flink; // Reset iteration
            }
        }
    }
    
    ExReleaseResourceLite(&g_WatchLock);
    return STATUS_SUCCESS;
}
