// DllLoadMon.cpp - DLL Load Monitor Hook Logic Implementation
// Rev6: This module ONLY provides hook logic, NOT injection functionality
// Injection is handled by UMController using HookCore::ApplyHook

#include "pch.h"
#include "DllLoadMon.h"
#include <vector>
#include <string>
#include <cstring>

// Forward declarations for helper functions
static const char* ReadModuleNameFromRDI(PVOID ModuleBase);
static bool IsModuleInWatchList(const char* moduleName, PVOID WatchList);
static void ExtractModuleNameFromBase(PVOID ModuleBase, char* outBuffer, size_t bufferSize);

// Global pointer to shared data (set by UMController via remote memory write)
static DllLoadMonSharedData* g_pSharedData = nullptr;

/**
 * Main hook callback function - exported via DllLoadMonHook
 * 
 * This function is injected by UMController into the target process
 * and executes when LdrLoadDll returns (via trampoline mechanism)
 * 
 * @param ModuleBase Base address of the DLL being loaded
 * @param hEventLoad Event to signal when target DLL is detected
 * @param hEventRelease Event to wait on before allowing LdrLoadDll to return
 * @param WatchList List of DLL names to monitor (without .dll extension)
 */
extern "C" __declspec(dllexport)
void DllLoadMonHook(
    PVOID ModuleBase,
    HANDLE hEventLoad,
    HANDLE hEventRelease,
    PVOID WatchList
)
{
    // Step 1: Extract module name from ModuleBase (points to newly loaded DLL)
    const char* moduleName = ReadModuleNameFromRDI(ModuleBase);
    
    if (!moduleName || strlen(moduleName) == 0) {
        // Failed to extract module name, skip monitoring
        return;
    }
    
    // Step 2: Check if this module is in our watch list
    if (IsModuleInWatchList(moduleName, WatchList)) {
        // Step 3: Target DLL detected - notify UMController
        if (hEventLoad) {
            SetEvent(hEventLoad);
        }
        
        // Step 4: CRITICAL - Block LdrLoadDll return until UMController applies hooks
        // Wait for release signal from UMController (with timeout for safety)
        if (hEventRelease) {
            DWORD waitResult = WaitForSingleObject(hEventRelease, 5000); // 5 second timeout
            if (waitResult == WAIT_TIMEOUT) {
                // Timeout occurred - log error and continue anyway
                // This prevents permanent deadlock if UMController crashes
            }
        }
    }
    
    // Step 5: Return to trampoline, which will restore registers and jump back
}

/**
 * Initialize DllLoadMon global state
 * Called by UMController if global state setup is needed
 * 
 * @param hEventLoad Load notification event handle
 * @param hEventRelease Release wait event handle
 * @return NTSTATUS success or error code
 */
extern "C" __declspec(dllexport)
NTSTATUS DllLoadMon_Initialize(
    HANDLE hEventLoad,
    HANDLE hEventRelease
)
{
    // Initialize global shared data structure
    // This is called by UMController before hooking begins
    
    if (!g_pSharedData) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Set event handles in shared data
    g_pSharedData->hLoadEvent = hEventLoad;
    g_pSharedData->hReleaseEvent = hEventRelease;
    
    // Initialize SRW lock for thread-safe watch list access
    InitializeSRWLock(&g_pSharedData->WatchListLock);
    
    return STATUS_SUCCESS;
}

/**
 * Extract module name from DLL base address
 * 
 * The ModuleBase parameter points to the DOS header of the loaded DLL.
 * We need to parse the PE structure to extract the module name.
 * 
 * @param ModuleBase Base address of the DLL (DOS header)
 * @return Pointer to module name string (may be static buffer)
 */
static const char* ReadModuleNameFromRDI(PVOID ModuleBase)
{
    if (!ModuleBase || !g_pSharedData) {
        return "";
    }
    
    // In LdrLoadDll return context, ModuleBase is the HMODULE of the newly loaded DLL
    // We need to extract the module name and compare with our watch list
    
    // Extract module name from base address
    static char moduleName[256] = {0};
    ExtractModuleNameFromBase(ModuleBase, moduleName, sizeof(moduleName));
    
    return moduleName;
}

/**
 * Extract just the filename (without extension) from a DLL path
 * 
 * This is a simplified implementation. In production, you might want to:
 * - Query the full path using NtQueryInformationProcess or similar
 * - Parse the ANSI_MODULE_INFO structure if available
 * 
 * @param ModuleBase Base address of the DLL
 * @return Static buffer containing module name (without .dll extension)
 */
static const char* ExtractModuleName(PCHAR ModuleBase)
{
    // In LdrLoadDll hook context, ModuleBase points to the newly loaded DLL image
    // We need to extract the module name from the full DLL path
    // Since we're in user mode hook context, we can use standard Win32 APIs
    
    static char moduleNameBuffer[256] = {0};
    memset(moduleNameBuffer, 0, sizeof(moduleNameBuffer));
    
    // Get the full path of the module using GetModuleFileNameExA
    // Note: This requires psapi.lib linkage
    char fullPath[MAX_PATH] = {0};
    
    // Try to get module filename - this works if we have the module handle
    // In LdrLoadDll return context, ModuleBase is the HMODULE
    HMODULE hModule = (HMODULE)ModuleBase;
    
    // GetModuleFileNameExA requires a process handle, which we don't have in hook context
    // Alternative: parse the LDR_DATA_TABLE_ENTRY or use RtlGetFullPathName_U
    // For now, we'll use a simpler approach - the watch list should be pre-populated
    // by UMController with module names only, and we compare against base addresses
    
    // Simplified approach: since we can't easily get the name in hook context,
    // we rely on UMController to set up a lookup table mapping base addresses to names
    // This is a placeholder indicating the limitation
    
    return moduleNameBuffer; // Empty for now - needs UMController support
}

/**
{
    // Extract module name from DLL base address
    // This is called in hook context where we have limited API access
    
    if (!ModuleBase || !outBuffer || bufferSize == 0) {
        return;
    }
    
    memset(outBuffer, 0, bufferSize);
    
    // Parse DOS header to validate PE structure
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }
    
    // Parse NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    
    // Get export directory
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) {
        return;
    }
    
    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModuleBase + exportDir.VirtualAddress);
    if (!exportTable || !exportTable->Name) {
        return;
    }
    
    // Get module name from export table
    const char* dllName = (const char*)((ULONG_PTR)ModuleBase + exportTable->Name);
    
    // Copy name to output buffer (removing .dll extension if present)
    strncpy_s(outBuffer, bufferSize, dllName, _TRUNCATE);
    
    // Remove .dll extension
    size_t len = strlen(outBuffer);
    if (len > 4 && _stricmp(outBuffer + len - 4, ".dll") == 0) {
        outBuffer[len - 4] = '\0';
    }
}

/**
 * Check if a module name exists in the watch list
 * 
 * @param moduleName Name of the module to check (without .dll extension)
 * @param WatchList Pointer to watch list (std::vector<std::string>*)
 * @return true if module is in watch list, false otherwise
 */
static bool IsModuleInWatchList(const char* moduleName, PVOID WatchList)
{
    // Acquire SRW lock for reading
    AcquireSRWLockShared(&g_pSharedData->WatchListLock);
    
    bool found = false;
    
    // Search through watch list
    for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
        const char* watchedName = &((char*)WatchList)[i * 256]; // Assuming 256 char per name
        if (_stricmp(moduleName, watchedName) == 0) {
            found = true;
            break;
        }
    }
    
    // Release SRW lock
    ReleaseSRWLockShared(&g_pSharedData->WatchListLock);
    
    return found;
}
