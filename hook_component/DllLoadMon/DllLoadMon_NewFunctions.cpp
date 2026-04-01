/**
 * Create memory-mapped file and populate watch list
 * Called by UMController to set up monitoring for a target process
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
) {
    if (!phFileMapping || moduleNames.empty()) {
        return FALSE;
    }
    
    // Construct shared memory name: Global\DllLoadMon_SharedData_{PID}
    wchar_t sharedMemName[64];
    _snwprintf_s(sharedMemName, _countof(sharedMemName), _TRUNCATE, 
                 L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    // Create file mapping with initial size
    HANDLE hMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DllLoadMonSharedData),
        sharedMemName
    );
    
    if (!hMapping) {
        return FALSE;
    }
    
    // Map view of file
    DllLoadMonSharedData* pShared = (DllLoadMonSharedData*)MapViewOfFile(
        hMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DllLoadMonSharedData)
    );
    
    if (!pShared) {
        CloseHandle(hMapping);
        return FALSE;
    }
    
    // Zero-initialize the shared structure
    RtlZeroMemory(pShared, sizeof(DllLoadMonSharedData));
    
    // Create event names: Global\DelayHook_Load_{PID} and Global\DelayHook_Release_{PID}
    wchar_t loadEventName[64];
    wchar_t releaseEventName[64];
    _snwprintf_s(loadEventName, _countof(loadEventName), _TRUNCATE,
                 L"Global\\DelayHook_Load_%lu", pid);
    _snwprintf_s(releaseEventName, _countof(releaseEventName), _TRUNCATE,
                 L"Global\\DelayHook_Release_%lu", pid);
    
    // Create synchronization events
    HANDLE hLoadEvent = CreateEventW(NULL, FALSE, FALSE, loadEventName);
    HANDLE hReleaseEvent = CreateEventW(NULL, FALSE, FALSE, releaseEventName);
    
    if (!hLoadEvent || !hReleaseEvent) {
        if (hLoadEvent) CloseHandle(hLoadEvent);
        if (hReleaseEvent) CloseHandle(hReleaseEvent);
        UnmapViewOfFile(pShared);
        CloseHandle(hMapping);
        return FALSE;
    }
    
    // Store event handles in shared structure
    pShared->hLoadEvent = hLoadEvent;
    pShared->hReleaseEvent = hReleaseEvent;
    
    // Populate watch list with module names
    UINT moduleCount = 0;
    for (const auto& moduleName : moduleNames) {
        if (moduleCount >= MAX_WATCHED_MODULES) {
            break; // Watch list full
        }
        
        // Copy module name (without .dll extension)
        size_t copyLen = min(moduleName.length(), MAX_MODULE_NAME_LEN - 1);
        wcsncpy_s(pShared->ModuleNames[moduleCount], _countof(pShared->ModuleNames[moduleCount]),
                  moduleName.c_str(), copyLen);
        pShared->ModuleNames[moduleCount][copyLen] = L'\0'; // Ensure null termination
        moduleCount++;
    }
    
    // Store module count
    pShared->ModuleCount = moduleCount;
    
    // Set the watch count so IsModuleInWatchList knows how many entries to check
    pShared->dwWatchCount = moduleCount;
    
    // Signal the data access event to indicate initialization is complete
    // This is a manual-reset event, so it will stay signaled until explicitly reset
    if (g_pSharedData && g_pSharedData->hDataAccessEvent) {
        SetEvent(g_pSharedData->hDataAccessEvent);
    }
    
    // Output handles
    *phFileMapping = hMapping;
    if (ppSharedData) {
        *ppSharedData = pShared;
    }
    
    return TRUE;
}

/**
 * Cleanup memory-mapped file resources
 * Called by UMController when watch is no longer needed
 * 
 * @param hFileMapping File mapping handle to close
 */
DLLLOADMON_API
VOID DllLoadMon_CleanupWatchList(HANDLE hFileMapping) {
    if (!hFileMapping) {
        return;
    }
    
    // Get shared data pointer before unmapping
    DllLoadMonSharedData* pShared = (DllLoadMonSharedData*)MapViewOfFile(
        hFileMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DllLoadMonSharedData)
    );
    
    if (pShared) {
        // Close event handles (owned by shared structure)
        if (pShared->hLoadEvent) {
            CloseHandle(pShared->hLoadEvent);
            pShared->hLoadEvent = NULL;
        }
        if (pShared->hReleaseEvent) {
            CloseHandle(pShared->hReleaseEvent);
            pShared->hReleaseEvent = NULL;
        }
        
        // Unmap view
        UnmapViewOfFile(pShared);
    }
    
    // Close file mapping handle
    CloseHandle(hFileMapping);
}
