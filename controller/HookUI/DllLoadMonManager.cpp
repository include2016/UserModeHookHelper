// DllLoadMonManager.cpp - Implementation of DllLoadMon management

#include "DllLoadMonManager.h"
#include "../ProcessHackerLib/phlib_expose.h"
#include <cstdio>
#include "../../Shared/LogMacros.h"
#include "../../Shared/SharedMacroDef.h"

DllLoadMonManager::DllLoadMonManager(IHookServices* services) 
    : m_services(services) {
}

DllLoadMonManager::~DllLoadMonManager() {
    Cleanup();
}

bool DllLoadMonManager::RegisterModuleWatch(DWORD pid, const wchar_t* moduleName) {
    if (!moduleName || wcslen(moduleName) == 0) {
        return false;
    }
    
    // Accumulate module name for this process
    m_WatchedModules[pid].push_back(moduleName);
    
    // If this is the first module, setup DllLoadMon infrastructure
    if (m_WatchedModules[pid].size() == 1) {
        return SetupDllLoadMon(pid);
    }
    
    // Subsequent modules are already covered by existing watch list
    return true;
}

void DllLoadMonManager::UnregisterModuleWatch(DWORD pid) {
    // Close load/release events
    auto itLoad = m_LoadEvents.find(pid);
    if (itLoad != m_LoadEvents.end() && itLoad->second) {
        CloseHandle(itLoad->second);
        m_LoadEvents.erase(itLoad);
    }
    
    auto itRelease = m_ReleaseEvents.find(pid);
    if (itRelease != m_ReleaseEvents.end() && itRelease->second) {
        CloseHandle(itRelease->second);
        m_ReleaseEvents.erase(itRelease);
    }
    
    // Unmap and close file mapping
    auto itMap = m_WatchFileMappings.find(pid);
    if (itMap != m_WatchFileMappings.end() && itMap->second) {
        UnmapViewOfFile((PVOID)(itMap->second));  // Note: stored as HANDLE but actually mapped view pointer
        CloseHandle(itMap->second);
        m_WatchFileMappings.erase(itMap);
    }
    
    // Clear watched modules list
    m_WatchedModules.erase(pid);
}

void DllLoadMonManager::Cleanup() {
    // Unregister all processes
    for (auto& pair : m_WatchedModules) {
        UnregisterModuleWatch(pair.first);
    }
    m_WatchedModules.clear();
    m_WatchFileMappings.clear();
    m_LoadEvents.clear();
    m_ReleaseEvents.clear();
}

bool DllLoadMonManager::SetupDllLoadMon(DWORD pid) {
    HANDLE hFileMapping = nullptr;
    DllLoadMonSharedData* pSharedData = nullptr;
    
    // Construct shared memory name: Global\DllLoadMon_SharedData_{PID}
    wchar_t sharedMemName[64];
    _snwprintf_s(sharedMemName, _countof(sharedMemName), _TRUNCATE,
                 L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    // Create file mapping with initial size
    hFileMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DllLoadMonSharedData),
        sharedMemName
    );
    
    if (!hFileMapping) {
        return false;
    }
    
    // Map view of file
    pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
        hFileMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DllLoadMonSharedData)
    );
    
    if (!pSharedData) {
        CloseHandle(hFileMapping);
        return false;
    }
    
    // Zero-initialize the shared structure
    RtlZeroMemory(pSharedData, sizeof(DllLoadMonSharedData));
    
    // Create event names
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
        UnmapViewOfFile(pSharedData);
        CloseHandle(hFileMapping);
        return false;
    }
    
    // Store event handles in shared structure
    pSharedData->hLoadEvent = hLoadEvent;
    pSharedData->hReleaseEvent = hReleaseEvent;
    
    // Initialize lock
    InitializeSRWLock((PSRWLOCK)&pSharedData->WatchListLock);
    
    // Populate watch list with module names
    UINT moduleCount = 0;
    for (const auto& modName : m_WatchedModules[pid]) {
        if (moduleCount >= DLM_MAX_WATCHED_MODULES) {
            break;
        }
        
        size_t copyLen = min(modName.length(), (size_t)(DLM_MAX_MODULE_NAME_LEN - 1));
        wcsncpy_s(pSharedData->ModuleNames[moduleCount], DLM_MAX_MODULE_NAME_LEN,
                  modName.c_str(), _TRUNCATE);
        pSharedData->ModuleNames[moduleCount][copyLen] = L'\0';
        moduleCount++;
    }
    
    // Store module count
    pSharedData->ModuleCount = moduleCount;
    
    // Store handles (note: storing mapped view pointer as HANDLE for compatibility)
    m_WatchFileMappings[pid] = hFileMapping;
    m_LoadEvents[pid] = hLoadEvent;
    m_ReleaseEvents[pid] = hReleaseEvent;
    
    // Now install the LdrLoadDll hook
    return InstallLdrLoadDllHook(pid);
}

DWORD64 DllLoadMonManager::CalculateNtdllLdrLoadDllRetOffset(DWORD pid, bool is64Bit) {
    // Call through IHookServices interface to delegate to UMController implementation
    // This uses the MD5-based lookup table from LdrLoadDllOffsets module
    return m_services->CalculateNtdllLdrLoadDllRetOffset(pid, is64Bit);
}

bool DllLoadMonManager::InstallLdrLoadDllHook(DWORD pid) {
    // Step 1: Determine target process architecture
    bool isTarget64Bit = false;
    if (!m_services->IsProcess64(pid, isTarget64Bit)) {
        return false;
    }
    
    // Step 2: Calculate LdrLoadDll return offset
    DWORD64 ldrLoadDllRetOffset = CalculateNtdllLdrLoadDllRetOffset(pid, isTarget64Bit);
    if (ldrLoadDllRetOffset == 0) {
        return false;
    }
    
    // Step 3: Get ntdll.dll base address in target process
    DWORD64 ntdllBase = 0;
    if (!m_services->GetModuleBase(pid, L"ntdll.dll", &ntdllBase)) {
        return false;
    }
    
    ULONGLONG ldrLoadDllRetAddr = ntdllBase + ldrLoadDllRetOffset;
    
 
	std::wstring dllPath= m_services->GetCurrentDirFilePath(DLL_LOAD_MON_DLL_NAME);
	// Step 3: Validate export in hook DLL
	DWORD hookCodeOffset = 0;
	if (!m_services->CheckExportFromFile(dllPath.c_str(), DLL_LOAD_MON_EXPORT_X64, &hookCodeOffset)) {
		LOG_UI(m_services, L"failed to call CheckExportFromFile\n");
		return false;
	}
    
    // Step 5: Inject DllLoadMon.dll into target process
    if (!m_services->InjectTrampoline(pid, dllPath.c_str())) {
		LOG_UI(m_services, L"failed to call InjectTrampoline\n");
        return false;
    }
    
    // Step 6: Wait for DllLoadMon.dll to load in target process
    DWORD64 dllLoadMonBase = 0;
    for (int i = 0; i < 50; i++) {
        if (m_services->GetModuleBase(pid, DLL_LOAD_MON_DLL_NAME, &dllLoadMonBase)) {
            break;
        }
        Sleep(100);
    }
    
    if (dllLoadMonBase == 0) {
		LOG_UI(m_services, L"%s filed to be injected into target Pid=%u\n", DLL_LOAD_MON_DLL_NAME, pid);
        return false;  // Timeout waiting for module to load
    }
    
    // Step 9: Calculate function address in TARGET process
    DWORD64 targetFuncAddr = dllLoadMonBase + hookCodeOffset;
    
    // Step 10: Apply hook using HookCore::ApplyHook with target process address
    DWORD oriLen = 0;
    PVOID trampolinePit = NULL;
    PVOID oriCodeAddr = NULL;
    
    bool hookSuccess = HookCore::ApplyHook(
        pid,
        ldrLoadDllRetAddr,
        nullptr,  // services - not needed for DllLoadMon hook
        targetFuncAddr,  // Use calculated target process address
		DLL_LOAD_MON_HOOK_ID,   // Hook ID (DELAYLOAD_MON)
        &oriLen,
        &trampolinePit,
        &oriCodeAddr
    );
    
    return hookSuccess;
}