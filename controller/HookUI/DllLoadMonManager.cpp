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

	// Check if this is the first module for this process
	bool isFirstModule = m_WatchedModules[pid].empty();
	
	// Accumulate module name for this process
	m_WatchedModules[pid].push_back(moduleName);

	// If this is the first module, setup DllLoadMon infrastructure
	if (isFirstModule) {
		return SetupDllLoadMon(pid);
	}

	// For subsequent modules, update the shared memory with the new watch list
	return UpdateWatchListInSharedMemory(pid);
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
		DLL_LOAD_MON_SHARED_DATA_FMT, pid);

	// Setup security descriptor to allow access from all processes (including low-privilege)
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, TRUE);  // NULL DACL = allow everyone
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;

	// Create file mapping with explicit security attributes
	hFileMapping = CreateFileMappingW(
		INVALID_HANDLE_VALUE,
		&sa,  // Security attributes allowing everyone
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


	// Store event handles in shared structure
	 

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
	pSharedData->dwWatchCount = moduleCount;  // ¡û ÐÂÔöÕâÒ»ÐÐ

	// Store handles (note: storing mapped view pointer as HANDLE for compatibility)
	m_WatchFileMappings[pid] = hFileMapping;
	 
	// Create event names
	wchar_t loadEventName[64];
	wchar_t releaseEventName[64];
	wchar_t accessEventName[64];
	_snwprintf_s(loadEventName, _countof(loadEventName), _TRUNCATE,
		DELAY_HOOK_LOAD_EVENT_FMT, pid);
	_snwprintf_s(releaseEventName, _countof(releaseEventName), _TRUNCATE,
		DELAY_HOOK_RELEASE_EVENT_FMT, pid);
	_snwprintf_s(accessEventName, _countof(accessEventName), _TRUNCATE,
		DLL_LOAD_MON_DATA_ACCESS_EVENT_FMT, pid);

	// Create synchronization events
	// Create events with explicit security attributes for cross-process access
	// 创建事件，句柄暂时先不管
	 CreateEventW(&sa, FALSE, FALSE, loadEventName);
	 CreateEventW(&sa, FALSE, FALSE, releaseEventName);



	// Now install the LdrLoadDll hook
	return InstallLdrLoadDllHook(pid);
}

// Helper function to create security descriptor that allows everyone access
bool DllLoadMonManager::UpdateWatchListInSharedMemory(DWORD pid) {
	// Get the file mapping for this process
	auto itMap = m_WatchFileMappings.find(pid);
	if (itMap == m_WatchFileMappings.end() || !itMap->second) {
		return false;  // No shared memory exists yet
	}

	// Get the mapped view pointer
	DllLoadMonSharedData* pSharedData = (DllLoadMonSharedData*)itMap->second;

	// Acquire exclusive access using mutex event
	wchar_t accessEventName[64];
	_snwprintf_s(accessEventName, _countof(accessEventName), _TRUNCATE,
		DLL_LOAD_MON_DATA_ACCESS_EVENT_FMT, pid);
	
	// Open with EVENT_MODIFY_STATE permission to allow SetEvent/ResetEvent operations
	HANDLE hAccessEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, accessEventName);
	if (!hAccessEvent) {
		LOG_UI(m_services, L"Failed to open access event for PID %d, Error=0x%x\n", pid, GetLastError());
		return false;
	}

	// Wait for exclusive access (timeout 5 seconds)
	DWORD waitResult = WaitForSingleObject(hAccessEvent, DLL_LOAD_MON_DATA_ACCESS_TIMEOUT);
	if (waitResult != WAIT_OBJECT_0) {
		LOG_UI(m_services, L"Failed to acquire access lock for PID %d, WaitResult=0x%x\n", pid, waitResult);
		CloseHandle(hAccessEvent);
		return false;
	}

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
	pSharedData->dwWatchCount = moduleCount;

	// Release exclusive access
	SetEvent(hAccessEvent);
	CloseHandle(hAccessEvent);

	return true;
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


	std::wstring dllPath = m_services->GetCurrentDirFilePath(DLL_LOAD_MON_DLL_NAME);


	// ¸´ÖÆ
	// ========== ÔÚ´Ë´¦Ìí¼Ó¸´ÖÆÂß¼­ ==========
	std::wstring pathToInject = dllPath;
	wchar_t* temp_dll_name = nullptr;

	{
		// ÌáÈ¡DLLÎÄ¼þÃû
		size_t pos = dllPath.find_last_of(L'\\');
		std::wstring dll_name = (pos != std::wstring::npos) ?
			dllPath.substr(pos + 1) : dllPath;

		// »ñÈ¡³ÌÐòËùÔÚÄ¿Â¼×÷ÎªÁÙÊ±ÎÄ¼þ¼Ð
		
		std::wstring modPath(dllPath);
		size_t p = modPath.find_last_of(L"\\/");
		std::wstring folder = (p == std::wstring::npos) ?
			L".\\" HOOK_CODE_TEMP_DIR_NAME :
			modPath.substr(0, p) + L"\\" HOOK_CODE_TEMP_DIR_NAME;

		// È·±£Ä¿Â¼´æÔÚ
		if (!CreateDirectoryW(folder.c_str(), NULL)) {
			DWORD err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				LOG_UI(m_services, L"CreateDirectoryW failed for %s err=%u\n", folder.c_str(), err);
			}
		}

		// Éú³É´øÊ±¼ä´ÁµÄÎÄ¼þÃû
		SYSTEMTIME st;
		GetLocalTime(&st);
		wchar_t ts[64];
		swprintf(ts, _countof(ts), L"%04d%02d%02d_%02d%02d%02d_%03d",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond,
			st.wMilliseconds);

		std::wstring new_dll_name = std::wstring(ts) + L"_" + dll_name;
		temp_dll_name = (wchar_t*)malloc(2 * (new_dll_name.length() + 1));
		ZeroMemory(temp_dll_name, 2 * (new_dll_name.length() + 1));
		memcpy(temp_dll_name, new_dll_name.c_str(), 2 * new_dll_name.length());

		std::wstring dest = folder + L"\\" + new_dll_name;

		// ¸´ÖÆÎÄ¼þ
		if (CopyFileW(dllPath.c_str(), dest.c_str(), FALSE)) {
			pathToInject = dest;  // Ê¹ÓÃ¸´ÖÆºóµÄÎÄ¼þ
			LOG_UI(m_services, L"Copied DllLoadMon DLL to %s\n", dest.c_str());
		}
		else {
			DWORD err = GetLastError();
			LOG_UI(m_services, L"CopyFileW failed src=%s dst=%s err=%u - falling back to original\n",
				dllPath.c_str(), dest.c_str(), err);
			return false;
			// ±£³ÖpathToInject ÎªÔ­Ê¼Â·¾¶
		}
	}




	// Step 3: Validate export in hook DLL
	DWORD hookCodeOffset = 0;
	if (!m_services->CheckExportFromFile(pathToInject.c_str(), DLL_LOAD_MON_EXPORT_X64, &hookCodeOffset)) {
		LOG_UI(m_services, L"failed to call CheckExportFromFile\n");
		return false;
	}
	 
	// Step 5: Inject DllLoadMon.dll into target process
	if (!m_services->InjectTrampoline(pid, pathToInject.c_str())) {
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
		m_services,  // services - not needed for DllLoadMon hook
		targetFuncAddr,  // Use calculated target process address
		DLL_LOAD_MON_HOOK_ID,   // Hook ID (DELAYLOAD_MON)
		&oriLen,
		&trampolinePit,
		&oriCodeAddr
	);

	return hookSuccess;
}