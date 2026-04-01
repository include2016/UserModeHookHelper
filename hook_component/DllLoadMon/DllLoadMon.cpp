// DllLoadMon.cpp - DLL Load Monitor Hook Implementation
// Rev6: Monitors LdrLoadDll return and signals UMController when target DLL is loaded

#include "pch.h"
#include "DllLoadMon.h"
#include <strsafe.h>
#include <evntprov.h>
#include "../HookCodeLib/HookCodeLib.h"
#include "../../Shared/SharedMacroDef.h"
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
#define DebugBreak() __debugbreak();
void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[DllLoadMon] %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
}
static BOOL InitializeEvents();
// Global pointer to shared data (stored in memory-mapped file)
static DllLoadMonSharedData* g_pSharedData = nullptr;
static HANDLE g_hFileMapping = NULL;
class HookServicesAdapter : public IHookServices {
	VOID HKLog(const wchar_t* fmt, ...) override {
		WCHAR Buffer[1024];
		va_list args;
		va_start(args, fmt);
		_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, fmt, args);
		va_end(args);
		Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

		WCHAR Prefixed[1100];
		_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HCLib]      %s", Buffer);
		Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
		EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
	}
};
static HookServicesAdapter g_HookServices; // singleton adapter instance
// PROLOG macros for capturing register values from hook context
// X64 version - extracts registers from stack
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                              \
        return;                                                                \
    }                                                                          \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                       \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);            \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);            \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);           \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);           \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);           \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);           \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);           \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);           \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);           \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);           \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

// Win32 version - extracts registers from stack
#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                              \
        return;                                                                \
    }                                                                          \
    ULONG original_esp = (esp) + 0x20;                                         \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                     \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                     \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                     \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                     \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                    \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                    \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);

/**
 * Initialize shared data from memory-mapped file
 * Called automatically in DllMain or on first use
 */
static BOOL InitializeSharedData() {
	if (g_pSharedData) {
		return TRUE; // Already initialized
	}

	// Get current process ID
	DWORD pid = GetCurrentProcessId();

	// Build file mapping name
	WCHAR szMappingName[MAX_PATH];
	HRESULT hr = StringCchPrintfW(szMappingName, MAX_PATH, DLL_LOAD_MON_SHARED_DATA_FMT, pid);
	if (FAILED(hr)) {
		return FALSE;
	}

	// Open existing file mapping (created by UMController)
	g_hFileMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, szMappingName);
	if (!g_hFileMapping) {
		// File mapping not found - UMController hasn't created it yet
		// This is OK, we'll try again later or hooks won't trigger
		return FALSE;
	}

	// Map view of file into our address space
	g_pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
		g_hFileMapping,
		FILE_MAP_ALL_ACCESS,
		0, 0, sizeof(DllLoadMonSharedData)
	);

	if (!g_pSharedData) {
		CloseHandle(g_hFileMapping);
		g_hFileMapping = NULL;
		return FALSE;
	}
	InitializeEvents();
	return TRUE;
}

/**
 * Initialize event handles from named events
 * Called automatically in DllMain or on first use
 */
static BOOL InitializeEvents() {
	if (!g_pSharedData) {
		if (!InitializeSharedData()) {
			return FALSE;
		}
	}

	// Check if already initialized (including hDataAccessEvent)
	if (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent && g_pSharedData->hDataAccessEvent) {
		return TRUE;
	}

	// Get current process ID
	DWORD pid = GetCurrentProcessId();

	// Build event names
	WCHAR szLoadEventName[MAX_PATH];
	WCHAR szReleaseEventName[MAX_PATH];
	WCHAR szDataAccessEventName[MAX_PATH];
	StringCchPrintfW(szLoadEventName, MAX_PATH, DELAY_HOOK_LOAD_EVENT_FMT, pid);
	StringCchPrintfW(szReleaseEventName, MAX_PATH, DELAY_HOOK_RELEASE_EVENT_FMT, pid);
	StringCchPrintfW(szDataAccessEventName, MAX_PATH, DLL_LOAD_MON_DATA_ACCESS_EVENT_FMT, pid);

	// Open existing events (created by UMController)
	g_pSharedData->hLoadEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, szLoadEventName);
	Log(L"get load event hanle=0x%x\tname=%s\tError=0x%x\n", g_pSharedData->hLoadEvent, szLoadEventName,GetLastError());
	g_pSharedData->hReleaseEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, szReleaseEventName);
	Log(L"get release event hanle=0x%x\tname=%s\tError=0x%x\n", g_pSharedData->hReleaseEvent, szReleaseEventName,GetLastError());
	g_pSharedData->hDataAccessEvent = OpenEventW(SYNCHRONIZE, FALSE, szDataAccessEventName);
	Log(L"get event handle\n");
	return (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent && g_pSharedData->hDataAccessEvent);
}

/**
 * Check if a DLL name exists in the watch list
 *
 * @param dllName PUNICODE_STRING containing DLL name (without path)
 * @return true if module is in watch list, false otherwise
 */
static BOOL IsModuleInWatchList(PUNICODE_STRING dllName) {
	Log(L"%wZ loading\n", dllName);

	if (!g_pSharedData || !dllName || !dllName->Buffer) {
		return FALSE;
	}

	// Validate watch count
	if (g_pSharedData->dwWatchCount > 256 || g_pSharedData->dwWatchCount == 0) {
		return FALSE;
	}

	BOOL found = FALSE;
	for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
		PCWSTR watchedName = g_pSharedData->ModuleNames[i];
		Log(L"checking watched name: %s\n", watchedName);
		// Validate string is null-terminated
		if (!watchedName[0]) {
			continue;
		}
		HookCode::UNICODE_STRING uniWatchedName;
		HookCode::STRLIB::RtlInitUnicodeString(&uniWatchedName, watchedName);

		if (HookCode::STRLIB::RtlSuffixUnicodeString(&uniWatchedName, (HookCode::PUNICODE_STRING)dllName, TRUE)) {
			Log(L"target dll is loaded\n");
			found = TRUE;
			break;
		}
	}

	return found;
}

/**
 * X64 Hook callback function
 * Called at LdrLoadDll return address
 *
 * Parameters (from stack via PROLOG):
 * - RCX: ModuleBase (not used, we get it from RDI)
 * - RDI: PUNICODE_STRING of DLL name being loaded
 */
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	// Capture registers from stack
	PROLOGX64(rsp);

	// Ensure shared data is initialized
	if (!g_pSharedData) {
		if (!InitializeSharedData()) {
			return;
		}
	}

	// Ensure events are initialized
	if (!g_pSharedData->hLoadEvent || !g_pSharedData->hReleaseEvent) {
		if (!InitializeEvents()) {
			return;
		}
	}

	// RDI points to PUNICODE_STRING of DLL name being loaded
	PUNICODE_STRING dllName = (PUNICODE_STRING)rdi;

	// Validate pointer
	if (!dllName || !dllName->Buffer || !dllName->Length) {
		return;
	}

	// Check if this DLL is in our watch list
	if (IsModuleInWatchList(dllName)) {
		// Target DLL detected! Notify UMController
		if (g_pSharedData->hLoadEvent) {
			SetEvent(g_pSharedData->hLoadEvent);
			Log(L"SetEvent error=0x%x\n", GetLastError());
		}

		// Wait for UMController to apply pending hooks
		// Timeout after 5 seconds to prevent permanent deadlock
		if (g_pSharedData->hReleaseEvent) {
			WaitForSingleObject(g_pSharedData->hReleaseEvent, 0);
			Log(L"wait finished\n");
		}
	}

	// Return to normal execution
	return;
}

/**
 * Optional initialization function
 * Can be called by UMController to pre-initialize state
 */
DLLLOADMON_API
NTSTATUS DllLoadMon_Initialize(HANDLE hEventLoad, HANDLE hEventRelease) {
	// Initialize shared data
	if (!InitializeSharedData()) {
		return STATUS_UNSUCCESSFUL;
	}

	// Store event handles if provided
	if (hEventLoad && hEventRelease) {
		g_pSharedData->hLoadEvent = hEventLoad;
		g_pSharedData->hReleaseEvent = hEventRelease;
	}

	return STATUS_SUCCESS;
}
 
/**
 * Cleanup memory-mapped file resources
 */
DLLLOADMON_API
VOID DllLoadMon_CleanupWatchList(HANDLE hFileMapping) {
	if (!hFileMapping) {
		return;
	}

	DllLoadMonSharedData* pShared = (DllLoadMonSharedData*)MapViewOfFile(
		hFileMapping,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(DllLoadMonSharedData)
	);

	if (pShared) {
		if (pShared->hLoadEvent) {
			CloseHandle(pShared->hLoadEvent);
			pShared->hLoadEvent = NULL;
		}
		if (pShared->hReleaseEvent) {
			CloseHandle(pShared->hReleaseEvent);
			pShared->hReleaseEvent = NULL;
		}

		UnmapViewOfFile(pShared);
	}

	CloseHandle(hFileMapping);
}

/**
 * DLL Entry Point
 * Automatically initializes shared data when DLL is loaded into a process
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		// Initialize shared data when DLL is loaded into a process
		// This will open the memory-mapped file created by UMController
		EventRegister(&ProviderGUID,
			NULL,
			NULL,
			&g_ProviderHandle);
		// set HookCodeLib interface
		HookCode::SetHookServices(&g_HookServices);
		InitializeSharedData();
		break;

	case DLL_PROCESS_DETACH:
		// Cleanup when DLL is unloaded
		if (g_pSharedData) {
			if (g_pSharedData->hLoadEvent) {
				CloseHandle(g_pSharedData->hLoadEvent);
				g_pSharedData->hLoadEvent = NULL;
			}
			if (g_pSharedData->hReleaseEvent) {
				CloseHandle(g_pSharedData->hReleaseEvent);
				g_pSharedData->hReleaseEvent = NULL;
			}

			UnmapViewOfFile(g_pSharedData);
			g_pSharedData = nullptr;
		}

		if (g_hFileMapping) {
			CloseHandle(g_hFileMapping);
			g_hFileMapping = NULL;
		}
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
