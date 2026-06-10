#include "pch.h"
#include "InstantHookManager.h"
#include "../HookCoreLib/HookCore.h"
#include "HookInterfaces.h"
#include "../../Shared/SharedMacroDef.h"
#include "../../Shared/HookRow.h"
#include "RegistryStore.h"
#include <process.h>
#include <atlbase.h>
#include <algorithm>
#include "../../Shared/LogMacros.h"
#include "UMController.h"

// Helper: create event with security attributes allowing all processes to signal/sync
static HANDLE CreateWorldAccessibleEventW(BOOL bManualReset, BOOL bInitialState, PCWSTR name) {
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	// Allow everyone access (SYNC | EVENT_MODIFY_STATE | READ_CONTROL)
	if (!SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE)) {
		return NULL;
	}

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;

	return CreateEventW(&sa, bManualReset, bInitialState, name);
}

// Helper: parse hex address string like "0x418b4" or "418b4"
static DWORD64 ParseAddressText(const wchar_t* input, bool& ok) {
	ok = false;
	if (!input || !input[0]) return 0ULL;
	std::wstring t(input);
	for (auto& c : t) c = towlower(c);
	if (t.rfind(L"0x", 0) == 0) t = t.substr(2);
	if (t.empty()) return 0ULL;
	DWORD64 val = 0ULL;
	for (wchar_t c : t) {
		val <<= 4;
		if (c >= L'0' && c <= L'9') val += c - L'0';
		else if (c >= L'a' && c <= L'f') val += c - L'a' + 10;
		else if (c >= L'A' && c <= L'F') val += c - L'A' + 10;
		else return 0ULL;
	}
	ok = true;
	return val;
}

InstantHookManager::InstantHookManager(IHookServices* services)
	: m_services(services)
{
}

InstantHookManager::~InstantHookManager() {
	StopAll();
}

bool InstantHookManager::AddTarget(const HookTarget& target) {
	ListenerContext* ctx = new ListenerContext;
	ctx->mgr = this;
	ctx->target = target;
	ctx->isPatchMode = (target.exportName.compare(0, 6, L"patch.") == 0);
	ctx->hLoadNotify = NULL;
	ctx->hHookNotify = NULL;
	ctx->hStopEvent = NULL;
	ctx->hThread = NULL;
	ctx->running = false;
	m_Listeners.push_back(ctx);
	return true;
}

void InstantHookManager::StartAllListeners() {
	for (auto* ctx : m_Listeners) {
		if (ctx->hThread) continue; // Already started

		// Create stop event
		ctx->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
		if (!ctx->hStopEvent) continue;

		ctx->running = true;
		ctx->hThread = (HANDLE)_beginthreadex(NULL, 0, [](void* lp) -> unsigned {
			ListenerContext* context = static_cast<ListenerContext*>(lp);
			reinterpret_cast<InstantHookManager*>(context->mgr)
				->ListenerThreadImpl(context);
			return 0;
		}, ctx, 0, NULL);
	}
}

void InstantHookManager::StopAll() {
	for (auto* ctx : m_Listeners) {
		// Signal stop
		if (ctx->hStopEvent) {
			SetEvent(ctx->hStopEvent);
		}
		ctx->running = false;

		// Wait for thread to exit
		if (ctx->hThread) {
			WaitForSingleObject(ctx->hThread, 5000);
			CloseHandle(ctx->hThread);
			ctx->hThread = NULL;
		}

		// Close events
		if (ctx->hStopEvent) {
			CloseHandle(ctx->hStopEvent);
			ctx->hStopEvent = NULL;
		}
		if (ctx->hLoadNotify) {
			CloseHandle(ctx->hLoadNotify);
			ctx->hLoadNotify = NULL;
		}
		if (ctx->hHookNotify) {
			CloseHandle(ctx->hHookNotify);
			ctx->hHookNotify = NULL;
		}

		delete ctx;
	}
	m_Listeners.clear();

	// Release all hook ID pools since everything is stopped
	while (InterlockedExchange(&m_HookIdLock, 1) != 0) Sleep(1);
	m_PidHookIdPools.clear();
	InterlockedExchange(&m_HookIdLock, 0);
}

void InstantHookManager::StopByProcessHashAndMode(unsigned long long processFnvHash, bool isPatch) {
	std::vector<ListenerContext*> toRemove;

	for (auto* ctx : m_Listeners) {
		if (ctx->target.processFnvHash == processFnvHash && ctx->isPatchMode == isPatch) {
			// Signal stop
			if (ctx->hStopEvent) {
				SetEvent(ctx->hStopEvent);
			}
			ctx->running = false;

			// Wait for thread to exit
			if (ctx->hThread) {
				WaitForSingleObject(ctx->hThread, 5000);
				CloseHandle(ctx->hThread);
				ctx->hThread = NULL;
			}

			// Close events
			if (ctx->hStopEvent) {
				CloseHandle(ctx->hStopEvent);
				ctx->hStopEvent = NULL;
			}
			if (ctx->hLoadNotify) {
				CloseHandle(ctx->hLoadNotify);
				ctx->hLoadNotify = NULL;
			}
			if (ctx->hHookNotify) {
				CloseHandle(ctx->hHookNotify);
				ctx->hHookNotify = NULL;
			}

			toRemove.push_back(ctx);
		}
	}

	// Remove from list
	for (auto* ctx : toRemove) {
		m_Listeners.erase(std::remove(m_Listeners.begin(), m_Listeners.end(), ctx), m_Listeners.end());
		delete ctx;
	}

	// Clean up hook ID pools for dead processes after stopping listeners
	CleanupDeadPidPools();
}

void InstantHookManager::StopByProcessHash(unsigned long long processFnvHash) {
	std::vector<ListenerContext*> toRemove;

	for (auto* ctx : m_Listeners) {
		if (ctx->target.processFnvHash == processFnvHash) {
			// Signal stop
			if (ctx->hStopEvent) {
				SetEvent(ctx->hStopEvent);
			}
			ctx->running = false;

			// Wait for thread to exit
			if (ctx->hThread) {
				WaitForSingleObject(ctx->hThread, 5000);
				CloseHandle(ctx->hThread);
				ctx->hThread = NULL;
			}

			// Close events
			if (ctx->hStopEvent) {
				CloseHandle(ctx->hStopEvent);
				ctx->hStopEvent = NULL;
			}
			if (ctx->hLoadNotify) {
				CloseHandle(ctx->hLoadNotify);
				ctx->hLoadNotify = NULL;
			}
			if (ctx->hHookNotify) {
				CloseHandle(ctx->hHookNotify);
				ctx->hHookNotify = NULL;
			}

			toRemove.push_back(ctx);
		}
	}

	// Remove from list
	for (auto* ctx : toRemove) {
		m_Listeners.erase(std::remove(m_Listeners.begin(), m_Listeners.end(), ctx), m_Listeners.end());
		delete ctx;
	}

	// Clean up hook ID pools for dead processes after stopping listeners
	CleanupDeadPidPools();
}

bool InstantHookManager::HasListenerForHash(unsigned long long processFnvHash) const {
	for (const auto* ctx : m_Listeners) {
		if (ctx->target.processFnvHash == processFnvHash && ctx->running) {
			return true;
		}
	}
	return false;
}

std::vector<unsigned long long> InstantHookManager::GetActiveProcessHashes() const {
	std::vector<unsigned long long> hashes;
	for (const auto* ctx : m_Listeners) {
		if (ctx->running) {
			hashes.push_back(ctx->target.processFnvHash);
		}
	}
	return hashes;
}

// Per-PID hook ID allocator
int InstantHookManager::AllocHookId(DWORD pid) {
	while (InterlockedExchange(&m_HookIdLock, 1) != 0) Sleep(1);
	int hookId = -1;
	PerPidHookIdPool& pool = m_PidHookIdPools[pid];
	for (int i = 0; i < 4; ++i) {
		if (pool.bitfield[i] != ~0ULL) {
			for (int bit = 0; bit < 64; ++bit) {
				if (!_bittest((LONG*)&pool.bitfield[i], bit)) {
					_bittestandset((LONG*)&pool.bitfield[i], bit);
					hookId = i * 64 + bit;
					break;
				}
			}
			if (hookId != -1) break;
		}
	}
	InterlockedExchange(&m_HookIdLock, 0);
	return hookId;
}

void InstantHookManager::ReleaseHookId(DWORD pid, int hookId) {
	if (hookId < 0 || hookId >= 256) return;
	while (InterlockedExchange(&m_HookIdLock, 1) != 0) Sleep(1);
	auto it = m_PidHookIdPools.find(pid);
	if (it != m_PidHookIdPools.end()) {
		_bittestandreset((LONG*)&it->second.bitfield[hookId / 64], hookId % 64);
		bool allZero = true;
		for (int i = 0; i < 4; ++i) {
			if (it->second.bitfield[i] != 0) { allZero = false; break; }
		}
		if (allZero) {
			m_PidHookIdPools.erase(it);
		}
	}
	InterlockedExchange(&m_HookIdLock, 0);
}

void InstantHookManager::ReleaseAllHookIdsForPid(DWORD pid) {
	while (InterlockedExchange(&m_HookIdLock, 1) != 0) Sleep(1);
	m_PidHookIdPools.erase(pid);
	InterlockedExchange(&m_HookIdLock, 0);
}

void InstantHookManager::CleanupDeadPidPools() {
	while (InterlockedExchange(&m_HookIdLock, 1) != 0) Sleep(1);
	std::vector<DWORD> deadPids;
	for (auto& kv : m_PidHookIdPools) {
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kv.first);
		if (!h) {
			deadPids.push_back(kv.first);
		} else {
			CloseHandle(h);
		}
	}
	for (DWORD pid : deadPids) {
		LOG_CTRL_INSHOOK(L"releasing hook ID pool for dead pid=%u\n", pid);
		m_PidHookIdPools.erase(pid);
	}
	InterlockedExchange(&m_HookIdLock, 0);
}


// Helper: signal LuaEngine to load a script via IPC
// 1. Find LuaEngineIPCSlot export address in target process
// 2. Write script_path|handler_name data there
// 3. Signal the LUA_ENGINE_SIGNAL event
static bool SignalLuaEngineScript(IHookServices* services, DWORD pid, int hookId,
    const std::wstring& scriptPath, const std::wstring& handlerName, DWORD64 luaEngineBase, bool is64)
{
    // Build arch-specific LuaEngine path for export resolution
    WCHAR luaEngineName[MAX_PATH] = { 0 };
    wcscpy_s(luaEngineName, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32);
    std::wstring luaEngineFullPath = services->GetCurrentDirFilePath(luaEngineName);

    // Get LuaEngineIPCSlot export offset
    DWORD ipcSlotOffset = 0;
    if (!services->CheckExportFromFile(luaEngineFullPath.c_str(), LUA_ENGINE_PLACEHOLDER_EXP_FUNC, &ipcSlotOffset)) {
        LOG_CTRL_INSHOOK_E(L"failed to get LuaEngineIPCSlot export offset\n");
        return false;
    }

    PVOID ipcSlotAddr = (PVOID)(luaEngineBase + ipcSlotOffset);

#ifdef _DEBUG
    // In debug builds the export function starts with a jmp instruction;
    // resolve the real address by reading the jmp operand.
    HANDLE hProcDbg = NULL;
    if (services->GetHighAccessProcHandle(pid, &hProcDbg) && hProcDbg) {
        DWORD oldProtect1 = 0;
        VirtualProtectEx(hProcDbg, (LPVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect1);
        DWORD e9Oprand = 0;
        ReadProcessMemory(hProcDbg, (LPVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_OPCODE_SIZE), &e9Oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, NULL);
        ipcSlotAddr = (PVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_SIZE + e9Oprand);
        VirtualProtectEx(hProcDbg, (LPVOID)((DWORD64)luaEngineBase + ipcSlotOffset + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, oldProtect1, &oldProtect1);
        CloseHandle(hProcDbg);
    }
#endif

    // Build IPC data: script_path|handler_name
    WCHAR ipcData[MAX_PATH + 256] = { 0 };
    int pos = 0;
    for (size_t i = 0; i < scriptPath.size() && pos < MAX_PATH - 1; i++) {
        ipcData[pos++] = scriptPath[i];
    }
    ipcData[pos++] = L'|';
    for (size_t i = 0; i < handlerName.size() && pos < MAX_PATH + 255; i++) {
        ipcData[pos++] = handlerName[i];
    }
	ipcData[pos] = L'\0';
    HANDLE hProc = NULL;
    if (!services->GetHighAccessProcHandle(pid, &hProc) || !hProc) {
        LOG_CTRL_INSHOOK_E(L"failed to get high access process handle, pid=%u\n", pid);
        return false;
    }

    DWORD oldProtect = 0;
    if (VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        SIZE_T written = 0;
        services->WriteProcessMemoryWrap(hProc, (LPVOID)ipcSlotAddr, ipcData, (pos + 1) * sizeof(WCHAR), &written);
        VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), oldProtect, &oldProtect);
    }
    CloseHandle(hProc);

    // Signal the event: Global\LUA_ENGINE_SIGNAL.<pid>_<hookId>
    WCHAR eventName[150];
    swprintf_s(eventName, LUA_ENGINE_UM_SIGNAL_EVENT, pid, hookId);
    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
    if (!hEvent) {
        LOG_CTRL_INSHOOK_E(L"failed to open IPC event %s, err=%u\n", eventName, GetLastError());
        return false;
    }
    SetEvent(hEvent);
    CloseHandle(hEvent);

    LOG_CTRL_INSHOOK(L"IPC signal sent: hookId=%d script=%s handler=%s\n", hookId, scriptPath.c_str(), handlerName.c_str());
    return true;
}

void InstantHookManager::ListenerThreadImpl(ListenerContext* ctx) {
	// construct event names (only once) — use mode-tagged names to separate hook vs patch
	WCHAR loadEventName[MAX_PATH];
	WCHAR hookEventName[MAX_PATH];
	if (ctx->isPatchMode) {
		swprintf_s(loadEventName, UM_LOAD_NOTIFY_PATCH_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
		swprintf_s(hookEventName, UM_HOOK_NOTIFY_PATCH_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
	} else {
		swprintf_s(loadEventName, UM_LOAD_NOTIFY_HOOK_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
		swprintf_s(hookEventName, UM_HOOK_NOTIFY_HOOK_EVENT_FMT, ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
	}

	// Create/open events once at startup
	ctx->hLoadNotify = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, loadEventName);
	if (ctx->hLoadNotify) {
		ResetEvent(ctx->hLoadNotify);
	}
	else {
		ctx->hLoadNotify = CreateWorldAccessibleEventW(FALSE, FALSE, loadEventName);
		if (!ctx->hLoadNotify) {
			LOG_CTRL_INSHOOK_E(L"failed to create event=%s, Error=0x%x\n", loadEventName, GetLastError());
			ctx->running = false;
			return;
		}
	}

	ctx->hHookNotify = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, hookEventName);
	if (ctx->hHookNotify) {
		ResetEvent(ctx->hHookNotify);
	}
	else {
		ctx->hHookNotify = CreateWorldAccessibleEventW(TRUE, FALSE, hookEventName);
		if (!ctx->hHookNotify) {
			LOG_CTRL_INSHOOK_E(L"failed to create event=%s, Error=0x%x\n", hookEventName, GetLastError());
			CloseHandle(ctx->hLoadNotify);
			ctx->hLoadNotify = NULL;
			ctx->running = false;
			return;
		}
	}

	// Main loop: wait for event and perform hook, then loop back for next instance
	while (ctx->running) {
		// Reset events for next iteration
		ResetEvent(ctx->hLoadNotify);
		ResetEvent(ctx->hHookNotify);

		// Wait for either LoadNotify event or stop event
		HANDLE handles[2] = { ctx->hLoadNotify, ctx->hStopEvent };
		DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

		if (waitResult == WAIT_OBJECT_0 + 1) {
			// Stop event signaled
			LOG_CTRL_INSHOOK(L"Stop event signaled, exiting listener thread for hash=%llx\n", ctx->target.processFnvHash);
			break;
		}

		if (waitResult != WAIT_OBJECT_0) {
			LOG_CTRL_INSHOOK_E(L"WaitForMultipleObjects failed, exiting listener thread\n");
			break;
		}

		// target dll is already loaded, we can apply hook now
		DWORD pid = 0;
		// Read hook event file to get PID
		WCHAR hookEventPath[MAX_PATH];
		if (ctx->isPatchMode) {
			swprintf_s(hookEventPath, UM_HOOK_EVENT_PID_FILE_PATCH_FMT,
				ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
		} else {
			swprintf_s(hookEventPath, UM_HOOK_EVENT_PID_FILE_HOOK_FMT,
				ctx->target.processFnvHash, ctx->target.dllFnvHash, ctx->target.offset);
		}

		FILE* hookEventFile = NULL;
		_wfopen_s(&hookEventFile, hookEventPath, L"rt");
		if (hookEventFile) {
			if (fscanf_s(hookEventFile, "%u", &pid) == 1) {
				LOG_CTRL_INSHOOK(L"Hook event file: PID=%u, processHash=%016llx, dllHash=%016llx\n",
					pid, ctx->target.processFnvHash, ctx->target.dllFnvHash);
			}
			fclose(hookEventFile);
		}

		if (pid == 0) {
			LOG_CTRL_INSHOOK_E(L"failed to get PID from hook event file\n");
			SetEvent(ctx->hHookNotify);
			continue;  // Continue to next iteration
		}


		bool isPatchMode = (ctx->target.exportName.compare(0, 6, L"patch.") == 0);
		bool isLuaMode = !ctx->target.script.empty();
		int hook_mode = isLuaMode ? HOOK_MODE_LUA : HOOK_MODE_DLL;

		// get module base (common to all modes)
		DWORD64 moduleBase = 0;
		if (!m_services->GetModuleBase(pid, ctx->target.module.c_str(), &moduleBase) || moduleBase == 0) {
			LOG_CTRL_INSHOOK_E(L"failed to get target module base\n");
			SetEvent(ctx->hHookNotify);
			continue;
		}

		// use pre-parsed offset
		DWORD64 offset = ctx->target.offset;
		DWORD64 targetAddress = moduleBase + offset;

		// ---- Patch mode: write bytes directly, skip hook application ----
		if (isPatchMode) {
			std::wstring hexStr = ctx->target.exportName.substr(6);
			std::wstring parseError;
			std::vector<BYTE> patchBytes = HexToBytes(hexStr, &parseError);
			if (patchBytes.empty()) {
				if (!parseError.empty()) {
					LOG_CTRL_INSHOOK_E(L"patch mode: %s (input: %s)huanhangfu", parseError.c_str(), hexStr.c_str());
					MessageBoxW(NULL, parseError.c_str(), L"Patch Format Error", MB_OK | MB_ICONERROR);
				} else {
					LOG_CTRL_INSHOOK_E(L"patch mode: empty byte sequence from export name: %shuanhangfu", ctx->target.exportName.c_str());
				}
				SetEvent(ctx->hHookNotify);
				continue;
			}

			HANDLE hProc = NULL;
			if (!m_services->GetHighAccessProcHandle(pid, &hProc) || !hProc) {
				LOG_CTRL_INSHOOK_E(L"patch mode: failed to get process handle, pid=%u\n", pid);
				SetEvent(ctx->hHookNotify);
				continue;
			}

			// Read original bytes before patching so we can restore later
			std::vector<BYTE> oriBytes(patchBytes.size(), 0);
			SIZE_T oriRead = 0;
			bool oriReadOk = false;
			{
				DWORD oldProt = 0;
				if (VirtualProtectEx(hProc, (LPVOID)targetAddress, patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProt)) {
					if (ReadProcessMemory(hProc, (LPVOID)targetAddress, oriBytes.data(), patchBytes.size(), &oriRead) && oriRead == patchBytes.size()) {
						oriReadOk = true;
					}
					VirtualProtectEx(hProc, (LPVOID)targetAddress, patchBytes.size(), oldProt, &oldProt);
				}
			}
			if (!oriReadOk) {
				LOG_CTRL_INSHOOK_E(L"patch mode: failed to read original bytes at 0x%llX, pid=%u\n", targetAddress, pid);
			}

			DWORD oldProtect = 0;
			bool patchOk = false;
			if (VirtualProtectEx(hProc, (LPVOID)targetAddress, patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
				SIZE_T written = 0;
				if (m_services->WriteProcessMemoryWrap(hProc, (LPVOID)targetAddress, patchBytes.data(), patchBytes.size(), &written)) {
					VirtualProtectEx(hProc, (LPVOID)targetAddress, patchBytes.size(), oldProtect, &oldProtect);
					patchOk = true;
				}
				else {
					LOG_CTRL_INSHOOK_E(L"patch mode: WriteProcessMemory failed at 0x%llX, pid=%u\n", targetAddress, pid);
				}
			}
			else {
				LOG_CTRL_INSHOOK_E(L"patch mode: VirtualProtectEx failed at 0x%llX, err=%u\n", targetAddress, GetLastError());
			}
			CloseHandle(hProc);

			if (!patchOk) {
				SetEvent(ctx->hHookNotify);
				continue;
			}

			LOG_CTRL_INSHOOK(L"Instant patch applied at 0x%llX, %zu bytes, pid=%u\n", targetAddress, patchBytes.size(), pid);

			// Persist patch info to registry so HookUI can display it
			FILETIME createTime = { 0 }, exitTime, kernelTime, userTime;
			HANDLE hProcInfo = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (hProcInfo) {
				if (GetProcessTimes(hProcInfo, &createTime, &exitTime, &kernelTime, &userTime)) {
					HookRow row;
					row.id = -1; // patch mode doesn't use hook IDs
					row.address = targetAddress;
					row.module = ctx->target.module;
					std::wstring oriHexStr;
					if (oriReadOk) {
						for (size_t i = 0; i < oriBytes.size(); ++i) {
							wchar_t h[3]; _snwprintf_s(h, 3, _TRUNCATE, L"%02X", oriBytes[i]);
							oriHexStr += h;
						}
					}
					row.expFunc = L"Patch:" + hexStr + L"|" + oriHexStr;

					row.ori_asm_code_addr = 0;
					row.ori_asm_code_len = (unsigned long)patchBytes.size();
					row.trampoline_pit = 0;

					std::vector<HookRow> rows;
					rows.push_back(row);

					if (!m_services->SaveProcHookList(pid, createTime.dwHighDateTime, createTime.dwLowDateTime, rows)) {
						LOG_CTRL_INSHOOK_E(L"patch mode: failed to persist patch info to registry for pid=%u\n", pid);
					}
					else {
						LOG_CTRL_INSHOOK(L"patch info persisted to registry: pid=%u, address=0x%llx\n", pid, targetAddress);
					}
				}
				CloseHandle(hProcInfo);
			}

			SetEvent(ctx->hHookNotify);
			LOG_CTRL_INSHOOK(L"Instant patch completed for pid=%u, waiting for next instance...\n", pid);
			continue;
		}

		DWORD64 hookFunctionAddress = 0;
		DWORD64 luaEngineBase = 0;
		bool is64 = false;
		m_services->IsProcess64(pid, is64);

		if (isLuaMode) {
			// Lua mode: hook using LuaEngine.dll dispatch function
			// 1. Get LuaEngine.dll base in target process (use arch-specific name)
			if (m_services->GetModuleBase(pid, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, &luaEngineBase) && luaEngineBase != 0) {
				LOG_CTRL_INSHOOK(L"LuaEngine.dll already loaded at 0x%llX (pid %u)\n", luaEngineBase, pid);
			}
			else {
				LOG_CTRL_INSHOOK(L"LuaEngine.dll not loaded, requesting injection (pid %u)\n", pid);
				WCHAR luaEngineName[MAX_PATH] = { 0 };
				wcscpy_s(luaEngineName, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32);
				std::wstring luaEngineFullPath = m_services->GetCurrentDirFilePath(luaEngineName);

				bool injected = m_services->InjectTrampoline(pid, luaEngineFullPath.c_str());
				LOG_CTRL_INSHOOK(L"LuaEngine %s inject result: %s\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, injected ? L"success" : L"failure");
				if (injected) {
					const int maxIter = 50;
					bool loaded = false;
					for (int iter = 0; iter < maxIter && !loaded; ++iter) {
						m_services->GetModuleBase(pid, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, &luaEngineBase);
						if (luaEngineBase != 0) {
							loaded = true;
							break;
						}
						Sleep(100);
					}
					if (!loaded) {
						LOG_CTRL_INSHOOK_E(L"LuaEngine %s NOT detected within 5s after injection (pid %u)\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, pid);
						SetEvent(ctx->hHookNotify);
						continue;
					}
					LOG_CTRL_INSHOOK(L"LuaEngine %s detected at 0x%llX after injection (pid %u)\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, luaEngineBase, pid);
				}
				else {
					LOG_CTRL_INSHOOK_E(L"failed to inject %s (pid %u), aborting\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, pid);
					SetEvent(ctx->hHookNotify);
					continue;
				}
			}

			// 2. Get LuaHookDispatch export offset (use full path for reliable resolution)
			WCHAR luaEngineName2[MAX_PATH] = { 0 };
			wcscpy_s(luaEngineName2, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32);
			std::wstring luaEngineFullPath2 = m_services->GetCurrentDirFilePath(luaEngineName2);

			DWORD dispatchOffset = 0;
			const char* dispatchName = is64 ? LUA_ENGINE_EXPORT_X64 : LUA_ENGINE_EXPORT_Win32;
			if (!m_services->CheckExportFromFile(luaEngineFullPath2.c_str(), dispatchName, &dispatchOffset)) {
				LOG_CTRL_INSHOOK_E(L"failed to get LuaEngine dispatch export: %s\n", is64 ? WIDEN(LUA_ENGINE_EXPORT_X64) : WIDEN(LUA_ENGINE_EXPORT_Win32));
				SetEvent(ctx->hHookNotify);
				continue;
			}
			hookFunctionAddress = luaEngineBase + dispatchOffset;

		} else {
			// DLL mode: wait for hook code dll to load and verify export
			DWORD64 hookDllBase = 0;
			int retries = 50;

			const wchar_t* dllFileName = wcsrchr(ctx->target.dllPath.c_str(), L'\\');
			if (dllFileName) {
				dllFileName++;
			} else {
				dllFileName = ctx->target.dllPath.c_str();
			}

			while (retries-- > 0) {
				if (m_services->GetModuleBase(pid, dllFileName, &hookDllBase) && hookDllBase != 0) {
					break;
				}
				Sleep(100);
			}

			if (hookDllBase == 0) {
				LOG_CTRL_INSHOOK_E(L"failed to get hook code dll base\n");
				SetEvent(ctx->hHookNotify);
				continue;
			}

			DWORD hookCodeOffset = 0;
			CT2A exportNameA(ctx->target.exportName.c_str());
			if (!m_services->CheckExportFromFile(ctx->target.dllPath.c_str(), exportNameA, &hookCodeOffset)) {
				LOG_CTRL_INSHOOK_E(L"failed to get target export function=%s of target dll %s\n",
					ctx->target.exportName.c_str(), ctx->target.dllPath.c_str());
				SetEvent(ctx->hHookNotify);
				continue;
			}
			hookFunctionAddress = hookDllBase + hookCodeOffset;
		}

		// clean up hook ID pools for dead processes
		CleanupDeadPidPools();

		// allocate hook ID (per-PID pool)
		int hookId = AllocHookId(pid);

		if (hookId == -1) {
			LOG_CTRL_INSHOOK_E(L"there is no enough hookid\n");
			SetEvent(ctx->hHookNotify);
			continue;  // Continue to next iteration
		}

		// execute hook
		DWORD oriLen = 0;
		PVOID trampoline = nullptr;
		PVOID oriAsmAddr = nullptr;


		// For Lua mode, signal LuaEngine to load the script before applying hook
		if (isLuaMode) {
			// lua script is already preloaded, so there is no need to signal

			// NOTHING_TO_DO_HERE
		}
		HookCore::SetHookServices(m_services);
		if (!HookCore::ApplyHook(pid, targetAddress, m_services, hookFunctionAddress, hookId, hook_mode, &oriLen, &trampoline, &oriAsmAddr)) {
			// release hook ID
			ReleaseHookId(pid, hookId);
			LOG_CTRL_INSHOOK_E(L"ApplyHook failed for pid=%u\n", pid);
			SetEvent(ctx->hHookNotify);
			continue;  // Continue to next iteration
		}

		// Persist hook info to registry so HookUI can display it
		FILETIME createTime = { 0 }, exitTime, kernelTime, userTime;
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProc) {
			if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
				HookRow row;
				row.id = hookId;
				row.address = targetAddress;
				row.module = ctx->target.module;
				if (hook_mode == HOOK_MODE_LUA) 
					row.expFunc = L"Lua:" + ctx->target.script + L"!" + ctx->target.handler;
				else 
					row.expFunc = ctx->target.dllPath+L"!"+ctx->target.exportName;
				row.ori_asm_code_addr = (unsigned long long)oriAsmAddr;
				row.ori_asm_code_len = oriLen;
				row.trampoline_pit = (unsigned long long)trampoline;

				std::vector<HookRow> rows;
				rows.push_back(row);

				if (!m_services->SaveProcHookList(pid, createTime.dwHighDateTime, createTime.dwLowDateTime, rows)) {
					LOG_CTRL_INSHOOK_E(L"failed to persist hook info to registry for pid=%u, hookId=%d\n", pid, hookId);
				}
				else {
					LOG_CTRL_INSHOOK(L"hook info persisted to registry: pid=%u, hookId=%d, address=0x%llx\n", pid, hookId, targetAddress);
				}
			}
			CloseHandle(hProc);
		}
		else {
			LOG_CTRL_INSHOOK_E(L"failed to open process for GetProcessTimes: pid=%u, Error=0x%x\n", pid, GetLastError());
		}

		// Signal HookNotify so handler code in UMHH.dll can continue
		SetEvent(ctx->hHookNotify);
		LOG_CTRL_INSHOOK(L"Instant hook completed for pid=%u, waiting for next instance...\n", pid);
		// Loop back and wait for next LoadNotify event
	}

	// Cleanup on exit
	if (ctx->hLoadNotify) {
		CloseHandle(ctx->hLoadNotify);
		ctx->hLoadNotify = NULL;
	}
	if (ctx->hHookNotify) {
		CloseHandle(ctx->hHookNotify);
		ctx->hHookNotify = NULL;
	}
	ctx->running = false;
}

// parse .hookseq file
bool InstantHookManager::ParseHookSeqFile(const wchar_t* filePath, std::vector<HookTarget>& outTargets) {
	FILE* f = NULL;
	_wfopen_s(&f, filePath, L"rt, ccs=UNICODE");
	if (!f) return false;

	wchar_t lineBuf[MAX_PATH * 2];
	HookTarget target;
	bool inHook = false;
	bool hasModule = false, hasOffset = false, hasDllPath = false, hasExport = false;
	bool hasScript = false, hasHandler = false;

	while (fgetws(lineBuf, MAX_PATH * 2, f)) {
		wchar_t* p = lineBuf;
		// skip tab and whitespace
		while (*p == L' ' || *p == L'\t') p++;
		// trim new line marker
		size_t len = wcslen(p);
		while (len > 0 && (p[len - 1] == L'\n' || p[len - 1] == L'\r' || p[len - 1] == L' ' || p[len - 1] == L'\t')) {
			p[--len] = L'\0';
		}

		if (p[0] == L'[' && wcsncmp(p + 1, L"hook]", 5) == 0) {
			bool dllMode = hasModule && hasOffset && hasDllPath && hasExport;
			bool luaMode = hasModule && hasOffset && hasScript && hasHandler;
			if (inHook && (dllMode || luaMode)) {
				outTargets.push_back(target);
			}
			memset(&target, 0, sizeof(target));
			inHook = true;
			hasModule = hasOffset = hasDllPath = hasExport = hasScript = hasHandler = false;
			continue;
		}

		if (!inHook) continue;

		wchar_t* eq = wcschr(p, L'=');
		if (!eq) continue;
		*eq = L'\0';
		wchar_t* key = p;
		wchar_t* val = eq + 1;
		// trim key
		size_t keyLen = wcslen(key);
		while (keyLen > 0 && (key[keyLen - 1] == L' ' || key[keyLen - 1] == L'\t')) keyLen--;
		key[keyLen] = L'\0';
		// trim val
		while (*val == L' ' || *val == L'\t') val++;

		if (wcscmp(key, L"module") == 0) {
			target.module = val;
			hasModule = true;
		}
		else if (wcscmp(key, L"offset") == 0) {
			target.offsetStr = std::wstring(val);
			// Parse offset string to numeric value
			bool ok = false;
			target.offset = ParseAddressText(val, ok);
			hasOffset = ok;
		}
		else if (wcscmp(key, L"dllPath") == 0) {
			target.dllPath = val;
			hasDllPath = true;
		}
		else if (wcscmp(key, L"export") == 0) {
			target.exportName = val;
			hasExport = true;
		}
		else if (wcscmp(key, L"script") == 0) {
			target.script = val;
			hasScript = true;
		}
		else if (wcscmp(key, L"handler") == 0) {
			target.handler = std::wstring(val);;
			hasHandler = true;
		}
	}

	{
		bool dllMode = hasModule && hasOffset && hasDllPath && hasExport;
		bool luaMode = hasModule && hasOffset && hasScript && hasHandler;
		if (inHook && (dllMode || luaMode)) {
			outTargets.push_back(target);
		}
	}

	fclose(f);
	return !outTargets.empty();
}

unsigned long long InstantHookManager::ComputeFnvHash(const wchar_t* str) {
	const unsigned long long FNV_prime = 1099511628211ULL;
	unsigned long long hash = 14695981039346656037ULL;
	const wchar_t* p = str;
	while (*p) {
		wchar_t c = *p++;
		// convert to lowercase
		if (c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
		BYTE bLow = (BYTE)(c & 0xFF);
		BYTE bHigh = (BYTE)((c >> 8) & 0xFF);
		hash ^= (unsigned long long)bLow;
		hash *= FNV_prime;
		hash ^= (unsigned long long)bHigh;
		hash *= FNV_prime;
	}
	return hash;
}

std::vector<BYTE> InstantHookManager::HexToBytes(const std::wstring& hex, std::wstring* outError) {
	std::vector<BYTE> bytes;
	if (outError) outError->clear();

	// Normalize: strip all known prefixes/separators, collect hex digits + allowed delimiters
	std::wstring normalized;
	enum Expect { HEX_OR_DELIM, HEX_DIGIT2 };
	Expect state = HEX_OR_DELIM;
	size_t i = 0;
	while (i < hex.size()) {
		wchar_t c = hex[i];

		// Skip whitespace and commas
		if (c == L' ' || c == L'\t' || c == L',' || c == L';') {
			i++;
			state = HEX_OR_DELIM;
			continue;
		}
		// Skip \x prefix
		if (c == L'\\' && i + 1 < hex.size() && hex[i + 1] == L'x') {
			i += 2;
			state = HEX_DIGIT2;
			continue;
		}
		// Skip 0x prefix
		if (c == L'0' && i + 1 < hex.size() && (hex[i + 1] == L'x' || hex[i + 1] == L'X')) {
			i += 2;
			state = HEX_DIGIT2;
			continue;
		}
		// Hex digit
		if ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')) {
			normalized += c;
			i++;
			// After collecting two hex digits, go back to expecting delimiter or hex
			if (normalized.size() % 2 == 0)
				state = HEX_OR_DELIM;
			continue;
		}
		// Anything else is illegal
		if (outError) {
			wchar_t buf[128];
			_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Illegal character '%c' at position %zu in byte sequence", c, i);
			*outError = buf;
		}
		return bytes;
	}

	if (normalized.empty()) return bytes;
	if (normalized.size() % 2 != 0) {
		if (outError) *outError = L"Odd number of hex digits in byte sequence";
		return bytes;
	}

	for (size_t j = 0; j < normalized.size(); j += 2) {
		BYTE hi = 0, lo = 0;
		wchar_t ch = normalized[j];
		if (ch >= L'0' && ch <= L'9') hi = (BYTE)(ch - L'0');
		else if (ch >= L'a' && ch <= L'f') hi = (BYTE)(ch - L'a' + 10);
		else if (ch >= L'A' && ch <= L'F') hi = (BYTE)(ch - L'A' + 10);
		ch = normalized[j + 1];
		if (ch >= L'0' && ch <= L'9') lo = (BYTE)(ch - L'0');
		else if (ch >= L'a' && ch <= L'f') lo = (BYTE)(ch - L'a' + 10);
		else if (ch >= L'A' && ch <= L'F') lo = (BYTE)(ch - L'A' + 10);
		bytes.push_back((BYTE)((hi << 4) | lo));
	}
	return bytes;
}

bool InstantHookManager::ParsePatchSeqFile(const wchar_t* filePath, std::vector<PatchEntry>& outEntries) {
	FILE* f = NULL;
	_wfopen_s(&f, filePath, L"rt, ccs=UNICODE");
	if (!f) return false;

	wchar_t lineBuf[MAX_PATH * 2];
	PatchEntry entry;
	bool inPatch = false;
	bool hasModule = false, hasOffset = false, hasPatch = false;

	while (fgetws(lineBuf, MAX_PATH * 2, f)) {
		wchar_t* p = lineBuf;
		while (*p == L' ' || *p == L'\t') p++;
		size_t len = wcslen(p);
		while (len > 0 && (p[len - 1] == L'\n' || p[len - 1] == L'\r' || p[len - 1] == L' ' || p[len - 1] == L'\t')) {
			p[--len] = L'\0';
		}

		if (p[0] == L'[' && wcsncmp(p + 1, L"patch]", 6) == 0) {
			if (inPatch && hasModule && hasOffset && hasPatch) {
				outEntries.push_back(entry);
			}
			entry = PatchEntry();
			inPatch = true;
			hasModule = hasOffset = hasPatch = false;
			continue;
		}

		if (!inPatch) continue;

		wchar_t* eq = wcschr(p, L'=');
		if (!eq) continue;
		*eq = L'\0';
		wchar_t* key = p;
		wchar_t* val = eq + 1;
		size_t keyLen = wcslen(key);
		while (keyLen > 0 && (key[keyLen - 1] == L' ' || key[keyLen - 1] == L'\t')) keyLen--;
		key[keyLen] = L'\0';
		while (*val == L' ' || *val == L'\t') val++;

		if (wcscmp(key, L"module") == 0) {
			entry.module = val;
			hasModule = true;
		}
		else if (wcscmp(key, L"offset") == 0) {
			entry.offsetStr = val;
			hasOffset = true;
		}
		else if (wcscmp(key, L"patch") == 0) {
			entry.patchHex = val;
			hasPatch = true;
		}
	}

	{
		if (inPatch && hasModule && hasOffset && hasPatch) {
			outEntries.push_back(entry);
		}
	}

	fclose(f);
	return !outEntries.empty();
}

bool InstantHookManager::ConvertPatchSeqToHookSeq(const wchar_t* patchSeqPath, std::wstring& outHookSeqPath) {
	std::vector<PatchEntry> entries;
	if (!ParsePatchSeqFile(patchSeqPath, entries)) return false;

	// Build output path: replace .patchseq extension with .hookseq
	outHookSeqPath = patchSeqPath;
	size_t dotPos = outHookSeqPath.rfind(L".patchseq");
	if (dotPos != std::wstring::npos) {
		outHookSeqPath.replace(dotPos, 9, L".hookseq");
	}
	else {
		outHookSeqPath += L".hookseq";
	}

	FILE* fout = NULL;
	_wfopen_s(&fout, outHookSeqPath.c_str(), L"wt, ccs=UNICODE");
	if (!fout) return false;

	for (const auto& e : entries) {
		fwprintf_s(fout, L"[hook]\n");
		fwprintf_s(fout, L"module=%s\n", e.module.c_str());
		fwprintf_s(fout, L"offset=%s\n", e.offsetStr.c_str());
		fwprintf_s(fout, L"dllPath=C:\\windows\\system32\\lsasrv.dll\n");
		fwprintf_s(fout, L"export=patch.%s\n\n", e.patchHex.c_str());
	}

	fclose(fout);
	return true;
}
