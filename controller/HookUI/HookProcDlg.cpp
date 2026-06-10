// Clean, corrected implementation with multi-column sorting support

#include "HookProcDlg.h"
#include "../../Shared/LogMacros.h"
#include "../../Shared/HookRow.h"
#include "../../Shared/HookServices.h"
#include <tlhelp32.h>
#include <cwchar>
#include <cwctype>
#include <CommCtrl.h> // for EM_SETCUEBANNER
#include <afxdlgs.h> // CFileDialog
#include "../HookCoreLib/HookCore.h"
#include "../UMController/Helper.h"
#include "../UMController/RegistryStore.h"
// Local HexToBytes helper - supports formats:
//   31C0C3 | \x31\xC0\xC3 | 0x31,0xC0,0xC3 | 31 C0 C3 | 0x31 0xC0 0xC3
static std::vector<BYTE> HexToBytes(const std::wstring& hex) {
	std::vector<BYTE> bytes;

	std::wstring normalized;
	size_t i = 0;
	while (i < hex.size()) {
		wchar_t c = hex[i];
		if (c == L' ' || c == L'	' || c == L',' || c == L';') { i++; continue; }
		if (c == L'\\' && i + 1 < hex.size() && hex[i + 1] == L'x') { i += 2; continue; }
		if (c == L'0' && i + 1 < hex.size() && (hex[i + 1] == L'x' || hex[i + 1] == L'X')) { i += 2; continue; }
		if ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')) {
			normalized += c; i++; continue;
		}
		return bytes;
	}
	if (normalized.empty() || normalized.size() % 2 != 0) return bytes;
	for (size_t j = 0; j < normalized.size(); j += 2) {
		BYTE hi = 0, lo = 0;
		wchar_t ch = normalized[j];
		if (ch >= L'0' && ch <= L'9') hi = (BYTE)(ch - L'0');
		else if (ch >= L'a' && ch <= L'f') hi = (BYTE)(ch - L'a' + 10);
		else hi = (BYTE)(ch - L'A' + 10);
		ch = normalized[j + 1];
		if (ch >= L'0' && ch <= L'9') lo = (BYTE)(ch - L'0');
		else if (ch >= L'a' && ch <= L'f') lo = (BYTE)(ch - L'a' + 10);
		else lo = (BYTE)(ch - L'A' + 10);
		bytes.push_back((BYTE)((hi << 4) | lo));
	}
	return bytes;
}
#include "../../Shared/HookRow.h"
#include "../../Shared/SharedMacroDef.h"
#include "../ProcessHackerLib/phlib_expose.h"
#include <psapi.h>
#include <algorithm>
static std::wstring Hex64(ULONGLONG v) {
	wchar_t buf[32];
	_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llX", v);
	return buf;
}

static void CopyTextToClipboard(const CString& text, HWND owner) {
	if (text.IsEmpty()) return;
	if (::OpenClipboard(owner)) {
		EmptyClipboard();
		size_t len = (text.GetLength() + 1) * sizeof(wchar_t);
		HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, len);
		if (h) {
			void* p = GlobalLock(h);
			if (p) {
				memcpy(p, (LPCWSTR)text.GetString(), len);
				GlobalUnlock(h);
				SetClipboardData(CF_UNICODETEXT, h);
			}
			else {
				GlobalFree(h);
			}
		}
		::CloseClipboard();
	}
}

const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x701;

// OnSize: reposition controls when the dialog is resized
void HookProcDlg::OnSize(UINT nType, int cx, int cy) {
	CDialogEx::OnSize(nType, cx, cy);
	if (m_ModuleList.GetSafeHwnd() && m_HookList.GetSafeHwnd()) {
		UpdateLayoutForSplitter(cx, cy);
	}
}
BEGIN_MESSAGE_MAP(HookProcDlg, CDialogEx)
	ON_BN_CLICKED(IDC_HOOKUI_BTN_APPLY, &HookProcDlg::OnBnClickedApplyHook)
	ON_BN_CLICKED(IDC_HOOKUI_BTN_APPLY_SEQ, &HookProcDlg::OnBnClickedApplyHookSequence)
	ON_BN_CLICKED(IDC_HOOKUI_BTN_RELOAD_LUA, &HookProcDlg::OnBnClickedReloadLua)
	ON_WM_SIZE()
	ON_WM_CONTEXTMENU()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_MOUSEMOVE()
	ON_WM_GETMINMAXINFO()
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnColumnClickModules)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnModuleItemChanged)
	ON_EN_SETFOCUS(IDC_HOOKUI_EDIT_OFFSET, &HookProcDlg::OnEnSetFocusOffset)
	ON_EN_SETFOCUS(IDC_HOOKUI_EDIT_DIRECT, &HookProcDlg::OnEnSetFocusDirect)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnCustomDrawModules)
END_MESSAGE_MAP()

void HookProcDlg::OnBnClickedApplyHookSequence() {
	// If the target process no longer exists, close this modeless dialog to avoid acting on a dead PID.
	bool procFound = false;
	bool rehook = false;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe = { sizeof(pe) };
		if (Process32First(hSnap, &pe)) {
			do {
				if ((DWORD)pe.th32ProcessID == m_pid) { procFound = true; break; }
			} while (Process32Next(hSnap, &pe));
		}
		CloseHandle(hSnap);
	}
	if (!procFound) {
		MessageBox(L"Target process does not appear to be running. Closing dialog.", L"Hook", MB_ICONWARNING);
		// Destroy the dialog window; parent will be notified in OnDestroy and will delete this object.
		DestroyWindow();
		return;
	}
	// Browse for a .hooseq file; simple INI-like format
	// Use '|' delimited filter string (MFC auto-converts to double-null)
	CString filter = L"Hook Sequence (*.hookseq)|*.hookseq|All Files (*.*)|*.*||";
	CFileDialog fd(TRUE, L"hookseq", NULL, OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST, filter, this);
	if (fd.DoModal() != IDOK) {
		// User cancelled selection; abort apply
		if (m_services) LOG_UI(m_services, L"ApplyHookSequence cancelled by user (no hookseq selected)\n");
		return;
	}
	CString path = fd.GetPathName();
	// Parse file: lines of key=value; hook blocks denoted by [hook]
	std::vector<std::tuple<std::wstring, std::wstring, std::wstring, std::wstring, std::wstring, std::wstring>> entries; // module, offset, dllPath, export, script, handler
	DWORD pidFromFile = 0;
	FILE* f = _wfopen(path.GetString(), L"rt, ccs=UNICODE");
	if (!f) { MessageBoxW(L"Failed to open hook sequence file.", L"HookSeq", MB_ICONERROR | MB_OK); return; }
	wchar_t line[1024]; bool inHook = false; std::wstring module, offset, dllPath, exportFn, script, handler;
	while (fgetws(line, _countof(line), f)) {
		// Trim
		std::wstring s(line); 
		while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) 
			s.pop_back();
		auto ltrim = [&](std::wstring &x) { 
			size_t i = 0;
			while (i < x.size() && iswspace(x[i])) 
				++i; 
			x.erase(0, i); 
		};
		auto rtrim = [&](std::wstring &x) { 
			while (!x.empty() && iswspace(x.back())) 
				x.pop_back();
		};
		ltrim(s); rtrim(s); 
		if (s.empty()) 
			continue;
		if (s[0] == L'#' || (s.size() >= 2 && s[0] == L'/' && s[1] == L'/')) 
			continue;
		if (s == L"[hook]") {
				if (!module.empty() || !offset.empty() || !dllPath.empty() || !exportFn.empty() || !script.empty() || !handler.empty())
			{
				entries.emplace_back(module, offset, dllPath, exportFn, script, handler);
				module.clear();
				offset.clear();
				dllPath.clear();
				exportFn.clear();
				script.clear();
				handler.clear();
			}
			inHook = true;
			continue;
		}
		size_t eq = s.find(L'='); 
		if (eq == std::wstring::npos)
			continue;
		std::wstring key = s.substr(0, eq), val = s.substr(eq + 1); 
		ltrim(key); 
		rtrim(key); 
		ltrim(val); 
		rtrim(val);
		if (_wcsicmp(key.c_str(), L"targetPid") == 0) {
			pidFromFile = (DWORD)_wtol(val.c_str());
		}
		else if (_wcsicmp(key.c_str(), L"module") == 0) module = val;
		else if (_wcsicmp(key.c_str(), L"offset") == 0) offset = val;
		else if (_wcsicmp(key.c_str(), L"dllPath") == 0) dllPath = val;
		else if (_wcsicmp(key.c_str(), L"export") == 0) exportFn = val;
			else if (_wcsicmp(key.c_str(), L"script") == 0) script = val;
			else if (_wcsicmp(key.c_str(), L"handler") == 0) handler = val;
	}
	fclose(f);
		if (!module.empty() || !offset.empty() || !dllPath.empty() || !exportFn.empty() || !script.empty() || !handler.empty()) 
		entries.emplace_back(module, offset, dllPath, exportFn, script, handler);
	if (entries.empty()) {
		MessageBoxW(L"No hooks found in sequence file.", L"HookSeq", MB_ICONWARNING | MB_OK);
		return;
	}
	// Decide target PID: prefer file PID, else current dialog PID
	DWORD targetPid = pidFromFile ? pidFromFile : m_pid;
	// Ensure master/trampoline DLL arch matches; Validate exports
	for (auto &e : entries) {
		const std::wstring &mod = std::get<0>(e);
		const std::wstring &off = std::get<1>(e);
		const std::wstring &dll = std::get<2>(e);
		const std::wstring &exp = std::get<3>(e);
		const std::wstring &scr = std::get<4>(e);
		const std::wstring &hdl = std::get<5>(e);
		bool isDllMode = !dll.empty() && !exp.empty();
		bool isLuaModeEntry = !scr.empty() && !hdl.empty();
		if (mod.empty() || off.empty() || (!isDllMode && !isLuaModeEntry)) {
			MessageBoxW(L"Invalid hook entry with missing fields.", L"HookSeq", MB_ICONERROR | MB_OK);
			return;
		}
		if (isDllMode && isLuaModeEntry) {
			MessageBoxW(L"Hook entry has both DLL and Lua fields - use one mode.", L"HookSeq", MB_ICONERROR | MB_OK);
			return;
		}
		bool is64 = false;
		if (!m_services->IsProcess64(targetPid, is64)) {
			MessageBoxW(L"Failed to query process arch.", L"HookSeq", MB_ICONERROR | MB_OK);
			return;
		}
		if (isDllMode) {
			bool dll64 = false;
			if (!m_services->CheckPeArch(dll.c_str(), dll64)) {
				MessageBoxW(L"DLL arch check failed.", L"HookSeq", MB_ICONERROR | MB_OK);
				return;
			}
			if (dll64 != is64) {
				MessageBoxW(L"DLL arch mismatches process arch.", L"HookSeq", MB_ICONERROR | MB_OK);
				return;
			}
			DWORD funcOff = 0;
			if (!m_services->CheckExportFromFile(dll.c_str(), std::string(CW2A(exp.c_str())).c_str(), &funcOff)) {
				MessageBoxW(L"Export not found in DLL.", L"HookSeq", MB_ICONERROR | MB_OK);
				return;
			}
		}
		// Lua mode: no DLL arch/export validation needed
	}
	CString msg;
	// Apply hooks
	int applied = 0;
	for (auto &e : entries) {
		const std::wstring &mod = std::get<0>(e);
		const std::wstring &off = std::get<1>(e);
		const std::wstring &dll = std::get<2>(e);
		const std::wstring &exp = std::get<3>(e);
		const std::wstring &scr = std::get<4>(e);
		const std::wstring &hdl = std::get<5>(e);
		bool isLuaModeEntry = !scr.empty() && !hdl.empty();
		// Resolve module base
		bool is64 = false; m_services->IsProcess64(targetPid, is64);
		DWORD64 base = 0;
		if (!m_services->GetModuleBase( targetPid, mod.c_str(), &base) || base == 0) {
			LOG_UI(m_services,L"HookSeq: module %s not loaded (base=%p), skipping\n", mod.c_str(), (void*)base);
			continue;
		}
		bool ok = true;		DWORD64 offVal = ParseAddressText(off, ok);
		// apply hook
		bool hookOk = false;
		if (isLuaModeEntry) {
			hookOk = HookCommonCodeLua(base, (DWORD)offVal, scr, hdl);
		} else {
			hookOk = HookCommonCode(base, (DWORD)offVal, dll, exp);
		}
		if (!hookOk) {
			// if any fault detected, we need to roll back and abort
			LOG_UI(m_services, L"fault detected when trying hooking at Addr=0x%p\n", base + offVal);
			LOG_UI(m_services, L"Rolling back\n");
			goto RollBack;
		}
		// annotate ExpFunc for the created row by matching address
		auto GetFilename = [](const std::wstring& path) -> std::wstring {
			size_t pos = path.find_last_of(L"\\/");
			return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
		};
		for (int iRow = 0; iRow < m_HookList.GetItemCount(); ++iRow) {
			HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(iRow));
			if (hr && hr->address == (base + offVal)) {
				if (isLuaModeEntry) {
					hr->expFunc = L"Lua:" + scr + L"!" + hdl;
				} else {
					hr->expFunc = GetFilename(dll) + L"!" + exp;
				}
				m_HookList.SetItemText(iRow, 3, hr->expFunc.c_str());
				break;
			}
		}
		applied++;
	}
		 msg.Format(L"Applied %d hooks from sequence.", applied);
	MessageBoxW(msg, L"HookSeq", MB_OK | MB_ICONINFORMATION);
	return;
RollBack:
	{
		std::vector<int> item_to_remove;
		for (int i = 0; i < m_HookList.GetItemCount(); ++i) {
			HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
			if (!hr) {
				LOG_UI_E(m_services, L"weird, hr can not be NULL during iteration\n");
				continue;
			}
		 
			for (auto &e : entries) {
				const std::wstring &mod = std::get<0>(e);
				const std::wstring &off = std::get<1>(e);
				const std::wstring &dll = std::get<2>(e);
				const std::wstring &exp = std::get<3>(e);
				// Resolve module base
				bool is64 = false; m_services->IsProcess64(targetPid, is64);
				DWORD64 base = 0;
				if (!m_services->GetModuleBase( targetPid, mod.c_str(), &base)) {
					LOG_UI(m_services, L"HookSeq: module %s not loaded\n", mod.c_str());
					continue;
				}
				bool ok = true;
				DWORD64 offVal = ParseAddressText(off, ok);
				DWORD64 addr = offVal + base;

				if (hr->address == addr) {
				
					item_to_remove.push_back(i);
				}
			}
		}
		if (!item_to_remove.empty()) {
			// Sort indices descending to avoid shift issues
			std::sort(item_to_remove.rbegin(), item_to_remove.rend());

			for (size_t k = 0; k < item_to_remove.size(); ++k) {
				int idx = item_to_remove[k];
				HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(idx));
				if (hr) {
					if (m_services) {
						FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
						if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
						DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
						(void)m_services->RemoveProcHookEntry(m_pid, hi, lo, hr->id);
					}
						if (hr->IsPatchEntry()) {
							auto oriVec = HexToBytes(hr->GetPatchOriHex());
							if (!oriVec.empty() && !HookCore::RemovePatch(m_pid, hr->address, m_services, oriVec.data(), (DWORD)oriVec.size())) {
								LOG_UI_E(m_services, L"failed to remove patch at Addr=0x%p\n", hr->address);
								MessageBox(L"Failed to remove patch before rehooking the same address", L"Hook",
									MB_OK | MB_ICONERROR);
								return;
							}
						} else {
							if (!HookCore::RemoveHook(m_pid, hr->address, m_services, hr->id,
								hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)) {
								LOG_UI_E(m_services, L"failed to remove hook at Addr=0x%p\n", hr->address);
								MessageBox(L"Failed to remove hook first before rehooking the same address", L"Hook",
									MB_OK | MB_ICONERROR);
								return;
							}
						}
					// remove succeed, mark this hookid available
					// its previous value should be 1
					if (!hr->IsPatchEntry() && !_bittestandreset((LONG*)m_exp_num_tracker_bitfield, hr->id)) {
						MessageBox(L"hookid should be set before reset", L"Hook", MB_OK | MB_ICONERROR);
						return ;
					}
					delete hr;
				}
				m_HookList.DeleteItem(idx);
			}
			 
		}
	}
}

void HookProcDlg::OnBnClickedReloadLua() {
	bool procFound = false;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe = { sizeof(pe) };
		if (Process32First(hSnap, &pe)) {
			do {
				if ((DWORD)pe.th32ProcessID == m_pid) { procFound = true; break; }
			} while (Process32Next(hSnap, &pe));
		}
		CloseHandle(hSnap);
	}
	if (!procFound) {
		MessageBox(L"Target process does not appear to be running. Closing dialog.", L"Hook", MB_ICONWARNING);
		// Destroy the dialog window; parent will be notified in OnDestroy and will delete this object.
		DestroyWindow();
		return;
	}

	// Collect all Lua-mode hooks from the hook list
	struct LuaHookInfo { int hookId; std::wstring scriptPath; std::wstring handlerName; };
	std::vector<LuaHookInfo> luaHooks;

	for (int i = 0; i < m_HookList.GetItemCount(); ++i) {
		HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
		if (!hr) continue;
		// expFunc format for Lua mode: "Lua:<script_path>!<handler_name>"
		if (hr->expFunc.size() > 5 && hr->expFunc.substr(0, 4) == L"Lua:") {
			std::wstring rest = hr->expFunc.substr(4);
			size_t sep = rest.find(L'!');
			if (sep != std::wstring::npos) {
				luaHooks.push_back({ hr->id, rest.substr(0, sep), rest.substr(sep + 1) });
			}
		}
	}

	if (luaHooks.empty()) {
		MessageBox(L"No Lua-mode hooks to reload.", L"Reload Lua", MB_ICONINFORMATION);
		return;
	}

	// Get LuaEngine.dll base in target process
	bool is64 = false;
	m_services->IsProcess64(m_pid, is64);
	const wchar_t* luaEngineName = is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32;
	DWORD64 luaEngineBase = 0;
	if (!m_services->GetModuleBase(m_pid, luaEngineName, &luaEngineBase) || luaEngineBase == 0) {
		MessageBox(L"LuaEngine.dll not loaded in target process.", L"Reload Lua", MB_ICONERROR);
		return;
	}

	// Get LuaEngineIPCSlot export offset
	WCHAR luaEngineNameBuf[MAX_PATH] = { 0 };
	wcscpy_s(luaEngineNameBuf, luaEngineName);
	std::wstring luaEngineFullPath = m_services->GetCurrentDirFilePath(luaEngineNameBuf);

	DWORD ipcSlotOffset = 0;
	if (!m_services->CheckExportFromFile(luaEngineFullPath.c_str(), LUA_ENGINE_PLACEHOLDER_EXP_FUNC, &ipcSlotOffset)) {
		MessageBox(L"Failed to find LuaEngineIPCSlot export.", L"Reload Lua", MB_ICONERROR);
		return;
	}

	PVOID ipcSlotAddr = (PVOID)(luaEngineBase + ipcSlotOffset);
#ifdef _DEBUG
	// In debug builds, resolve E9 jmp to get real function address
	HANDLE hProcDbg = NULL;
	if (m_services->GetHighAccessProcHandle(m_pid, &hProcDbg) && hProcDbg) {
		DWORD e9Oprand = 0;
		ReadProcessMemory(hProcDbg, (LPVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_OPCODE_SIZE),
			&e9Oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, NULL);
		ipcSlotAddr = (PVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_SIZE + e9Oprand);
		CloseHandle(hProcDbg);
	}
#endif

	int reloaded = 0;
	int failed = 0;

	for (const auto& lh : luaHooks) {
		// Build IPC data: script_path|handler_name
		WCHAR ipcData[MAX_PATH + 256] = { 0 };
		int pos = 0;
		for (size_t i = 0; i < lh.scriptPath.size() && pos < MAX_PATH - 1; i++)
			ipcData[pos++] = lh.scriptPath[i];
		ipcData[pos++] = LUA_IPC_SEPARATOR;
		for (size_t i = 0; i < lh.handlerName.size() && pos < MAX_PATH + 255; i++)
			ipcData[pos++] = lh.handlerName[i];
		ipcData[pos] = L'\0';

		// Write IPC data to target process
		HANDLE hProc = NULL;
		if (!m_services->GetHighAccessProcHandle(m_pid, &hProc) || !hProc) {
			LOG_UI_E(m_services, L"ReloadLua: failed to get high access handle, pid=%u\n", m_pid);
			failed++;
			continue;
		}

		DWORD oldProtect = 0;
		bool writeOk = false;
		if (VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			SIZE_T written = 0;
			writeOk = m_services->WriteProcessMemoryWrap(hProc, (LPVOID)ipcSlotAddr,
				ipcData, (pos + 1) * sizeof(WCHAR), &written);
			VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), oldProtect, &oldProtect);
		}
		CloseHandle(hProc);

		if (!writeOk) {
			LOG_UI_E(m_services, L"ReloadLua: failed to write IPC data for hookId=%d\n", lh.hookId);
			failed++;
			continue;
		}

		// Signal the event
		WCHAR eventName[150];
		swprintf_s(eventName, LUA_ENGINE_UM_SIGNAL_EVENT, m_pid, lh.hookId);
		HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
		if (!hEvent) {
			LOG_UI_E(m_services, L"ReloadLua: failed to open signal event %s, err=%u\n", eventName, GetLastError());
			failed++;
			continue;
		}
		SetEvent(hEvent);
		CloseHandle(hEvent);

		// Wait for loaded event (timeout 3s)
		WCHAR loadedEventName[150];
		swprintf_s(loadedEventName, LUA_ENGINE_UM_LOADED_EVENT, m_pid, lh.hookId);
		HANDLE hLoaded = OpenEventW(SYNCHRONIZE, FALSE, loadedEventName);
		if (hLoaded) {
			WaitForSingleObject(hLoaded, 3000);
			CloseHandle(hLoaded);
		}

		LOG_UI(m_services, L"ReloadLua: signaled reload for hookId=%d script=%s handler=%s\n",
			lh.hookId, lh.scriptPath.c_str(), lh.handlerName.c_str());
		reloaded++;
	}

	CString msg;
	if (failed > 0)
		msg.Format(L"Reloaded %d Lua hook(s), %d failed.", reloaded, failed);
	else
		msg.Format(L"Reloaded %d Lua hook(s).", reloaded);
	MessageBox(msg, L"Reload Lua", MB_OK | (failed ? MB_ICONWARNING : MB_ICONINFORMATION));
}

HookProcDlg::HookProcDlg(DWORD pid, const std::wstring& name, IHookServices* services, CWnd* parent)
	: CDialogEx(IDD_HOOKUI_PROC_DLG, parent), m_pid(pid), m_name(name), m_services(services) {
}

BOOL HookProcDlg::CreateModeless(CWnd* parent) { return Create(IDD_HOOKUI_PROC_DLG, parent); }

BOOL HookProcDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();
	CString title; title.Format(L"Hook Process PID %lu - %s", m_pid, m_name.c_str());
	SetWindowText(title);
	m_ModuleList.Attach(GetDlgItem(IDC_HOOKUI_LIST_MODULES)->m_hWnd);
	m_ModuleList.InsertColumn(0, L"Base", LVCFMT_LEFT, 80);
	m_ModuleList.InsertColumn(1, L"Size", LVCFMT_LEFT, 70);
	m_ModuleList.InsertColumn(2, L"Name", LVCFMT_LEFT, 140);
	m_ModuleList.InsertColumn(3, L"Path", LVCFMT_LEFT, 300);
	m_ModuleList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
	LONG lvStyle = ::GetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE);
	lvStyle |= LVS_SHOWSELALWAYS; ::SetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE, lvStyle);
	::SetWindowPos(m_ModuleList.GetSafeHwnd(), nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

	// set process hacker and hook core lib service interface
	PHLIB::SetHookServices(m_services);
	HookCore::SetHookServices(m_services);
	PopulateModuleList();
	// Hook list initialization
	m_HookList.Attach(GetDlgItem(IDC_HOOKUI_LIST_HOOKS)->m_hWnd);
	m_HookList.InsertColumn(0, L"Hook ID", LVCFMT_LEFT, 80);
	m_HookList.InsertColumn(1, L"Address", LVCFMT_LEFT, 100);
	m_HookList.InsertColumn(2, L"Module", LVCFMT_LEFT, 180);
	m_HookList.InsertColumn(3, L"ExpFunc", LVCFMT_LEFT, 220);
	m_HookList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	PopulateHookList();
	// Load persisted hook rows for this PID (use PID + startTime key stored by controller)
	// Attempt to obtain process creation FILETIME to form the key components
	FILETIME createTime{ 0,0 };
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) {
		FILETIME exitTime, kernelTime, userTime;
		if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
			// success
		}
		CloseHandle(h);
	}
	// If createTime is zero, we still attempt load with hi/lo = 0
	DWORD hi = createTime.dwHighDateTime;
	DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow> persisted;
	if (m_services && m_services->LoadProcHookList(m_pid, hi, lo, persisted)) {
		for (auto &pr : persisted) {
			// controller returns HookRow populated; we still need to verify PID+FILETIME
			// For backward-compatibility the controller should only return rows for this PID+FILETIME.
			// We'll accept any returned HookRow and add those matching m_pid.
			// Note: If the controller uses a combined key, it may choose to return only matching rows.
			// restore row preserving hook id
			if (pr.id == -1) {
				// Patch mode entry: display in UI but skip bitfield tracking
				HookRow* hr = new HookRow(pr);
				CString addrC; addrC.Format(L"0x%llX", hr->address);
				int idx = m_HookList.GetItemCount();
				int i = m_HookList.InsertItem(idx, L"P");
				m_HookList.SetItemText(i, 1, addrC);
				m_HookList.SetItemText(i, 2, hr->module.c_str());
				if (!hr->expFunc.empty()) m_HookList.SetItemText(i, 3, hr->expFunc.c_str());
				m_HookList.SetItemData(i, (DWORD_PTR)hr);
			} else {
				if (pr.id < 0 || pr.id >= 256) continue; // skip invalid
				HookRow* hr = new HookRow(pr);
				// If caller didn't populate ori_asm_code_addr, it will be zero.
				CString idC; idC.Format(L"%d", hr->id);
				CString addrC; addrC.Format(L"0x%llX", hr->address);
				int idx = m_HookList.GetItemCount();
				int i = m_HookList.InsertItem(idx, idC);
				m_HookList.SetItemText(i, 1, addrC);
				m_HookList.SetItemText(i, 2, hr->module.c_str());
				if (!hr->expFunc.empty()) m_HookList.SetItemText(i, 3, hr->expFunc.c_str());
				m_HookList.SetItemData(i, (DWORD_PTR)hr);
				// mark unvaliable
				if (_bittestandset((LONG*)m_exp_num_tracker_bitfield, hr->id)) {
					MessageBox(L"OnInitDialog: hook id reuse deteced, abort!", L"Hook", MB_OK | MB_ICONERROR);
					return FALSE;
				}
			}
		}
	}
	// apply initial splitter
	CRect rc; GetClientRect(&rc); UpdateLayoutForSplitter(rc.Width(), rc.Height());
	// preview banner removed for cleaner UI
	return TRUE;
}

void HookProcDlg::OnDestroy() {
	FreeModuleRows();
	FreeHookRows();
	m_ModuleList.DeleteAllItems();
	m_HookList.DeleteAllItems();
	m_ModuleList.Detach();
	CDialogEx::OnDestroy();
	if (CWnd* parent = GetParent()) {
		::PostMessage(parent->GetSafeHwnd(), HookProcDlg::kMsgHookDlgDestroyed, (WPARAM)this, 0);
	}
	// Delete self: created by factory with 'new' and responsible for own lifetime.
	delete this;
}

void HookProcDlg::UpdateLayoutForSplitter(int cx, int cy) {
	const int margin = 7;
	int leftWidth = m_splitPos; if (leftWidth < 120) leftWidth = 120; if (leftWidth > cx - 160) leftWidth = cx - 160;
	// Position module list just below the "Modules" label if present
	int listTop = margin + 11;
	if (CWnd* modulesLabel = GetDlgItem(IDC_HOOKUI_STATIC_MODULE)) {
		CRect rcLabel; modulesLabel->GetWindowRect(&rcLabel); ScreenToClient(&rcLabel);
		listTop = rcLabel.bottom + 2; // small gap to avoid overlap
	}
	// Make module list bottom align with dialog bottom using same margin as hooks list
	int listHeight = cy - listTop - margin; if (listHeight < 80) listHeight = 80;
	m_ModuleList.MoveWindow(margin, listTop, leftWidth, listHeight);
	int panelX = margin + leftWidth + margin;
	auto moveCtrl = [&](int id, int x, int y, int w, int h) { CWnd* c = GetDlgItem(id); if (c) c->MoveWindow(x, y, w, h); };
	moveCtrl(IDC_HOOKUI_STATIC_OFFSET, panelX, 18, 70, 14);
	moveCtrl(IDC_HOOKUI_EDIT_OFFSET, panelX, 30, 140, 18);
	moveCtrl(IDC_HOOKUI_STATIC_DIRECT, panelX, 55, 140, 14);
	moveCtrl(IDC_HOOKUI_EDIT_DIRECT, panelX, 67, 140, 18);
	// Export function label + edit directly under Direct Address
	moveCtrl(IDC_HOOKUI_STATIC_EXPORT, panelX, 85, 140, 14);
	moveCtrl(IDC_HOOKUI_EDIT_EXPORT, panelX, 97, 140, 18);
	// Place Apply/Sequence buttons directly below the Export edit dynamically
	int hooksW = cx - panelX - margin;
	int btnW = 65; int btnH = 22;
	int applyY = 120;
	if (CWnd* exportEdit = GetDlgItem(IDC_HOOKUI_EDIT_EXPORT)) {
		CRect rcExp; exportEdit->GetWindowRect(&rcExp); ScreenToClient(&rcExp);
		applyY = rcExp.bottom + 5;
	}
	int applyX = panelX;
	if (CWnd* exportEdit = GetDlgItem(IDC_HOOKUI_EDIT_EXPORT)) {
		CRect rcExp; exportEdit->GetWindowRect(&rcExp); ScreenToClient(&rcExp);
		applyX = rcExp.left;
	}
	int applyBtnW = 65; int seqBtnW = 95; int reloadBtnW = 65;
	moveCtrl(IDC_HOOKUI_BTN_APPLY, applyX, applyY, applyBtnW, btnH);
	moveCtrl(IDC_HOOKUI_BTN_APPLY_SEQ, applyX + applyBtnW + 5, applyY, seqBtnW, btnH);
	moveCtrl(IDC_HOOKUI_BTN_RELOAD_LUA, applyX + applyBtnW + 5 + seqBtnW + 5, applyY, reloadBtnW, btnH);
	int hooksY = applyY + btnH + 2;
	int hooksH = listTop + listHeight - hooksY; if (hooksH < 40) hooksH = 40;
	moveCtrl(IDC_HOOKUI_LIST_HOOKS, panelX, hooksY, hooksW, hooksH);
}



void HookProcDlg::OnLButtonDown(UINT nFlags, CPoint point) {
	CRect rc; GetClientRect(&rc);
	int rightPanelLeft = m_splitPos + 14; CRect splRect(rightPanelLeft - m_splitterWidth, 0, rightPanelLeft + m_splitterWidth, rc.Height());
	if (splRect.PtInRect(point)) { m_draggingSplitter = true; SetCapture(); }
	CDialogEx::OnLButtonDown(nFlags, point);
}

void HookProcDlg::OnLButtonUp(UINT nFlags, CPoint point) {
	if (m_draggingSplitter) { m_draggingSplitter = false; ReleaseCapture(); }
	CDialogEx::OnLButtonUp(nFlags, point);
}

void HookProcDlg::OnMouseMove(UINT nFlags, CPoint point) {
	if (m_draggingSplitter) {
		int newLeft = point.x - 7; m_splitPos = newLeft; CRect rc; GetClientRect(&rc); UpdateLayoutForSplitter(rc.Width(), rc.Height());
	}
	else {
		int rightPanelLeft = m_splitPos + 14; CRect splRect(rightPanelLeft - m_splitterWidth, 0, rightPanelLeft + m_splitterWidth, 10000);
		if (splRect.PtInRect(point)) SetCursor(::LoadCursor(NULL, IDC_SIZEWE));
	}
	CDialogEx::OnMouseMove(nFlags, point);
}

void HookProcDlg::PopulateHookList() {
	m_HookList.DeleteAllItems();
	// TODO: read persisted hooks for this pid or wire live update.
}

int HookProcDlg::AddHookEntry(const HookRow& row) {
	// remove duplicated hookentry by checking hookid
	for (int j = 0; j < m_HookList.GetItemCount(); ++j) {
		HookRow* existing = reinterpret_cast<HookRow*>(m_HookList.GetItemData(j));
		if (existing && !existing->IsPatchEntry() && existing->id == row.id) {
			// Remove old UI row and free it; keep bitfield state as-is since we reuse the same id
			m_HookList.DeleteItem(j);
			delete existing;
			break; // there should be at most one
		}
	}
	
	int idx = m_HookList.GetItemCount();
	CString addrC; addrC.Format(L"0x%llX", row.address);
	CString useIdC; if (row.IsPatchEntry()) useIdC = L"P"; else useIdC.Format(L"%d", row.id);
	int i = m_HookList.InsertItem(idx, useIdC);
	m_HookList.SetItemText(i, 1, addrC);
	m_HookList.SetItemText(i, 2, row.module.c_str());
	// Allocate a HookRow copy and attach to the list item so we can later locate by address
	HookRow* hr = new HookRow(row);
	hr->id = row.id;
	m_HookList.SetItemData(i, (DWORD_PTR)hr);
	// Persist updated list for this PID using RegistryStore
	// Build entries vector and write
	FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
	DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow*> rows;
	int count = m_HookList.GetItemCount();
	for (int j = 0; j < count; ++j) {
		HookRow* r = reinterpret_cast<HookRow*>(m_HookList.GetItemData(j));
		if (!r) continue;
		rows.push_back(r);
	}
	if (m_services) {
		// Convert vector<HookRow*> to vector<HookRow> for service
		std::vector<HookRow> outRows; outRows.reserve(rows.size());
		for (auto pr : rows) if (pr) outRows.push_back(*pr);
		m_services->SaveProcHookList(m_pid, hi, lo, outRows);
	}
	return i;
}

void HookProcDlg::PopulateModuleList() {
	if (!m_services) {
		MessageBoxW(L"m_services NULL", L"HookDlg", MB_ICONERROR);
		return;
	}
	FreeModuleRows();
	m_ModuleList.DeleteAllItems();

	PPH_MODULE_LIST_NODE head = NULL;
	LONG status = (LONG)(ULONG_PTR)PHLIB::PhBuildModuleList((void*)(ULONG_PTR)m_pid, (void*)(ULONG_PTR)&head);
	if (status != 0) {
		LOG_UI_E(m_services, L"failed to call PHLIB::PhBuildModuleList, Status=0x%x\n", status);
		MessageBoxW(L"failed to call PHLIB::PhBuildModuleList", L"HookDlg", MB_ICONERROR);
		return;
	}
	int i = 0;
	for (PPH_MODULE_LIST_NODE n = head; n != NULL; n = n->Next) {
		std::wstring baseStr = L"0x" + Hex64((ULONGLONG)n->Base);
		int idx = m_ModuleList.InsertItem(i, baseStr.c_str());
		// Size unknown via this path; leave blank for now
		m_ModuleList.SetItemText(idx, 1, (std::wstring(L"0x") + Hex64((ULONGLONG)n->Size)).c_str());
		// Extract module name from path
		std::wstring name = n->Path ? std::wstring(n->Path) : L"";
		size_t pos = name.find_last_of(L"\\");
		std::wstring justName = (pos != std::wstring::npos) ? name.substr(pos + 1) : name;
		m_ModuleList.SetItemText(idx, 2, justName.c_str());
		m_ModuleList.SetItemText(idx, 3, name.c_str());
		m_ModuleList.SetItemData(idx, (DWORD_PTR)n->Base);
		ModuleRow* row = new ModuleRow{ (ULONGLONG)n->Base,(ULONGLONG)n->Size,justName, name };
		m_ModuleList.SetItemData(idx, (DWORD_PTR)row);
		i++;
	}
	// Free list
	while (head) { auto* next = head->Next; if (head->Path) free(head->Path); free(head); head = next; }
	return;
}

bool HookProcDlg::GetSelectedModule(std::wstring& name, ULONGLONG& base) const {
	int sel = m_ModuleList.GetNextItem(-1, LVNI_SELECTED);
	if (sel == -1) return false;
	ModuleRow* row = reinterpret_cast<ModuleRow*>(m_ModuleList.GetItemData(sel));
	if (!row) return false;
	name = row->name;
	base = row->base;
	return true;
}

int CALLBACK HookProcDlg::ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
	HookProcDlg* self = reinterpret_cast<HookProcDlg*>(lParamSort); if (!self) return 0;
	ModuleRow* r1 = reinterpret_cast<ModuleRow*>(lParam1); ModuleRow* r2 = reinterpret_cast<ModuleRow*>(lParam2);
	if (!r1 || !r2) return 0;
	int r = 0;
	switch (self->m_sortColumn) {
	case 0: r = (r1->base < r2->base) ? -1 : (r1->base > r2->base ? 1 : 0); break; // Base
	case 1: r = (r1->size < r2->size) ? -1 : (r1->size > r2->size ? 1 : 0); break; // Size
	case 2: r = _wcsicmp(r1->name.c_str(), r2->name.c_str()); break; // Name
	case 3: r = _wcsicmp(r1->path.c_str(), r2->path.c_str()); break; // Path
	default: r = 0; break;
	}
	if (!self->m_sortAscending) r = -r;
	return r;
}

void HookProcDlg::OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	int col = pNMLV->iSubItem;
	if (m_sortColumn == col) m_sortAscending = !m_sortAscending; else { m_sortColumn = col; m_sortAscending = true; }
	m_ModuleList.SortItems(ModuleCompare, (LPARAM)this);
	if (pResult) *pResult = 0;
}

void HookProcDlg::FreeModuleRows() {
	int count = m_ModuleList.GetItemCount();
	for (int i = 0; i < count; i++) {
		ModuleRow* row = reinterpret_cast<ModuleRow*>(m_ModuleList.GetItemData(i));
		if (row) { delete row; }
		m_ModuleList.SetItemData(i, 0);
	}
}

void HookProcDlg::FreeHookRows() {
	int count = m_HookList.GetItemCount();
	for (int i = 0; i < count; ++i) {
		HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
		if (hr) delete hr;
		m_HookList.SetItemData(i, 0);
	}
}

void HookProcDlg::OnContextMenu(CWnd* pWnd, CPoint point) {
	// Determine which list receives the context menu: modules or hooks
	if (m_ModuleList.GetSafeHwnd() && pWnd && pWnd->GetSafeHwnd() == m_ModuleList.GetSafeHwnd()) {
		// Context menu for module list: provide Copy entry for selected row
		CPoint clientPoint = point; m_ModuleList.ScreenToClient(&clientPoint);
		LVHITTESTINFO ht = { 0 }; ht.pt = clientPoint;
		int item = m_ModuleList.HitTest(&ht); if (item == -1) return;
		CMenu menu; menu.CreatePopupMenu();
		const UINT CMD_MOD_COPY = 0x8101;
		menu.AppendMenuW(MF_STRING, CMD_MOD_COPY, L"Copy Entry");
		// Build entry text: Base, Size, Name, Path
		CString base = m_ModuleList.GetItemText(item, 0);
		CString size = m_ModuleList.GetItemText(item, 1);
		CString name = m_ModuleList.GetItemText(item, 2);
		CString path = m_ModuleList.GetItemText(item, 3);
		CString entry; entry.Format(L"Base=%s\r\nSize=%s\r\nName=%s\r\nPath=%s", base.GetString(), size.GetString(), name.GetString(), path.GetString());
		int cmd = menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, this);
		if (cmd == CMD_MOD_COPY) {
			CopyTextToClipboard(entry, this->GetSafeHwnd());
		}
		return;
	}

	// Default: hook list context menu
	if (!m_HookList.GetSafeHwnd()) return;
	CPoint clientPoint = point;
	m_HookList.ScreenToClient(&clientPoint);
	LVHITTESTINFO ht = { 0 }; ht.pt = clientPoint;
	int item = m_HookList.HitTest(&ht);
	if (item == -1) return; // click not on an item

	CMenu menu; menu.CreatePopupMenu();
	const UINT CMD_DISABLE = 0x8001;
	const UINT CMD_ENABLE = 0x8002;
	const UINT CMD_REMOVE = 0x8003;
	const UINT CMD_COPY_ADDR = 0x8004;
	menu.AppendMenuW(MF_STRING, CMD_DISABLE, L"Disable");
	menu.AppendMenuW(MF_STRING, CMD_ENABLE, L"Enable");
	menu.AppendMenuW(MF_STRING, CMD_REMOVE, L"Remove");
	menu.AppendMenuW(MF_SEPARATOR, 0, (LPCTSTR)NULL);
	menu.AppendMenuW(MF_STRING, CMD_COPY_ADDR, L"Copy Address");

	bool isDisabled = false;
	HookRow* testHr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
	if (testHr) { if (testHr->module.rfind(L"[DISABLED] ", 0) == 0) isDisabled = true; }

	CString addrText = m_HookList.GetItemText(item, 1);
	menu.EnableMenuItem(CMD_DISABLE, MF_BYCOMMAND | (isDisabled ? MF_GRAYED : MF_ENABLED));
	menu.EnableMenuItem(CMD_ENABLE, MF_BYCOMMAND | (isDisabled ? MF_ENABLED : MF_GRAYED));
	menu.EnableMenuItem(CMD_COPY_ADDR, MF_BYCOMMAND | (!addrText.IsEmpty() ? MF_ENABLED : MF_GRAYED));

	SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)item);
	int cmd = menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, this);
	if (cmd == 0) return;
	switch (cmd) {
	case 0x8001: OnHookMenuDisable(); break;
	case 0x8002: OnHookMenuEnable(); break;
	case 0x8003: OnHookMenuRemove(); break;
	case 0x8004: CopyTextToClipboard(addrText, this->GetSafeHwnd()); break;
	}
}


// Handlers: left as stubs for user implementation
void HookProcDlg::OnHookMenuDisable() {
	int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
	if (item < 0 || item >= m_HookList.GetItemCount()) return;
	HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
	if (!hr) return;
	// UI-only: mark disabled (prepend [DISABLED] to module text)
	std::wstring mod = hr->module;
	if (mod.find(L"[DISABLED]") == std::wstring::npos) {
		mod = std::wstring(L"[DISABLED] ") + mod;
		hr->module = mod;
		m_HookList.SetItemText(item, 2, mod.c_str());
	}


	if (hr->IsPatchEntry()) {
		auto oriVec = HexToBytes(hr->GetPatchOriHex());
		if (oriVec.empty() || !HookCore::DisablePatch(m_pid, hr->address, m_services, oriVec.data(), (DWORD)oriVec.size())) {
			LOG_UI_E(m_services, L"failed to call HookCore::DisablePatch\n");
			MessageBoxW(L"failed to call HookCore::DisablePatch\n", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	} else {
		if (!HookCore::DisableHook(m_pid, hr->address, m_services, (PVOID)hr->ori_asm_code_addr, hr->ori_asm_code_len)) {
			LOG_UI_E(m_services, L"failed to call HookCore::DisableHook\n");
			MessageBoxW(L"failed to call HookCore::DisableHook\n", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	}

	// Persist change
	FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
	DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow*> rows;
	
	if (m_services) {
		// Convert vector<HookRow*> to vector<HookRow> for service
		std::vector<HookRow> outRows; outRows.reserve(rows.size());
		for (auto pr : rows) if (pr) outRows.push_back(*pr);
		m_services->SaveProcHookList(m_pid, hi, lo, outRows);
	}
}

void HookProcDlg::OnHookMenuEnable() {
	int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
	if (item < 0 || item >= m_HookList.GetItemCount()) return;
	HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
	if (!hr) return;
	// UI-only: remove [DISABLED] marker if present
	std::wstring mod = hr->module;
	size_t pos = mod.find(L"[DISABLED] ");
	if (pos != std::wstring::npos) {
		mod = mod.substr(pos + wcslen(L"[DISABLED] "));
		hr->module = mod;
		m_HookList.SetItemText(item, 2, mod.c_str());
	}

	if (hr->IsPatchEntry()) {
		auto patchVec = HexToBytes(hr->GetPatchHex());
		if (patchVec.empty() || !HookCore::EnablePatch(m_pid, hr->address, m_services, patchVec.data(), (DWORD)patchVec.size())) {
			LOG_UI_E(m_services, L"failed to call HookCore::EnablePatch\n");
			MessageBoxW(L"failed to call HookCore::EnablePatch\n", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	} else {
		HookCore::EnableHook(m_pid, hr->address, m_services, (PVOID)hr->trampoline_pit);
	}

	// Persist change
	FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
	DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow*> rows;
	
	if (m_services) {
		// Convert vector<HookRow*> to vector<HookRow> for service
		std::vector<HookRow> outRows; outRows.reserve(rows.size());
		for (auto pr : rows) if (pr) outRows.push_back(*pr);
		m_services->SaveProcHookList(m_pid, hi, lo, outRows);
	}
}

void HookProcDlg::OnHookMenuRemove() {
	// Do not blindly decrement next ID; maintain generator based on remaining rows
	int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
	if (item < 0 || item >= m_HookList.GetItemCount()) return;
	HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
	if (!hr) return;
	// Persist removal of this specific hook entry first to avoid stale records
	// Persist removal of this specific hook entry first to avoid stale records
	if (hr->IsPatchEntry()) {
		auto oriVec = HexToBytes(hr->GetPatchOriHex());
		if (!oriVec.empty() && !HookCore::RemovePatch(m_pid, hr->address, m_services, oriVec.data(), (DWORD)oriVec.size())) {
			if (m_services)
				LOG_UI_E(m_services, L"failed to call HookCore::RemovePatch\n");
			MessageBoxW(L"failed to call HookCore::RemovePatch\n", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	} else {
		if (!HookCore::RemoveHook(m_pid, hr->address, m_services, hr->id, hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)) {
			if (m_services)
				LOG_UI_E(m_services, L"failed to call HookCore::RemoveHook\n");
			MessageBoxW(L"failed to call HookCore::RemoveHook\n", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	}
	// remove succeed, mark this hookid available
	// its previous value should be 1
	if (!hr->IsPatchEntry() && !_bittestandreset((LONG*)m_exp_num_tracker_bitfield, hr->id)) {
		MessageBox(L"hookid should be set before reset", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}
	if (m_services) {
		FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
		if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
		DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
		(void)m_services->RemoveProcHookEntry(m_pid, hi, lo, hr->id);
	}
	// UI-only: remove the item and free memory
	m_HookList.DeleteItem(item);
	delete hr;
}

void HookProcDlg::OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult) { if (pResult) *pResult = 0; }
void HookProcDlg::OnEnSetFocusOffset() { }
void HookProcDlg::OnEnSetFocusDirect() { }
void HookProcDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI) { CDialogEx::OnGetMinMaxInfo(lpMMI); lpMMI->ptMinTrackSize.x = 480; lpMMI->ptMinTrackSize.y = 260; }

void HookProcDlg::OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult) {
	NMLVCUSTOMDRAW* pCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	if (!pCD || !pResult) return;
	switch (pCD->nmcd.dwDrawStage) {
	case CDDS_PREPAINT:
		*pResult = CDRF_NOTIFYITEMDRAW; return;
	case CDDS_ITEMPREPAINT:
	{
		UINT itemIndex = (UINT)pCD->nmcd.dwItemSpec;
		BOOL isSelected = (m_ModuleList.GetItemState(itemIndex, LVIS_SELECTED) & LVIS_SELECTED) != 0;
		if (isSelected) {
			pCD->clrTextBk = GetSysColor(COLOR_HIGHLIGHT);
			pCD->clrText = GetSysColor(COLOR_HIGHLIGHTTEXT);
		}
		*pResult = CDRF_DODEFAULT; return;
	}
	}
	*pResult = CDRF_DODEFAULT;
}

ULONGLONG HookProcDlg::ParseAddressText(const std::wstring& input, bool& ok) const {
	ok = false; if (input.empty()) return 0ULL; std::wstring t = input; for (auto &c : t) c = towlower(c);
	// allow optional 0x prefix
	if (t.rfind(L"0x", 0) == 0) t = t.substr(2);
	// allow backtick separators for readability (e.g. 7ff8`e8320088) - strip them
	std::wstring stripped; stripped.reserve(t.size());
	for (wchar_t c : t) {
		if (c == L'`') continue;
		stripped.push_back(c);
	}
	// validate remaining characters are hex digits
	for (wchar_t c : stripped) {
		if (!(iswdigit(c) || (c >= L'a' && c <= L'f'))) return 0ULL;
	}
	wchar_t* end = nullptr; ULONGLONG v = wcstoull(stripped.c_str(), &end, 16); if (end && *end == 0) { ok = true; return v; } return 0ULL;
}
bool HookProcDlg::HookCommonCode(DWORD64 module_base, DWORD module_offset,std::wstring hook_code_path,std::wstring export_func_name) {
	// check export exist
	char ansi_exportToCheck[MAX_PATH] = { 0 };
	DWORD hook_code_offset = 0;
	if (!m_services->ConvertWcharToChar(export_func_name.c_str(), ansi_exportToCheck, MAX_PATH)) {
		LOG_UI_E(m_services, L"failed to call ConvertWcharToChar\n");
		MessageBox(L"failed to call ConvertWcharToChar", L"Hook", MB_OK | MB_ICONERROR);
		return false;
	}
	if (!m_services->CheckExportFromFile(hook_code_path.c_str(), ansi_exportToCheck, &hook_code_offset)) {
		LOG_UI_E(m_services, L"failed to call CheckExportFromFile, PE_Path=%s\n", hook_code_path.c_str());
		MessageBox(L"failed to call CheckExportFromFile", L"Hook", MB_OK | MB_ICONERROR);
		return false;
	}
	if (!hook_code_offset) {
		LOG_UI_E(m_services, L"failed to get required export function: %s\n", export_func_name.c_str());
		MessageBox(L"failed to get required export function from HookCode dll", L"Hook", MB_OK | MB_ICONERROR);
		return false;
	}


	std::wstring pathToInject = hook_code_path;
	size_t pos = hook_code_path.find_last_of(L'\\');

	std::wstring hook_code_dll_name;
	if (pos != std::wstring::npos)
		hook_code_dll_name = hook_code_path.substr(pos + 1);
	else
		hook_code_dll_name = hook_code_path; // no backslash, take entire string
	wchar_t* temp_hook_code_dll_name = 0;
	{
		wchar_t modPathBuf[MAX_PATH] = { 0 };
		DWORD modLen = GetModuleFileNameW(AfxGetInstanceHandle(), modPathBuf, _countof(modPathBuf));
		std::wstring folder;
		if (modLen == 0) {
			folder = L".\\" HOOK_CODE_TEMP_DIR_NAME;
		}
		else {
			std::wstring modPath(modPathBuf);
			size_t p = modPath.find_last_of(L"\\/");
			if (p == std::wstring::npos) folder = L".\\" HOOK_CODE_TEMP_DIR_NAME;
			else folder = modPath.substr(0, p) + L"\\" HOOK_CODE_TEMP_DIR_NAME;
		}
		// Ensure directory exists (CreateDirectoryW is fine if already exists)
		if (!CreateDirectoryW(folder.c_str(), NULL)) {
			DWORD err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				LOG_UI_E(m_services, L"CreateDirectoryW failed for %s err=%u\n", folder.c_str(), err);
			}
		}
		// Build timestamped filename
		SYSTEMTIME st; GetLocalTime(&st);
		wchar_t ts[64];
		swprintf(ts, _countof(ts), L"%04d%02d%02d_%02d%02d%02d_%03d",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		std::wstring new_dll_name = L"";
		new_dll_name = new_dll_name + ts + L"_" + hook_code_dll_name;
		temp_hook_code_dll_name = (wchar_t*)malloc(2 * (new_dll_name.length() + 1));
		ZeroMemory(temp_hook_code_dll_name, 2 * (new_dll_name.length() + 1));
		memcpy(temp_hook_code_dll_name, new_dll_name.c_str(), 2 * new_dll_name.length());
		std::wstring dest = folder + L"\\" + ts + L"_" + hook_code_dll_name;
		if (CopyFileW(hook_code_path.c_str(), dest.c_str(), FALSE)) {
			pathToInject = dest; // use copied file
			LOG_UI(m_services, L"Copied hook DLL to %s\n", dest.c_str());
		}
		else {
			DWORD err = GetLastError();
			LOG_UI_E(m_services, L"CopyFileW failed src=%s dst=%s err=%u - falling back to original\n", hook_code_path.c_str(), dest.c_str(), err);
			return false;
			// keep pathToInject as original selectedPath
		}
	}
	DWORD64 hook_code_dll_base = 0;
	// Signal master DLL (via IHookServices) to load the selected DLL inside target process
	if (m_services) {
		if (!m_services->InjectTrampoline(m_pid, pathToInject.c_str())) {
			LOG_UI_E(m_services, L"InjectTrampoline failed for pid=%u path=%s\n", m_pid, pathToInject.c_str());
			MessageBox(L"Failed to request master DLL to load selected DLL. Check logs.", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}
		LOG_UI(m_services, L"HookCode injection signaled pid=%u path=%s\n", m_pid, pathToInject.c_str());
		// check if HookCode injected

			// Poll up to 5 seconds (50 * 100ms) for trampoline module presence.
		const int maxIterations = 50;
	
	
		for (int iter = 0; iter < maxIterations && !hook_code_dll_base; ++iter) {
			if(!m_services->GetModuleBase(m_pid, temp_hook_code_dll_name, &hook_code_dll_base)){
				LOG_UI_E(m_services, L"faile to call GetModuleBase, Pid=%u, Module=%s\n", m_pid, temp_hook_code_dll_name);
				MessageBox(L"faile to call GetModuleBase", L"Hook", MB_OK | MB_ICONERROR);
				return false;
			}
			if (!hook_code_dll_base) Sleep(100);
		}
		if (!hook_code_dll_base) {
			LOG_UI_E(m_services, L"faile to load hookcode dll: %s\n", hook_code_path.c_str());
			MessageBox(L"faile to load hookcode dll", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}
	}
	DWORD64 addr = module_base + module_offset;
	bool rehook = false;
	// check if user is rehook before apply hook
	for (int i = 0; i < m_HookList.GetItemCount(); ++i) {
		HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
		if (!hr) {
			LOG_UI_E(m_services, L"weird, hr can not be NULL during iteration\n");
			continue;
		}
		if (hr->address == addr) {
			rehook = true;
			LOG_UI(m_services, L"trying hook address that has already been hooked, recover to original code first\n");
				if (hr->IsPatchEntry()) {
					auto oriVec = HexToBytes(hr->GetPatchOriHex());
					if (!oriVec.empty() && !HookCore::RemovePatch(m_pid, addr, m_services, oriVec.data(), (DWORD)oriVec.size())) {
						LOG_UI_E(m_services, L"failed to remove patch first before rehooking the same address\n");
						MessageBox(L"Failed to remove patch first before rehooking the same address", L"Hook", MB_OK | MB_ICONERROR);
						return false;
					}
				} else {
					if (!HookCore::RemoveHook(m_pid, addr, m_services, hr->id, hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)) {
						LOG_UI_E(m_services, L"failed to remove hook first before rehooking the same address\n");
						MessageBox(L"Failed to remove hook first before rehooking the same address", L"Hook", MB_OK | MB_ICONERROR);
						return false;
					}
				}
			// remove succeed, mark this hookid available
			// its previous value should be 1
			if (!hr->IsPatchEntry() && !_bittestandreset((LONG*)m_exp_num_tracker_bitfield, hr->id)) {
				MessageBox(L"hookid should be set before reset", L"Hook", MB_OK | MB_ICONERROR);
				return false;
			}
			// if we remove succeed, we delete corresponded registry entry, so we can always call add entry without checking rehook
			{// remove from registry
				FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
				if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
				DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
				(void)m_services->RemoveProcHookEntry(m_pid, hi, lo, hr->id);
			}
		}
	}

	// Proceed with the existing hook attempt (ApplyHook) after requesting trampoline load
	DWORD ori_asm_code_len = 0;
	PVOID trampoline_pit = 0;
	PVOID ori_asm_code_addr = 0;
	// this is where HookId generated, we use bittest to find a valiable id
	int assignedHookId = 0;
	for (size_t i = 0; i < TRAMPOLINE_EXP_NUM_MAX; i++) {
		if (!_bittest((LONG*)m_exp_num_tracker_bitfield, i)) {
			assignedHookId = i;
			break;
		}
	}
	
	bool success = HookCore::ApplyHook(m_pid, module_base+module_offset, m_services, hook_code_dll_base + hook_code_offset, assignedHookId, HOOK_MODE_DLL, &ori_asm_code_len,
		&trampoline_pit, &ori_asm_code_addr);
	if (success) {
		// once hook succeed we need to mark hookid unvaliable
		// mark current hookid unvaliable, and we need make sure it's previously available
		if (_bittestandset((LONG*)m_exp_num_tracker_bitfield, assignedHookId)) {
			MessageBox(L"hook id reuse deteced, abort!", L"Hook", MB_OK | MB_ICONERROR);
			return 0;
		}
		if (m_services) 
			LOG_UI(m_services, L"HookCore::ApplyHook succeeded at 0x%llX\n", addr);

		//MessageBox(L"Hook succeed", L"Hook", MB_OK | MB_ICONINFORMATION);
		// Add entry to hook list UI: resolve owning module and show module+offset as hook id
		std::wstring moduleName = L"(unknown)";
		ULONGLONG moduleBase = 0;
		std::vector<HookCore::ModuleInfo> mods; HookCore::EnumerateModules(m_pid, mods);
		for (auto &m : mods) {
			if (addr >= m.base && addr < m.base + m.size) { moduleName = m.name; moduleBase = m.base; break; }
		}
		// Add numeric hook entry (auto-incrementing ID), only new hook addr will be added
		 // always add entry, because we remove entry when rehooking is detected
			HookRow r; r.id = assignedHookId; r.address = addr; r.module = moduleName;
			r.ori_asm_code_len = ori_asm_code_len; r.trampoline_pit = (unsigned long long)trampoline_pit;
			r.ori_asm_code_addr = (DWORD64)ori_asm_code_addr;

			auto GetFilename = [](const std::wstring& path) -> std::wstring {
				size_t pos = path.find_last_of(L"\\/");
				return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
			};
			r.expFunc = GetFilename(hook_code_path )+L"!"+export_func_name;
			
			AddHookEntry(r);
		 
		return true;
	}
	else {
		if (m_services) LOG_UI_E(m_services, L"HookCore::ApplyHook failed at 0x%llX\n", addr);
		MessageBox(L"Hook failed", L"Hook", MB_OK | MB_ICONERROR);
	}
	return false;
}

bool HookProcDlg::HookCommonCodeLua(DWORD64 module_base, DWORD module_offset, std::wstring script_path, std::wstring handler_name) {
	bool is64 = false;
	m_services->IsProcess64(m_pid, is64);

	WCHAR luaEngineName[MAX_PATH] = { 0 };
	wcscpy_s(luaEngineName, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32);
	std::wstring luaEngineFullPath = m_services->GetCurrentDirFilePath(luaEngineName);
	// Lua mode: hook using LuaEngine.dll dispatch function
	// 1. Get LuaEngine.dll base in target process
	DWORD64 luaEngineBase = 0;
	if (m_services->GetModuleBase(m_pid, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, &luaEngineBase) && luaEngineBase != 0) {
		LOG_UI(m_services, L"HookCommonCodeLua: LuaEngine.dll already loaded at 0x%llX (pid %u)\n", luaEngineBase, m_pid);
	}
	else {
		LOG_UI(m_services, L"HookCommonCodeLua: LuaEngine.dll not loaded, requesting injection (pid %u)\n", m_pid);
		
		bool injected = m_services->InjectTrampoline(m_pid, luaEngineFullPath.c_str());
		LOG_UI(m_services, L"HookCommonCodeLua: %s inject result: %s\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, injected ? L"success" : L"failure");
		if (injected) {
			const int maxIter = 50;
			bool loaded = false;
			for (int iter = 0; iter < maxIter && !loaded; ++iter) {
				m_services->GetModuleBase(m_pid, is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, &luaEngineBase);
				if (luaEngineBase != 0) {
					loaded = true;
					break;
				}
				Sleep(100);
			}
			if (!loaded) {
				LOG_UI(m_services, L"HookCommonCodeLua: %s NOT detected within 5s after injection (pid %u)\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, m_pid);
				return false;
			}
			LOG_UI(m_services, L"HookCommonCodeLua: %s detected at 0x%llX after injection (pid %u)\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, luaEngineBase, m_pid);
		}
		else {
			LOG_UI_E(m_services, L"HookCommonCodeLua: failed to inject %s (pid %u), aborting\n", is64 ? LUA_ENGINE_DLL_X64 : LUA_ENGINE_DLL_Win32, m_pid);
			return false;
		}
	}

	// 2. Get dispatch export offset
	const char* dispatchName = is64 ? LUA_ENGINE_EXPORT_X64 : LUA_ENGINE_EXPORT_Win32;
	DWORD dispatchOffset = 0;
	if (!m_services->CheckExportFromFile(luaEngineFullPath.c_str(), dispatchName, &dispatchOffset)) {
		LOG_UI_E(m_services, L"failed to get LuaEngine dispatch export: %S\n", dispatchName);
		MessageBox(L"Failed to find LuaEngine dispatch export", L"Hook", MB_OK | MB_ICONERROR);
		return false;
	}
	DWORD64 hook_code_addr = luaEngineBase + dispatchOffset;

	// 3. Check for rehook
	DWORD64 addr = module_base + module_offset;
	for (int i = 0; i < m_HookList.GetItemCount(); ++i) {
		HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
		if (!hr) continue;
		if (hr->address == addr) {
				LOG_UI(m_services, L"rehook detected at 0x%llX\n", addr);
				if (hr->IsPatchEntry()) {
					auto oriVec = HexToBytes(hr->GetPatchOriHex());
					if (!oriVec.empty() && !HookCore::RemovePatch(m_pid, addr, m_services, oriVec.data(), (DWORD)oriVec.size())) {
						MessageBox(L"Failed to remove patch before rehooking", L"Hook", MB_OK | MB_ICONERROR);
						return false;
					}
				} else {
					if (!HookCore::RemoveHook(m_pid, addr, m_services, hr->id, hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)) {
						MessageBox(L"Failed to remove hook before rehooking", L"Hook", MB_OK | MB_ICONERROR);
						return false;
					}
				}
			if (!hr->IsPatchEntry()) _bittestandreset((LONG*)m_exp_num_tracker_bitfield, hr->id);
			FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
			if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
			DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
			(void)m_services->RemoveProcHookEntry(m_pid, hi, lo, hr->id);
		}
	}

	// 4. Allocate hook ID
	DWORD ori_asm_code_len = 0;
	PVOID trampoline_pit = 0;
	PVOID ori_asm_code_addr = 0;
	int assignedHookId = 0;
	for (size_t i = 0; i < TRAMPOLINE_EXP_NUM_MAX; i++) {
		if (!_bittest((LONG*)m_exp_num_tracker_bitfield, i)) {
			assignedHookId = i;
			break;
		}
	}

	// 5. Signal LuaEngine to load the script
	DWORD ipcSlotOffset = 0;
	if (m_services->CheckExportFromFile(luaEngineFullPath.c_str(), LUA_ENGINE_PLACEHOLDER_EXP_FUNC, &ipcSlotOffset)) {
		PVOID ipcSlotAddr = (PVOID)(luaEngineBase + ipcSlotOffset);
#ifdef _DEBUG
		// In debug builds the export function starts with a jmp instruction;
		// resolve the real address by reading the jmp operand.
		HANDLE hProcDbg = NULL;
		if (m_services->GetHighAccessProcHandle(m_pid, &hProcDbg) && hProcDbg) {
			DWORD oldProtect1 = 0;
			VirtualProtectEx(hProcDbg, (LPVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect1);
			DWORD e9Oprand = 0;
			ReadProcessMemory(hProcDbg, (LPVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_OPCODE_SIZE), &e9Oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, NULL);
			ipcSlotAddr = (PVOID)((DWORD64)ipcSlotAddr + E9_JMP_INSTRUCTION_SIZE + e9Oprand);
			VirtualProtectEx(hProcDbg, (LPVOID)((DWORD64)luaEngineBase + ipcSlotOffset + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, oldProtect1, &oldProtect1);
			CloseHandle(hProcDbg);
		}
#endif
		WCHAR ipcData[MAX_PATH + 256] = { 0 };
		int pos = 0;
		for (size_t i = 0; i < script_path.size() && pos < MAX_PATH - 1; i++)
			ipcData[pos++] = script_path[i];
		ipcData[pos++] = L'|';
		for (size_t i = 0; i < handler_name.size() && pos < MAX_PATH + 255; i++)
			ipcData[pos++] = handler_name[i];
		ipcData[pos] = L'\0';

		HANDLE hProc = NULL;
		if (!m_services->GetHighAccessProcHandle(m_pid, &hProc) || !hProc) {
			LOG_UI_E(m_services, L"HookCommonCodeLua: failed to get high access process handle, pid=%u\n", m_pid);
		}
		else {
			DWORD oldProtect = 0;
			if (VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), PAGE_EXECUTE_READWRITE, &oldProtect)) {
				SIZE_T written = 0;
				m_services->WriteProcessMemoryWrap(hProc, (LPVOID)ipcSlotAddr, ipcData, (pos + 1) * sizeof(WCHAR), &written);
				VirtualProtectEx(hProc, (LPVOID)ipcSlotAddr, (pos + 1) * sizeof(WCHAR), oldProtect, &oldProtect);
			}
			CloseHandle(hProc);
		}
		WCHAR eventName[150];
		swprintf_s(eventName, LUA_ENGINE_UM_SIGNAL_EVENT, m_pid, assignedHookId);
		HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
		if (hEvent) {
			SetEvent(hEvent);
			CloseHandle(hEvent);
		}
	}

	// 6. Apply hook
	bool success = HookCore::ApplyHook(m_pid, module_base + module_offset, m_services, hook_code_addr, assignedHookId, HOOK_MODE_LUA, &ori_asm_code_len,
		&trampoline_pit, &ori_asm_code_addr);
	if (success) {
		if (_bittestandset((LONG*)m_exp_num_tracker_bitfield, assignedHookId)) {
			MessageBox(L"hook id reuse detected, abort!", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}
		LOG_UI(m_services, L"LuaHook ApplyHook succeeded at 0x%llX\n", addr);
		HookRow r; r.id = assignedHookId; r.address = addr; r.module = L"(unknown)";
		ULONGLONG moduleBase = 0;
		std::vector<HookCore::ModuleInfo> mods; HookCore::EnumerateModules(m_pid, mods);
		for (auto &m : mods) {
			if (addr >= m.base && addr < m.base + m.size) { r.module = m.name; moduleBase = m.base; break; }
		}
		r.ori_asm_code_len = ori_asm_code_len; r.trampoline_pit = (unsigned long long)trampoline_pit;
		r.ori_asm_code_addr = (DWORD64)ori_asm_code_addr;
		r.expFunc = L"Lua:" + script_path + L"!" + handler_name;
		AddHookEntry(r);
		return true;
	}
	else {
		LOG_UI_E(m_services, L"LuaHook ApplyHook failed at 0x%llX\n", addr);
		MessageBox(L"Hook failed", L"Hook", MB_OK | MB_ICONERROR);
	}
	return false;
}

void HookProcDlg::OnBnClickedApplyHook() {
	// If the target process no longer exists, close this modeless dialog to avoid acting on a dead PID.
	bool procFound = false;
	bool rehook = false;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe = { sizeof(pe) };
		if (Process32First(hSnap, &pe)) {
			do {
				if ((DWORD)pe.th32ProcessID == m_pid) { procFound = true; break; }
			} while (Process32Next(hSnap, &pe));
		}
		CloseHandle(hSnap);
	}
	if (!procFound) {
		MessageBox(L"Target process does not appear to be running. Closing dialog.", L"Hook", MB_ICONWARNING);
		// Destroy the dialog window; parent will be notified in OnDestroy and will delete this object.
		DestroyWindow();
		return;
	}


	CString directStr; GetDlgItemText(IDC_HOOKUI_EDIT_DIRECT, directStr);
	CString offsetStr; GetDlgItemText(IDC_HOOKUI_EDIT_OFFSET, offsetStr);
	CString exportFuncStr; GetDlgItemText(IDC_HOOKUI_EDIT_EXPORT, exportFuncStr);
	std::wstring direct = directStr.GetString();
	std::wstring offset = offsetStr.GetString();
	std::wstring exportFunc = exportFuncStr.GetString();
	if (!m_services) {
		MessageBox(L"Fatal error! m_services not initialized!", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}
	// Trim simple whitespace
	auto trimWS = [](std::wstring& s) { while (!s.empty() && iswspace(s.back())) s.pop_back(); size_t i = 0; while (i < s.size() && iswspace(s[i])) i++; if (i) s = s.substr(i); };
	trimWS(direct); trimWS(offset); trimWS(exportFunc);

	ULONGLONG addr = 0ULL; bool ok = false;
	if (!direct.empty()) {
		addr = ParseAddressText(direct, ok);
		if (!ok) { MessageBox(L"Invalid direct address. Use hex (e.g. 0x7FF612341000).", L"Hook", MB_ICONERROR); return; }
	}
	else {
		// Module base + optional offset mode
		std::wstring modName; ULONGLONG base = 0ULL; if (!GetSelectedModule(modName, base)) {
			MessageBox(L"Select a module (Base column) or provide a direct address.", L"Hook", MB_ICONWARNING); return;
		}
		
		// Verify the module is actually loaded by querying the process
		DWORD64 actualBase = 0;
		if (!m_services->GetModuleBase(m_pid, modName.c_str(), &actualBase) || actualBase == 0) {
			MessageBox(L"target module is not loaded yet.", L"Hook", MB_ICONERROR); return;
		}
		
		// Module is loaded, use the actual base address (not stale UI data)
		base = actualBase;
		ULONGLONG offVal = 0ULL; bool offOk = true; // empty offset means 0
		if (!offset.empty()) { offVal = ParseAddressText(offset, offOk); }
		if (!offOk) { MessageBox(L"Invalid offset. Use hex like 0x200 or leave empty.", L"Hook", MB_ICONERROR); return; }
		addr = base + offVal; ok = true;
		if (m_services) LOG_UI(m_services, L"Using module '%s' base 0x%llX + offset 0x%llX => 0x%llX", modName.c_str(), base, offVal, addr);
	}

	if (m_services) LOG_UI(m_services, L"Attempting hook at 0x%llX for pid %u (%s)\n", addr, m_pid, m_name.c_str());



	// Ask user to select a DLL to be loaded inside the target process (file explorer)
	CString filter = L"DLL Files (*.dll)|*.dll|All Files (*.*)|*.*||";
	CFileDialog fd(TRUE, L"dll", NULL, OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST, filter, this);
	if (fd.DoModal() != IDOK) {
		// User cancelled selection; abort apply
		if (m_services) LOG_UI(m_services, L"ApplyHook cancelled by user (no DLL selected)\n");
		return;
	}
	CString selectedPath = fd.GetPathName();
	CString hook_code_dll_name = selectedPath.Mid(selectedPath.ReverseFind('\\') + 1);
	// we can not use LoadLibrary to check if required export function exist
	// because we can only load x64 hookcode.dll, if user is trying to hook SysWOW64 process
	// I can do shit about it
	// we need to mannuly check it from file
	bool is64 = false;
	m_services->IsProcess64(m_pid, is64);
	// we should update the code to let user specify export function name
	// so they won't need write a lot dll with same export function but different logic code
	// preferred export function name from user input (falls back to defaults if empty)
	std::wstring preferredExport = exportFunc;
	const wchar_t* exportToCheck = nullptr;
	std::wstring exportWide;
	if (!preferredExport.empty()) {
		exportToCheck = preferredExport.c_str();
	}
	else {
		exportToCheck = is64 ? L"" HOOK_CODE_EXPORT_X64 L"" : L"" HOOK_CODE_EXPORT_X86 L"";
	}

	// we also need to check hookcode.dll meet the arch of target process
	bool is_pe_64;
	if (!m_services->CheckPeArch(selectedPath.GetString(), is_pe_64)) {
		LOG_UI_E(m_services, L"failed to call CheckPeArch, PE_Path=%s, CPU=%s\n", selectedPath.GetString(), is64 ? L"x64" : L"x86");
		MessageBox(L"failed to call CheckPeArch", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}
	if (is_pe_64 != is64) {
		LOG_UI(m_services, L"target process Arch=%s mismatch HookCode.dll Arch=%s\n", is64 ? L"x64" : L"x86", is_pe_64 ? L"x64" : L"x86");
		return;
	}

	ULONGLONG moduleBase = 0;
	std::vector<HookCore::ModuleInfo> mods; HookCore::EnumerateModules(m_pid, mods);
	for (auto &m : mods) {
		if (addr >= m.base && addr < m.base + m.size) { moduleBase = m.base; break; }
	}

	// If moduleBase is 0, the address is not within any loaded module.
	// This could mean the user entered an invalid address, or the module hasn't loaded yet.
	// For delayed hook support, we need to determine which module this address should belong to.
	if (moduleBase == 0) {
		// Try to extract module name from the hook code path
		std::wstring hookDllPath = selectedPath.GetString();
		size_t lastSlash = hookDllPath.find_last_of(L"\\/");
		std::wstring hookDllName = (lastSlash != std::wstring::npos) ? hookDllPath.substr(lastSlash + 1) : hookDllPath;
		
		// Convert to lowercase for comparison
		auto toLower = [](std::wstring& s) {
			for (auto& c : s) c = towlower(c);
		};
		std::wstring dllNameLower = hookDllName;
		toLower(dllNameLower);
		
		// Check if this looks like a module+offset pattern
		// For now, we'll just warn the user that the address is invalid
		LOG_UI(m_services, L"Manual Hook: address 0x%llX not within any loaded module for pid %u\n", addr, m_pid);
		MessageBox(L"The specified address is not within any loaded module.\nPlease verify the address is correct, or the target module has loaded.", 
			L"Hook", MB_OK | MB_ICONWARNING);
		return;
	}

	// Copy the selected DLL to a local temp folder beside this module so the
	// master DLL can reliably open it. Use a timestamped filename to avoid
	// collisions. If the copy fails, fall back to the original selected path.
	std::wstring pathToInject = selectedPath.GetString();
	HookCommonCode(moduleBase, (DWORD)(addr - moduleBase), pathToInject, exportToCheck);
}

// (removed duplicate OnSize implementation)
