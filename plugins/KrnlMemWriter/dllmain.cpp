#include <Windows.h>
#include <cwctype>
#include <cwchar>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include "resource.h"
#include "../../Shared/HookServices.h"

#pragma comment(lib, "comctl32.lib")

static HINSTANCE g_hInstance = nullptr;
static HWND g_hDialog = nullptr;
static IHookServices* g_services = nullptr;

void KMWLog(_In_ PCWSTR Format, ...) {
	if (!g_services) return;
	wchar_t buffer[1024];
	va_list ap;
	va_start(ap, Format);
	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, Format, ap);
	va_end(ap);
	g_services->Log(L"[KMW]        %s", buffer);
}

ULONGLONG ParseHexAddress(const std::wstring& input, bool& ok) {
	ok = false;
	if (input.empty()) return 0ULL;
	std::wstring t(input);
	for (auto& c : t) c = towlower(c);
	if (t.rfind(L"0x", 0) == 0) t = t.substr(2);
	for (wchar_t c : t) {
		if (!(iswdigit(c) || (c >= L'a' && c <= L'f'))) return 0ULL;
	}
	wchar_t* end = nullptr;
	ULONGLONG v = wcstoull(t.c_str(), &end, 16);
	if (end && *end == 0) { ok = true; return v; }
	return 0ULL;
}

bool ParseHexBytes(const std::wstring& input, std::vector<UCHAR>& outBytes) {
	outBytes.clear();
	std::wstring t;
	t.reserve(input.size());
	for (wchar_t c : input) {
		if (iswspace(c)) continue;
		if (!(iswdigit(c) || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) return false;
		t += towlower(c);
	}
	if (t.size() % 2 != 0) return false;
	for (size_t i = 0; i < t.size(); i += 2) {
		wchar_t pair[3] = { t[i], t[i + 1], 0 };
		wchar_t* end = nullptr;
		ULONG val = wcstoul(pair, &end, 16);
		if (!end || *end != 0) return false;
		outBytes.push_back(static_cast<UCHAR>(val & 0xFF));
	}
	return true;
}

void AppendResultLine(HWND hResult, const wchar_t* text) {
	int len = GetWindowTextLengthW(hResult);
	SendMessageW(hResult, EM_SETSEL, len, len);
	SendMessageW(hResult, EM_REPLACESEL, FALSE, (LPARAM)text);
	SendMessageW(hResult, EM_REPLACESEL, FALSE, (LPARAM)L"\n");
}

void HandleWrite(HWND hDlg) {
	if (!g_services) {
		MessageBoxW(hDlg, L"Hook services unavailable.", L"Error", MB_ICONERROR);
		return;
	}
	wchar_t addrBuf[128] = {};
	GetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_ADDR, addrBuf, _countof(addrBuf));
	bool addrOk = false;
	ULONGLONG addr = ParseHexAddress(addrBuf, addrOk);
	if (!addrOk || addr == 0) {
		KMWLog(L"Invalid address: %s", addrBuf);
		return;
	}
	wchar_t bytesBuf[2048] = {};
	GetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_BYTES, bytesBuf, _countof(bytesBuf));
	std::vector<UCHAR> bytes;
	if (!ParseHexBytes(bytesBuf, bytes) || bytes.empty()) {
		KMWLog(L"Invalid hex bytes input");
		return;
	}
	BOOLEAN ok = g_services->WritePrimitive(reinterpret_cast<LPVOID>(addr), bytes.data(), bytes.size());
	HWND hResult = GetDlgItem(hDlg, IDC_KRNLMEM_EDIT_RESULT);
	if (ok) {
		wchar_t msg[256];
		swprintf_s(msg, L"[OK] Wrote %zu bytes to 0x%llX", bytes.size(), addr);
		AppendResultLine(hResult, msg);
		KMWLog(L"Write OK: %zu bytes to 0x%llX", bytes.size(), addr);
		MessageBoxW(hDlg, msg, L"KrnlMemWriter", MB_ICONINFORMATION);
	} else {
		wchar_t msg[256];
		swprintf_s(msg, L"[FAIL] WritePrimitive failed for 0x%llX (%zu bytes)", addr, bytes.size());
		AppendResultLine(hResult, msg);
		KMWLog(L"Write FAILED: 0x%llX (%zu bytes)", addr, bytes.size());
		MessageBoxW(hDlg, msg, L"KrnlMemWriter", MB_ICONERROR);
	}
}

void HandleRead(HWND hDlg) {
	if (!g_services) {
		MessageBoxW(hDlg, L"Hook services unavailable.", L"Error", MB_ICONERROR);
		return;
	}
	wchar_t addrBuf[128] = {};
	GetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_ADDR, addrBuf, _countof(addrBuf));
	bool addrOk = false;
	ULONGLONG addr = ParseHexAddress(addrBuf, addrOk);
	if (!addrOk || addr == 0) {
		KMWLog(L"Invalid address: %s", addrBuf);
		return;
	}
	wchar_t sizeBuf[32] = {};
	GetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_SIZE, sizeBuf, _countof(sizeBuf));
	SIZE_T readSize = 0;
	if (sizeBuf[0] == 0) {
		readSize = 16;
	} else {
		wchar_t* end = nullptr;
		readSize = wcstoul(sizeBuf, &end, 0);
		if (readSize == 0 || readSize > 4096) {
			KMWLog(L"Invalid memory size: %s (must be 1-4096)", sizeBuf);
			return;
		}
	}
	std::vector<UCHAR> buf(readSize);
	BOOLEAN ok = g_services->ReadPrimitive(reinterpret_cast<LPVOID>(addr), buf.data(), buf.size());
	HWND hResult = GetDlgItem(hDlg, IDC_KRNLMEM_EDIT_RESULT);
	if (ok) {
		std::wstring hex;
		wchar_t tmp[8];
		for (size_t i = 0; i < buf.size(); i++) {
			swprintf_s(tmp, L"%02X", buf[i]);
			hex += tmp;
			if ((i + 1) % 16 == 0 && i + 1 < buf.size()) hex += L"\n";
			else if ((i + 1) % 8 == 0) hex += L" ";
			else hex += L" ";
		}
		wchar_t header[128];
		swprintf_s(header, L"[OK] Read %zu bytes from 0x%llX:", readSize, addr);
		AppendResultLine(hResult, header);
		AppendResultLine(hResult, hex.c_str());
		KMWLog(L"Read OK: %zu bytes from 0x%llX", readSize, addr);
		MessageBoxW(hDlg, header, L"KrnlMemWriter", MB_ICONINFORMATION);
	} else {
		wchar_t msg[256];
		swprintf_s(msg, L"[FAIL] ReadPrimitive failed for 0x%llX (%zu bytes)", addr, readSize);
		AppendResultLine(hResult, msg);
		KMWLog(L"Read FAILED: 0x%llX (%zu bytes)", addr, readSize);
		MessageBoxW(hDlg, msg, L"KrnlMemWriter", MB_ICONERROR);
	}
}

void UpdateSizeFromBytes(HWND hDlg) {
	wchar_t bytesBuf[2048] = {};
	GetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_BYTES, bytesBuf, _countof(bytesBuf));
	std::vector<UCHAR> bytes;
	if (ParseHexBytes(bytesBuf, bytes) && !bytes.empty()) {
		wchar_t sizeText[32];
		swprintf_s(sizeText, L"%zu", bytes.size());
		SetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_SIZE, sizeText);
	}
}

INT_PTR CALLBACK KrnlMemDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
	switch (msg) {
	case WM_INITDIALOG:
	{
		auto* svc = reinterpret_cast<IHookServices*>(lParam);
		g_services = svc;
		SetDlgItemTextW(hDlg, IDC_KRNLMEM_EDIT_SIZE, L"16");
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_KRNLMEM_EDIT_BYTES:
			if (HIWORD(wParam) == EN_CHANGE) {
				UpdateSizeFromBytes(hDlg);
			}
			return TRUE;
		case IDC_KRNLMEM_BTN_WRITE:
			HandleWrite(hDlg);
			return TRUE;
		case IDC_KRNLMEM_BTN_READ:
			HandleRead(hDlg);
			return TRUE;
		case IDCANCEL:
			DestroyWindow(hDlg);
			return TRUE;
		default:
			break;
		}
		break;
	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;
	case WM_DESTROY:
		if (g_hDialog == hDlg) g_hDialog = nullptr;
		return TRUE;
	}
	return FALSE;
}

extern "C" __declspec(dllexport) void PluginMain(HWND parentHwnd, IHookServices* services) {
	g_services = services;
	if (g_hDialog && IsWindow(g_hDialog)) {
		ShowWindow(g_hDialog, SW_SHOWNORMAL);
		SetForegroundWindow(g_hDialog);
		return;
	}
	HWND dlg = CreateDialogParamW(g_hInstance, MAKEINTRESOURCEW(IDD_KRNLMEM_DIALOG), parentHwnd, KrnlMemDialogProc, reinterpret_cast<LPARAM>(services));
	if (!dlg) {
		MessageBoxW(parentHwnd, L"Failed to create Kernel Memory Writer dialog.", L"KrnlMemWriter", MB_ICONERROR);
		return;
	}
	g_hDialog = dlg;
	ShowWindow(dlg, SW_SHOWNORMAL);
	UpdateWindow(dlg);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		g_hInstance = hModule;
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		g_hDialog = nullptr;
		g_services = nullptr;
	}
	return TRUE;
}
