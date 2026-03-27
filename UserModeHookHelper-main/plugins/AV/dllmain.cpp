// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>  
#include <evntprov.h>
#include "../../controller/UMController/HookInterfaces.h"
#include "../libs/AVLIB/AVLib.h"

using namespace AVLIB;

static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
static void FormatObjectName(PWCHAR out, size_t outCount, PCWSTR fmt, DWORD pid)
{
	// Use swprintf_s for simplicity (UMController is user-mode)
	swprintf_s(out, outCount, fmt, (unsigned)pid);
}

void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[AV]         %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	if (g_ProviderHandle)
		EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
	else
		// fall back to debugger output
		OutputDebugStringW(Prefixed);
} 
VOID EntryCode() {
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);
}
extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(HWND hwnd, IHookServices* services) {
	if (!services) {
		MessageBoxW(NULL, L"Failed to load plugin DLL.", L"Plugin Error", MB_ICONERROR);
		return FALSE;
	}

	// set hook service so we can use UMHH platform log feature
	SetHookServices(services);

	// connect to scanner daemen socket
	AV av("localhost", 3310);
}
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		EntryCode();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

