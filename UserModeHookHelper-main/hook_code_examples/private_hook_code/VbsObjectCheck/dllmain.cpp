// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <sstream>  
#include <stdio.h>  
#include <vector>  
#include <iomanip>  // <-- for setprecision

#include <evntprov.h>
#include <chrono>
#include <string>
#include "../../../hook_component/HookCodeLib/HookCodeLib.h"
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
#define DebugBreak() __debugbreak();

uint32_t crc32_table[256];
uint32_t CRC32(const void* data, size_t size);
void InitCRC32();
using namespace std::chrono;
static const std::vector<uint32_t> sBlackList = {
	0xC5ACF960,
	0xF8754B66,
	0xFEAB3DB5,
	0xAD8E8027,
	0x89E14C3E,
	0x95A147AA,
	0xA106A319,
	0x59252671,
	0x4B510922,
	0x0990B883,   // 补全前导零
	0x11EB8C32,
	0x31A2C1AB,
	0x4FB0E453,
	0x571B1ED8,
	0x581DF160
};
typedef struct _RollingBuffer {
	DWORD capacity;				 // +0x00: 缓冲区总容量
	DWORD field_0x4_unk;		// 未知字段
	DWORD64 basePtr;            // +0x08: 数据数组基指针
	DWORD size;					// 缓冲区当前缓存size
	DWORD offset;				// +0x14: 当前读取偏移量
}RollingBuffer;

void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[VbsChk]     %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
}
void DLog(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HookCode]   %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	OutputDebugString(Prefixed);
}
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
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                     \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);          \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);          \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);         \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);         \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);         \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);         \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);         \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);         \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);         \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);         \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
                                                                             \
    /* original_esp can be used to access original parameters */             \
    ULONG original_esp = (esp) + 0x20;                                       \
                                                                             \
    /* original register values saved on stack */                             \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                   \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                   \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                   \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                   \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                  \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                  \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);
extern "C" __declspec(dllexport) VOID HookCodeWin32(ULONG esp) {
	PROLOGWin32(esp);

	// WRITE YOUR CODE HERE
	Log(L"CreateFileW opening: %s\n", *(DWORD*)((ULONG_PTR)original_esp + 0x4));
	// HOOK CODE END


	return;
}

// vbscript.dll 
// sha256 4eef02d54ee182aeef9376dac86537bf4e28cf844c7c9de27d6cc8a7ab931b71
// 黑名单crc32
/*
0xC5ACF960
0xF8754B66
0xFEAB3DB5
0xAD8E8027
0x89E14C3E
0x95A147AA
0xA106A319
0x59252671
0x4B510922
0x0990B883
0x11EB8C32
0x31A2C1AB
0x4FB0E453
0x571B1ED8
0x581DF160
*/
extern "C" __declspec(dllexport) VOID VbObjChk(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PROLOGX64(rsp);


	// WRITE YOUR CODE HERE
	/*
	 * hook at 0xE480 of vbscript.dll, eax is the calculated value
	 * get rolling buffer from poi(rbp+0x8)
	 * get buffer address from poi(poi(rbp+0x8)+0x8)
	 * get buffer size from poi(poi(rbp+0x8)+0x10)
	 * then dump to disk with value and epoch as name
	 */
	RollingBuffer* rb = (RollingBuffer*)*(DWORD64*)((DWORD64)rbp + 0x8);
	// 第一个宽字节好像没有意义，我们直接跳过
	wchar_t* ws = (wchar_t*)(rb->basePtr + 2);
	size_t bufferSize = (size_t)rb->size - 2;

	auto epoch = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
	std::wstring filePath =
		L"C:\\users\\public\\vb_dump\\"
		+ std::to_wstring(epoch) + L"_"
		+ std::to_wstring((DWORD)rdx) + L".dmp";

	HANDLE h = CreateFile(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	WriteFile(h, ws, bufferSize, NULL, nullptr);
	CloseHandle(h);
	if (std::find(sBlackList.begin(), sBlackList.end(),(DWORD) rax) != sBlackList.end()) {
		Log(L"SelfChk Amsi Trigger: 0x%X -> %s\n", (DWORD)rax, ws);
	}
	else {
		Log(L"0x%X -> %s\n", (DWORD)rax, ws);
	}
	
	// HOOK CODE END

	return;
} 
 
// check dispatch ID L"_%08x", a3);
extern "C" __declspec(dllexport) VOID CheckDispId(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PROLOGX64(rsp);


	// WRITE YOUR CODE HERE
	/*
	 * hook at 0xDFF0, r8d is dispatch id
	 */
	DWORD dispatchID = (DWORD)(DWORD64)r8;

	// we need to calculate crc32 of it
	wchar_t wDispatchId[0x10] = { 0 };
	wsprintf(wDispatchId, L"_%08x", dispatchID);
	DWORD crcRes = 0;

	crcRes = CRC32(wDispatchId, lstrlenW(wDispatchId)*sizeof(wchar_t));

	Log(L"dispatch id=%s, crc32=0x%08x\n", wDispatchId, crcRes);
	// HOOK CODE END

	return;
}



extern "C" __declspec(dllexport) VOID DelayHookTest(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PROLOGX64(rsp);


	// WRITE YOUR CODE HERE
	Log(L"0x%p\n", rcx);
	// HOOK CODE END

	return;
}

// this hook will be triggered if AMSI scan request is going to be sent
extern "C" __declspec(dllexport) VOID VbAmsiTrigger(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PROLOGX64(rsp);


	// WRITE YOUR CODE HERE
	/*
	 * hook at 0xE4EF of vbscript.dll, eax is the calculated value
	 * get rolling buffer from poi(rbp+0x8)
	 * get buffer address from poi(poi(rbp+0x8)+0x8)
	 * get buffer size from poi(poi(rbp+0x8)+0x10)
	 * then dump to disk with value and epoch as name
	 */
	RollingBuffer* rb = (RollingBuffer*)*(DWORD64*)((DWORD64)rbp + 0x8);
	// 第一个宽字节好像没有意义，我们直接跳过
	wchar_t* ws = (wchar_t*)(rb->basePtr + 2);
	size_t bufferSize = (size_t)rb->size - 2;

	
	Log(L"buffer size=%u\n", bufferSize);
	if (bufferSize > 8000)
		DebugBreak();
	// Log(L"AmiTrigger: 0x%X -> %s\n", (DWORD)rax, ws);
	// HOOK CODE END

	return;
}

VOID EntryCode() {
	InitCRC32();
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);
	// set HookCodeLib interface
	HookCode::SetHookServices(&g_HookServices);
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
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



// 初始化 CRC32 表
void InitCRC32()
{
	uint32_t poly = 0xEDB88320;
	for (uint32_t i = 0; i < 256; i++)
	{
		uint32_t crc = i;
		for (int j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

uint32_t CRC32(const void* data, size_t size)
{
	uint32_t crc = 0xFFFFFFFF;
	const unsigned char* p = (const unsigned char*)data;

	for (size_t i = 0; i < size; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc ^ p[i]) & 0xFF];
	}

	return ~crc;
}
