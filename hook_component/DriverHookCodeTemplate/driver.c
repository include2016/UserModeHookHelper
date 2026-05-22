
#include "../../DriverHookCodeLib/DriverHCLib.h"
#include <evntrace.h>
#include <ntstrsafe.h>

REGHANDLE g_ProviderHandle = 0;

#define LOG_EVENT_ID 1

EVENT_DESCRIPTOR g_LogEventDescriptor = {
	LOG_EVENT_ID,      // Id
	0,                 // Version
	0,                 // Channel
	5 ,  // Level
	0,                 // Opcode
	0,                 // Task
	0                  // Keyword
};
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };

void Log(_In_ PCWSTR Format, ...);
typedef struct {
	IHookServices iface;  // must be first
} HookServicesImpl;
void MyDKLog(IHookServices *self, const wchar_t* fmt, ...) {
	(self);
	va_list args;
	va_start(args, fmt);
	Log(fmt, args);
	va_end(args);
}
const IHookServicesVtbl g_HookServicesVtbl = {
	MyDKLog
};
HookServicesImpl g_services = {
	.iface = { &g_HookServicesVtbl }
};
void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	RtlStringCchVPrintfW(
		Buffer,
		RTL_NUMBER_OF(Buffer),
		Format,
		args
	);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	RtlStringCchPrintfW(
		Prefixed,
		RTL_NUMBER_OF(Prefixed),
		L"[KrnlHC]     %s",
		Buffer
	);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	EVENT_DATA_DESCRIPTOR data[1];
	EventDataDescCreate(
		&data[0],
		Prefixed,
		1100
	);
	EtwWrite(
		g_ProviderHandle,
		&g_LogEventDescriptor,
		NULL,
		1,
		data
	);
}

void DLog(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	RtlStringCchVPrintfW(
		Buffer,
		RTL_NUMBER_OF(Buffer),
		Format,
		args
	);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	RtlStringCchPrintfW(
		Prefixed,
		RTL_NUMBER_OF(Prefixed),
		L"[KrnlHC]     %s",
		Buffer
	);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	DbgPrint("%s", Prefixed);
}

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
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);		 \
	(r15);(r14);(r13);(r12);(r11);(r10);(r9);(r8);(rdx);(rcx);(rbp);(rdi);(rsi);(rbx);(rax);(original_rsp);
VOID __declspec(dllexport) HookMiCreateImageOrDataSection(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {

	PROLOGX64(rsp);
	if (!rcx)
		return;

	if (!*(DWORD64*)((PUCHAR)rcx + 0x28))
		return;

	// current process should be windbg.exe
	UNICODE_STRING a;
	RtlInitUnicodeString(&a, L"windbg.exe");
	PUNICODE_STRING cur_proc_image_name = NULL;
	NTSTATUS status = DRVHCLIB_NT_LocateImageByPID(PsGetCurrentProcessId(), &cur_proc_image_name);
	if (!NT_SUCCESS(status) || (!cur_proc_image_name)) {
		if ((DWORD)(ULONG_PTR)PsGetCurrentProcessId() != 4)
			Log(L"failed to call DRVHCLIB_NT_LocateImageByPID, target Pid=%u\n", PsGetCurrentProcessId());
		return;
	}
	if (!DRVHCLIB_STR_RtlSuffixUnicodeString(&a, cur_proc_image_name, TRUE)) {
		ExFreePool(cur_proc_image_name);
		return;
	}
	ExFreePool(cur_proc_image_name);
	HANDLE handle =(HANDLE)(ULONG_PTR) *(DWORD64*)((PUCHAR)rcx + 0x28);
	PUNICODE_STRING image_path;
	 status = DRVHCLIB_NT_GetFilePathByHandle(handle, &image_path);
	if (0 != status) {
		DLog(L"failed to call DRVHCLIB_NT_GetFilePathByHandle, Status=0x%x\n", status);
		return;
	}
	// check if mapping cfgtest.exe
	UNICODE_STRING b;
	RtlInitUnicodeString(&b, L"cfgtest.exe");
	if (!DRVHCLIB_STR_RtlSuffixUnicodeString(&b, image_path, TRUE)) {
		ExFreePool(image_path);
		return;
	}
	ExFreePool(image_path);
	DbgBreakPoint();
	return;
}

VOID __declspec(dllexport) HookLoadImageNotify(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {

	PROLOGX64(rsp);
	if (!rcx)
		return;

	static volatile LONG g_Enabled = 0;

	UNICODE_STRING a;
	RtlInitUnicodeString(&a, L"cfgtest.exe");
	PUNICODE_STRING image_name = NULL;
	NTSTATUS status = DRVHCLIB_NT_LocateImageByPID(PsGetCurrentProcessId(), &image_name);
	if (!NT_SUCCESS(status) || (!image_name)) {
		if((DWORD)(ULONG_PTR)PsGetCurrentProcessId()!=4)
		Log(L"failed to call DRVHCLIB_NT_LocateImageByPID, target Pid=%u\n", PsGetCurrentProcessId());
		return;
	}
	if (DRVHCLIB_STR_RtlSuffixUnicodeString(&a, image_name, TRUE)) {
		if (g_Enabled)
			DbgBreakPoint();
		// then check if we're loading ntdll.dll
		UNICODE_STRING b;
		RtlInitUnicodeString(&b, L"ntdll.dll");
		if (DRVHCLIB_STR_RtlSuffixUnicodeString(&b, rcx, TRUE)) {
			DLog(L"target process is loading ntdll.dll");
			// turn on switch
			InterlockedCompareExchange(&g_Enabled, 1, 0);
			DbgBreakPoint();
		}
	}
	if (image_name)
		ExFreePool(image_name);

	return;
}





NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS status = EtwRegister(
		&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle
	);
	if (0 != status) {
		DbgPrint("failed to register ETW, abort\n");
		return STATUS_UNSUCCESSFUL;
	}
	SetHookServices(&g_services.iface);
	return STATUS_SUCCESS;
}
