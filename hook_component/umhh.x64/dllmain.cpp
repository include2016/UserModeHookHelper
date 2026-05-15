
#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1


//
// Include NTDLL-related headers.
//
#define NTDLL_NO_INLINE_INIT_STRING
#include <ntdll.h>
#include "../controller/UMController/IPC.h"
#include "../controller/UMController/ETW.h"
#include "../../Shared/SharedMacroDef.h"
#include "detours/detours.h"
#include "capstone/capstone.h"

// Minimum bytes needed for inline hook: movabs rcx, addr (10) + jmp rcx (2) = 12
#define MIN_HOOK_BYTES 12
static bool WriteJump(PVOID addr, PVOID target);
// This is necessary for x86 builds because of SEH,
// which is used by Detours.  Look at loadcfg.c file
// in Visual Studio's CRT source codes for the original
// implementation.
//
bool ApplyLocalHook(
	_In_  PVOID   hookAddr,
	_In_  PVOID   hookHandler,
	_Out_ PVOID*  outTrampoline,
	_Out_ DWORD*  outOriLen
);
void __fastcall LdrLoadDll_HookHandler(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp);
VOID EtwLog(_In_ PCWSTR Format, ...);
static BOOL GetNtdllFnvHash(WCHAR* hashStr, DWORD hashStrSize);
static BOOL GetHookOffsetFromConfig(const WCHAR* fnvHash, DWORD* outOffset);
typedef int(__cdecl * _snwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	...
	);
static _snwprintf_fn_t _snwprintf_ = NULL;
#if defined(_M_IX86) || defined(_X86_)

EXTERN_C PVOID __safe_se_handler_table[]; /* base of safe handler entry table */
EXTERN_C BYTE  __safe_se_handler_count;   /* absolute symbol whose address is
											 the count of table entries */
EXTERN_C
CONST
DECLSPEC_SELECTANY
IMAGE_LOAD_CONFIG_DIRECTORY
_load_config_used = {
	sizeof(_load_config_used),
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	(SIZE_T)__safe_se_handler_table,
	(SIZE_T)&__safe_se_handler_count,
};

#endif
#define PAGE_SIZE 0x1000 

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define WFILE WIDEN(__FILE__)


HANDLE g_EventHandle;
typedef NTSTATUS(NTAPI *PFN_NtDelayExecution)(
	BOOLEAN Alertable,        // TRUE = APCs can wake the thread
	PLARGE_INTEGER Interval   // Relative (negative) or absolute (positive) time in 100-ns units
	);
typedef ULONG_PTR(NTAPI *PFN_EntryFuncProto)(
	ULONG_PTR a1,
	ULONG_PTR a2,
	ULONG_PTR a3,
	ULONG_PTR a4,
	ULONG_PTR a5,
	ULONG_PTR a6,
	ULONG_PTR a7,
	ULONG_PTR a8
	);
PFN_EntryFuncProto original_entry = nullptr;
DWORD64 trampoline_back = NULL;
ULONG_PTR PutIntoSleep(ULONG_PTR a1,
	ULONG_PTR a2,
	ULONG_PTR a3,
	ULONG_PTR a4,
	ULONG_PTR a5,
	ULONG_PTR a6,
	ULONG_PTR a7,
	ULONG_PTR a8
) {
	// put into sleep

	// waiting for event, we can wake it up from UMController
	{
		WCHAR event_name[100];
		_snwprintf_(event_name, RTL_NUMBER_OF(event_name) - 1, HOOK_DLL_NT_WAKEUP_EVENT L"%d", NtCurrentProcessId());

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, event_name);


		HANDLE EvtHandle = NULL;
		SECURITY_DESCRIPTOR sd = { 0 };

		// Use revision 1
		sd.Revision = 1;

		// Set control flags (SE_DACL_PRESENT = 0x04)
		sd.Control = SE_DACL_PRESENT;

		// Set a NULL DACL (everyone full access)
		sd.Dacl = NULL;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(
			&oa,
			&name,
			OBJ_CASE_INSENSITIVE,
			NULL,
			&sd
		);
		NTSTATUS status = NtCreateEvent(
			&EvtHandle,
			EVENT_ALL_ACCESS,
			&oa,
			NotificationEvent,   // or SynchronizationEvent
			FALSE                // Initial state
		);

		if (status != 0) {
			EtwLog(L"failed to call NtCreateEvent to create wakeup Event=%s, status=0x%x\n", &event_name, status);
		}
		NtWaitForSingleObject(EvtHandle, FALSE, NULL);
		EtwLog(L"early break process signaled to wake up\n");
		// this is an one time event, no need to reset
	}

	return ((PFN_EntryFuncProto)(ULONG_PTR)trampoline_back)(a1, a2, a3, a4, a5, a6, a7, a8);
}
inline LPVOID GetPEModuleBase()
{
	PPEB peb = NULL;
#if defined(_WIN64)
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif
	PPEB_LDR_DATA ldr = peb->Ldr;
	LIST_ENTRY list = ldr->InLoadOrderModuleList;

	PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
	PLDR_DATA_TABLE_ENTRY curr_module = Flink;
	// first module is PE module
	if (curr_module != NULL && curr_module->DllBase != NULL)
		return curr_module->DllBase;
	return NULL;
}
typedef NTSTATUS(NTAPI *PFN_NtQueryInformationProcess)(
	HANDLE,
	PROCESSINFOCLASS,
	PVOID,
	ULONG,
	PULONG
	);
BOOLEAN GetNtPathOfCurrentProcess(HANDLE NtdllHandle, wchar_t* ntPath, size_t* outLen);
BOOLEAN CheckSignalFile(UCHAR* ntPath, size_t len, const wchar_t* format);
//
// Include support for ETW logging.
// Note that following functions are mocked, because they're
// located in advapi32.dll.  Fortunatelly, advapi32.dll simply
// redirects calls to these functions to the ntdll.dll.
//

// Map Event* symbols to the standard ETW APIs provided by evntprov.h
#define EventActivityIdControl  EventActivityIdControl
#define EventEnabled            EventEnabled
#define EventProviderEnabled    EventProviderEnabled
#define EventRegister           EventRegister
#define EventSetInformation     EventSetInformation
#define EventUnregister         EventUnregister
#define EventWrite              EventWrite
#define EventWriteEndScenario   EventWriteEndScenario
#define EventWriteEx            EventWriteEx
#define EventWriteStartScenario EventWriteStartScenario
#define EventWriteString        EventWriteString
#define EventWriteTransfer      EventWriteTransfer

#include <evntprov.h>

#include <stdarg.h>


//
// Include Detours.
//


// This is necessary for x86 builds because of SEH,
// which is used by Detours.  Look at loadcfg.c file
// in Visual Studio's CRT source codes for the original
// implementation.
//


//
// Unfortunatelly sprintf-like functions are not exposed
// by ntdll.lib, which we're linking against.  We have to
// load them dynamically.
//

// vsnwprintf signature and function pointer (we'll resolve at runtime)
typedef int(__cdecl * _vsnwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	va_list args
	);

static _vsnwprintf_fn_t _vsnwprintf_ = NULL;
//
// ETW provider GUID and global provider handle.
//

//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

REGHANDLE ProviderHandle = 0;

//
// Hooking functions and prototypes.
//




typedef NTSTATUS(NTAPI *PNtDeleteFile)(
	POBJECT_ATTRIBUTES ObjectAttributes
	);
typedef NTSTATUS(NTAPI *PFN_LdrLoadDll)(
	PWSTR               PathToFile OPTIONAL, // Usually NULL for system search
	PULONG              Flags OPTIONAL,      // Normally 0
	PUNICODE_STRING     ModuleFileName,      // DLL name
	PHANDLE             ModuleHandle         // out: handle to loaded module
	);

// Minimal typedefs in case winternl.h not present
typedef NTSTATUS(NTAPI *PFN_NtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);
typedef ULONG(NTAPI *PRtlGetCurrentProcessId)(void);

typedef NTSTATUS(NTAPI *PFN_NtReadFile)(
	HANDLE            FileHandle,
	HANDLE            Event OPTIONAL,
	PIO_APC_ROUTINE   ApcRoutine OPTIONAL,
	PVOID             ApcContext OPTIONAL,
	PIO_STATUS_BLOCK  IoStatusBlock,
	PVOID             Buffer,
	ULONG             Length,
	PLARGE_INTEGER    ByteOffset OPTIONAL,
	PULONG            Key OPTIONAL
	);




typedef NTSTATUS(NTAPI *PNtCreateEvent)(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE EventType,
	BOOLEAN InitialState
	);

typedef NTSTATUS(NTAPI *PNtOpenEvent)(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(NTAPI *PNtSetEvent)(
	HANDLE EventHandle,
	PLONG PreviousState OPTIONAL
	);

typedef NTSTATUS(NTAPI *PNtWaitForSingleObject)(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout OPTIONAL
	);

// Section/map support removed, this DLL no longer creates native sections for IPC.
// IPC uses an event-based signal and file for the payload; keep event APIs only.

typedef NTSTATUS(NTAPI *PFN_NtClose)(HANDLE Handle);
static NTSTATUS ReadBytesFromFileNt(
	_In_z_ PCWSTR dosPath,
	_Out_writes_bytes_(BufferLen) PVOID Buffer,
	_In_ ULONG BufferLen,
	_Out_opt_ PULONG BytesRead
)
{


	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"ntOpenFile");
	PFN_NtOpenFile pNtOpenFile = 0;
	PFN_NtReadFile pNtReadFile = 0;
	PFN_NtClose pNtClose = 0;
	PFN_NtDelayExecution pNtDelay = 0;
	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtReadFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtReadFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDelayExecution");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDelay);



	if (!pNtOpenFile || !pNtReadFile || !pNtClose)
		return STATUS_ENTRYPOINT_NOT_FOUND;

	UNICODE_STRING uPath;
	RtlInitUnicodeString(&uPath, dosPath);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// Open for read attributes + read data
	NTSTATUS status = pNtOpenFile(
		&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
	);

	if (!NT_SUCCESS(status)) return status;

	// Read from beginning. Since opened synchronous, ByteOffset NULL is fine.
	status = pNtReadFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&iosb,
		Buffer,
		BufferLen,
		NULL,   // read from current file pointer (start)
		NULL
	);

	if (BytesRead && NT_SUCCESS(status)) {
		*BytesRead = (ULONG)iosb.Information;
	}

	pNtClose(hFile);
	return status;
}
// Read a 32-bit unsigned integer from start of file
BOOL ReadUint32FromFile(_In_z_ PCWSTR path, _Out_ UINT32 *out)
{
	if (!path || !out) return FALSE;
	UINT32 val = 0;
	ULONG bytesRead = 0;
	NTSTATUS st = ReadBytesFromFileNt(path, &val, sizeof(val), &bytesRead);
	if (!NT_SUCCESS(st) || bytesRead < sizeof(val)) return FALSE;
	*out = val;
	return TRUE;
}

// Read a 64-bit unsigned integer from start of file
BOOL ReadUint64FromFile(_In_z_ PCWSTR path, _Out_ UINT64 *out)
{
	if (!path || !out) return FALSE;
	UINT64 val = 0;
	ULONG bytesRead = 0;
	NTSTATUS st = ReadBytesFromFileNt(path, &val, sizeof(val), &bytesRead);
	if (!NT_SUCCESS(st) || bytesRead < sizeof(val)) return FALSE;
	*out = val;
	return TRUE;
}
PFN_NtOpenFile pNtOpenFile = 0;
PFN_NtReadFile pNtReadFile = 0;
PFN_NtClose pNtClose = 0;
PFN_NtDelayExecution pNtDelay = 0;
PFN_LdrLoadDll pLdrLoadDll = 0;
PNtDeleteFile pNtDeleteFile = 0;
PRtlGetCurrentProcessId pRtlGetCurrentProcessId = 0;

// Returns TRUE if file exists (NT view), FALSE otherwise.

BOOL FileExistsViaNtOpenFile(const wchar_t *ntPath);
// int ReadFileParsePidAndDllPath(WCHAR* patbuf, char* dllPath);

PNtCreateEvent                 pNtCreateEvent = 0;
PNtOpenEvent                   pNtOpenEvent = 0;
PNtSetEvent                    pNtSetEvent = 0;
PNtWaitForSingleObject         pNtWaitForSingleObject = 0;


#include <ntdef.h>

VOID EtwLog(_In_ PCWSTR Format, ...)
{
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';
	// Prepend stable prefix unless caller already provided one.
	if (Buffer[0] == L'[') {
		EventWriteString(ProviderHandle, 0, 0, Buffer);
	}
	else {
		WCHAR Prefixed[1100];
		_snwprintf_(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[MasterDLL]  %s", Buffer);
		Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
		if (ProviderHandle)
			EventWriteString(ProviderHandle, 0, 0, Prefixed);
		else {
			UNICODE_STRING u;
			RtlInitUnicodeString(&u, Prefixed);
			DbgPrint("%wZ\n", u);
		}
	}
}

extern "C" __declspec(dllexport) int MASETER_EXP_FUNC_NAME(WCHAR* patbuf, char* dllPath) {


	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, patbuf);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// DesiredAccess: FILE_READ_ATTRIBUTES is enough to check existence.
	// OpenOptions: FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	NTSTATUS status = NtOpenFile(&hFile,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_ALL_ACCESS,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	if (status != 0) {

		return -1;
	}
	IO_STATUS_BLOCK isb = { 0 };
	char fileContextBuffer[256] = { 0 };
	if (0 != pNtReadFile(hFile, 0, 0, 0, &isb, fileContextBuffer, 256, 0, 0)) {
		
		pNtClose(hFile);
		return -2;
	}
	ULONG_PTR actualBufferLen = isb.Information;
	DWORD pid = 0;
	for (size_t i = 0; i < actualBufferLen; i++)
	{
		if (fileContextBuffer[i] != '$') {
			*((UCHAR*)(&pid) + i) = fileContextBuffer[i];
		}
		else {
			for (size_t j = i + 1; j < actualBufferLen; j++)
			{
				if (fileContextBuffer[j] != '$')
					dllPath[j - i - 1] = fileContextBuffer[j];
				else
					goto endloop;
			}
		}
	}
endloop:
	int ret = *(DWORD*)(&pid);
	pNtClose(hFile);
	return ret;
}

// mainn


NTSTATUS AgentCode(_In_ PVOID ThreadParameter) {
	// 

	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenFile");

	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtReadFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtReadFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDelayExecution");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDelay);
	RtlInitAnsiString(&RoutineName, (PSTR)"LdrLoadDll");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pLdrLoadDll);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDeleteFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDeleteFile);



	RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtSetEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtSetEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtWaitForSingleObject");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtWaitForSingleObject);

	// Event-based IPC only: construct event name for this process and create/open it.

	HANDLE curPid = NtCurrentProcessId();
	WCHAR pathBuf[MAX_PATH] = { 0 };

	_snwprintf_(pathBuf, RTL_NUMBER_OF(pathBuf), DLL_IPC_SIGNAL_FILE_FMT, NtCurrentProcessId());
	WCHAR eventFile[MAX_PATH] = { 0 };
	_snwprintf_(eventFile, RTL_NUMBER_OF(eventFile), DLL_IPC_EVENT_FILE_FMT, NtCurrentProcessId());

	for (;;) {
		// wait for injection signal event, if signaled, we proceed
		NtWaitForSingleObject(g_EventHandle, FALSE, NULL);


		EtwLog(L"current process is signaled to inject a dll\n");
		char dllPath[MAX_PATH] = { 0 };

		// read out to be injected dll path from code memory, I use an export function as data storage
		// MASETER_EXP_FUNC_NAME is actually an obsolete function I used when I first start this project
		UCHAR* data_addr = (UCHAR*)(ULONG_PTR)&MASETER_EXP_FUNC_NAME;
#ifdef _DEBUG
		data_addr = *(DWORD*)(data_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE) + data_addr + E9_JMP_INSTRUCTION_SIZE;
#endif
		for (size_t i = 0; i < MAX_PATH; i++) {
			if (data_addr[i] == IPC_DLL_PATH_END_MARK)
				break;
			dllPath[i] = data_addr[i];
		}

		UNICODE_STRING str;
		WCHAR buffer[260];
		{
			PUNICODE_STRING ustr = &str;
			USHORT i = 0;
			char* src = dllPath;
			// simple widening
			while (src[i] && (i * sizeof(WCHAR) + sizeof(WCHAR)) <= 256) {
				buffer[i] = (WCHAR)(unsigned char)src[i];
				i++;
			}
			buffer[i] = L'\0';

			ustr->Buffer = buffer;
			ustr->Length = i * sizeof(WCHAR);
			ustr->MaximumLength = (i + 1) * sizeof(WCHAR);

			EtwLog(L"constructed to be injected dll path: %s\n", buffer);

			NTSTATUS st = pLdrLoadDll(0, 0, ustr, (PHANDLE)dllPath);
			if (st != 0) {
				EtwLog(L"LdrLoadDll call with DllPath=%s failed with Status=0x%x\n", buffer, st);
			}
			else {
				// signal back to umcontroller
				EtwLog(L"LdrLoadDll SUCCESS: %s\n", buffer);

				// construct event name
				WCHAR eventName[150];
				const wchar_t* dllName = wcsrchr(buffer, L'\\');
				dllName = dllName ? dllName + 1 : buffer;

				_snwprintf_(eventName, RTL_NUMBER_OF(eventName) - 1,
					HOOK_DLL_NT_INJECTED_DLL_LOADED_EVENT L"%u_%s",
					NtCurrentProcessId(), dllName);

				UNICODE_STRING uName;
				RtlInitUnicodeString(&uName, eventName);

				OBJECT_ATTRIBUTES oa;
				InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

				HANDLE hEvent = NULL;
				NTSTATUS evtStatus = NtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);
				if (NT_SUCCESS(evtStatus)) {
					NtSetEvent(hEvent, NULL);
					EtwLog(L"Signaled injection success: %s\n", eventName);
					NtClose(hEvent);
				}
				else {
					EtwLog(L"Failed to open injection success event (caller may not be waiting): Status=0x%x\n", evtStatus);
				}
			}
		}
		NtResetEvent(g_EventHandle, NULL);
	}

	return 0;

}
// endd
// Returns TRUE if file exists (NT view), FALSE otherwise.
BOOL FileExistsViaNtOpenFile(const wchar_t *ntPath)
{
	if (!ntPath) return FALSE;

	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, ntPath);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// DesiredAccess: FILE_READ_ATTRIBUTES is enough to check existence.
	// OpenOptions: FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	NTSTATUS status = NtOpenFile(&hFile,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);


	if (NT_SUCCESS(status)) {
		// file open succeeded => exists
		NtClose(hFile);
		return TRUE;
	}
	// if you want to check specific reasons:
	// if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) -> not exists
	return FALSE;
}

NTSTATUS
NTAPI
OnProcessAttach(
	_In_ PVOID ModuleHandle
)
{


	// add dll reference, so we can be unloaded by calling freelibrary
	LdrAddRefDll(LDR_ADDREF_DLL_PIN, ModuleHandle);

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");

	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_snwprintf_);

	RtlInitAnsiString(&RoutineName, (PSTR)"LdrLoadDll");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pLdrLoadDll);

	RtlInitAnsiString(&RoutineName, (PSTR)"_vsnwprintf");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_vsnwprintf_);
	EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&ProviderHandle);


	// try creating a mutex here, so we won't load ourself twice
	{
		WCHAR mutant_name[100];
		_snwprintf_(mutant_name, RTL_NUMBER_OF(mutant_name) - 1, HOOK_DLL_LOAD_MUTANT_FMT, NtCurrentProcessId());

		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, mutant_name);

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
		HANDLE hMutant;
		NTSTATUS status = NtCreateMutant(&hMutant, MUTANT_ALL_ACCESS, &oa, TRUE);
		if (0 != status) {
			EtwLog(L"NtCreateMutant Name=%s failed, maybe Master DLL has already been loaded, Status=0x%x\n", mutant_name, status);

			return 0;
		}
	}
	// we need to open and set an event to signal we're loaded
	// this is used for time-sensitive operation, such as the force injection called by our AVProcessHandleLocater
	{

		WCHAR event_name[100];
		_snwprintf_(event_name, RTL_NUMBER_OF(event_name) - 1, HOOK_DLL_NT_MASTER_LOADED_SIGNAL_BACK_EVENT L"%d", NtCurrentProcessId());

		UNICODE_STRING uName;
		RtlInitUnicodeString(&uName, event_name);

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hEvent = NULL;
		NTSTATUS status = NtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);
		if (!NT_SUCCESS(status)) {
			EtwLog(L"failed to open event, Name=%s, Status=0x%x\n", event_name, status);
		}
		else {
			// Signal event
			NtSetEvent(hEvent, NULL);

			EtwLog(L"Signal back master dll loaded\n");
			// close event handle
			NtClose(hEvent);
		}
	}


	// we should create an event to signal that we have master dll loaded
	// this event is used for MasterLoaded attribute polling by UMController
	{
		WCHAR event_name[100];
		_snwprintf_(event_name, RTL_NUMBER_OF(event_name) - 1, HOOK_DLL_NT_MASTER_LOAD_EVENT L"%d", NtCurrentProcessId());

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, event_name);

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(
			&oa,
			&name,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);

		HANDLE hEvent = NULL;

		NTSTATUS status = NtCreateEvent(
			&hEvent,
			EVENT_ALL_ACCESS,
			&oa,
			NotificationEvent,   // or SynchronizationEvent
			FALSE                // Initial state
		);

		if (status != 0) {
			EtwLog(L"failed to call NtCreateEvent to create master loaded signal Event=%s, status=0x%x\n", &event_name, status);
		}
	}

	// create injection signal event
	// this event is used to receive signal from UMController when loading extra dll by master dll
	{
		WCHAR event_name[100];
		_snwprintf_(event_name, RTL_NUMBER_OF(event_name) - 1, HOOK_DLL_NT_INJECTION_SIGNAL_EVENT L"%d", NtCurrentProcessId());

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, event_name);


		g_EventHandle = NULL;
		SECURITY_DESCRIPTOR sd = { 0 };

		// Use revision 1
		sd.Revision = 1;

		// Set control flags (SE_DACL_PRESENT = 0x04)
		sd.Control = SE_DACL_PRESENT;

		// Set a NULL DACL (everyone full access)
		sd.Dacl = NULL;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(
			&oa,
			&name,
			OBJ_CASE_INSENSITIVE,
			NULL,
			&sd
		);
		NTSTATUS status = NtCreateEvent(
			&g_EventHandle,
			EVENT_ALL_ACCESS,
			&oa,
			NotificationEvent,   // or SynchronizationEvent
			FALSE                // Initial state
		);

		if (status != 0) {
			EtwLog(L"failed to call NtCreateEvent to create injection signal Event=%s, status=0x%x\n", &event_name, status);
		}
	}



	// early break check code
	wchar_t ntPath[MAX_PATH * 4] = { 0 };
	size_t len = 0;
	GetNtPathOfCurrentProcess(NtdllHandle, ntPath, &len);
	// get hash and check
	if (CheckSignalFile((UCHAR*)ntPath, len, EARLY_BREAK_SIGNAL_FILE_FMT)) {
		EtwLog(L"current process is marked as early break, now breaking into debugger\n");

		// put it into sleep using Detours at PE entry
		{
			DWORD64 PEBASE = (DWORD64)GetPEModuleBase();
			auto dos = (PIMAGE_DOS_HEADER)PEBASE;
			auto nt = (PIMAGE_NT_HEADERS)(PEBASE + dos->e_lfanew);
			DWORD64 EntryAddr = PEBASE + nt->OptionalHeader.AddressOfEntryPoint;
			DetourTransactionBegin();
			{
				original_entry = (PFN_EntryFuncProto)EntryAddr;

				DetourAttachEx((PVOID*)&original_entry, PutIntoSleep, (PDETOUR_TRAMPOLINE*)&trampoline_back, NULL, NULL);
			}
			DetourTransactionCommit();
		}
	}

	// for now we only support x64
#ifdef _WIN64

	 // we need to hook ldrloaddll before ret and get unicode string from rdi
	 // we can use capstone to locate ret instruction and search back to get enough space to write
	 // trampoline code
	while(1){
		// first check if dealy_hook.hash exist, we can reuse CheckSignalFile, only change format
		if (CheckSignalFile((UCHAR*)ntPath, len, DELAY_HOOK_SIGNAL_FILE_FMT)) {
			// we already have LdrLoadDll function address: pLdrLoadDll
			DWORD hook_offset = 0;
			DbgBreakPoint();
			// read config file get offset based on ntdll FNV-1a hash
			WCHAR fnvStr[17] = { 0 };
			if (GetNtdllFnvHash(fnvStr, 17)) {
				if (!GetHookOffsetFromConfig(fnvStr, &hook_offset)) {
					EtwLog(L"FNV %s not found in config\n", fnvStr);
					break;
				}
			}
			
			EtwLog(L"failed to get ntdll FNV hash\n");
			break;

			DWORD oriLen = 0;
			PVOID tramp = nullptr;
			PVOID hookAddr = (PVOID)((uintptr_t)NtdllHandle + hook_offset);
			if (!ApplyLocalHook(hookAddr, (PVOID)LdrLoadDll_HookHandler, &tramp, &oriLen)) {
				EtwLog(L"NTDLL ApplyLocalHook failed\n");
				break;
			}
			// try install hook
			{
				DWORD oldProt = 0;
				SIZE_T protLen = MIN_HOOK_BYTES;
				DWORD trampSize = 128;
				NtProtectVirtualMemory(NtCurrentProcess(), &hookAddr, &protLen, PAGE_EXECUTE_READWRITE, &oldProt);

				bool ok = WriteJump((PVOID)((uintptr_t)NtdllHandle + hook_offset), tramp);
				DWORD tmp;
				NtProtectVirtualMemory(NtCurrentProcess(), &hookAddr, &protLen, oldProt, &tmp);

				if (!ok) {
					SIZE_T z = 0;
					NtFreeVirtualMemory(NtCurrentProcess(), &tramp, (PSIZE_T)&trampSize, MEM_RELEASE);
					return false;
				}
			}
		}
	}

#endif
	RtlCreateUserThread(NtCurrentProcess(),
		NULL,
		FALSE,
		0,
		0,
		0,
		(PUSER_THREAD_START_ROUTINE)&AgentCode,
		NULL,
		NULL,
		NULL);

	return 0; // Early exit: remaining legacy code removed as unreachable
}

NTSTATUS
NTAPI
OnProcessDetach(
	_In_ HANDLE ModuleHandle
)
{
	//
	// Unhook all functions.
	//


	return 0;
}

EXTERN_C
BOOL
NTAPI
NtDllMain(
	_In_ HANDLE ModuleHandle,
	_In_ ULONG Reason,
	_In_ LPVOID Reserved
)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		OnProcessAttach(ModuleHandle);
		break;


	case DLL_PROCESS_DETACH:
		OnProcessDetach(ModuleHandle);
		break;

	case DLL_THREAD_ATTACH:

		break;

	case DLL_THREAD_DETACH:

		break;
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		// Sleep(60000);
	 //  __debugbreak();
		return OnProcessAttach(hModule);
		break;

	case DLL_PROCESS_DETACH:
		OnProcessDetach(hModule);
		break;

	case DLL_THREAD_ATTACH:

		break;

	case DLL_THREAD_DETACH:

		break;
	}

	return TRUE;
}


BOOLEAN CheckSignalFile(UCHAR* ntPath, size_t len, const wchar_t* format) {
	const DWORD64 FNV_prime = 1099511628211ULL;
	DWORD64 hash = 14695981039346656037ULL;

	// Process exact number of bytes provided by the caller. This ensures
	// UTF-16LE buffers (which may contain embedded zero bytes) are hashed
	// correctly.
	const UCHAR* p = ntPath;
	const UCHAR* end = ntPath + len;
	while (p < end) {
		hash ^= (DWORD64)(*p);
		hash *= FNV_prime;
		++p;
	}
	// then we check if a file with this hash as name exist
	WCHAR pathBuf[MAX_PATH] = { 0 };

	unsigned long long h = (unsigned long long)hash;
	_snwprintf_(pathBuf, RTL_NUMBER_OF(pathBuf), format, h);

	if (!FileExistsViaNtOpenFile(pathBuf)) {
		return FALSE;
	}

	return TRUE;
}

BOOLEAN GetNtPathOfCurrentProcess(HANDLE NtdllHandle, wchar_t* ntPath, size_t* outLen)
{
	PFN_NtQueryInformationProcess NtQueryInformationProcess = nullptr;

	// Resolve NtQueryInformationProcess
	ANSI_STRING aName;
	RtlInitAnsiString(&aName, "NtQueryInformationProcess");


	if (LdrGetProcedureAddress(NtdllHandle, &aName, 0,
		(PVOID*)&NtQueryInformationProcess) < 0)
	{
		EtwLog(L"can not get function %Z address\n", aName);
		RtlFreeAnsiString(&aName);
		return FALSE;
	}

	ULONG returnLength = 0;

	PBYTE buff[MAX_PATH * 4] = { 0 };
	NTSTATUS status = NtQueryInformationProcess(
		HANDLE(-1),
		ProcessImageFileName,
		buff,
		MAX_PATH * 4,
		&returnLength
	);

	if (status < 0) {
		EtwLog(L"failed to call NtQueryInformationProcess, status=0x%x\n", status);
		return FALSE;
	}

	// This structure:
	// typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
	UNICODE_STRING* us = (UNICODE_STRING*)buff;
	for (size_t i = 0; i < us->Length; i++)
	{
		ntPath[i] = us->Buffer[i];
	}
	*outLen = us->Length;

	return TRUE;
}

static bool WriteJump(PVOID addr, PVOID target) {
	BYTE code[12] = {
		0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // movabs rcx, target
		0xFF, 0xE1                               // jmp rcx
	};
	*(uint64_t*)&code[2] = (uint64_t)target;
	SIZE_T written = 0;
	return NT_SUCCESS(NtWriteVirtualMemory(NtCurrentProcess(), addr, code, MIN_HOOK_BYTES, &written)) && written == MIN_HOOK_BYTES;
}

bool ApplyLocalHook(
	_In_  PVOID   hookAddr,
	_In_  PVOID   hookHandler,
	_Out_ PVOID*  outTrampoline,
	_Out_ DWORD*  outOriLen
) {
	if (!hookAddr || !hookHandler || !outTrampoline || !outOriLen) return false;

	// get original asm code length by iterating from hook address, loop break when len>=6
	uint8_t buf[0x30] = { 0 };
	SIZE_T bytesRead = 0;
	if (NtReadVirtualMemory(NtCurrentProcess(), hookAddr, buf, sizeof(buf), &bytesRead) < 0 || bytesRead < MIN_HOOK_BYTES)
		return false;

	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn* ins = cs_malloc(handle);
	uint64_t rip = (uint64_t)hookAddr;
	size_t remaining = bytesRead;
	const uint8_t *code_ptr = buf;
	size_t totalLen = 0;
	while (cs_disasm_iter(handle, (const uint8_t**)&code_ptr, &remaining, &rip, ins)) {
		totalLen += ins->size;
		if (totalLen >= MIN_HOOK_BYTES) break;
	}
	cs_free(ins, 1);
	cs_close(&handle);

	if (totalLen < MIN_HOOK_BYTES) return false;
	*outOriLen = (DWORD)totalLen;

	// read original asm code out based on the origianl code length we get above
	BYTE oriBytes[32] = { 0 };
	SIZE_T r = 0;
	if (NtReadVirtualMemory(NtCurrentProcess(), hookAddr, oriBytes, totalLen, &r) < 0 || r != totalLen)
		return false;

	// allocate trampoline
	SIZE_T trampSize = 128;
	PVOID trampoline = nullptr;
	NTSTATUS st = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&trampoline,
		0,
		&trampSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!NT_SUCCESS(st) || !trampoline) return false;

	// construct shellcode
	BYTE* p = (BYTE*)trampoline;
	PVOID backAddr = (PVOID)((uintptr_t)hookAddr + totalLen);

	// pushfq
	*p++ = 0x9C;
	
	*p++ = 0x50; // push rax
	*p++ = 0x51; // push rcx
	*p++ = 0x52; // push rdx
	*p++ = 0x41; *p++ = 0x50; // push r8
	*p++ = 0x41; *p++ = 0x51; // push r9
	*p++ = 0x41; *p++ = 0x52; // push r10
	*p++ = 0x41; *p++ = 0x53; // push r11

	
	*p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;

	
	*p++ = 0x48; *p++ = 0xB8;
	*(uint64_t*)p = (uint64_t)hookHandler;
	p += 8;

	// call rax (2 bytes: FF D0)
	*p++ = 0xFF; *p++ = 0xD0;

	
	*p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;

	// pop r11 r10 r9 r8 rdx rcx rax
	*p++ = 0x41; *p++ = 0x5B; // pop r11
	*p++ = 0x41; *p++ = 0x5A; // pop r10
	*p++ = 0x41; *p++ = 0x59; // pop r9
	*p++ = 0x41; *p++ = 0x58; // pop r8
	*p++ = 0x5A; // pop rdx
	*p++ = 0x59; // pop rcx
	*p++ = 0x58; // pop rax
	// popfq
	*p++ = 0x9D;

	memcpy(p, oriBytes, totalLen);
	p += totalLen;

	// we have to use instruction like jmp absaddr, because the address we located is far beyond 4GB
	*p++ = 0x48; *p++ = 0xB9;
	*(uint64_t*)p = (uint64_t)backAddr;
	p += 8;
	// jmp rcx (FF E1)
	*p++ = 0xFF; *p++ = 0xE1;



	*outTrampoline = trampoline;
	return true;
}

// calculate FNV-1a hash based on ntdll disk file, not mapped file
static BOOL GetNtdllFnvHash(WCHAR* hashStr, DWORD hashStrSize) {
	if (!hashStr || hashStrSize < 17) return FALSE;

	UNICODE_STRING us;
	RtlInitUnicodeString(&us, NTDLL_PATH);
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hFile = NULL;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) return FALSE;

	const DWORD64 FNV_prime = 1099511628211ULL;
	DWORD64 hash = 14695981039346656037ULL;
	WCHAR hexChars[] = L"0123456789abcdef";

	__try {
		BYTE buf[8192];
		while (TRUE) {
			status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, buf, sizeof(buf), NULL, NULL);
			if (!NT_SUCCESS(status)) break;
			if (iosb.Information == 0) break;

			for (SIZE_T i = 0; i < iosb.Information; i++) {
				hash ^= (DWORD64)buf[i];
				hash *= FNV_prime;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }

	NtClose(hFile);

	if (NT_SUCCESS(status) || status == STATUS_END_OF_FILE) {
		for (int i = 0; i < 8; i++) {
			hashStr[i * 2] = hexChars[(hash >> (60 - i * 8)) & 0xF];
			hashStr[i * 2 + 1] = hexChars[(hash >> (56 - i * 8)) & 0xF];
		}
		hashStr[16] = L'\0';
		return TRUE;
	}
	return FALSE;
}

// ntdll hash-> offset json parser
static BOOL GetHookOffsetFromConfig(const WCHAR* fnvHash, DWORD* outOffset) {
	if (!fnvHash || !outOffset) return FALSE;
	*outOffset = 0;

	const WCHAR* configPath = L"\\??\\C:\\users\\public\\umhh_offset.json";

	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
	RtlInitUnicodeString(&us, configPath);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hFile = NULL;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) return FALSE;

	FILE_STANDARD_INFORMATION fsi;
	status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
	if (!NT_SUCCESS(status) || fsi.EndOfFile.QuadPart > 1024 * 1024) {
		NtClose(hFile);
		return FALSE;
	}

	char fileContent[512] = { 0 };
	status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, fileContent, (ULONG)fsi.EndOfFile.QuadPart, NULL, NULL);
	NtClose(hFile);
	if (!NT_SUCCESS(status)) return FALSE;

	const char* archKey = NULL;
#ifdef _WIN64
	archKey = "x64";
#else
	archKey = "x86";
#endif

	const char* p = fileContent;
	const char* configEnd = fileContent + fsi.EndOfFile.QuadPart;

	while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
	if (p >= configEnd || *p != '{') return FALSE;
	p++;

	char keyBuf[64] = { 0 };

	while (p < configEnd) {
		while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
		if (p >= configEnd) break;

		if (*p == '"') {
			p++;
			SIZE_T keyBufPos = 0;
			while (p < configEnd && *p != '"' && keyBufPos < 63) {
				keyBuf[keyBufPos++] = *p++;
			}
			keyBuf[keyBufPos] = '\0';
			if (p < configEnd && *p == '"') p++;

			while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
			if (p < configEnd && *p == ':') p++;
			while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;

			if (keyBufPos == strlen(archKey) && strncmp(keyBuf, archKey, keyBufPos) == 0) {
				if (p < configEnd && *p == '{') p++;

				while (p < configEnd && *p != '}') {
					while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
					if (p >= configEnd || *p == '}') break;

					if (*p == '"') {
						p++;
						char hashBuf[64] = { 0 };
						SIZE_T hashPos = 0;
						while (p < configEnd && *p != '"' && hashPos < 63) {
							hashBuf[hashPos++] = *p++;
						}
						hashBuf[hashPos] = '\0';
						if (p < configEnd && *p == '"') p++;

						while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
						if (p < configEnd && *p == ':') p++;
						while (p < configEnd && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;

						if (hashPos == 16) {
							// compare to char and wchar, so we need to multiply fnvHash with sizeof(fnvHash[0]
							BOOL matched = TRUE;
							for (SIZE_T i = 0; i < 16; i++) {
								if (hashBuf[i] != *((char*)fnvHash + i * sizeof(fnvHash[0]))) {
									matched = FALSE;
									break;
								}
							}
							if (matched) {
								p += 2;
								char offsetBuf[32] = { 0 };
								SIZE_T offsetPos = 0;
								while (p < configEnd && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) {
									offsetBuf[offsetPos++] = *p++;
								}
								if (offsetPos > 0) {
									DWORD offset = 0;
									for (char* q = offsetBuf; *q; q++) {
										offset = offset * 16 + (*q >= 'a' ? (*q - 'a' + 10) : *q >= 'A' ? (*q - 'A' + 10) : (*q - '0'));
									}
									*outOffset = offset;
									return TRUE;
								}
							}
						}
					}
					else {
						break;
					}
				}
				break;
			}
			else if (p < configEnd && *p == '{') {
				int depth = 1;
				p++;
				while (p < configEnd && depth > 0) {
					if (*p == '{') depth++;
					else if (*p == '}') depth--;
					p++;
				}
			}
		}
		else if (*p == '}') {
			break;
		}
		else {
			p++;
		}
	}

	return FALSE;
}

void __fastcall LdrLoadDll_HookHandler(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	// the only thing we need is rdi, which is a unicode string pointer
}