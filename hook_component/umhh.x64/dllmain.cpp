
#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1


//
// Include NTDLL-related headers.
//
#define NTDLL_NO_INLINE_INIT_STRING
#include <ntdll.h>
#include "../controller/UMController/IPC.h"
#include "../controller/UMController/ETW.h"
#include "../../Shared/SharedMacroDef.h"
#include "../../drivers/UserModeHookHelper/UKShared.h"
#include "detours/detours.h"
#include "capstone/capstone.h"
typedef PVOID(*PFNGetRdi)();
PFNGetRdi pGetRdi;
VOID CopyCharToWchar(WCHAR* dst, CHAR* src, SIZE_T len) {
	for (size_t i = 0; i < len && src[i]!=0xd && src[i]!=0xa; i++) {
		*((CHAR*)dst + i * sizeof(WCHAR)) = src[i];
	}
}
static PVOID GetProcessHeapFromPEB() {
#if defined(_WIN64)
	return (PVOID)*(ULONG_PTR*)((ULONG_PTR)__readgsqword(0x60) + 0x30);
#else
	return (PVOID)*(ULONG_PTR*)((ULONG_PTR)__readfsdword(0x30) + 0x30);
#endif
}

// Minimum bytes needed for inline hook: movabs rcx, addr (10) + jmp rcx (2) = 12
#define MIN_HOOK_BYTES 12
static bool WriteJump(PVOID addr, PVOID target);

// InstantHook target list (for delay hook feature)
struct InstantHookTarget {
	wchar_t targetDllName[MAX_PATH];        // target dll name
	USHORT targetDllNameLen;
	unsigned long long dllFnvHash;           // FNV hash of target dll name
	unsigned long long offset;               // target offset for hooking
	HANDLE hLoadNotifyEvent;                // LoadNotify.<pFnv>.<dllFnv>.<offset>
	HANDLE hHookNotifyEvent;                // HookNotify.<pFnv>.<dllFnv>.<offset>
	wchar_t dllPath[MAX_PATH];              // hook code dll path
	InstantHookTarget* next;
};
static InstantHookTarget* g_InstantHookList = nullptr;
static BOOL ScanDelayHookFiles(const WCHAR* ntPath, size_t byteLen);


// Find suitable hook offset for LdrLoadDll
// Reads 0x1000 bytes from ldrLoadDllAddr, uses capstone to decode,
// finds RET instruction, records first 5 instructions, then returns
// the offset of the first instruction where (instr_addr - ret_addr) >= MIN_HOOK_BYTES
static DWORD FindHookOffset(PVOID ldrLoadDllAddr) {
	BYTE codeBuf[0x1000] = { 0 };
	SIZE_T bytesRead = 0;
	NTSTATUS status = NtReadVirtualMemory(NtCurrentProcess(), ldrLoadDllAddr, codeBuf, sizeof(codeBuf), &bytesRead);
	if (!NT_SUCCESS(status) || bytesRead < MIN_HOOK_BYTES) {
		return 0;
	}

	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		return 0;
	}

	cs_insn* ins = cs_malloc(handle);
	uint64_t rip = (uint64_t)ldrLoadDllAddr;
	const uint8_t* code_ptr = codeBuf;
	size_t remaining = bytesRead;

	// Record first 5 instructions
	uint64_t firstFiveAddrs[5] = { 0 };
	int firstFiveCount = 0;

	uint64_t retAddr = 0;
	while (cs_disasm_iter(handle, &code_ptr, &remaining, &rip, ins)) {
		 
		// Check for RET instruction
		if (ins->id == X86_INS_RET) {
			retAddr = ins->address;
			break;
		}
		firstFiveAddrs[firstFiveCount%5] = ins->address;
		firstFiveCount++;
	}

	if (retAddr == 0) {
		cs_free(ins, 1);
		cs_close(&handle);
		return 0;
	}

	for (size_t i = firstFiveCount-1,j=0; j<5; j++,i--) {
		if (retAddr - firstFiveAddrs[i % 5] >= MIN_HOOK_BYTES)
			return (DWORD)(firstFiveAddrs[i % 5] - (DWORD64)ldrLoadDllAddr);
	}

	cs_free(ins, 1);
	cs_close(&handle);
	return 0;
}

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

PVOID GetRdi() {
	EtwLog(L"this is just palceholder function\n");
	return NULL;
}
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
BOOLEAN CheckSignalFile(UCHAR* ntPath, size_t len, const wchar_t* format, BOOLEAN caseInsensitive);
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

// Load trampoline.dll from UMController's directory
static bool LoadTrampolineDll(PFN_LdrLoadDll pLdrLoadDll);
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
	if (CheckSignalFile((UCHAR*)ntPath, len, EARLY_BREAK_SIGNAL_FILE_FMT, TRUE)) {
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
	do {
		// first check if dealy_hook.hash exist, we can reuse CheckSignalFile, only change format
		if (CheckSignalFile((UCHAR*)ntPath, len, DELAY_HOOK_SIGNAL_FILE_FMT, TRUE)) {
			// write place holder function to GetRdi code: mov rax, rdi; ret
			{ 
				// DbgBreakPoint();
				PVOID function_addr = &GetRdi;
#ifdef _DEBUG
				function_addr = (PVOID)(DWORD64)(*(DWORD*)((DWORD64)function_addr + 1) + (DWORD64)function_addr + 5);
#endif
				pGetRdi = (PFNGetRdi)function_addr;
				// align down, a page is 4KB
				PVOID page_base = (PVOID)((DWORD64)function_addr & (~0xFFF));
				DWORD oldProt = 0;
				DWORD written = 0;
				SIZE_T protLen = 0x1000;
				DWORD trampSize = 4;
				if (0 != NtProtectVirtualMemory(NtCurrentProcess(), &page_base, &protLen, PAGE_EXECUTE_READWRITE, &oldProt)) {
					EtwLog(L"failed to call NtProtectVirtualMemory target page_base=0x%p\n", page_base);
					break;
				}
				UCHAR code[4] = { 0x48, 0x89, 0xF8, 0xC3 };
				NtWriteVirtualMemory(NtCurrentProcess(), function_addr, (PVOID)code, 4, (PSIZE_T)&written);

				DWORD tmp;
				NtProtectVirtualMemory(NtCurrentProcess(), &page_base, &protLen, oldProt, &tmp);
			}
			// we already have LdrLoadDll function address: pLdrLoadDll
			DWORD hook_offset = 0;
			// Scan delay.hook files and build InstantHook list
			if (!ScanDelayHookFiles(ntPath, len)) {
				EtwLog(L"ScanDelayHookFiles failed\n");
				break;
			}

			// Install LdrLoadDll hook if we have InstantHook targets
			if (g_InstantHookList == nullptr)
				break;

			// Load trampoline.dll from UMController's directory
			LoadTrampolineDll(pLdrLoadDll);

			// Load all hook code DLLs
			InstantHookTarget* pNode = g_InstantHookList;
			while (pNode) {
				UNICODE_STRING dllPathUs;
				RtlInitUnicodeString(&dllPathUs, pNode->dllPath);
				HANDLE hModule = NULL;
				ULONG flags = 0;
				NTSTATUS loadStatus = pLdrLoadDll(NULL, &flags, &dllPathUs, &hModule);
				if (!NT_SUCCESS(loadStatus)) {
					EtwLog(L"Failed to load hook code dll: %s, status=0x%x\n", pNode->dllPath, loadStatus);
				}
				pNode = pNode->next;
			}

			{
				// get hook offset by using capstone
				hook_offset = FindHookOffset(pLdrLoadDll);
				if (hook_offset == 0) {
					EtwLog(L"FindHookOffset failed\n");
					break;
				}
				EtwLog(L"FindHookOffset returned offset=0x%x\n", hook_offset);
			}


			DWORD oriLen = 0;
			PVOID tramp = nullptr;
			PVOID hookAddr = (PVOID)((uintptr_t)pLdrLoadDll + hook_offset);
			if (!ApplyLocalHook(hookAddr, (PVOID)LdrLoadDll_HookHandler, &tramp, &oriLen)) {
				EtwLog(L"NTDLL ApplyLocalHook failed\n");
				break;
			}
			// try install hook
			{
				DWORD oldProt = 0;
				SIZE_T protLen = 0x1000;
				DWORD trampSize = 128;  // ← Move here (outside inner block)

				PVOID page_base = (PVOID)((DWORD64)hookAddr & (~0xFFF));

				NtProtectVirtualMemory(NtCurrentProcess(), &page_base, &protLen, PAGE_EXECUTE_READWRITE, &oldProt);

				bool ok = WriteJump(hookAddr, tramp);
				DWORD tmp;
				NtProtectVirtualMemory(NtCurrentProcess(), &page_base, &protLen, oldProt, &tmp);

				if (!ok) {
					SIZE_T z = 0;
					NtFreeVirtualMemory(NtCurrentProcess(), &tramp, (PSIZE_T)&trampSize, MEM_RELEASE);
					return STATUS_UNSUCCESSFUL;  // Also fix return type
				}
				break;
			}
		}
	} while (false);

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
BOOLEAN CheckSignalFile(UCHAR* ntPath, size_t len, const wchar_t* format, BOOLEAN caseInsensitive) {
	const DWORD64 FNV_prime = 1099511628211ULL;
	DWORD64 hash = 14695981039346656037ULL;

	// Process exact number of bytes provided by the caller. This ensures
	// UTF-16LE buffers (which may contain embedded zero bytes) are hashed
	// correctly.
	const UCHAR* p = ntPath;
	const UCHAR* end = ntPath + len;
	while (p < end) {
		UCHAR byte = *p;
		// If case insensitive, convert to lowercase before hashing
		if (caseInsensitive && byte >= 'A' && byte <= 'Z') {
			byte = byte + ('a' - 'A');
		}
		hash ^= (DWORD64)byte;
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


static unsigned long long ComputeFnvHash(const WCHAR* str, USHORT charCount, bool caseInsensitive = true) {
	const DWORD64 FNV_prime = 1099511628211ULL;
	DWORD64 hash = 14695981039346656037ULL;
	for (USHORT i = 0; i < charCount; i++) {
		WCHAR c = str[i];
		if (caseInsensitive && c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
		BYTE bLow = (BYTE)(c & 0xFF);
		BYTE bHigh = (BYTE)((c >> 8) & 0xFF);
		hash ^= (DWORD64)bLow;
		hash *= FNV_prime;
		hash ^= (DWORD64)bHigh;
		hash *= FNV_prime;
	}
	return hash;
}

// Write current PID to hook event file
static VOID WriteHookEventFile(unsigned long long processFnvHash, unsigned long long dllFnvHash, unsigned long long offset) {
	WCHAR hookEventPath[MAX_PATH];
	UNICODE_STRING hookEventPathUs;
	OBJECT_ATTRIBUTES oaFile;
	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;
	LARGE_INTEGER byteOffset = { 0 };

	// Get current PID
	ULONG pid = (ULONG)(ULONG_PTR)NtCurrentProcessId();

	// Build path: \??\C:\users\public\hookevent.{processFnvHash}.{dllFnvHash}.{offset}
	swprintf_s(hookEventPath, NT_HOOK_EVENT_PID_FILE_FMT, processFnvHash, dllFnvHash, offset);

	// Initialize unicode string and object attributes
	RtlInitUnicodeString(&hookEventPathUs, hookEventPath);
	InitializeObjectAttributes(&oaFile, &hookEventPathUs, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Create/open file
	NTSTATUS status = NtCreateFile(&hFile,
		FILE_GENERIC_WRITE | SYNCHRONIZE,
		&oaFile,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (NT_SUCCESS(status)) {
		// Convert PID to string
		char pidBuf[32];
		int pidLen = sprintf_s(pidBuf, "%u", pid);

		// Write PID to file
		NtWriteFile(hFile, NULL, NULL, NULL, &iosb, pidBuf, pidLen, &byteOffset, NULL);
		NtClose(hFile);
	}
}

// Helper: remove .dll suffix from module name, return new length
static USHORT RemoveDllSuffix(const wchar_t* module, USHORT len) {
	if (len <= 4) return len;
	const wchar_t* suffix = L".dll";
	for (int i = 0; i < 4; i++) {
		wchar_t c = module[len - 4 + i];
		if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
		if (c != suffix[i]) return len;
	}
	return len - 4;
}

// Helper: remove .dll suffix from UNICODE_STRING, return new char count
static USHORT RemoveDllSuffixFromUnicodeString(const UNICODE_STRING* us) {
	if (!us || !us->Buffer || us->Length < 10) return us ? us->Length / sizeof(WCHAR) : 0;
	USHORT charCount = us->Length / sizeof(WCHAR);
	for (int i = 0; i < 4; i++) {
		WCHAR c = us->Buffer[charCount - 4 + i];
		if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
		if (c != L".dll"[i]) return charCount;
	}
	return charCount - 4;
}

// Helper: parse hex string to unsigned long long
static unsigned long long ParseHexString(const wchar_t* str) {
	if (!str) return 0;
	const wchar_t* p = str;
	if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) p += 2;
	unsigned long long val = 0;
	while (*p) {
		wchar_t c = *p++;
		if (c >= L'0' && c <= L'9') val = val * 16 + (c - L'0');
		else if (c >= L'a' && c <= L'f') val = val * 16 + (c - L'a' + 10);
		else if (c >= L'A' && c <= L'F') val = val * 16 + (c - L'A' + 10);
	}
	return val;
}

// Parsed hook entry
struct HookEntry {
	wchar_t module[MAX_PATH];
	wchar_t offsetStr[32];
	wchar_t dllPath[MAX_PATH];
	wchar_t exportName[MAX_PATH];
};

// Parse hookseq content, returns number of entries parsed
static int ParseHookSeqContent(const char* content, size_t len, HookEntry* entries, int maxEntries) {
	const char* p = content;
	const char* end = p + len;
	int count = 0;

	// Skip UTF-16 LE BOM if present
	if (len >= 2 && (unsigned char)content[0] == 0xFF && (unsigned char)content[1] == 0xFE) {
		// this indicates that the file is orginized as wide char, so we need to convert it to ascii first
		content = content + 2;
		char* ascii_content = (char*)content;
		size_t j = 0;
		for (size_t i = 0; i < len - 2; i += 2, j++) {
			ascii_content[j]= content[i];
		}

		p = ascii_content;
		end = ascii_content + j;
	}
	
	while (p < end && count < maxEntries) {
		// Skip whitespace and comments
		while (p < end) {
			while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
			if (p >= end) break;
			if (*p == '#') {
				while (p < end && *p != '\n') p++;
				continue;
			}
			break;
		}

		// Look for [hook] section
		if (p >= end || strncmp(p, "[hook]", 6) != 0) break;
		p += 6;
		if (p < end && *p == '\n') p++;

		// Parse entry
		HookEntry* entry = &entries[count];
		memset(entry, 0, sizeof(HookEntry));

		while (p < end && p[0] != '[') {
			while (p < end && (*p == ' ' || *p == '\t')) p++;
			if (p >= end || *p == '[' || *p == '\n') {
				if (p < end && *p == '\n') p++;
				break;
			}

			// Read line
			char lineBuf[MAX_PATH * 2] = {0};
			SIZE_T lineLen = 0;
			while (p < end && *p != '\n' && *p != '\r' && lineLen < sizeof(lineBuf) - 1) {
				lineBuf[lineLen++] = *p++;
			}
			if (p < end && *p == '\r') p++;
			if (p < end && *p == '\n') p++;

			// Parse key=value
			char* eq = strchr(lineBuf, '=');
			if (!eq) continue;
			*eq = '\0';
			char* key = lineBuf;
			char* val = eq + 1;

			// Trim key
			while (*key == ' ' || *key == '\t') key++;
			char* keyEnd = eq - 1;
			while (keyEnd > key && (*keyEnd == ' ' || *keyEnd == '\t')) *keyEnd-- = '\0';

			// Trim value
			while (*val == ' ' || *val == '\t') val++;
			size_t valLen = strlen(val);
			while (valLen > 0 && (val[valLen-1] == ' ' || val[valLen-1] == '\t')) val[--valLen] = '\0';

			// Store
			if (strcmp(key, "module") == 0) CopyCharToWchar(entry->module, val, MAX_PATH - 1);
			else if (strcmp(key, "offset") == 0) CopyCharToWchar(entry->offsetStr, val, 31);
			else if (strcmp(key, "dllPath") == 0) CopyCharToWchar(entry->dllPath, val, MAX_PATH - 1);
			else if (strcmp(key, "export") == 0) CopyCharToWchar(entry->exportName, val, MAX_PATH - 1);
		}

		// Only count if required fields present
		if (entry->module[0] && entry->offsetStr[0] && entry->dllPath[0]) {
			count++;
		}
	}

	return count;
}

static bool LoadTrampolineDll(PFN_LdrLoadDll pLdrLoadDll) {
	// Read UMController PID from file
	ULONG umcontrollerPid = 0;
	FILE* f = NULL;
	_wfopen_s(&f, UMCONTROLLER_PID_FILE, L"r");
	if (f) {
		fscanf_s(f, "%u", &umcontrollerPid);
		fclose(f);
	}

	if (umcontrollerPid == 0) {
		return false;
	}

	// Open UMController process
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)(ULONG_PTR)umcontrollerPid;
	cid.UniqueThread = NULL;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid);

	if (!NT_SUCCESS(status)) {
		return false;
	}

	bool result = false;

	// Get UMController process image path
	ULONG returnLength = 0;
	PBYTE buff[MAX_PATH * 4] = { 0 };
	status = NtQueryInformationProcess(
		hProcess,
		ProcessImageFileName,
		buff,
		MAX_PATH * 4,
		&returnLength
	);

	if (NT_SUCCESS(status)) {
		UNICODE_STRING* us = (UNICODE_STRING*)buff;
		WCHAR processPath[MAX_PATH];
		RtlZeroMemory(processPath, sizeof(processPath));

		// Copy process path
		ULONG pathLen = us->Length / sizeof(WCHAR);
		if (pathLen < MAX_PATH) {
			RtlCopyMemory(processPath, us->Buffer, us->Length);

			// Extract directory from process path
			WCHAR* lastSlash = wcsrchr(processPath, L'\\');
			if (lastSlash) {
				*(lastSlash + 1) = L'\0';

				// Convert NT path to DOS path format
				// NT path: \Device\HarddiskVolume2\path
				// DOS path: C:\path
				WCHAR dosPath[MAX_PATH];
				RtlZeroMemory(dosPath, sizeof(dosPath));

				if (wcsncmp(processPath, L"\\Device\\HarddiskVolume", 22) == 0) {
					// Find volume number
					WCHAR* volumeNumStart = processPath + 22;
					ULONG volumeNum = 0;
					WCHAR* p = volumeNumStart;
					while (*p >= L'0' && *p <= L'9') {
						volumeNum = volumeNum * 10 + (*p - L'0');
						p++;
					}
					// Simple mapping: volume 2 = C, volume 3 = D, etc.
					WCHAR driveLetter = (WCHAR)(L'C' + (volumeNum > 1 ? volumeNum - 2 : 0));

					// Build DOS path: C:\path
					swprintf_s(dosPath, L"%c:%s", driveLetter, volumeNumStart + 1);
				}

				// Append trampoline DLL name
				WCHAR trampDllPath[MAX_PATH];
				swprintf_s(trampDllPath, L"%s%s", dosPath, TRAMP_X64_DLL);

				// Load trampoline.dll
				UNICODE_STRING trampPathUs;
				RtlInitUnicodeString(&trampPathUs, trampDllPath);
				HANDLE hTramp = NULL;
				ULONG flags = 0;
				NTSTATUS trampStatus = pLdrLoadDll(NULL, &flags, &trampPathUs, &hTramp);
				if (!NT_SUCCESS(trampStatus)) {
					EtwLog(L"Failed to load trampoline.dll: %s, status=0x%x\n", trampDllPath, trampStatus);
				}
				else {
					EtwLog(L"Successfully loaded trampoline.dll: %s\n", trampDllPath);
					result = true;
				}
			}
		}
	}

	NtClose(hProcess);
	return result;
}
static BOOL ScanDelayHookFiles(const WCHAR* ntPath, size_t byteLen) {
	unsigned long long processFnvHash = ComputeFnvHash(ntPath, (USHORT)(byteLen / sizeof(WCHAR)));

	WCHAR filePath[MAX_PATH];
	swprintf_s(filePath, NT_DELAY_HOOK_FILE_FMT, processFnvHash);

	// Open delay hook file
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
	RtlInitUnicodeString(&us, filePath);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hFile = NULL;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) return FALSE;

	// Get file size
	FILE_STANDARD_INFORMATION fsi;
	status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
	if (!NT_SUCCESS(status) || fsi.EndOfFile.QuadPart > 64 * 1024) {
		NtClose(hFile);
		return FALSE;
	}

	// Read file content
	SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
	char* fileContent = (char*)RtlAllocateHeap(GetProcessHeapFromPEB(), HEAP_ZERO_MEMORY, fileSize + 2);
	if (!fileContent) {
		NtClose(hFile);
		return FALSE;
	}
	status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, fileContent, (ULONG)fileSize, NULL, NULL);
	NtClose(hFile);
	if (!NT_SUCCESS(status)) {
		RtlFreeHeap(GetProcessHeapFromPEB(), 0, fileContent);
		return FALSE;
	}

	// Parse hookseq content
	HookEntry entries[64];
	int numEntries = ParseHookSeqContent(fileContent, fileSize, entries, 64);
	RtlFreeHeap(GetProcessHeapFromPEB(), 0, fileContent);

	// Process each entry
	for (int i = 0; i < numEntries; i++) {
		HookEntry* e = &entries[i];

		USHORT moduleLen = (USHORT)wcslen(e->module);
		USHORT nameLen = RemoveDllSuffix(e->module, moduleLen);
		unsigned long long dllFnvHash = ComputeFnvHash(e->module, nameLen);
		unsigned long long offsetValue = ParseHexString(e->offsetStr);

		// Open events
		WCHAR loadEventName[MAX_PATH], hookEventName[MAX_PATH];
		swprintf_s(loadEventName, NT_LOAD_NOTIFY_EVENT_FMT, processFnvHash, dllFnvHash, offsetValue);
		swprintf_s(hookEventName, NT_HOOK_NOTIFY_EVENT_FMT, processFnvHash, dllFnvHash, offsetValue);

		UNICODE_STRING usLoad, usHook;
		RtlInitUnicodeString(&usLoad, loadEventName);
		RtlInitUnicodeString(&usHook, hookEventName);

		OBJECT_ATTRIBUTES oaLoad, oaHook;
		InitializeObjectAttributes(&oaLoad, &usLoad, OBJ_CASE_INSENSITIVE, NULL, NULL);
		InitializeObjectAttributes(&oaHook, &usHook, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hLoad = NULL, hHook = NULL;
		NTSTATUS st1 = NtOpenEvent(&hLoad, EVENT_MODIFY_STATE | SYNCHRONIZE, &oaLoad);
		NTSTATUS st2 = NtOpenEvent(&hHook, EVENT_MODIFY_STATE | SYNCHRONIZE, &oaHook);
		if (!NT_SUCCESS(st1) || !NT_SUCCESS(st2)) {
			if (NT_SUCCESS(st1)) NtClose(hLoad);
			if (NT_SUCCESS(st2)) NtClose(hHook);
			continue;
		}

		// Add to list
		InstantHookTarget* node = (InstantHookTarget*)RtlAllocateHeap(GetProcessHeapFromPEB(), HEAP_ZERO_MEMORY, sizeof(InstantHookTarget));
		if (node) {
			wcscpy_s(node->targetDllName, e->module);
			node->targetDllNameLen = nameLen;
			node->dllFnvHash = dllFnvHash;
			node->offset = offsetValue;
			node->hLoadNotifyEvent = hLoad;
			node->hHookNotifyEvent = hHook;
			wcscpy_s(node->dllPath, e->dllPath);
			node->next = g_InstantHookList;
			g_InstantHookList = node;
		}
	}

	return g_InstantHookList != nullptr;
}

void __fastcall LdrLoadDll_HookHandler(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	// DbgBreakPoint();
	// rcx = PUNICODE_STRING DllName (LdrLoadDll 第一个参数 DllName)
	PUNICODE_STRING fullDllName = NULL;
#ifdef _DEBUG
	fullDllName = (PUNICODE_STRING)*(DWORD64*)pGetRdi();
#else
	fullDllName = (PUNICODE_STRING)pGetRdi();
#endif
	// EtwLog(L"Dll=%s is loaded\n", fullDllName->Buffer);
	if (!fullDllName || !fullDllName->Buffer || fullDllName->Length == 0) return;

	USHORT hashCharCount = RemoveDllSuffixFromUnicodeString(fullDllName);
	unsigned long long dllFnvHash = ComputeFnvHash(fullDllName->Buffer, hashCharCount);

	// Traverse InstantHook list
	InstantHookTarget** ppNode = &g_InstantHookList;
	while (*ppNode) {
		InstantHookTarget* node = *ppNode;
		if (node->dllFnvHash == dllFnvHash) {
			// Get current process path and calculate processFnvHash
			ULONG returnLength = 0;
			PBYTE buff[MAX_PATH * 4] = { 0 };
			NTSTATUS status = NtQueryInformationProcess(
				HANDLE(-1),
				ProcessImageFileName,
				buff,
				MAX_PATH * 4,
				&returnLength
			);
			unsigned long long processFnvHash = 0;
			if (NT_SUCCESS(status)) {
				UNICODE_STRING* us = (UNICODE_STRING*)buff;
				processFnvHash = ComputeFnvHash(us->Buffer, us->Length / sizeof(WCHAR));

				// Write current PID to hook event file
				WriteHookEventFile(processFnvHash, dllFnvHash, node->offset);
			}
			// Match! Signal LoadNotify and wait for HookNotify
			if (node->hLoadNotifyEvent) {
				EtwLog(L"signaling UMController that dll=%s is loaded with event=%llx.%llx.%llx\n", node->targetDllName, processFnvHash, dllFnvHash, node->offset);
				NtSetEvent(node->hLoadNotifyEvent, NULL);
			}
			if (node->hHookNotifyEvent) {
				// Wait for UMController to finish applying hook
				NtWaitForSingleObject(node->hHookNotifyEvent, FALSE, NULL);
				EtwLog(L"being signaled that dll=%s is hooked with hook code dll=%s", node->targetDllName, node->dllPath);
				// Close handles and remove from list
				CloseHandle(node->hLoadNotifyEvent);
				CloseHandle(node->hHookNotifyEvent);
				*ppNode = node->next;
				HeapFree(GetProcessHeap(), 0, node);
				// Continue processing remaining nodes in the list
				continue;
			}
		}
		ppNode = &node->next;
	}
}