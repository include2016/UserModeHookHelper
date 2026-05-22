#pragma once

// LuaEngine.dll -- Lua script execution engine for user-mode hooks
// Only uses ntdll exports (same constraint as umhh.dll) so it can
// be loaded early in the target process lifecycle.

#include <ntdll.h>
#include "../../Shared/SharedMacroDef.h"
#include "../../drivers/UserModeHookHelper/UKShared.h"

// ---- ntdll function pointers (resolved at runtime) ----

typedef NTSTATUS(NTAPI* PNtCreateEvent)(
    PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
typedef NTSTATUS(NTAPI* PNtOpenEvent)(
    PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* PNtSetEvent)(HANDLE EventHandle, PLONG PreviousState);
typedef NTSTATUS(NTAPI* PNtResetEvent)(HANDLE EventHandle, PLONG PreviousState);
typedef NTSTATUS(NTAPI* PNtWaitForSingleObject)(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI* PNtClose)(HANDLE Handle);
typedef VOID(NTAPI* PRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* PLdrGetDllHandle)(
    PULONG PathToFile, ULONG Reserved, PUNICODE_STRING ModuleName,
    PVOID* ModuleHandle);
typedef NTSTATUS(NTAPI* PLdrGetProcedureAddress)(
    PVOID ModuleHandle, PANSI_STRING Name, ULONG Ordinal, PVOID* Function);
typedef NTSTATUS(NTAPI* PLdrLoadDll)(
    PULONG PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName,
    PVOID* ModuleHandle);
typedef VOID(NTAPI* PRtlZeroMemory)(PVOID Destination, ULONG Length);
typedef int(NTAPI* P_snwprintf)(wchar_t* dest, size_t count, const wchar_t* fmt, ...);
typedef int(NTAPI* P_vsnwprintf)(wchar_t* dest, size_t count, const wchar_t* fmt, va_list args);
typedef NTSTATUS(NTAPI* PNtReadFile)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(NTAPI* PNtWriteFile)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(NTAPI* PNtOpenFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(NTAPI* PNtDeleteFile)(POBJECT_ATTRIBUTES ObjectAttributes);
typedef VOID(NTAPI* PNtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER Delay);
typedef VOID(NTAPI* PRtlAddRefDll)(ULONG Flags, PVOID ModuleHandle);
typedef NTSTATUS(NTAPI *PFN_NtQueryInformationProcess)(
	HANDLE,
	PROCESSINFOCLASS,
	PVOID,
	ULONG,
	PULONG
	);
typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);
typedef NTSTATUS(NTAPI* PNtQueryInformationFile)(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass);

// ---- Resolved ntdll function pointers ----

extern PNtCreateEvent          pNtCreateEvent;
extern PNtOpenEvent            pNtOpenEvent;
extern PNtSetEvent             pNtSetEvent;
extern PNtResetEvent           pNtResetEvent;
extern PNtWaitForSingleObject  pNtWaitForSingleObject;
extern PNtClose                pNtClose;
extern PRtlInitUnicodeString   pRtlInitUnicodeString;
extern PLdrGetDllHandle        pLdrGetDllHandle;
extern PLdrGetProcedureAddress pLdrGetProcedureAddress;
extern PLdrLoadDll             pLdrLoadDll;
extern PRtlZeroMemory          pRtlZeroMemory;
extern P_snwprintf             _snwprintf_;

extern PNtReadFile             pNtReadFile;
extern PNtWriteFile            pNtWriteFile;
extern PNtOpenFile             pNtOpenFile;
extern PNtDeleteFile           pNtDeleteFile;
extern PNtDelayExecution       pNtDelay;
extern PRtlAddRefDll           pLdrAddRefDll;
extern PNtQueryInformationProcess pNtQueryInformationProcess;
extern PNtQueryInformationFile    pNtQueryInformationFile;

// ---- ETW logging ----




// ---- Lua state management ----

#define LUA_ENGINE_MAX_HOOKS 256

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

// Per-hook Lua state and function reference
struct LuaHookEntry {
    lua_State* L;
    int        funcRef;   // LUA_NOREF if not bound
};

extern LuaHookEntry g_luaHooks[LUA_ENGINE_MAX_HOOKS];

// ---- IPC event name format ----

// Controller -- LuaEngine: trigger script load for a hook_id
//   Event:   Global\LUA_ENGINE_SIGNAL.<hook_id>
//   Data:    written to export function address (same trick as umhh.dll)
//            Format: script_path_wchar + L'|' + handler_name_wchar + L'\0'
//   File:    C:\Users\Public\lua_ipc.<hook_id>  (fallback, not used initially)






// ---- Mutex to prevent double-load ----

#define LUA_ENGINE_LOAD_MUTANT_FMT L"\\BaseNamedObjects\\LUAENGINE_DLL_MUTANT.%d"
