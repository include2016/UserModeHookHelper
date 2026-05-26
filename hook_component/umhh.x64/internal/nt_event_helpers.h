#pragma once
#include <stdarg.h>

typedef int(__cdecl *umhh_vsnwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	va_list args
	);

// Must be resolved by caller (dllmain.cpp resolves it in OnProcessAttach).
extern umhh_vsnwprintf_fn_t _vsnwprintf_;

static inline VOID InitNullDaclSd(SECURITY_DESCRIPTOR* sd) {
	RtlZeroMemory(sd, sizeof(*sd));
	sd->Revision = 1;
	sd->Control = SE_DACL_PRESENT;
	sd->Dacl = NULL;
}

static inline NTSTATUS CreateNamedEventByName(_Out_ PHANDLE phEvent,
	_In_ EVENT_TYPE type,
	_In_ BOOLEAN initialState,
	_In_opt_ SECURITY_DESCRIPTOR* pSd,
	_In_ PCWSTR name) {
	UNICODE_STRING usName;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&usName, name);
	InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, NULL, pSd);
	return NtCreateEvent(phEvent, EVENT_ALL_ACCESS, &oa, type, initialState);
}

static inline NTSTATUS PulseNamedEventByName(_In_ PCWSTR name) {
	UNICODE_STRING usName;
	OBJECT_ATTRIBUTES oa;
	HANDLE hEvent = NULL;
	RtlInitUnicodeString(&usName, name);
	InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = NtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);
	if (NT_SUCCESS(status)) {
		NtSetEvent(hEvent, NULL);
		NtClose(hEvent);
	}
	return status;
}

static inline NTSTATUS CreateNamedEventF(_Out_ PHANDLE phEvent,
	_In_ EVENT_TYPE type,
	_In_ BOOLEAN initialState,
	_In_opt_ SECURITY_DESCRIPTOR* pSd,
	_In_ PCWSTR fmt, ...) {
	WCHAR name[260];
	va_list args;
	va_start(args, fmt);
	if (!_vsnwprintf_) {
		va_end(args);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	_vsnwprintf_(name, RTL_NUMBER_OF(name) - 1, fmt, args);
	va_end(args);
	name[RTL_NUMBER_OF(name) - 1] = L'\0';
	return CreateNamedEventByName(phEvent, type, initialState, pSd, name);
}

static inline NTSTATUS PulseNamedEventF(PCWSTR fmt, ...) {
	WCHAR name[260];
	va_list args;
	va_start(args, fmt);
	if (!_vsnwprintf_) {
		va_end(args);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	_vsnwprintf_(name, RTL_NUMBER_OF(name) - 1, fmt, args);
	va_end(args);
	name[RTL_NUMBER_OF(name) - 1] = L'\0';
	return PulseNamedEventByName(name);
}
