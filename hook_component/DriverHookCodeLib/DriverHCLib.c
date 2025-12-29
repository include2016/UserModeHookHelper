#include "DriverHCLib.h"

static IHookServices* g_services = NULL;
#define HKLog(...) g_services->vtbl->LogV(g_services,__VA_ARGS__)
void SetHookServices(IHookServices* services) {
	g_services = services;
}

BOOLEAN
// STR
DRVHCLIB_STR_RtlSuffixUnicodeString(
		_In_ PUNICODE_STRING Suffix,
		_In_ PUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	)
{
	//
	// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
	//

	return String2->Length >= Suffix->Length &&
		RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - Suffix->Length) / sizeof(WCHAR),
			Suffix->Length / sizeof(WCHAR),
			Suffix->Buffer,
			Suffix->Length / sizeof(WCHAR),
			CaseInSensitive) == 0;

}

// NT
 NTSTATUS DRVHCLIB_NT_LocateImageByPID(
	_In_ HANDLE pid,
	PUNICODE_STRING* image_name_out) {
	 PUNICODE_STRING image_name;
	PEPROCESS process = NULL; 
	NTSTATUS stLookup = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
	if (NT_SUCCESS(stLookup) && process != NULL) {
		NTSTATUS st = SeLocateProcessImageName(process, &image_name);
		if (!NT_SUCCESS(st) || image_name == NULL || image_name->Length == 0) {
			// imageName not available; ensure we don't hold a stale pointer
			if (image_name) {
				ExFreePool(image_name);
				image_name = NULL;
			}
		}
		*image_name_out = image_name;
		ObDereferenceObject(process);
		return st;
	}
	else {
		if (!process) {
			HKLog(L"FATAL, can not get EPROCESS by pid");
			ObDereferenceObject(process);
			return STATUS_UNSUCCESSFUL;
		}
		if (!NT_SUCCESS(stLookup)) {
			HKLog(L"failed to call PsLookupProcessByProcessId, Status=0x%x\n", stLookup);
			ObDereferenceObject(process);
			return stLookup;
		}
	}
	return STATUS_SUCCESS;
}

 NTSTATUS
	 DRVHCLIB_NT_GetFilePathByHandle(
		 _In_ HANDLE FileHandle,
		 _Outptr_ PUNICODE_STRING* FilePath
	 )
 {
	 NTSTATUS status;
	 PFILE_OBJECT fileObject = NULL;
	 PUNICODE_STRING fileName = NULL;

	 if (!FilePath)
		 return STATUS_INVALID_PARAMETER;

	 *FilePath = NULL;

	 // Get FILE_OBJECT from handle
	 status = ObReferenceObjectByHandle(
		 FileHandle,
		 FILE_READ_ATTRIBUTES,
		 *IoFileObjectType,
		 KernelMode,
		 (PVOID*)&fileObject,
		 NULL
	 );
	 if (!NT_SUCCESS(status))
		 return status;

	 // Query DOS-style path
	 status = IoQueryFileDosDeviceName(
		 fileObject,
		(POBJECT_NAME_INFORMATION*)&fileName
	 );

	 ObDereferenceObject(fileObject);

	 if (!NT_SUCCESS(status))
		 return status;

	 // Caller must free with ExFreePool
	 *FilePath = fileName;
	 return STATUS_SUCCESS;
 }