#pragma warning(push)
#pragma warning(disable:4141)
#include <ntifs.h>
#pragma warning(pop)
typedef struct IHookServices IHookServices;

typedef struct IHookServicesVtbl {
	void(*LogV)(
		IHookServices* self,
		_In_ PCWSTR fmt,
		...
		);
} IHookServicesVtbl;

struct IHookServices {
	const IHookServicesVtbl* vtbl;
};
void SetHookServices(IHookServices* services);

// STR
BOOLEAN DRVHCLIB_STR_RtlSuffixUnicodeString(
				_In_ PUNICODE_STRING Suffix,
				_In_ PUNICODE_STRING String2,
				_In_ BOOLEAN CaseInSensitive
			);

// NT
NTSTATUS DRVHCLIB_NT_LocateImageByPID(
	_In_ HANDLE pid,
	PUNICODE_STRING* image_name_out);

NTSTATUS
DRVHCLIB_NT_GetFilePathByHandle(
	_In_ HANDLE FileHandle,
	_Outptr_ PUNICODE_STRING* FilePath
);