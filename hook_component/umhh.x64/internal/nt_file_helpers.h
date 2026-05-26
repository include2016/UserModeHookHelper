#pragma once

static inline VOID InitObjectAttrFromPath(OBJECT_ATTRIBUTES* oa,
	UNICODE_STRING* us,
	PCWSTR path) {
	RtlInitUnicodeString(us, path);
	InitializeObjectAttributes(oa, us, OBJ_CASE_INSENSITIVE, NULL, NULL);
}

static inline NTSTATUS NtOpenFileForRead(PHANDLE phFile, PCWSTR ntPath) {
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
	IO_STATUS_BLOCK iosb;
	InitObjectAttrFromPath(&oa, &us, ntPath);
	return NtOpenFile(phFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
}

static inline NTSTATUS NtCreateFileOverwrite(PHANDLE phFile, PCWSTR ntPath) {
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
	IO_STATUS_BLOCK iosb;
	InitObjectAttrFromPath(&oa, &us, ntPath);
	return NtCreateFile(phFile,
		FILE_GENERIC_WRITE | SYNCHRONIZE,
		&oa,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
}
