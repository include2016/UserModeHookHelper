#pragma once
#include <stddef.h>
#include <string.h>

typedef struct HookEntry {
	wchar_t module[MAX_PATH];
	wchar_t offsetStr[32];
	wchar_t dllPath[MAX_PATH];
	wchar_t exportName[MAX_PATH];
	wchar_t script[MAX_PATH];
	wchar_t handler[256];
} HookEntry;

VOID CopyCharToWchar(WCHAR* dst, CHAR* src, SIZE_T len);

typedef struct {
	const char* key;
	SIZE_T fieldOffset;
	SIZE_T maxChars;
} HOOKSEQ_FIELD;

static const HOOKSEQ_FIELD kHookSeqFields[] = {
	{ "module", offsetof(HookEntry, module), MAX_PATH - 1 },
	{ "offset", offsetof(HookEntry, offsetStr), 31 },
	{ "dllPath", offsetof(HookEntry, dllPath), MAX_PATH - 1 },
	{ "export", offsetof(HookEntry, exportName), MAX_PATH - 1 },
	{ "script", offsetof(HookEntry, script), MAX_PATH - 1 },
	{ "handler", offsetof(HookEntry, handler), 255 },
};

static inline void AssignHookSeqField(HookEntry* e, const char* key, const char* val) {
	for (SIZE_T i = 0; i < RTL_NUMBER_OF(kHookSeqFields); ++i) {
		if (strcmp(key, kHookSeqFields[i].key) == 0) {
			WCHAR* dst = (WCHAR*)((BYTE*)e + kHookSeqFields[i].fieldOffset);
			CopyCharToWchar(dst, (CHAR*)val, kHookSeqFields[i].maxChars);
			return;
		}
	}
}
