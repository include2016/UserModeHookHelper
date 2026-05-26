#pragma once

#define RESOLVE_NTDLL_FN(hNtdll, name, pfn)                             \
	do {                                                                 \
		ANSI_STRING _rn_;                                                \
		RtlInitAnsiString(&_rn_, (PSTR)#name);                           \
		LdrGetProcedureAddress((hNtdll), &_rn_, 0, (PVOID*)&(pfn));      \
	} while (0)

typedef struct {
	const char* name;
	PVOID* ppfn;
} NTDLL_IMPORT_ENTRY;

static inline VOID ResolveNtdllImports(HANDLE hNtdll, const NTDLL_IMPORT_ENTRY* table, SIZE_T count) {
	ANSI_STRING n;
	for (SIZE_T i = 0; i < count; ++i) {
		RtlInitAnsiString(&n, (PSTR)table[i].name);
		LdrGetProcedureAddress(hNtdll, &n, 0, table[i].ppfn);
	}
}
