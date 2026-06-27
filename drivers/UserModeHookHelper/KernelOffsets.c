#include "KernelOffsets.h"
// Exact per-build offsets table (generated); no ranges.
typedef struct _BUILD_OFFSETS {
	ULONG Build;
	ULONG Prot;
	ULONG SecSig;
	// add an inner structure for MitigationFlag and ACG
	struct __ACG_MitigationOffPos {
		ULONG mitigation_offset;
		UCHAR acg_pos;
		UCHAR acg_audit_pos;
	}_ACG_MitigationOffPos;
	ULONG Peb; // EPROCESS -> Peb pointer offset
} BUILD_OFFSETS;

// This file can be auto-generated from version offset sources.
// Peb offsets: Win10 (10240-20348) = 0x3F8, Win11 (22000+) = 0x550
static const BUILD_OFFSETS g_BuildOffsets[] = {
	{10240,  0x6AA, 0x6A9, {0,0,0},          0x3F8},
	{10586,  0x6B1, 0x6B0, {0,0,0},          0x3F8},
	{14393,  0x6C2, 0x6C1, {0,0,0},          0x3F8},
	{15063,  0x6CA, 0x6C9, {0,0,0},          0x3F8},
	{16299,  0x6Ca, 0x6C9, {0x828,0x8,0xb},  0x3F8},
	{17134,  0x6Ca, 0x6C9, {0,0,0},          0x3F8},
	{17763,  0x6Ca, 0x6C9, {0,0,0},          0x3F8},
	{18362,  0x6FA, 0x6F9, {0,0,0},          0x3F8},
	{19041,  0x87A, 0x879, {0,0,0},          0x3F8},
	{19042,  0x87A, 0x879, {0,0,0},          0x3F8},
	{19043,  0x87A, 0x879, {0,0,0},          0x3F8},
	{19044,  0x87A, 0x879, {0,0,0},          0x3F8},
	{19045,  0x87A, 0x879, {0,0,0},          0x3F8},
	{20348,  0x87A, 0x879, {0,0,0},          0x3F8},
	{22000,  0x87A, 0x879, {0,0,0},          0x550},
	{22621,  0x87A, 0x879, {0,0,0},          0x550},
	{22631,  0x87A, 0x879, {0x9d0,0x8,0xb},  0x550},
	{26100,  0x5FA, 0x5F9, {0,0,0},          0x550},
	{26200,  0x5FA, 0x5F9, {0,0,0},          0x550},
};

static int FindOffsetsExact(ULONG build, const BUILD_OFFSETS* table, int count)
{
	for (int i = 0; i < count; ++i) {
		if (table[i].Build == build) { return i; }
	}
	return -1;
}

BOOLEAN KO_GetEprocessOffsets(PEPROCESS_OFFSETS Offsets)
{
	if (!Offsets) return FALSE;
	DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();

	int ok = FindOffsetsExact(ver.Build, g_BuildOffsets, RTL_NUMBER_OF(g_BuildOffsets));
	if (ok < 0) {
		Log(L"not supported version, build number=%u\n", ver.Build);
		return FALSE;
	}
	static BOOLEAN s_loggedOnce = FALSE;
	if (!s_loggedOnce) {
		Log(L"get EPROCESS kernel structure offset successfully, build number=%u\n", ver.Build);
		s_loggedOnce = TRUE;
	}
	Offsets->ProtectionOffset = g_BuildOffsets[ok].Prot;
	Offsets->SectionSignatureLevelOffset = g_BuildOffsets[ok].SecSig;
	Offsets->ACG_MitigationOffPos.mitigation_offset = g_BuildOffsets[ok]._ACG_MitigationOffPos.mitigation_offset;
	Offsets->ACG_MitigationOffPos.acg_pos = g_BuildOffsets[ok]._ACG_MitigationOffPos.acg_pos;
	Offsets->ACG_MitigationOffPos.acg_audit_pos = g_BuildOffsets[ok]._ACG_MitigationOffPos.acg_audit_pos;
	Offsets->PebOffset = g_BuildOffsets[ok].Peb;
	return TRUE;
}

// --- FLT_FILTER offset table ---
// FLT_FILTER -> Operations (FLT_OPERATION_REGISTRATION*) offset per build.
// Build 19045 verified: 0x1A8
typedef struct _FLT_FILTER_BUILD_OFFSETS {
	ULONG Build;
	ULONG FltFilterToOps; // FLT_FILTER* -> Operations pointer offset
} FLT_FILTER_BUILD_OFFSETS;

// Fill in per build. 0 = TBD.
static const FLT_FILTER_BUILD_OFFSETS g_FltFilterBuildOffsets[] = {
	{10240,  0},
	{10586,  0},
	{14393,  0},
	{15063,  0},
	{16299,  0},
	{17134,  0},
	{17763,  0},
	{18362,  0},
	{19041,  0},
	{19042,  0},
	{19043,  0},
	{19044,  0},
	{19045,  0x1A8},
	{20348,  0},
	{22000,  0},
	{22621,  0},
	{22631,  0},
	{26100,  0},
	{26200,  0},
};

static int FindFltFilterOffsetsExact(ULONG build, const FLT_FILTER_BUILD_OFFSETS* table, int count)
{
	for (int i = 0; i < count; ++i) {
		if (table[i].Build == build) { return i; }
	}
	return -1;
}

NTSTATUS KO_GetFltFilterOffsets(PFLT_FILTER_OFFSETS Offsets)
{
	if (!Offsets) return STATUS_INVALID_PARAMETER;
	DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();

	int ok = FindFltFilterOffsetsExact(ver.Build, g_FltFilterBuildOffsets, RTL_NUMBER_OF(g_FltFilterBuildOffsets));
	if (ok < 0) {
		Log(L"not supported version for FLT_FILTER offsets, build number=%u\n", ver.Build);
		return STATUS_NOT_SUPPORTED;
	}

	Offsets->FltFilterToOps = g_FltFilterBuildOffsets[ok].FltFilterToOps;

	if (Offsets->FltFilterToOps == 0) {
		Log(L"FLT_FILTER offsets not yet filled for build=%u\n", ver.Build);
		return STATUS_DRIVER_INTERNAL_ERROR;
	}

	static BOOLEAN s_loggedOnce = FALSE;
	if (!s_loggedOnce) {
		Log(L"get FLT_FILTER kernel structure offset successfully, build number=%u\n", ver.Build);
		s_loggedOnce = TRUE;
	}
	return STATUS_SUCCESS;
}
