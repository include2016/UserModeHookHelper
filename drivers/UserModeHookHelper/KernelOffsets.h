#ifndef KERNELOFFSETS_H
#define KERNELOFFSETS_H

#include "Common.h"
#include "DriverCtx.h"
#include "Trace.h"

typedef struct _EPROCESS_OFFSETS {
	ULONG ProtectionOffset;
	ULONG SectionSignatureLevelOffset;
	struct _ACG_MitigationOffPos {
		ULONG mitigation_offset;
		UCHAR acg_pos;
		UCHAR acg_audit_pos;
	}ACG_MitigationOffPos;
	// EPROCESS -> Peb pointer offset (varies by build)
	ULONG PebOffset;
} EPROCESS_OFFSETS, *PEPROCESS_OFFSETS;
typedef struct _EPROCESS_ORI_VALUE {
	UCHAR  ProtectionValue;
	UCHAR SectionSignatureLevelValue;
} EPROCESS_ORI_VALUE, *PEPROCESS_ORI_VALUE;

// Offsets for traversing FLT_FILTER -> FLT_OPERATION_REGISTRATION
// to locate minifilter section synchronization (IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)
// callbacks. Based on _FLT_FILTER layout:
//   +0x1A0 SectionNotification (PVOID)
//   +0x1A8 Operations         (PFLT_OPERATION_REGISTRATION)
typedef struct _FLT_FILTER_OFFSETS {
	ULONG FltFilterToOps; // FLT_FILTER* -> Operations (FLT_OPERATION_REGISTRATION*) pointer offset
} FLT_FILTER_OFFSETS, *PFLT_FILTER_OFFSETS;

// Returns NTSTATUS:
//   STATUS_SUCCESS          — offsets found and filled
//   STATUS_NOT_SUPPORTED    — build not in table (unsupported OS version)
//   STATUS_DRIVER_INTERNAL_ERROR — build in table but offsets not yet filled (TBD)
NTSTATUS KO_GetFltFilterOffsets(PFLT_FILTER_OFFSETS Offsets);

// Returns TRUE and fills offsets when found based on OS version.
// Uses YAML files under "\??\C:\Users\x\Pictures\1\.vs\1" that encode
// kernel structure offsets for Win10/Win11.
BOOLEAN KO_GetEprocessOffsets(PEPROCESS_OFFSETS Offsets);

#endif
