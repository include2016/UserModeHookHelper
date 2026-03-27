#ifndef Common_h
#define Common_h
#pragma warning(push)
#pragma warning(disable:4141)
#include <fltkernel.h>
#pragma warning(pop)
#include <ntstrsafe.h>
#include <wdm.h>

// Compatibility macros
#ifndef ExAllocatePoolZero
#define ExAllocatePoolZero(poolType, numberOfBytes, tag) ExAllocatePoolWithTag(poolType, numberOfBytes, tag)
#endif

#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED ((NTSTATUS)0xC000002DL)
#endif
#include "MacroDef.h"
#include "Tag.h"
// Global driver state has been encapsulated into dedicated modules:
// - DriverCtx (filter + server port)
// - PortCtx (client port contexts)
// - HookList (hook entries)

#endif