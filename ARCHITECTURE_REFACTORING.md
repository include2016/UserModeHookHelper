# Architecture Refactoring - Module Decoupling

## Date
March 30, 2026

## Objective
Execute architectural improvements specified in `prompt_4.md` to decouple UMController from DllLoadMon module.

## Problems Addressed

### 1. Module Coupling
**Before**: UMController directly included `DllLoadMon.h` and called its export functions:
- `DllLoadMon_Initialize()`
- `DllLoadMon_CreateWatchList()`
- `DllLoadMon_CleanupWatchList()`

**Issue**: This violated module separation principles. UMController should manage memory-mapped file infrastructure independently; DllLoadMon should only provide hook logic.

### 2. Initialization Responsibility
**Before**: UMController called `DllLoadMon_Initialize()` to set up shared data.

**Issue**: Initialization should happen automatically when DllLoadMon is loaded into the target process via `DllMain`.

## Changes Made

### 1. Created Shared Header (`Shared/DllLoadMonShared.h`)
**Purpose**: Define shared data structures accessible by both UMController and DllLoadMon without module coupling.

**Contents**:
```cpp
#ifndef _DLL_LOAD_MON_SHARED_H_
#define _DLL_LOAD_MON_SHARED_H_

#include <windows.h>

#define DLM_MAX_WATCHED_MODULES 256
#define DLM_MAX_MODULE_NAME_LEN 64

typedef struct _DllLoadMonSharedData {
    volatile LONG WatchListLock;      // Spin lock
    UINT ModuleCount;                  // Number of modules in watch list
    UINT Reserved[3];                  // Alignment
    HANDLE hLoadEvent;                 // Event: signal when module load detected
    HANDLE hReleaseEvent;              // Event: signal when hook processing complete
    WCHAR ModuleNames[DLM_MAX_WATCHED_MODULES][DLM_MAX_MODULE_NAME_LEN];
} DllLoadMonSharedData;

#endif // _DLL_LOAD_MON_SHARED_H_
```

### 2. Updated DllLoadMon.h
**Removed**:
- `DllLoadMon_Initialize()` declaration
- `DllLoadMon_CreateWatchList()` declaration  
- `DllLoadMon_CleanupWatchList()` declaration

**Kept**:
- `DllLoadMonHook_X64()` - Hook logic entry point
- `DllLoadMonHook_Win32()` - Hook logic entry point

**Added**:
- `#include "../../Shared/DllLoadMonShared.h"` - Include shared structure definition

### 3. Updated DllLoadMon.cpp
**Deleted Functions** (~200 lines):
- `DllLoadMon_Initialize()` - No longer needed, initialization happens in DllMain
- `DllLoadMon_CreateWatchList()` - UMController now implements this directly
- `DllLoadMon_CleanupWatchList()` - UMController now implements this directly

**Retained**:
- `DllMain()` - Automatic initialization when loaded into target process
- `DllLoadMonHook_X64()` / `DllLoadMonHook_Win32()` - Hook logic
- Shared data management inside target process

### 4. Updated DllLoadMon.def
**Removed Export**:
```
-    DllLoadMon_Initialize @2 PRIVATE
```

**Remaining Export**:
```
EXPORTS
    DllLoadMonHook @1 PRIVATE
```

### 5. Updated UMControllerDlg.cpp
**Changed Include**:
```cpp
- #include "../hook_component/DllLoadMon/DllLoadMon.h"
+ #include "../../Shared/DllLoadMonShared.h"
```

**Updated `RegisterModuleWatch()`**:
- Replaced call to `DllLoadMon_CreateWatchList()` with inline implementation
- Now directly calls Windows API:
  - `CreateFileMappingW()` - Create shared memory
  - `MapViewOfFile()` - Map shared memory view
  - `CreateEventW()` - Create synchronization events
  - Populates `DllLoadMonSharedData` structure directly

**Updated Process Exit Handler**:
- Replaced call to `DllLoadMon_CleanupWatchList()` with inline cleanup
- Directly closes handles:
  - Event handles from shared structure
  - File mapping handle via `CloseHandle()`
  - Unmaps view via `UnmapViewOfFile()`

**Added Method**:
```cpp
void CUMControllerDlg::CleanupWatchListByPid(DWORD pid)
```
- Encapsulates cleanup logic for reuse (called from HookActions.cpp)

### 6. Updated UMControllerDlg.h
**No changes required** - Member variables remain the same:
- `std::map<DWORD, std::vector<std::wstring>> m_WatchedModules`
- `std::map<DWORD, HANDLE> m_WatchFileMappings`

## Architectural Benefits

### 1. Module Independence
- **UMController**: Owns memory-mapped file lifecycle, no dependency on DllLoadMon exports
- **DllLoadMon**: Only provides hook logic, auto-initializes in DllMain

### 2. Clear Responsibilities
- **Infrastructure** (memory-mapped files, events): UMController
- **Hook Logic** (detouring, code injection): DllLoadMon

### 3. Reduced Coupling
- Shared structures defined in independent header (`Shared/DllLoadMonShared.h`)
- Both modules include shared header, but don't depend on each other
- Follows dependency inversion principle

### 4. Simplified Initialization
- No explicit initialization call from UMController
- DllLoadMon initializes automatically when loaded via `DllMain`
- Reduces chance of initialization order bugs

## Testing Checklist

- [ ] Build solution - verify no compilation errors
- [ ] Verify DllLoadMon.dll exports only `DllLoadMonHook`
- [ ] Test module loading - verify DllMain initialization works
- [ ] Test hook injection - verify memory-mapped file communication works
- [ ] Test process exit - verify cleanup happens correctly
- [ ] Test delayed hooking - verify event synchronization works

## Files Modified

1. `Shared/DllLoadMonShared.h` - Created
2. `hook_component/DllLoadMon/DllLoadMon.h` - Removed helper declarations
3. `hook_component/DllLoadMon/DllLoadMon.cpp` - Deleted helper functions
4. `hook_component/DllLoadMon/DllLoadMon.def` - Removed export
5. `controller/UMController/UMControllerDlg.cpp` - Inlined memory-mapped file logic
6. `controller/UMController/UMControllerDlg.h` - No changes (member variables unchanged)

## Migration Notes

### For Developers
If you need to use DllLoadMon functionality in new code:

1. **For shared data structures**: Include `../../Shared/DllLoadMonShared.h`
2. **For hook logic**: Call `DllLoadMonHook_X64()` or `DllLoadMonHook_Win32()`
3. **For memory-mapped file management**: Implement directly in your module (see `UMControllerDlg.cpp::RegisterModuleWatch()` for example)

### DO NOT
- ❌ Include `DllLoadMon.h` in UMController or other controller modules
- ❌ Call initialization functions - DllMain handles this
- ❌ Expect helper functions - they've been removed

## Related Documents
- `prompt_4.md` - Original architectural improvement requirements
- `MEMORY_MAPPED_FILE_IMPLEMENTATION.md` - Previous implementation details (now obsolete)
- `result_3.md` - Initial memory-mapped file specification
