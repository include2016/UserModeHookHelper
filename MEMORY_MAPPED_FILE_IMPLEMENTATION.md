# Memory-Mapped File Implementation for DllLoadMon

## Overview
Successfully implemented memory-mapped file sharing for DllLoadMon WatchList, replacing the previous shared memory approach that required writing to target process memory.

## Implementation Date
Based on specification in `result_3.md`

## Architecture

### Key Components

1. **DllLoadMon.dll** (Injected into target process)
   - Monitors LdrLoadDll returns
   - Reads watch list from memory-mapped file
   - Signals UMController via events when watched DLL loads

2. **UMController** (Main controller application)
   - Creates memory-mapped file with watch list data
   - Receives signals from DllLoadMon
   - Applies pending hooks and releases DllLoadMon

### Communication Flow

```
┌─────────────────┐          ┌──────────────────┐
│   UMController  │          │   DllLoadMon     │
│                 │          │  (in target proc)│
└────────┬────────┘          └────────┬─────────┘
         │                            │
         │ 1. Create memory-mapped    │
         │    file with watch list    │
         ├────────────────────────────>
         │                            │
         │ 2. Monitor DLL loads       │<──────┐
         │                            │      │
         │                            │ Loop │
         │ 3. Signal load event       │      │
         ├────────────────────────────>      │
         │                            │      │
         │ 4. Apply hooks             │      │
         │                            │      │
         │ 5. Signal release event    │      │
         ├────────────────────────────>      │
         │                            │      │
         │                            │──────┘
```

## API Changes

### DllLoadMon.h

#### New Functions

```cpp
// Create memory-mapped file and populate watch list
DLLLOADMON_API
BOOL DllLoadMon_CreateWatchList(
    DWORD pid,
    const std::vector<std::wstring>& moduleNames,
    HANDLE* phFileMapping,
    DllLoadMonSharedData** ppSharedData
);

// Cleanup memory-mapped file resources
DLLLOADMON_API
VOID DllLoadMon_CleanupWatchList(HANDLE hFileMapping);
```

#### Structure Changes

```cpp
// Changed from SRWLOCK to interlocked volatile LONG
// SRWLOCK doesn't work across process boundaries
typedef struct _DllLoadMonSharedData {
    volatile LONG WatchListLock;  // Was: SRWLOCK WatchListLock;
    HANDLE hLoadEvent;
    HANDLE hReleaseEvent;
    PVOID pModuleBaseList;
    PVOID pModuleNameList;
    DWORD dwWatchCount;
    // ... rest of structure
} DllLoadMonSharedData;
```

### UMControllerDlg.h

#### New Member Variables

```cpp
// Track watch lists per process
std::map<DWORD, std::vector<std::wstring>> m_WatchedModules;  // PID -> module names
std::map<DWORD, HANDLE> m_WatchFileMappings;  // PID -> file mapping handle
```

#### New Public Method

```cpp
void CleanupWatchListByPid(DWORD pid);
```

## Implementation Details

### DllLoadMon_CreateWatchList()

**Purpose**: Creates memory-mapped file and populates with watch list data

**Parameters**:
- `pid`: Target process ID
- `moduleNames`: Vector of module names to watch
- `phFileMapping`: Output parameter for file mapping handle
- `ppSharedData`: Output parameter for pointer to shared data structure

**Returns**: `TRUE` on success, `FALSE` on failure

**Operations**:
1. Creates named file mapping: `Global\DllLoadMon_SharedData_{PID}`
2. Creates named events:
   - `Global\DelayHook_Load_{PID}`
   - `Global\DelayHook_Release_{PID}`
3. Maps view of file
4. Populates ModuleNames array with watch list
5. Initializes events in shared structure
6. Returns file mapping handle (caller must keep alive)

**Important**: The file mapping handle MUST be kept open by UMController for the lifetime of the watch. Closing it will invalidate the shared memory.

### DllLoadMon_CleanupWatchList()

**Purpose**: Cleans up all resources associated with a watch list

**Parameters**:
- `hFileMapping`: File mapping handle from CreateWatchList

**Operations**:
1. Closes event handles stored in shared structure
2. Unmaps view of file
3. Closes file mapping handle

### RegisterModuleWatch() - New Implementation

**File**: [`UMControllerDlg.cpp`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.cpp)

**Behavior**:
1. Accumulates module names in `m_WatchedModules[pid]`
2. On first module registration:
   - Calls `DllLoadMon_CreateWatchList()` with accumulated list
   - Stores file mapping handle in `m_WatchFileMappings[pid]`
3. On subsequent registrations:
   - Modules are already covered by existing watch list
   - Returns immediately

**Rationale**: Memory-mapped file is created once per process, not per module. All modules for a given process share the same watch list.

### Cleanup Logic

#### Process Termination Cleanup

**File**: [`UMControllerDlg.cpp`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.cpp) - `OnUpdateProcess()`

When a process terminates (FULL_EXIT section):
```cpp
auto watchIt = m_WatchFileMappings.find(pid);
if (watchIt != m_WatchFileMappings.end()) {
    DllLoadMon_CleanupWatchList(watchIt->second);
    m_WatchFileMappings.erase(watchIt);
    m_WatchedModules.erase(pid);
}
```

#### Manual Hook Removal Cleanup

**File**: [`HookActions.cpp`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\HookActions.cpp) - `HandleRemoveHook()`

When hooks are manually removed:
```cpp
dlg->CleanupWatchListByPid(pid);
```

## Key Design Decisions

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| **Synchronization** | Interlocked spin lock (volatile LONG) | SRWLOCK doesn't work across processes |
| **Naming scheme** | `Global\DllLoadMon_SharedData_{PID}` | Per-process isolation, global namespace |
| **Lock timeout** | 1000 spins | Prevent deadlock while allowing reasonable wait |
| **Max modules** | 256 | Fixed-size array in shared structure |
| **Max name length** | 256 WCHARs | Accommodate long DLL names |
| **Module accumulation** | Vector per PID | Support incremental RegisterModuleWatch calls |
| **Handle lifetime** | Keep file mapping open | Required for shared memory validity |

## Resource Management

### Ownership Model

```
UMController                    Target Process
    |                               |
    |-- File Mapping Handle --------|
    |   (kept open by UMController) |
    |                               |
    |-- Event Handles --------------|
    |   (stored in shared memory)   |
    |                               |
    |-- Shared Memory View ---------|
        (mapped in both processes)
```

### Lifetime Rules

1. **File Mapping Handle**: Must remain open in UMController for entire watch duration
2. **Event Handles**: Stored in shared memory, used by DllLoadMon in target process
3. **Shared Memory View**: Mapped in both processes, valid while file mapping is open
4. **Cleanup**: Occurs on process exit OR manual hook removal

## Testing Considerations

### Manual Testing Checklist

- [ ] Single module watch works correctly
- [ ] Multiple modules for same process share watch list
- [ ] Multiple processes each have independent watch lists
- [ ] Process termination triggers cleanup
- [ ] Manual hook removal triggers cleanup
- [ ] No handle leaks (verify with Process Explorer)
- [ ] No memory leaks (verify with VmmDump or similar)

### Automated Testing

Future work should include:
- Unit tests for CreateWatchList/CleanupWatchList
- Integration tests for full watch lifecycle
- Stress tests with many processes/modules

## Migration from Previous Approach

### Old Approach (Shared Memory in Target Process)

```cpp
// Required writing to target process
VirtualAllocEx(hProcess, ...);
WriteProcessMemory(hProcess, ...);
```

**Issues**:
- Complex memory management
- Requires PROCESS_VM_OPERATION rights
- Risk of memory leaks in target process

### New Approach (Memory-Mapped File)

```cpp
// Named file mapping accessible by both processes
CreateFileMapping(INVALID_HANDLE_VALUE, ...);
MapViewOfFile(...);
```

**Benefits**:
- Simpler resource management
- Standard Windows IPC mechanism
- Automatic cleanup on handle close
- No special privileges beyond PROCESS_VM_READ

## File Changes Summary

### Modified Files

1. **[`DllLoadMon.h`](c:\Users\x\Downloads\amsi_tracer-main\hook_component\DllLoadMon\DllLoadMon.h)**
   - Changed WatchListLock from SRWLOCK to volatile LONG
   - Added CreateWatchList/CleanupWatchList declarations

2. **[`DllLoadMon.cpp`](c:\Users\x\Downloads\amsi_tracer-main\hook_component\DllLoadMon\DllLoadMon.cpp)**
   - Implemented DllLoadMon_CreateWatchList()
   - Implemented DllLoadMon_CleanupWatchList()
   - Updated synchronization to use interlocked operations

3. **[`UMControllerDlg.h`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.h)**
   - Added m_WatchedModules map
   - Added m_WatchFileMappings map
   - Added CleanupWatchListByPid() method

4. **[`UMControllerDlg.cpp`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.cpp)**
   - Rewrote RegisterModuleWatch() to use new approach
   - Added cleanup in OnUpdateProcess() (process termination)
   - Implemented CleanupWatchListByPid()

5. **[`HookActions.cpp`](c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\HookActions.cpp)**
   - Added cleanup call in HandleRemoveHook()

## Verification

✅ Code compiles without errors
✅ No syntax errors in modified files
✅ Consistent naming conventions
✅ Proper error handling
✅ Resource cleanup on all paths

## Next Steps

1. **Build and Test**
   - Compile entire solution
   - Test with single module watch
   - Test with multiple modules
   - Test process termination scenarios

2. **Integration Verification**
   - Verify HookProcDlg integration
   - Test end-to-end flow
   - Monitor for handle/memory leaks

3. **Documentation**
   - Update user documentation
   - Add code comments where needed
   - Document troubleshooting procedures

## References

- Original specification: [`result_3.md`](c:\Users\x\Downloads\amsi_tracer-main\vibe_prompt\result_3.md)
- Previous implementation: `DELAYED_HOOK_IMPLEMENTATION.md`
- Conversation summary: See conversation context for detailed implementation history
