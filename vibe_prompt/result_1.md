# DllLoadMon.cpp Modification Plan

## Problems Identified (from prompt_1.md)

1. **Missing PROLOG Macro**: `DllLoadMonHook` should call `PROLOGX64` (64-bit) or `PROLOGWin32` (32-bit) to capture register values from hook context
2. **Incorrect Module Name Extraction**: Should cast `RDI` register to `PUNICODE_STRING` and compare with watch list DLL names
3. **Missing WatchList Retrieval Mechanism**: DllLoadMon is injected as DLL into target process, needs mechanism to get watchlist from UMController

## Reference Implementation

**Source**: `C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp`

### Key Patterns to Follow

#### 1. PROLOG Macro Usage
```cpp
// X64 version
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                     \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);          \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);          \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);         \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);         \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);         \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);         \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);         \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);         \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);         \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);         \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

// Win32 version
#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
    ULONG original_esp = (esp) + 0x20;                                       \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                   \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                   \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                   \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                   \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                  \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                  \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);
```

#### 2. Export Function Signature
```cpp
// X64
extern "C" __declspec(dllexport) VOID HookCodeX64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    PROLOGX64(rsp);
    // Access registers: rdi, rsi, rbx, etc.
    // ...
}

// Win32
extern "C" __declspec(dllexport) VOID HookCodeWin32(ULONG esp) {
    PROLOGWin32(esp);
    // Access registers: edi, esi, ebx, etc.
    // ...
}
```

## Required Modifications

### 1. Add PROLOG Macros to DllLoadMon.cpp

**Location**: Top of file, after includes

```cpp
// Add PROLOG macros (copy from HookCodeTemplate/dllmain.cpp)
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                            \
        return;                                                              \
    }                                                                        \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                     \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);          \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);          \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);         \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);         \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);         \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);         \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);         \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);         \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);         \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);         \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                            \
        return;                                                              \
    }                                                                        \
    ULONG original_esp = (esp) + 0x20;                                       \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                   \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                   \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                   \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                   \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                  \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                  \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);
```

### 2. Update DllLoadMonHook Function Signature

**Current**:
```cpp
extern "C" __declspec(dllexport)
void DllLoadMonHook(
    PVOID ModuleBase,
    HANDLE hEventLoad,
    HANDLE hEventRelease,
    PVOID WatchList
)
```

**Should be (X64)**:
```cpp
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    PROLOGX64(rsp);
    
    // RDI contains PUNICODE_STRING of DLL name being loaded
    PUNICODE_STRING dllName = (PUNICODE_STRING)rdi;
    
    // Access shared data from global pointer
    if (!g_pSharedData) {
        return;
    }
    
    // Compare with watch list
    if (IsModuleInWatchList(dllName)) {
        // Target DLL detected
        SetEvent(g_pSharedData->hLoadEvent);
        
        // Wait for UMController to apply hooks
        WaitForSingleObject(g_pSharedData->hReleaseEvent, 5000);
    }
}
```

**Should be (Win32)**:
```cpp
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_Win32(ULONG esp) {
    PROLOGWin32(esp);
    
    // EDI contains PUNICODE_STRING of DLL name being loaded
    PUNICODE_STRING dllName = (PUNICODE_STRING)edi;
    
    // Similar logic as X64 version
    // ...
}
```

### 3. Update Watch List Comparison Function

**Current**:
```cpp
static bool IsModuleInWatchList(const char* moduleName, PVOID WatchList)
```

**Should be**:
```cpp
static bool IsModuleInWatchList(PUNICODE_STRING dllName)
{
    if (!g_pSharedData || !dllName || !dllName->Buffer) {
        return false;
    }
    
    AcquireSRWLockShared(&g_pSharedData->WatchListLock);
    
    bool found = false;
    
    // Iterate through watch list
    for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
        PCWSTR watchedDll = &((WCHAR*)g_pSharedData->pModuleNameList)[i * 256];
        
        // Compare UNICODE_STRING with watch list entry
        if (_wcsnicmp(dllName->Buffer, watchedDll, dllName->Length / sizeof(WCHAR)) == 0) {
            found = true;
            break;
        }
    }
    
    ReleaseSRWLockShared(&g_pSharedData->WatchListLock);
    
    return found;
}
```

### 4. WatchList Retrieval Mechanism

**Problem**: DllLoadMon is injected as DLL, needs to get watchlist from UMController

**Solution**: Use shared memory allocated by UMController

**Implementation**:

#### Step 1: UMController allocates shared memory in target process
```cpp
// In UMController::RegisterModuleWatch
SIZE_T sharedDataSize = sizeof(DllLoadMonSharedData);
PVOID pSharedData = VirtualAllocEx(hProcess, NULL, sharedDataSize, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Prepare watch list data
std::vector<std::wstring> moduleNames = { L"ntdll", L"kernel32", ... };
SIZE_T watchListSize = moduleNames.size() * 256 * sizeof(WCHAR);
PVOID pWatchList = VirtualAllocEx(hProcess, NULL, watchListSize, 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Copy watch list to target process
for (size_t i = 0; i < moduleNames.size(); i++) {
    WriteProcessMemory(hProcess, 
                      (PBYTE)pWatchList + (i * 256 * sizeof(WCHAR)),
                      moduleNames[i].c_str(),
                      (moduleNames.size() + 1) * sizeof(WCHAR),
                      NULL);
}
```

#### Step 2: Write shared data structure to target process
```cpp
DllLoadMonSharedData sharedData = {0};
sharedData.hLoadEvent = hEventLoad;  // Will be duplicated
sharedData.hReleaseEvent = hEventRelease;
sharedData.pModuleNameList = (WCHAR*)pWatchList;
sharedData.dwWatchCount = moduleNames.size();
InitializeSRWLock(&sharedData.WatchListLock);

WriteProcessMemory(hProcess, pSharedData, &sharedData, sizeof(sharedData), NULL);
```

#### Step 3: Pass shared data pointer to hook code
```cpp
// When calling ApplyHook, pass shared data pointer as parameter
HookCore::ApplyHook(pid, ldrLoadDllRetAddress, &g_HookServices,
                   (DWORD64)DllLoadMonHook, -1, &originalAsmLen,
                   &trampolinePit, &originalAsmAddr);

// The hook code accesses g_pSharedData which is set via shared memory
```

#### Step 4: DllLoadMon accesses shared data via global pointer
```cpp
// In DllLoadMon.cpp
static DllLoadMonSharedData* g_pSharedData = nullptr;

// UMController writes the address of shared data to g_pSharedData variable
// This requires finding the address of g_pSharedData in the injected DLL
// and writing the actual shared data address to it

PVOID pSharedDataInTarget = ...; // Address in target process
PVOID g_pSharedDataAddr = GetProcAddress(hDllLoadMon, "g_pSharedData");
WriteProcessMemory(hProcess, g_pSharedDataAddr, &pSharedDataInTarget, sizeof(PVOID), NULL);
```

**Alternative Approach**: Hardcode shared data address in DllLoadMon
```cpp
// Define a fixed address for shared data (must match UMController allocation)
#define SHARED_DATA_ADDRESS ((DllLoadMonSharedData*)0x7FFFFFFFF0000000)

static DllLoadMonSharedData* g_pSharedData = SHARED_DATA_ADDRESS;
```

## Implementation Checklist

- [ ] Add PROLOGX64 and PROLOGWin32 macros to DllLoadMon.cpp
- [ ] Change DllLoadMonHook signature to accept rsp/esp parameter
- [ ] Call PROLOG macro at start of DllLoadMonHook
- [ ] Extract PUNICODE_STRING from RDI/EDI register
- [ ] Update IsModuleInWatchList to accept PUNICODE_STRING
- [ ] Implement UNICODE_STRING comparison (not ANSI string)
- [ ] Add mechanism for UMController to write shared data pointer to DllLoadMon
- [ ] Update DllLoadMon.h with correct function signatures
- [ ] Update UMController to allocate shared memory and watch list
- [ ] Update UMController to write shared data address to DllLoadMon global variable
- [ ] Test with both x64 and x86 targets

## Critical Notes

1. **UNICODE_STRING vs ANSI**: LdrLoadDll uses UNICODE_STRING (PUNICODE_STRING), not ANSI strings
2. **RDI Register**: In LdrLoadDll return context, RDI points to PUNICODE_STRING of DLL name
3. **Shared Memory**: Must be allocated in target process address space
4. **Global Variable Injection**: UMController must write shared data address to `g_pSharedData` variable in injected DLL
5. **Architecture Specific**: Need separate implementations for x64 (PROLOGX64) and x86 (PROLOGWin32)

## References

- `C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp` - PROLOG macro reference
- `C:\Users\x\Downloads\amsi_tracer-main\doc\iteration_record\delay_hook_feature\result\result_6\DelayHook_Implementation_Plan_CN_Rev6.md` - Architecture design
- `C:\Users\x\Downloads\amsi_tracer-main\Shared\HookServices.h` - Hook services interface
