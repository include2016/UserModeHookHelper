# DllLoadMon.cpp 修改方案

## 发现的问题（来自 prompt_1.md）

1. **缺少 PROLOG 宏**：`DllLoadMonHook` 应该调用 `PROLOGX64`（64 位）或 `PROLOGWin32`（32 位）来获取 hook 现场的寄存器值
2. **错误的模块名提取方式**：应该将 `RDI` 寄存器强制转为 `PUNICODE_STRING`，然后与 watch list 中的 DLL 名对比
3. **缺少 WatchList 获取机制**：DllLoadMon 作为 DLL 注入到目标进程，需要从 UMController 获取 watchlist

## 参考实现

**来源**: `C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp`

### 关键模式

#### 1. PROLOG 宏用法
```cpp
// X64 版本
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

// Win32 版本
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

#### 2. 导出函数签名
```cpp
// X64
extern "C" __declspec(dllexport) VOID HookCodeX64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    PROLOGX64(rsp);
    // 访问寄存器：rdi, rsi, rbx 等
    // ...
}

// Win32
extern "C" __declspec(dllexport) VOID HookCodeWin32(ULONG esp) {
    PROLOGWin32(esp);
    // 访问寄存器：edi, esi, ebx 等
    // ...
}
```

## 需要的修改

### 1. 添加 PROLOG 宏到 DllLoadMon.cpp

**位置**: 文件顶部，includes 之后

```cpp
// 添加 PROLOG 宏（从 HookCodeTemplate/dllmain.cpp 复制）
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

### 2. 更新 DllLoadMonHook 函数签名

**当前**:
```cpp
extern "C" __declspec(dllexport)
void DllLoadMonHook(
    PVOID ModuleBase,
    HANDLE hEventLoad,
    HANDLE hEventRelease,
    PVOID WatchList
)
```

**应该是 (X64)**:
```cpp
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    PROLOGX64(rsp);
    
    // RDI 包含正在加载的 DLL 名称的 PUNICODE_STRING
    PUNICODE_STRING dllName = (PUNICODE_STRING)rdi;
    
    // 从全局指针访问共享数据
    if (!g_pSharedData) {
        return;
    }
    
    // 与 watch list 比较
    if (IsModuleInWatchList(dllName)) {
        // 检测到目标 DLL
        SetEvent(g_pSharedData->hLoadEvent);
        
        // 等待 UMController 应用 hooks
        WaitForSingleObject(g_pSharedData->hReleaseEvent, 5000);
    }
}
```

**应该是 (Win32)**:
```cpp
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_Win32(ULONG esp) {
    PROLOGWin32(esp);
    
    // EDI 包含正在加载的 DLL 名称的 PUNICODE_STRING
    PUNICODE_STRING dllName = (PUNICODE_STRING)edi;
    
    // 与 X64 版本类似的逻辑
    // ...
}
```

### 3. 更新 Watch List 比较函数

**当前**:
```cpp
static bool IsModuleInWatchList(const char* moduleName, PVOID WatchList)
```

**应该是**:
```cpp
static bool IsModuleInWatchList(PUNICODE_STRING dllName)
{
    if (!g_pSharedData || !dllName || !dllName->Buffer) {
        return false;
    }
    
    AcquireSRWLockShared(&g_pSharedData->WatchListLock);
    
    bool found = false;
    
    // 遍历 watch list
    for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
        PCWSTR watchedDll = &((WCHAR*)g_pSharedData->pModuleNameList)[i * 256];
        
        // 比较 UNICODE_STRING 与 watch list 条目
        if (_wcsnicmp(dllName->Buffer, watchedDll, dllName->Length / sizeof(WCHAR)) == 0) {
            found = true;
            break;
        }
    }
    
    ReleaseSRWLockShared(&g_pSharedData->WatchListLock);
    
    return found;
}
```

### 4. WatchList 获取机制

**问题**: DllLoadMon 作为 DLL 注入，需要从 UMController 获取 watchlist

**解决方案**: 使用 UMController 分配的共享内存

**实现**:

#### 步骤 1: UMController 在目标进程中分配共享内存
```cpp
// 在 UMController::RegisterModuleWatch 中
SIZE_T sharedDataSize = sizeof(DllLoadMonSharedData);
PVOID pSharedData = VirtualAllocEx(hProcess, NULL, sharedDataSize, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 准备 watch list 数据
std::vector<std::wstring> moduleNames = { L"ntdll", L"kernel32", ... };
SIZE_T watchListSize = moduleNames.size() * 256 * sizeof(WCHAR);
PVOID pWatchList = VirtualAllocEx(hProcess, NULL, watchListSize, 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 复制 watch list 到目标进程
for (size_t i = 0; i < moduleNames.size(); i++) {
    WriteProcessMemory(hProcess, 
                      (PBYTE)pWatchList + (i * 256 * sizeof(WCHAR)),
                      moduleNames[i].c_str(),
                      (moduleNames.size() + 1) * sizeof(WCHAR),
                      NULL);
}
```

#### 步骤 2: 写入共享数据结构到目标进程
```cpp
DllLoadMonSharedData sharedData = {0};
sharedData.hLoadEvent = hEventLoad;  // 将被复制
sharedData.hReleaseEvent = hEventRelease;
sharedData.pModuleNameList = (WCHAR*)pWatchList;
sharedData.dwWatchCount = moduleNames.size();
InitializeSRWLock(&sharedData.WatchListLock);

WriteProcessMemory(hProcess, pSharedData, &sharedData, sizeof(sharedData), NULL);
```

#### 步骤 3: 传递共享数据指针到 hook 代码
```cpp
// 调用 ApplyHook 时，传递共享数据指针作为参数
HookCore::ApplyHook(pid, ldrLoadDllRetAddress, &g_HookServices,
                   (DWORD64)DllLoadMonHook, -1, &originalAsmLen,
                   &trampolinePit, &originalAsmAddr);

// hook 代码通过 g_pSharedData 访问共享数据
```

#### 步骤 4: DllLoadMon 通过全局指针访问共享数据
```cpp
// 在 DllLoadMon.cpp 中
static DllLoadMonSharedData* g_pSharedData = nullptr;

// UMController 将共享数据的地址写入 g_pSharedData 变量
// 这需要在注入的 DLL 中找到 g_pSharedData 的地址
// 然后将实际共享数据的地址写入其中

PVOID pSharedDataInTarget = ...; // 目标进程中的地址
PVOID g_pSharedDataAddr = GetProcAddress(hDllLoadMon, "g_pSharedData");
WriteProcessMemory(hProcess, g_pSharedDataAddr, &pSharedDataInTarget, sizeof(PVOID), NULL);
```

**替代方法**: 在 DllLoadMon 中硬编码共享数据地址
```cpp
// 定义共享数据的固定地址（必须与 UMController 分配匹配）
#define SHARED_DATA_ADDRESS ((DllLoadMonSharedData*)0x7FFFFFFFF0000000)

static DllLoadMonSharedData* g_pSharedData = SHARED_DATA_ADDRESS;
```

## 实现清单

- [ ] 添加 PROLOGX64 和 PROLOGWin32 宏到 DllLoadMon.cpp
- [ ] 修改 DllLoadMonHook 签名接受 rsp/esp 参数
- [ ] 在 DllLoadMonHook 开始时调用 PROLOG 宏
- [ ] 从 RDI/EDI寄存器提取PUNICODE_STRING
- [ ] 更新 IsModuleInWatchList 接受 PUNICODE_STRING
- [ ] 实现 UNICODE_STRING 比较（不是 ANSI 字符串）
- [ ] 添加 UMController 写入共享数据指针到 DllLoadMon 的机制
- [ ] 更新 DllLoadMon.h 使用正确的函数签名
- [ ] 更新 UMController 分配共享内存和 watch list
- [ ] 更新 UMController 写入共享数据地址到 DllLoadMon 全局变量
- [ ] 测试 x64 和 x86 目标

## 关键注意事项

1. **UNICODE_STRING vs ANSI**: LdrLoadDll 使用 UNICODE_STRING (PUNICODE_STRING)，不是 ANSI 字符串
2. **RDI 寄存器**: 在 LdrLoadDll 返回上下文中，RDI 指向 PUNICODE_STRING 的 DLL 名称
3. **共享内存**: 必须在目标进程地址空间中分配
4. **全局变量注入**: UMController 必须将共享数据地址写入 `g_pSharedData` 变量到注入的 DLL
5. **架构特定**: 需要分别为 x64 (PROLOGX64) 和 x86 (PROLOGWin32) 实现不同的版本

## 参考资料

- `C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp` - PROLOG 宏参考
- `C:\Users\x\Downloads\amsi_tracer-main\doc\iteration_record\delay_hook_feature\result\result_6\DelayHook_Implementation_Plan_CN_Rev6.md` - 架构设计
- `C:\Users\x\Downloads\amsi_tracer-main\Shared\HookServices.h` - Hook 服务接口
