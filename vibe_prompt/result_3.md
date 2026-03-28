# DllLoadMon WatchList 获取机制 - 基于文件映射的方案

## 修改意见（来自 prompt_2.md）

**原方案问题**：
- 使用共享内存需要 UMController 向目标进程中写入内存
- 涉及进程句柄权限问题（PROCESS_ALL_ACCESS 或 PROCESS_VM_OPERATION）
- 在某些场景下可能无法获取足够的权限

**新方案要求**：
- 使用文件进行数据共享
- 避免直接写入目标进程内存
- 降低权限要求

## 推荐方案：内存映射文件（Memory-Mapped File）

### 方案概述

使用 Windows 内存映射文件（Memory-Mapped File）机制，通过命名文件映射对象在 UMController 和 DllLoadMon 之间共享数据。

**优势**：
- ✅ 不需要向目标进程写入内存
- ✅ 只需要标准的文件映射权限
- ✅ 支持命名全局对象，跨进程访问
- ✅ 自动处理内存管理
- ✅ 更好的安全性和隔离性

### 架构设计

```
┌─────────────────┐                    ┌─────────────────┐
│  UMController   │                    │   Target Process│
│                 │                    │   (DllLoadMon)  │
│                 │                    │                 │
│  CreateFileMapping ────────────────► │ OpenFileMapping │
│  (Global\Name)  │                    │  (Global\Name)  │
│                 │                    │                 │
│  MapViewOfFile │                    │  MapViewOfFile  │
│        │        │                    │        │        │
│        ▼        │                    │        ▼        │
│  [Shared Data]  │◄────Memory────►│  [Shared Data]  │
│  - WatchList    │     Mapping      │  - WatchList    │
│  - Events       │                    │  - Events       │
│  - Lock         │                    │  - Lock         │
└─────────────────┘                    └─────────────────┘
```

## 详细实现方案

### 1. 数据结构定义

**文件**: `DllLoadMon.h`

```cpp
// 共享数据结构（位于内存映射文件中）
struct DllLoadMonSharedData {
    HANDLE hLoadEvent;          // 加载通知事件
    HANDLE hReleaseEvent;       // 释放等待事件
    DWORD dwWatchCount;         // Watch list 中的 DLL 数量
    SRWLOCK WatchListLock;      // SRW 锁（进程间同步）
    WCHAR ModuleNames[256][256]; // DLL 名称数组（Unicode，不含扩展名）
    // 总大小：sizeof(DllLoadMonSharedData) ≈ 256 * 256 * 2 + 其他字段 ≈ 132KB
};
```

### 2. UMController 端实现

#### 步骤 1: 创建命名文件映射对象

```cpp
// UMControllerDlg.cpp - RegisterModuleWatch 函数中

#include <Windows.h>
#include <strsafe.h>

// 生成唯一的文件映射名称（基于 PID）
WCHAR szMappingName[MAX_PATH];
StringCchPrintf(szMappingName, MAX_PATH, L"Global\\DllLoadMon_SharedData_%lu", pid);

// 计算共享数据大小
const SIZE_T SHARED_DATA_SIZE = sizeof(DllLoadMonSharedData);

// 创建文件映射对象（使用 pagefile，不需要实际文件）
HANDLE hFileMapping = CreateFileMappingW(
    INVALID_HANDLE_VALUE,      // 使用系统页文件
    NULL,                      // 默认安全属性
    PAGE_READWRITE,            // 读写权限
    0,                         // 最大大小高 32 位
    (DWORD)SHARED_DATA_SIZE,   // 最大大小低 32 位
    szMappingName              // 对象名称（全局）
);

if (!hFileMapping) {
    LOG_CTRL_ETW(L"[UMCtrl] 创建文件映射失败：%lu", GetLastError());
    return false;
}

// 映射到当前进程地址空间
DllLoadMonSharedData* pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
    hFileMapping,
    FILE_MAP_WRITE,
    0, 0, SHARED_DATA_SIZE
);

if (!pSharedData) {
    LOG_CTRL_ETW(L"[UMCtrl] 映射视图失败：%lu", GetLastError());
    CloseHandle(hFileMapping);
    return false;
}

// 初始化共享数据
ZeroMemory(pSharedData, SHARED_DATA_SIZE);
```

#### 步骤 2: 创建事件句柄并初始化 SRWLOCK

```cpp
// 创建事件（命名事件，DllLoadMon 可以打开）
WCHAR szLoadEventName[MAX_PATH];
WCHAR szReleaseEventName[MAX_PATH];
StringCchPrintf(szLoadEventName, MAX_PATH, L"Global\\DelayHook_Load_%lu", pid);
StringCchPrintf(szReleaseEventName, MAX_PATH, L"Global\\DelayHook_Release_%lu", pid);

HANDLE hEventLoad = CreateEventW(NULL, FALSE, FALSE, szLoadEventName);
HANDLE hEventRelease = CreateEventW(NULL, FALSE, FALSE, szReleaseEventName);

// 注意：事件句柄不能直接放入共享内存（每个进程有自己的句柄表）
// 需要在 DllLoadMon 中通过 OpenEvent 打开
```

#### 步骤 3: 写入 Watch List

```cpp
// 复制 watch list 到共享内存
std::vector<std::wstring> moduleNames = { L"ntdll", L"kernel32", L"user32" };

pSharedData->dwWatchCount = (DWORD)moduleNames.size();

for (size_t i = 0; i < moduleNames.size(); i++) {
    StringCchCopyW(
        pSharedData->ModuleNames[i],
        256,
        moduleNames[i].c_str()
    );
}

// 初始化 SRW 锁（注意：SRWLOCK 在进程间可能不工作，需要用临界区替代）
// 或者使用无锁设计，通过标志位控制
```

#### 步骤 4: 保持文件映射句柄

```cpp
// 重要：不要关闭文件映射句柄，直到不再需要共享数据
// 将句柄保存到某个地方，稍后清理时使用

// 映射视图在使用完后可以解除映射，但文件映射对象要保持打开
UnmapViewOfFile(pSharedData);

// 文件映射句柄 hFileMapping 要保持打开，直到 DllLoadMon 不再需要
// 可以将 hFileMapping 保存到一个全局列表，进程退出时清理
```

### 3. DllLoadMon 端实现

#### 步骤 1: 打开命名文件映射对象

```cpp
// DllLoadMon.cpp - 在 DllMain 或首次使用时

#include <Windows.h>

// 全局指针
static DllLoadMonSharedData* g_pSharedData = nullptr;
static HANDLE g_hFileMapping = NULL;

// 初始化函数（由 UMController 通过某种机制触发，或在 DllMain 中自动执行）
BOOL InitializeSharedData(DWORD pid) {
    // 构建文件映射名称
    WCHAR szMappingName[MAX_PATH];
    StringCchPrintf(szMappingName, MAX_PATH, L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    // 打开已有的文件映射对象
    g_hFileMapping = OpenFileMappingW(
        FILE_MAP_READ,         // 只读访问
        FALSE,                 // 不继承
        szMappingName          // 对象名称
    );
    
    if (!g_hFileMapping) {
        return FALSE;
    }
    
    // 映射到当前进程地址空间
    g_pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
        g_hFileMapping,
        FILE_MAP_READ,
        0, 0, sizeof(DllLoadMonSharedData)
    );
    
    if (!g_pSharedData) {
        CloseHandle(g_hFileMapping);
        g_hFileMapping = NULL;
        return FALSE;
    }
    
    return TRUE;
}
```

#### 步骤 2: 打开事件句柄

```cpp
// 在 DllMain 中，打开命名事件
BOOL InitializeEvents(DWORD pid) {
    WCHAR szLoadEventName[MAX_PATH];
    WCHAR szReleaseEventName[MAX_PATH];
    StringCchPrintf(szLoadEventName, MAX_PATH, L"Global\\DelayHook_Load_%lu", pid);
    StringCchPrintf(szReleaseEventName, MAX_PATH, L"Global\\DelayHook_Release_%lu", pid);
    
    g_pSharedData->hLoadEvent = OpenEventW(SYNCHRONIZE, FALSE, szLoadEventName);
    g_pSharedData->hReleaseEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, szReleaseEventName);
    
    return (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent);
}
```

#### 步骤 3: 在 Hook 函数中访问共享数据

```cpp
// DllLoadMonHook_X64 实现
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    PROLOGX64(rsp);
    
    // 确保共享数据已初始化
    if (!g_pSharedData) {
        return;
    }
    
    // RDI 指向 PUNICODE_STRING（DLL 名称）
    PUNICODE_STRING dllName = (PUNICODE_STRING)rdi;
    
    if (!dllName || !dllName->Buffer) {
        return;
    }
    
    // 检查是否在 watch list 中
    BOOL found = FALSE;
    for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
        // 比较 Unicode 字符串
        if (wcsncmp(dllName->Buffer, g_pSharedData->ModuleNames[i], 
                    dllName->Length / sizeof(WCHAR)) == 0) {
            found = TRUE;
            break;
        }
    }
    
    if (found && g_pSharedData->hLoadEvent) {
        // 通知 UMController
        SetEvent(g_pSharedData->hLoadEvent);
        
        // 等待 UMController 应用 hooks
        if (g_pSharedData->hReleaseEvent) {
            WaitForSingleObject(g_pSharedData->hReleaseEvent, 5000);
        }
    }
}
```

### 4. 清理机制

#### UMController 端清理

```cpp
// 当不再需要共享数据时（例如进程退出或取消监控）

void CleanupSharedData(HANDLE hFileMapping) {
    if (hFileMapping) {
        CloseHandle(hFileMapping);
        // 文件映射对象会在所有句柄关闭后自动销毁
    }
}
```

#### DllLoadMon 端清理

```cpp
// 在 DLL_PROCESS_DETACH 时

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_DETACH:
        if (g_pSharedData) {
            UnmapViewOfFile(g_pSharedData);
            g_pSharedData = nullptr;
        }
        if (g_hFileMapping) {
            CloseHandle(g_hFileMapping);
            g_hFileMapping = NULL;
        }
        if (g_pSharedData && g_pSharedData->hLoadEvent) {
            CloseHandle(g_pSharedData->hLoadEvent);
        }
        if (g_pSharedData && g_pSharedData->hReleaseEvent) {
            CloseHandle(g_pSharedData->hReleaseEvent);
        }
        break;
    }
    return TRUE;
}
```

## 完整实现流程

### UMController 端

```cpp
BOOL UMController::RegisterModuleWatch(DWORD pid, const std::vector<std::wstring>& moduleNames) {
    // 1. 创建命名文件映射
    WCHAR szMappingName[MAX_PATH];
    StringCchPrintf(szMappingName, MAX_PATH, L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    HANDLE hFileMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DllLoadMonSharedData),
        szMappingName
    );
    
    if (!hFileMapping) {
        return FALSE;
    }
    
    // 2. 映射视图
    DllLoadMonSharedData* pData = (DllLoadMonSharedData*)MapViewOfFile(
        hFileMapping, FILE_MAP_WRITE, 0, 0, sizeof(DllLoadMonSharedData)
    );
    
    if (!pData) {
        CloseHandle(hFileMapping);
        return FALSE;
    }
    
    // 3. 初始化数据
    ZeroMemory(pData, sizeof(DllLoadMonSharedData));
    pData->dwWatchCount = (DWORD)moduleNames.size();
    
    for (size_t i = 0; i < moduleNames.size(); i++) {
        StringCchCopyW(pData->ModuleNames[i], 256, moduleNames[i].c_str());
    }
    
    // 4. 创建事件
    WCHAR szLoadEventName[MAX_PATH], szReleaseEventName[MAX_PATH];
    StringCchPrintf(szLoadEventName, MAX_PATH, L"Global\\DelayHook_Load_%lu", pid);
    StringCchPrintf(szReleaseEventName, MAX_PATH, L"Global\\DelayHook_Release_%lu", pid);
    
    HANDLE hEventLoad = CreateEventW(NULL, FALSE, FALSE, szLoadEventName);
    HANDLE hEventRelease = CreateEventW(NULL, FALSE, FALSE, szReleaseEventName);
    
    // 5. 解除映射（数据已在共享内存中）
    UnmapViewOfFile(pData);
    
    // 6. 保持 hFileMapping 打开，稍后清理
    // 可以将 hFileMapping 保存到全局列表
    
    return TRUE;
}
```

### DllLoadMon 端

```cpp
// 全局变量
static DllLoadMonSharedData* g_pSharedData = nullptr;
static HANDLE g_hFileMapping = NULL;

// 初始化（在 DllMain 中调用）
BOOL InitializeForPid(DWORD pid) {
    WCHAR szMappingName[MAX_PATH];
    StringCchPrintf(szMappingName, MAX_PATH, L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    g_hFileMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, szMappingName);
    if (!g_hFileMapping) {
        return FALSE;
    }
    
    g_pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
        g_hFileMapping, FILE_MAP_READ, 0, 0, sizeof(DllLoadMonSharedData)
    );
    
    if (!g_pSharedData) {
        CloseHandle(g_hFileMapping);
        return FALSE;
    }
    
    // 打开事件
    WCHAR szEventName[MAX_PATH];
    StringCchPrintf(szEventName, MAX_PATH, L"Global\\DelayHook_Load_%lu", pid);
    g_pSharedData->hLoadEvent = OpenEventW(SYNCHRONIZE, FALSE, szEventName);
    
    StringCchPrintf(szEventName, MAX_PATH, L"Global\\DelayHook_Release_%lu", pid);
    g_pSharedData->hReleaseEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, szEventName);
    
    return (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent);
}
```

## 安全性考虑

### 1. 命名冲突防护

使用 PID 作为命名的一部分，确保不同进程间的隔离：
- `Global\\DllLoadMon_SharedData_{PID}`
- `Global\\DelayHook_Load_{PID}`
- `Global\\DelayHook_Release_{PID}`

### 2. 权限控制

```cpp
// 使用安全描述符限制访问
SECURITY_ATTRIBUTES sa = {0};
sa.nLength = sizeof(SECURITY_ATTRIBUTES);

// 创建 SDDL 字符串，只允许创建者和 SYSTEM 访问
LPCWSTR sddl = L"D:(A;;GA;;;CO)(A;;GA;;;SY)";
ConvertStringSecurityDescriptorToSecurityDescriptorW(
    sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL
);

CreateFileMappingW(..., &sa, ...);
```

### 3. 数据验证

DllLoadMon 在读取共享数据时应验证：
- `dwWatchCount` 不超过最大值（256）
- 字符串以 null 结尾
- 事件句柄有效

## 优缺点分析

### 优点

✅ **无需目标进程句柄**：不需要 `PROCESS_VM_OPERATION` 或 `PROCESS_ALL_ACCESS`
✅ **权限要求低**：只需要标准的文件映射权限
✅ **自动内存管理**：系统自动处理映射和释放
✅ **跨进程同步**：支持命名对象，易于同步
✅ **更好的隔离性**：每个进程有自己的视图

### 缺点

❌ **性能略低**：相比直接内存访问，有轻微的开销
❌ **需要同步机制**：需要处理进程间同步（建议使用事件或原子操作）
❌ **命名空间污染**：全局命名对象可能被恶意程序探测

## 实现清单

- [ ] 更新 `DllLoadMon.h` 中的 `DllLoadMonSharedData` 结构
- [ ] 实现 UMController 端的 `CreateFileMapping` 逻辑
- [ ] 实现 DllLoadMon 端的 `OpenFileMapping` 逻辑
- [ ] 添加命名事件创建和打开代码
- [ ] 实现清理机制（`DLL_PROCESS_DETACH`）
- [ ] 添加错误处理和日志记录
- [ ] 测试跨进程文件映射访问
- [ ] 验证权限要求是否降低
- [ ] 测试多进程并发场景

## 参考资料

- [MSDN: CreateFileMapping](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappinga)
- [MSDN: MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [MSDN: OpenFileMapping](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-openfilemappinga)
- `C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp` - Hook 代码模板
