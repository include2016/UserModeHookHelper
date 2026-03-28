# 延迟钩子实现方案设计 (Rev6)

## 概述

本文档描述延迟钩子 (Delay Hook) 功能的完整实现方案。延迟钩子允许用户在目标 DLL 尚未加载时预先注册钩子，系统会在 DLL 加载时自动应用这些钩子。

**核心特性**:
- ✅ **预先注册**: 模块未加载时可提前注册钩子
- ✅ **自动应用**: DLL 加载时自动激活待处理钩子
- ✅ **永久监控**: DllLoadMon 钩子代码永久驻留，持续监控后续 DLL 加载
- ✅ **代码复用**: UMController 复用 HookCore 现有基础设施进行注入
- ✅ **职责分离**: DllLoadMon 仅提供钩子代码，UMController 负责注入操作
- ✅ **平台支持**: 支持 x64 和 x86 平台

---

## 组件架构

### 1. DllLoadMon.dll (钩子代码提供者)

**位置**: `hook_component/DllLoadMon/`

**核心职责** ⭐ **Rev6 修正**:
- ⭐ **不提供注入功能**：注入由 UMController 负责
- ⭐ **仅提供钩子代码**：通过导出函数 `DllLoadMonHook` 提供钩子逻辑
- 通过 RDI 机制识别被加载的 DLL 名称
- 与监视列表比对，判断是否命中目标 DLL
- 通过事件通知 UMController
- 阻塞 LdrLoadDll 返回直到 UMController 应用完待处理钩子

**Rev6 关键修正**:
```
❌ Rev5 错误理解:
   DllLoadMon 自己负责 hook ntdll 的 LdrLoadDll
   
✅ Rev6 正确架构:
   UMController 负责注入操作 (复用 HookCore::ApplyHook)
   DllLoadMon 仅提供钩子代码 (DllLoadMonHook 导出函数)
```

**实现细节**:

#### 1.1 导出函数定义

**DllLoadMon.h**:
```cpp
#pragma once

// 钩子回调函数类型定义
typedef void (*PFN_DllLoadMonHook)(
    PVOID ModuleBase,      // RDI 指向的模块基址
    HANDLE hEventLoad,     // 加载通知事件
    HANDLE hEventRelease,  // 释放等待事件
    PVOID WatchList        // 监视列表（共享内存或全局变量）
);

// 导出函数：提供钩子逻辑代码
extern "C" __declspec(dllexport)
void DllLoadMonHook(
    PVOID ModuleBase,
    HANDLE hEventLoad,
    HANDLE hEventRelease,
    PVOID WatchList
);

// 可选：初始化函数（如果需要设置全局状态）
extern "C" __declspec(dllexport)
NTSTATUS DllLoadMon_Initialize(HANDLE hEventLoad, HANDLE hEventRelease);
```

#### 1.2 钩子逻辑实现

**DllLoadMon.cpp**:
```cpp
// 钩子回调函数 - 这是 DllLoadMon 提供的核心逻辑
extern "C" __declspec(dllexport)
void DllLoadMonHook(
    PVOID ModuleBase,      // RDI 指向的模块基址
    HANDLE hEventLoad,     // 加载通知事件
    HANDLE hEventRelease,  // 释放等待事件
    PVOID WatchList        // 监视列表
)
{
    // 1. 从 RDI 读取模块名（不含 .dll 后缀）
    const char* moduleName = ReadModuleNameFromRDI(ModuleBase);
    
    // 2. 检查是否在监视列表中
    if (IsModuleInWatchList(moduleName, WatchList)) {
        // 3. 触发加载通知事件
        SetEvent(hEventLoad);
        
        // 4. ⭐ 关键：等待释放信号，阻塞 LdrLoadDll 返回
        WaitForSingleObject(hEventRelease, 5000); // 5 秒超时
    }
    
    // 5. 恢复执行，跳回原返回位置（由 trampoline 处理）
}

// 辅助函数：从 RDI 读取模块名
const char* ReadModuleNameFromRDI(PVOID ModuleBase)
{
    // RDI 指向 DLL 基址，DOS 头在基址处
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + dosHeader->e_lfanew);
    
    // 获取导出目录 RVA
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    // 模块名通常在导出表中，或者直接从文件名推断
    // 简单实现：从完整路径提取文件名（不含 .dll）
    // 更精确的实现需要解析 PE 结构的导出名
    return ExtractModuleName((PCHAR)ModuleBase);
}

// 辅助函数：检查模块是否在监视列表中
bool IsModuleInWatchList(const char* moduleName, PVOID WatchList)
{
    // WatchList 存储不含 .dll 后缀的 DLL 名
    // 例如：["ntdll", "kernel32", "user32"]
    auto* pList = (std::vector<std::string>*)WatchList;
    
    for (const auto& watched : *pList) {
        if (_stricmp(moduleName, watched.c_str()) == 0) {
            return true;
        }
    }
    
    return false;
}
```

#### 1.3 平台特定路径

**ntdll.dll 位置**:
- **x64 平台**: `C:\Windows\System32\ntdll.dll`
- **x86 平台**: `C:\Windows\Syswow64\ntdll.dll`

**注意**: DllLoadMon 本身不需要计算 ntdll 的 MD5 或偏移量，这些由 UMController 在注入前计算好。

#### 1.4 事件机制

**事件对象由 UMController 创建并传递**:
1. `Global\DelayHook_Load_{PID}` - 加载通知事件（DllLoadMon → UMController）
2. `Global\DelayHook_Release_{PID}` - 释放等待事件（UMController → DllLoadMon）

**DllLoadMon 使用方式**:
- 在钩子回调中接收这两个句柄
- 命中目标时触发 Load 事件
- 等待 Release 事件解除阻塞

---

### 2. UMController (注入操作执行者) ⭐ **Rev6 重点**

**位置**: `controller/UMController/UMControllerDlg.cpp`

**核心职责**:
- ⭐ **负责注入操作**：复用 `HookCore::ApplyHook` 注入钩子代码
- 提供 `RegisterModuleWatch` 接口
- 计算 ntdll MD5 并确定 LdrLoadDll 返回位置
- 创建事件监听线程
- 管理待处理钩子列表
- 应用待处理钩子并通知释放

**实现步骤**:

#### 2.1 注册模块监视（完整注入流程）

**接口定义**:
```cpp
NTSTATUS RegisterModuleWatch(
    DWORD processId,
    const std::vector<std::wstring>& moduleNames // 不含 .dll 后缀
);
```

**实现逻辑** ⭐ **Rev6 修正**:
```cpp
NTSTATUS RegisterModuleWatch(DWORD processId, const std::vector<std::wstring>& moduleNames)
{
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 2. 创建命名事件
    WCHAR loadEventName[64], releaseEventName[64];
    swprintf_s(loadEventName, L"Global\\DelayHook_Load_%lu", processId);
    swprintf_s(releaseEventName, L"Global\\DelayHook_Release_%lu", processId);
    
    HANDLE hEventLoad = CreateEventW(NULL, FALSE, FALSE, loadEventName);
    HANDLE hEventRelease = CreateEventW(NULL, FALSE, FALSE, releaseEventName);
    
    // 3. ⭐ 计算 ntdll MD5 并获取 LdrLoadDll 返回位置偏移量
    DWORD64 ldrLoadDllRetOffset = CalculateNtdllLdrLoadDllRetOffset(processId);
    if (ldrLoadDllRetOffset == 0) {
        CloseHandle(hProcess);
        CloseHandle(hEventLoad);
        CloseHandle(hEventRelease);
        return STATUS_UNSUCCESSFUL; // 不支持的 ntdll 版本
    }
    
    // 4. ⭐ 计算 LdrLoadDll 返回位置的绝对地址
    ULONGLONG ntdllBase = GetNtdllBaseInTargetProcess(processId);
    ULONGLONG ldrLoadDllAddr = ntdllBase + ldrLoadDllRetOffset;
    
    // 5. ⭐ 加载 DllLoadMon.dll 获取导出函数地址
    HMODULE hDllLoadMon = LoadLibraryExW(L"DllLoadMon.dll", NULL, 0);
    if (!hDllLoadMon) {
        CloseHandle(hProcess);
        CloseHandle(hEventLoad);
        CloseHandle(hEventRelease);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 获取导出函数：DllLoadMonHook（钩子代码地址）
    typedef void (*PFN_DllLoadMonHook)(PVOID, HANDLE, HANDLE, PVOID);
    PFN_DllLoadMonHook pfnDllLoadMonHook = 
        (PFN_DllLoadMonHook)GetProcAddress(hDllLoadMon, "DllLoadMonHook");
    
    if (!pfnDllLoadMonHook) {
        FreeLibrary(hDllLoadMon);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 6. ⭐ 关键：复用 HookCore::ApplyHook 注入钩子代码
    // 参数说明:
    // - pid: 目标进程 ID
    // - ldrLoadDllAddr: LdrLoadDll 返回位置（钩子目标地址）
    // - g_services: IHookServices 接口
    // - pfnDllLoadMonHook: DllLoadMon 提供的钩子代码地址
    // - HOOKID_DELAYLOAD_MON: 钩子 ID
    DWORD oriLen = 0;
    PVOID trampolinePit = NULL;
    PVOID oriCodeAddr = NULL;
    
    bool success = HookCore::ApplyHook(
        processId, 
        ldrLoadDllAddr, 
        g_services,
        (DWORD64)pfnDllLoadMonHook, // ⭐ DllLoadMon 提供的钩子代码
        HOOKID_DELAYLOAD_MON,
        &oriLen,
        &trampolinePit,
        &oriCodeAddr
    );
    
    if (!success) {
        FreeLibrary(hDllLoadMon);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 7. ⭐ 将事件句柄和监视列表传递给 DllLoadMon
    // 通过共享内存、全局变量或 IPC 机制
    PassParametersToHook(processId, hEventLoad, hEventRelease, moduleNames);
    
    // 8. 创建事件监听线程
    MonitorParams* params = new MonitorParams{
        processId,
        hProcess,
        hEventLoad,
        hEventRelease
    };
    CreateThread(NULL, 0, DelayHookMonitorThread, params);
    
    // 日志记录
    LOG_CTRL_ETW("[UMCtrl] RegisterModuleWatch: PID=%lu, Modules=%zu, HookAddr=%p", 
                 processId, moduleNames.size(), pfnDllLoadMonHook);
    
    return STATUS_SUCCESS;
}
```

**日志记录规范**:
```cpp
// 使用标准日志格式
LOG_CTRL_ETW("[UMCtrl] RegisterModuleWatch: PID=%lu, Modules=%zu", 
             processId, moduleNames.size());
```

日志前缀规范：
- 使用 `[UMCtrl]` 标识 UMController 组件
- 总宽度 13 字符（与其他前缀对齐）
- 或使用 `LOG_CTRL_ETW` 宏自动处理前缀

#### 2.2 计算 ntdll MD5 和偏移量

**辅助函数**:
```cpp
DWORD64 CalculateNtdllLdrLoadDllRetOffset(DWORD processId)
{
    // 1. 确定平台并获取 ntdll 路径
    BOOL isWow64 = IsTargetProcessWow64(processId);
    const wchar_t* ntdllPath = isWow64 ? 
        L"C:\\Windows\\Syswow64\\ntdll.dll" : 
        L"C:\\Windows\\System32\\ntdll.dll";
    
    // 2. 读取本地 ntdll.dll 文件并计算 MD5
    std::string md5Hash = CalculateFileMD5(ntdllPath);
    
    // 3. 在预定义映射表中查找
    NtdllVersionEntry* entry = FindNtdllVersionByMD5(md5Hash);
    if (!entry) {
        return 0; // 不支持的版本
    }
    
    // 4. 验证平台匹配
    Platform currentPlatform = isWow64 ? PLATFORM_X86 : PLATFORM_AMD64;
    if (entry->platform != currentPlatform) {
        return 0; // 平台不匹配
    }
    
    return entry->ldrLoadDllRetOffset;
}

ULONGLONG GetNtdllBaseInTargetProcess(DWORD processId)
{
    // 枚举目标进程的模块，获取 ntdll.dll 基址
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (_stricmp(szModName, "ntdll.dll") == 0) {
                    CloseHandle(hProcess);
                    return (ULONGLONG)hMods[i];
                }
            }
        }
    }
    
    CloseHandle(hProcess);
    return 0;
}
```

#### 2.3 事件监听线程

**线程函数**:
```cpp
DWORD WINAPI DelayHookMonitorThread(LPVOID lpParam)
{
    MonitorParams* params = (MonitorParams*)lpParam;
    
    // 等待加载通知事件
    WaitForSingleObject(params->hEventLoad, INFINITE);
    
    // 检索该进程的待处理钩子
    auto pendingHooks = GetPendingHooks(params->processId);
    
    // 应用所有待处理钩子
    for (auto& hook : pendingHooks) {
        // 复用 HookCore::ApplyHook 应用实际的钩子
        ApplyTargetHook(params->hProcess, hook.moduleBase, hook.hookInfo);
    }
    
    // ⭐ 关键：通知 DllLoadMon（钩子代码）解除阻塞
    SetEvent(params->hEventRelease);
    
    // 从未处理列表移除已应用的钩子
    RemovePendingHooks(params->processId);
    
    // 更新 UI 显示钩子状态
    NotifyHookUI_StatusChanged(params->processId, HookStatus::Active);
    
    return 0;
}
```

#### 2.4 应用待处理钩子

**实现逻辑**:
- 遍历待处理钩子列表
- 对每个钩子调用 `HookCore::ApplyHook` 或专用的钩子应用函数
- 从未处理列表移除已应用的钩子
- 更新 UI 显示钩子状态

---

### 3. HookUI

**位置**: `controller/HookUI/HookProcDlg.cpp`

**职责**:
- 允许用户通过 UI 注册延迟钩子
- 在钩子序列列表中显示待处理的钩子
- 区分活动钩子和待处理钩子

**实现步骤**:

#### 3.1 添加 UI 元素

- 在钩子列表中添加"状态"列
- 显示"待处理"或"活动"状态
- 使用不同颜色或图标区分：
  - 🟡 黄色：待处理（Pending）
  - 🟢 绿色：活动（Active）

#### 3.2 延迟钩子注册流程

```
用户添加钩子
    ↓
检查模块是否已加载
    ↓
[模块未加载]
    ├─> 添加到待处理钩子列表
    ├─> 调用 RegisterModuleWatch
    └─> 显示"待处理"状态
    
[模块已加载]
    ├─> 直接应用钩子
    └─> 显示"活动"状态
```

#### 3.3 UI 更新

- 当待处理钩子变为活动时
- UMController 通知 HookUI 刷新显示
- 更新状态为"活动"

---

## 通信流程（完整时序图）⭐ **Rev6 修正**

```
HookUI                    UMController                DllLoadMon.dll              被 Hook 的进程
  │                          │                            │                           │
  │ 添加延迟钩子              │                            │                           │
  │─────────────────────────>│                            │                           │
  │                          │                            │                           │
  │                          │ 检查模块是否已加载          │                           │
  │                          │(枚举进程模块)               │                           │
  │                          │                            │                           │
  │                          │ [模块未加载]                │                           │
  │                          │                            │                           │
  │                          │ 创建命名事件：              │                           │
  │                          │ - Global\DelayHook_Load_{PID}     │                           │
  │                          │ - Global\DelayHook_Release_{PID}  │                           │
  │                          │                            │                           │
  │                          │ 计算 ntdll MD5 和偏移量     │                           │
  │                          │                            │                           │
  │                          │ 加载 DllLoadMon.dll         │                           │
  │                          │ 获取 DllLoadMonHook 地址    │                           │
  │                          │                            │                           │
  │                          │ ⭐ 调用 HookCore::ApplyHook │                           │
  │                          │ 注入 DllLoadMonHook 代码    │                           │
  │                          │ 到 LdrLoadDll 返回位置      │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 传递参数 (事件句柄、监视列表)                           │
  │                          │ (通过共享内存/全局变量)    │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 创建事件监听线程            │                           │
  │                          │ (等待 Global\DelayHook_Load_{PID})│                           │
  │                          │                            │                           │
  │ 返回，显示"待处理"状态     │                            │                            │ LdrLoadDll 被调用
  │<─────────────────────────│                            │<──────────────────────────│
  │                          │                            │                           │
  │                          │                            │ LdrLoadDll 执行           │
  │                          │                            │ (加载目标 DLL)             │
  │                          │                            │                           │
  │                          │                            │ 接近返回指令              │
  │                          │                            │ (被 hook 的位置)           │
  │                          │                            │                           │
  │                          │                            │ Trampoline 触发           │
  │                          │                            │ 跳转到 DllLoadMonHook 代码  │
  │                          │                            │                           │
  │                          │                            │ ⭐ DllLoadMonHook 执行:    │
  │                          │                            │ 1. 读取 RDI 获取 DLL 名     │
  │                          │                            │ 2. 检查监视列表           │
  │                          │                            │                           │
  │                          │                            │ [匹配成功]                 │
  │                          │                            │                           │
  │                          │                            │ 触发 Global\DelayHook_Load_{PID} │
  │                          │                            │──────────────────────────>│
  │                          │                            │                           │
  │                          │                            │ 等待 Global\DelayHook_Release_{PID}
  │                          │                            │ (阻塞，防止 LdrLoadDll 返回)│
  │                          │                            │                           │
  │                          │ 等待线程接收到事件          │                           │
  │                          │<───────────────────────────│                           │
  │                          │                            │                           │
  │                          │ 检索待处理钩子列表          │                           │
  │                          │                            │                           │
  │                          │ 应用所有待处理钩子          │                           │
  │                          │ (调用 HookCore::ApplyHook) │                           │
  │                          │                            │                           │
  │                          │ 触发 Global\DelayHook_Release_{PID}
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │                            │ 从等待状态唤醒             │
  │                          │                            │                           │
  │                          │                            │ 恢复执行，跳回原返回位置   │
  │                          │                            │──────────────────────────>│
  │                          │                            │                           │ LdrLoadDll 返回
  │                          │                            │                           │ (钩子已就绪)
  │                          │                            │                           │
  │                          │ 从未处理列表移除            │                           │
  │                          │                            │                           │
  │                          │ 通知 HookUI 更新状态        │                           │
  │                          │──────────────────────────>│                           │
  │                          │                            │                           │
  │<─────────────────────────│                            │                           │
  │ 更新 UI 显示"活动"状态     │                            │                           │
  │                          │                            │                           │
  │                          │                            │ [DllLoadMonHook 继续驻留]  │
  │                          │                            │ 监控后续 DLL 加载事件      │
```

### 流程说明 ⭐ **Rev6 修正**

1. **用户注册延迟钩子**: HookUI 调用 UMController 注册
2. **UMController 检查模块状态**: 如果未加载，准备监控
3. **UMController 计算 ntdll MD5**: 确定 LdrLoadDll 返回位置偏移量
4. **UMController 加载 DllLoadMon**: 获取 `DllLoadMonHook` 导出函数地址
5. **UMController 调用 HookCore::ApplyHook**: ⭐ 注入 DllLoadMonHook 代码到目标位置
6. **UMController 传递参数**: 将事件句柄和监视列表传递给钩子代码
7. **启动监听线程**: UMController 等待加载通知事件
8. **目标进程调用 LdrLoadDll**: 正常加载 DLL
9. **Trampoline 触发**: 在 LdrLoadDll 返回指令处跳转到 DllLoadMonHook
10. **DllLoadMonHook 执行**: ⭐ 读取 RDI、比对监视列表
11. **检测目标 DLL**: 命中时触发加载通知事件
12. **等待释放事件**: **防止 LdrLoadDll 立即返回** ⭐ **关键**
13. **UMController 应用钩子**: 检索并应用所有待处理钩子
14. **触发释放事件**: 通知 DllLoadMonHook 解除阻塞 ⭐ **关键**
15. **恢复执行**: 跳回原返回位置
16. **LdrLoadDll 返回**: 此时所有钩子已就绪
17. **更新 UI**: 显示钩子状态为"活动"
18. **钩子代码继续驻留**: ⭐ 不移除，继续监控后续 DLL 加载

---

## 需要修改/创建的文件

### 需要删除的文件（已完成）
1. `drivers/UserModeHookHelper/ModuleWatch.c` ✓ 已删除
2. `drivers/UserModeHookHelper/ModuleWatch.h` ✓ 已删除
3. 移除以下文件中的引用：
   - `drivers/UserModeHookHelper/SysCallback.c`（移除 ModuleWatch 包含和调用）✓ 已完成
   - `drivers/UserModeHookHelper/UserModeHookHelper.vcxproj`（移除 ModuleWatch.c 编译）✓ 已完成
   - `drivers/UserModeHookHelper/FltCommPort.c`（移除 Handle_RegisterModuleWatch 处理器）✓ 已完成

### 需要创建的文件

#### 新增组件
1. **`hook_component/DllLoadMon/DllLoadMon.h`**
   - 导出函数声明：`DllLoadMonHook`
   - 可选：`DllLoadMon_Initialize`
   - 数据结构定义（如果需要）

2. **`hook_component/DllLoadMon/DllLoadMon.cpp`**
   - ⭐ **仅提供钩子逻辑代码**
   - RDI 监控和模块名提取
   - 监视列表比对逻辑
   - 事件通知与等待实现
   - **不包含** ntdll MD5 计算、注入逻辑

3. **`hook_component/DllLoadMon/DllLoadMon.vcxproj`**
   - 项目配置文件
   - 导出符号定义

4. **`hook_component/DllLoadMon/ntdll_versions.h`**（移至 UMController 使用）
   - 预定义的 ntdll 版本映射表
   - MD5 哈希值和对应偏移量
   - **由 UMController 使用**，DllLoadMon 不使用

### 需要修改的文件

#### 共享层
1. **`Shared/HookServices.h`**
   - 已有 `PendingHook` 结构 ✓
   - 已有 `RegisterModuleWatch` 接口 ✓
   - 已有 `AddPendingHook`、`GetPendingHooks`、`RemovePendingHooks` ✓
   - 可能需要添加：`UnregisterModuleWatch` 接口

#### Controller 层
2. **`controller/UMController/UMControllerDlg.cpp`** ⭐ **Rev6 重点**
   - 实现 `RegisterModuleWatch`:
     - ⭐ **计算 ntdll MD5 和偏移量**
     - ⭐ **获取 DllLoadMonHook 导出函数地址**
     - ⭐ **调用 `HookCore::ApplyHook` 注入钩子代码**（不是注入整个 DLL）
     - 创建两个命名事件：`Global\DelayHook_Load_{ProcessId}` 和 `Global\DelayHook_Release_{ProcessId}`
     - 传递参数给钩子代码（事件句柄、监视列表）
   - 添加事件监听线程函数
   - 实现待处理钩子应用逻辑
   - **在钩子应用完成后触发释放事件**
   - 参考 [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76) 的实现机制

3. **`controller/UMController/FilterCommPort.cpp`**
   - 可能不需要修改（如果不再通过 FilterComm 与驱动通信）
   - 或者保留作为备用机制

4. **`controller/UMController/FilterCommPort.h`**
   - 可能不需要修改

#### HookUI 层
5. **`controller/HookUI/HookProcDlg.cpp`**
   - 更新 UI 以显示待处理的钩子
   - 添加"状态"列显示"待处理"/"活动"
   - 添加延迟钩子时调用 `RegisterModuleWatch`
   - 实现 UI 刷新逻辑

#### HookCore 层（无需修改）
6. **`controller/HookCoreLib/HookCore.cpp`** ⭐ **Rev6 说明**
   - **无需修改**: 现有 `ApplyHook` 函数已足够强大，支持注入任意钩子代码
   - **无需修改**: 钩子管理机制完善，支持常驻钩子

7. **`controller/HookCoreLib/HookCore.h`** ⭐ **Rev6 说明**
   - **无需修改**: 接口设计已经满足需求

---

## 关于职责分离的说明 ⭐ **Rev6 重点**

### 1. UMController 的职责

**注入操作执行者**:
- ⭐ **计算 ntdll MD5 和偏移量**: 确定 LdrLoadDll 返回位置
- ⭐ **加载 DllLoadMon.dll**: 仅用于获取 `DllLoadMonHook` 函数地址
- ⭐ **调用 HookCore::ApplyHook**: 将 DllLoadMonHook 代码注入到目标位置
- ⭐ **传递参数**: 通过共享内存/全局变量传递事件句柄和监视列表
- ⭐ **创建事件监听线程**: 等待 DllLoadMonHook 的通知

### 2. DllLoadMon 的定位

**钩子代码提供者**:
- ⭐ **不提供注入功能**: 注入完全由 UMController 负责
- ⭐ **仅提供钩子逻辑**: 通过导出函数 `DllLoadMonHook`
- ⭐ **被动执行**: 被注入到目标进程，在 trampoline 触发时执行
- ⭐ **轻量级**: 只包含必要的钩子逻辑，不包含复杂的注入逻辑

**架构图** ⭐ **Rev6 修正**:
```
UMController (注入操作执行者)
    ↓ (1. 计算 ntdll MD5 和偏移量)
    ↓ (2. 获取 DllLoadMonHook 地址)
    ↓ (3. 调用 HookCore::ApplyHook 注入)
DllLoadMonHook 代码 (注入到目标进程)
    ↓ (4. 在 LdrLoadDll 返回时触发)
    ↓ (5. 执行 DllLoadMonHook 逻辑)
    ↓ (6. 读取 RDI、比对监视列表)
    ↓ (7. 事件通知)
UMController (应用其他钩子)
```

### 3. 钩子常驻策略

**Rev6 明确要求**:
- ⭐ **不移除 LdrLoadDll 钩子**: 保持永久监控能力
- ⭐ **随时响应 DLL 加载**: 用户可能随时需要添加新的延迟钩子
- ⭐ **性能影响可控**: LdrLoadDll 钩子只在返回时触发，开销很小

**实现方式**:
- 调用 `HookCore::ApplyHook` 后，**不调用**`HookCore::RemoveHook`
- DllLoadMonHook 代码保持在目标进程内存中
- 钩子持续有效，直到进程终止

---

## 实现注意事项

### MD5-偏移量映射表维护

1. **数据收集**:
   - 收集多个 Windows 版本的 ntdll.dll
   - 包括 32 位和 64 位版本
   - 记录每个文件的版本信息
   - **由用户负责收集和提供映射关系**

2. **偏移量测量**:
   - 使用调试器分析 LdrLoadDll 函数
   - 找到返回指令（RET）的位置
   - 记录相对于 ntdll 基址的偏移量

3. **映射表更新**:
   - 定期更新映射表以支持新版本的 Windows
   - 提供 fallback 机制（如果找不到匹配的 MD5）

### 同步和线程安全

1. **监视列表保护**:
   - 使用 SRW 锁或临界区保护监视列表
   - 注册/注销操作需要加锁
   - DllLoadMonHook 中读取列表也需要加锁

2. **事件处理**:
   - UMController 中每个进程一个事件等待线程
   - 避免多个线程同时处理同一进程的事件
   - 待处理钩子列表访问需要同步

3. **等待超时处理**:
   - DllLoadMonHook 等待释放事件时应设置超时（如 5 秒）
   - 防止 UMController 崩溃导致死锁
   - 超时后记录日志并继续执行

### 错误处理

1. **MD5 匹配失败**:
   - 如果当前 ntdll 的 MD5 不在映射表中
   - 记录日志并返回错误
   - 提示用户该场景暂不支持

2. **注入失败**:
   - ApplyHook 失败时的回滚机制
   - 清理已创建的事件对象
   - 从待处理列表中移除失败的钩子

3. **超时处理**:
   - 设置合理的等待超时时间
   - 避免无限期等待模块加载
   - 提供手动取消延迟钩子的能力

---

## 测试计划

### 单元测试
1. MD5 计算和匹配逻辑测试（UMController）
2. DllLoadMonHook 钩子逻辑测试
3. RDI 读取和模块名提取测试
4. 事件通知机制测试
5. HookCore::ApplyHook 注入功能测试

### 集成测试
1. 延迟钩子注册流程测试
2. 多进程并发测试
3. 长时间运行稳定性测试
4. 异常场景测试（进程崩溃、超时等）

### UI 测试
1. 待处理钩子显示测试
2. 状态更新及时性测试
3. 用户交互友好性测试

---

## 修订历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|----------|
| Rev2 | - | - | 初始延迟钩子设计方案 |
| Rev3 | - | - | 引入 DllLoadMon 组件 |
| Rev4 | - | - | 1. 明确复用 HookCore 基础设施<br>2. 钩子永久驻留策略<br>3. 删除驱动层 ModuleWatch 组件 |
| Rev5 | 2026-01-XX | - | 1. **平台特定路径**: x64 使用 `System32\ntdll.dll`，x86 使用 `Syswow64\ntdll.dll`<br>2. **日志前缀标准化**: `[UMCtrl]` 13 字符宽度或 `LOG_CTRL_ETW` 宏<br>3. **RDI 监控澄清**: 监视列表存储不含 `.dll` 后缀的 DLL 名，与 RDI 内容直接匹配 |
| Rev6 | 2026-01-XX | - | 1. **职责分离**: DllLoadMon 仅提供钩子代码，不负责注入<br>2. **UMController 职责**: 负责计算 MD5、获取钩子代码地址、调用 ApplyHook 注入<br>3. **修正架构**: DllLoadMonHook 作为导出函数提供钩子逻辑，UMController 执行注入操作 |

---

## 附录

### 附录 A: 术语表

- **延迟钩子 (Delay Hook)**: 模块未加载时预先注册，待模块加载后自动应用的钩子
- **DllLoadMon**: DLL 加载监控钩子代码提供者，通过导出函数 `DllLoadMonHook` 提供钩子逻辑
- **DllLoadMonHook**: DllLoadMon 导出的钩子回调函数，在 LdrLoadDll 返回时执行
- **RDI**: RUNTIME_FUNCTION 指针，在 LdrLoadDll 返回时指向被加载 DLL 的模块基址
- **待处理钩子 (Pending Hook)**: 已注册但尚未应用的钩子，等待目标模块加载
- **UMController**: 用户模式控制器，负责注入操作、事件管理、钩子应用

### 附录 B: 参考文档

- [`HookCore::ApplyHook` 实现](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76)
- [Shared/HookServices.h](file://c:\Users\x\Downloads\amsi_tracer-main\Shared\HookServices.h)
- [UMControllerDlg.cpp](file://c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.cpp)
- [HookProcDlg.cpp](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookUI\HookProcDlg.cpp)

### 附录 C: 待办事项

- [ ] 创建 DllLoadMon 组件骨架（仅包含 DllLoadMonHook 导出函数）
- [ ] 实现 DllLoadMonHook 钩子逻辑（RDI 读取、监视列表比对、事件通知）
- [ ] 在 UMController 中实现 ntdll MD5 计算和偏移量匹配
- [ ] 实现 UMController RegisterModuleWatch 接口（调用 ApplyHook 注入）
- [ ] 更新 HookUI 显示待处理/活动状态
- [ ] 编写集成测试用例
