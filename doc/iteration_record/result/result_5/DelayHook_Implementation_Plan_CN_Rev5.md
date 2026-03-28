# 延迟钩子实现方案设计 (Rev5)

## 概述

本文档描述延迟钩子 (Delay Hook) 功能的完整实现方案。延迟钩子允许用户在目标 DLL 尚未加载时预先注册钩子，系统会在 DLL 加载时自动应用这些钩子。

**核心特性**:
- ✅ **预先注册**: 模块未加载时可提前注册钩子
- ✅ **自动应用**: DLL 加载时自动激活待处理钩子
- ✅ **永久监控**: DllLoadMon 组件永久驻留，持续监控后续 DLL 加载
- ✅ **代码复用**: 完全复用 HookCore 现有基础设施
- ✅ **平台支持**: 支持 x64 和 x86 平台

---

## 组件架构

### 1. DllLoadMon.dll (新增组件)

**位置**: `hook_component/DllLoadMon/`

**职责**:
- 监控目标进程的 DLL 加载事件
- 通过 RDI (RUNTIME_FUNCTION) 机制识别被加载的 DLL
- 通过事件通知 UMController 有待匹配的 DLL 加载
- 阻塞 LdrLoadDll 返回直到 UMController 应用完待处理钩子

**实现细节**:

#### 1.1 ntdll 版本适配机制

**问题**: 不同 Windows 版本的 `ntdll.dll` 中 `LdrLoadDll` 函数的返回指令位置不同

**解决方案**:
- 使用 MD5 哈希识别 ntdll 版本
- 预存储 MD5 → 偏移量映射表
- 根据匹配结果确定钩子位置

**实现流程**:
```
1. 计算目标进程 ntdll.dll 的 MD5
2. 在预定义映射表中查找匹配的 MD5
3. 如果匹配成功，获取 LdrLoadDll 返回位置的偏移量
4. 计算绝对地址：ntdll_base + offset
5. 在该地址设置钩子
```

**MD5 映射表示例**:
```cpp
struct NtdllVersionEntry {
    const char* md5Hash;      // ntdll.dll 的 MD5
    DWORD64 ldrLoadDllRetOffset; // LdrLoadDll 返回位置偏移
    Platform platform;        // x64 或 x86
};

// 初始数据
NtdllVersionEntry g_ntdllVersions[] = {
    {"35b03f5d9c6da76fec950a36f9d357b3", 0x16B34, PLATFORM_AMD64},
    // ... 更多版本由用户收集补充
};
```

**平台差异**:
- **x64 平台**: `C:\Windows\System32\ntdll.dll`
- **x86 平台**: `C:\Windows\Syswow64\ntdll.dll`

#### 1.2 LdrLoadDll 钩取实现

**关键设计**:
- ⭐ **复用 HookCore 基础设施**: 通过 `HookCore::ApplyHook` 注入并设置钩子
- ⭐ **钩子位置**: LdrLoadDll 函数的返回指令处
- ⭐ **永久驻留**: 钩子永久保留，持续监控 DLL 加载

**实现步骤**:
```cpp
// DllLoadMon.cpp - 初始化流程

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // 1. 计算 ntdll.dll MD5 并匹配偏移量
        DWORD64 retOffset = MatchNtdllVersion();
        if (retOffset == 0) {
            return FALSE; // 不支持的版本
        }
        
        // 2. 计算 LdrLoadDll 返回位置的绝对地址
        ULONGLONG ntdllBase = GetNtdllBase();
        ULONGLONG hookAddress = ntdllBase + retOffset;
        
        // 3. ⭐ 复用 HookCore::ApplyHook 设置钩子
        // 注意：这里 DllLoadMon 既是钩子代码提供者，也是钩子目标
        // 需要在外部 UMController 中调用 ApplyHook 注入 DllLoadMon
        
        break;
    }
    }
    return TRUE;
}
```

#### 1.3 RDI 监控机制

**RDI (RUNTIME_FUNCTION) 内容**:
- 当 LdrLoadDll 成功加载 DLL 后，RDI 寄存器指向被加载 DLL 的模块基址
- ⭐ **重要**: RDI 指向的内容包含 DLL 名称（不含 `.dll` 扩展名）
- 例如：加载 `abc.dll` 时，RDI 指向的字符串是 `"abc"`

**监视列表设计**:
- 存储要监视的 DLL 名称（**不含 `.dll` 后缀**）
- 与 RDI 内容直接比较，无需额外处理
- 示例：监视 `["ntdll", "kernel32", "user32"]`

**实现逻辑**:
```cpp
// 在 LdrLoadDll 钩子回调中
void OnLdrLoadDllReturned()
{
    // 1. 从 RDI 读取模块名
    const char* moduleName = ReadModuleNameFromRDI(); // 例如："abc"
    
    // 2. 检查是否在监视列表中
    if (g_watchList.contains(moduleName)) {
        // 3. 触发加载通知事件
        SetEvent(g_hEventLoad);
        
        // 4. ⭐ 关键：等待释放信号，阻塞 LdrLoadDll 返回
        WaitForSingleObject(g_hEventRelease, 5000); // 5 秒超时
    }
    
    // 5. 恢复执行，跳回原返回位置
    JumpToOriginalReturn();
}
```

#### 1.4 事件机制

**创建三个命名事件**:
1. `Global\DelayHook_Load_{PID}` - 加载通知事件
2. `Global\DelayHook_Release_{PID}` - 释放等待事件
3. `Global\DllLoadMon_Ready_{PID}` - DllLoadMon 初始化完成事件

**事件用途**:
- **Load 事件**: DllLoadMon → UMController (通知 DLL 加载)
- **Release 事件**: UMController → DllLoadMon (通知可以返回)
- **Ready 事件**: DllLoadMon → UMController (通知初始化完成)

**命名规范**:
- 使用 `Global\` 前缀确保跨进程可见性
- `{PID}` 替换为实际进程 ID
- 示例：`Global\DelayHook_Load_12345`

---

### 2. UMController (扩展功能)

**位置**: `controller/UMController/UMControllerDlg.cpp`

**新增职责**:
- 提供 `RegisterModuleWatch` 接口
- 注入 DllLoadMon.dll 到目标进程
- 创建事件监听线程
- 管理待处理钩子列表
- 应用待处理钩子并通知释放

**实现步骤**:

#### 2.1 注册模块监视

**接口定义**:
```cpp
NTSTATUS RegisterModuleWatch(
    DWORD processId,
    const std::vector<std::wstring>& moduleNames // 不含 .dll 后缀
);
```

**实现逻辑**:
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
    
    // 3. ⭐ 复用 HookCore::ApplyHook 注入 DllLoadMon.dll
    HMODULE hDllLoadMon = LoadLibraryExW(L"DllLoadMon.dll", NULL, 0);
    if (!hDllLoadMon) {
        CloseHandle(hProcess);
        CloseHandle(hEventLoad);
        CloseHandle(hEventRelease);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 获取导出函数：DllLoadMon_Initialize
    typedef NTSTATUS (*PFN_Initialize)(HANDLE, HANDLE, HANDLE);
    PFN_Initialize pfnInitialize = 
        (PFN_Initialize)GetProcAddress(hDllLoadMon, "DllLoadMon_Initialize");
    
    if (!pfnInitialize) {
        FreeLibrary(hDllLoadMon);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 4. 调用 ApplyHook 注入 DllLoadMon.dll
    // 注意：这里需要指定 LdrLoadDll 返回位置的地址
    ULONGLONG ldrLoadDllAddr = GetLdrLoadDllReturnAddress(pid); // 需要实现
    if (!ldrLoadDllAddr) {
        FreeLibrary(hDllLoadMon);
        return STATUS_UNSUCCESSFUL;
    }
    
    DWORD oriLen = 0;
    PVOID trampolinePit = NULL;
    PVOID oriCodeAddr = NULL;
    
    bool success = HookCore::ApplyHook(
        pid, 
        ldrLoadDllAddr, 
        g_services, // IHookServices 接口
        (DWORD64)pfnInitialize, // 钩子代码地址
        HOOKID_DELAYLOAD_MON,   // 钩子 ID
        &oriLen,
        &trampolinePit,
        &oriCodeAddr
    );
    
    if (!success) {
        FreeLibrary(hDllLoadMon);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 5. 调用初始化函数，传入事件句柄
    pfnInitialize(hProcess, hEventLoad, hEventRelease);
    
    // 6. 注册要监视的模块名（通过共享内存或 IPC 传递）
    PassWatchListToDllLoadMon(processId, moduleNames);
    
    // 7. 创建事件监听线程
    CreateThread(NULL, 0, DelayHookMonitorThread, params);
    
    return STATUS_SUCCESS;
}
```

**日志记录**:
```cpp
// 使用标准日志格式
LOG_CTRL_ETW("[UMCtrl] RegisterModuleWatch: PID=%lu, Modules=%zu", 
             processId, moduleNames.size());
```

日志前缀规范：
- 使用 `[UMCtrl]` 标识 UMController 组件
- 总宽度 13 字符（与其他前缀对齐）
- 或使用 `LOG_CTRL_ETW` 宏自动处理

#### 2.2 添加事件监听线程

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
    
    // ⭐ 关键：通知 DllLoadMon 解除阻塞
    SetEvent(params->hEventRelease);
    
    // 从未处理列表移除已应用的钩子
    RemovePendingHooks(params->processId);
    
    // 更新 UI 显示钩子状态
    NotifyHookUI_StatusChanged(params->processId, HookStatus::Active);
    
    return 0;
}
```

#### 2.3 应用待处理钩子

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

## 通信流程（完整时序图）

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
  │                          │ 调用 HookCore::ApplyHook   │                           │
  │                          │ 注入 DllLoadMon.dll         │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 调用初始化函数              │                           │
  │                          │ (传入事件句柄)              │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 注册监视模块名              │                           │
  │                          │ (通过共享内存/IPC)         │                           │
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
  │                          │                            │ 跳转到 DllLoadMon 钩子回调  │
  │                          │                            │                           │
  │                          │                            │ 读取 RDI 获取 DLL 名        │
  │                          │                            │ 检查监视列表              │
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
  │                          │                            │ [DllLoadMon 继续驻留]      │
  │                          │                            │ 监控后续 DLL 加载事件      │
```

### 流程说明

1. **用户注册延迟钩子**: HookUI 调用 UMController 注册
2. **UMController 检查模块状态**: 如果未加载，准备监控
3. **调用 HookCore::ApplyHook**: ⭐ 复用现有基础设施注入 DllLoadMon.dll
4. **创建事件对象**: 创建加载通知事件和释放等待事件
5. **初始化监控**: 调用 DllLoadMon 导出函数设置监视列表
6. **启动监听线程**: UMController 等待加载通知事件
7. **目标进程调用 LdrLoadDll**: 正常加载 DLL
8. **DllLoadMon 钩子触发**: 在返回指令处拦截（通过 trampoline）
9. **检测目标 DLL**: 读取 RDI 获取模块名并匹配
10. **触发加载事件**: 通知 UMController
11. **等待释放事件**: **防止 LdrLoadDll 立即返回** ⭐ **关键**
12. **UMController 应用钩子**: 检索并应用所有待处理钩子
13. **触发释放事件**: 通知 DllLoadMon 解除阻塞 ⭐ **关键**
14. **DllLoadMon 恢复执行**: 跳回原返回位置
15. **LdrLoadDll 返回**: 此时所有钩子已就绪
16. **更新 UI**: 显示钩子状态为"活动"
17. **DllLoadMon 继续驻留**: ⭐ **Rev4 新增** 不移除钩子，继续监控后续 DLL 加载

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
   - 导出函数声明
   - 数据结构定义
   - MD5-偏移量映射表结构

2. **`hook_component/DllLoadMon/DllLoadMon.cpp`**
   - ntdll MD5 计算和匹配逻辑
   - LdrLoadDll 返回位置钩取实现（**复用 HookCore 基础设施**）
   - RDI 监控和模块名提取
   - 事件通知与等待实现
   - 监视列表管理

3. **`hook_component/DllLoadMon/DllLoadMon.vcxproj`**
   - 项目配置文件
   - 导出符号定义

4. **`hook_component/DllLoadMon/ntdll_versions.h`**
   - 预定义的 ntdll 版本映射表
   - MD5 哈希值和对应偏移量
   - **初始数据**:
     ```cpp
     {"35b03f5d9c6da76fec950a36f9d357b3", 0x16B34, PLATFORM_AMD64}
     ```

### 需要修改的文件

#### 共享层
1. **`Shared/HookServices.h`**
   - 已有 `PendingHook` 结构 ✓
   - 已有 `RegisterModuleWatch` 接口 ✓
   - 已有 `AddPendingHook`、`GetPendingHooks`、`RemovePendingHooks` ✓
   - 可能需要添加：`UnregisterModuleWatch` 接口

#### Controller 层
2. **`controller/UMController/UMControllerDlg.cpp`**
   - 实现 `RegisterModuleWatch`:
     - 创建两个命名事件：`Global\DelayHook_Load_{ProcessId}` 和 `Global\DelayHook_Release_{ProcessId}`
     - **调用 `HookCore::ApplyHook` 注入 DllLoadMon.dll** ⭐ **Rev4 关键变更**
     - 调用导出函数初始化和注册监视
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
6. **`controller/HookCoreLib/HookCore.cpp`** ⭐ **Rev4 说明**
   - **无需修改**: 现有 `ApplyHook` 函数已足够强大，支持 DllLoadMon 注入
   - **无需修改**: 钩子管理机制完善，支持常驻钩子

7. **`controller/HookCoreLib/HookCore.h`** ⭐ **Rev4 说明**
   - **无需修改**: 接口设计已经满足需求

---

## 关于 HookCore 复用的说明 ⭐ **Rev4 重点**

根据新的设计要求，**DllLoadMon 组件将完全复用现有的 HookCore 基础设施**:

### 1. 复用 ApplyHook 函数

**位置**: [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76)

**功能**:
- 验证目标地址有效性
- 注入 trampoline DLL（如果需要）
- 分配远程内存用于 trampoline 代码
- 构建 trampoline 和钩子跳转代码
- 应用钩子到目标位置

**优势**:
- ✅ **无需重新实现钩子逻辑**: 直接使用成熟的钩子基础设施
- ✅ **保证稳定性**: 复用经过验证的代码，降低 bug 风险
- ✅ **统一管理机制**: 所有钩子使用相同的管理接口
- ✅ **简化维护**: 未来钩子机制的改进自动惠及 DllLoadMon

### 2. DllLoadMon 的定位

**DllLoadMon 是一个特殊的钩子代码 DLL**:
- 它本身是通过 `ApplyHook` 注入到目标进程的
- 它的钩子代码会钩住 `LdrLoadDll` 的返回位置
- 它在钩子回调中实现 DLL 加载监控逻辑
- 它通过事件与 UMController 通信

**架构图**:
```
UMController
    ↓ (调用 HookCore::ApplyHook)
DllLoadMon.dll (注入到目标进程)
    ↓ (钩子回调)
LdrLoadDll 返回位置 (通过 trampoline 机制)
    ↓ (触发)
DllLoadMon 钩子回调
    ↓ (事件通知)
UMController (应用其他钩子)
```

### 3. 钩子常驻策略

**Rev4 明确要求**:
- ⭐ **不移除 LdrLoadDll 钩子**: 保持永久监控能力
- ⭐ **随时响应 DLL 加载**: 用户可能随时需要添加新的延迟钩子
- ⭐ **性能影响可控**: LdrLoadDll 钩子只在返回时触发，开销很小

**实现方式**:
- 调用 `HookCore::ApplyHook` 后，**不调用**`HookCore::RemoveHook`
- DllLoadMon.dll 保持在目标进程内存中
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
   - LdrLoadDll 钩子中读取列表也需要加锁

2. **事件处理**:
   - UMController 中每个进程一个事件等待线程
   - 避免多个线程同时处理同一进程的事件
   - 待处理钩子列表访问需要同步

3. **等待超时处理**:
   - DllLoadMon 等待释放事件时应设置超时（如 5 秒）
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
1. MD5 计算和匹配逻辑测试
2. LdrLoadDll 钩取功能测试（通过 HookCore::ApplyHook）
3. RDI 读取和模块名提取测试
4. 事件通知机制测试

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

---

## 附录

### 附录 A: 术语表

- **延迟钩子 (Delay Hook)**: 模块未加载时预先注册，待模块加载后自动应用的钩子
- **DllLoadMon**: DLL 加载监控组件，注入到目标进程监控 LdrLoadDll 调用
- **RDI**: RUNTIME_FUNCTION 指针，在 LdrLoadDll 返回时指向被加载 DLL 的模块基址
- **待处理钩子 (Pending Hook)**: 已注册但尚未应用的钩子，等待目标模块加载

### 附录 B: 参考文档

- [`HookCore::ApplyHook` 实现](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76)
- [Shared/HookServices.h](file://c:\Users\x\Downloads\amsi_tracer-main\Shared\HookServices.h)
- [UMControllerDlg.cpp](file://c:\Users\x\Downloads\amsi_tracer-main\controller\UMController\UMControllerDlg.cpp)
- [HookProcDlg.cpp](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookUI\HookProcDlg.cpp)

### 附录 C: 待办事项

- [ ] 创建 DllLoadMon 组件骨架
- [ ] 实现 MD5 计算和匹配逻辑
- [ ] 收集 ntdll.dll MD5-偏移量映射数据
- [ ] 实现 UMController RegisterModuleWatch 接口
- [ ] 实现 HookUI 状态显示
- [ ] 编写集成测试用例
