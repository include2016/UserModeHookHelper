# 延迟钩子实现方案 (修订版 4)

## 概述

本文档描述了延迟钩子（Delay Hook）功能的实现方案。延迟钩子允许在目标 DLL 加载之前注册钩子，系统会自动监控 DLL 加载并在加载完成后自动应用钩子。

**主要改进点（Rev4）**：
- ✅ **复用现有 HookCore 基础设施**：直接使用 [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76) 函数，无需重新实现钩子逻辑
- ✅ **LdrLoadDll 钩子常驻**：不对 LdrLoadDll 的钩子进行移除，保持永久监控能力
- ✅ **简化架构设计**：DllLoadMon 作为标准钩子代码，通过 ApplyHook 注入和管理
- ✅ 完善事件通知机制和命名规则
- ✅ 优化通知流程，确保 DllLoadMon 正确等待和释放

---

## 核心组件

### 1. DllLoadMon.dll（专用监控 DLL）

**位置**: `hook_component/DllLoadMon/`

**职责**:
- 作为标准钩子代码通过 `HookCore::ApplyHook` 注入到目标进程
- 钩住目标进程中 `LdrLoadDll` 函数的返回位置
- 监控特定 DLL 的加载完成事件
- 通过事件通知 UMController
- **等待 UMController 完成钩子应用后释放阻塞**

**关键设计变更（Rev4）**：
- ⭐ **不复用 umhh.x64**：DllLoadMon 是独立的专用钩子 DLL
- ⭐ **复用 HookCore 基础设施**：使用现有的 `ApplyHook` 函数进行注入和钩子管理
- ⭐ **钩子常驻**：一旦注入，LdrLoadDll 钩子将持续存在，随时响应 DLL 加载事件


**MD5-偏移量映射表**:
```cpp
struct NtdllVersionInfo {
    const char* md5Hash;      // MD5 哈希值（小写）
    ULONG_PTR returnOffset;   // LdrLoadDll 返回指令偏移
    USHORT platform;          // 平台标识 (AMD64/X86)
};

// 预定义的映射表（示例）
static const NtdllVersionInfo g_ntdllVersions[] = {
    {"35b03f5d9c6da76fec950a36f9d357b3", 0x16B34, PLATFORM_AMD64},
};
```

**实现步骤**:
1. **计算 ntdll.dll 的 MD5**：
   - 获取 ntdll.dll 文件路径：`C:\Windows\System32\ntdll.dll`
   - 读取文件内容并计算 MD5 哈希值
   - 转换为小写十六进制字符串

2. **匹配偏移量**：
   - 遍历 `g_ntdllVersions` 映射表
   - 找到匹配的 MD5 条目

3. **Fallback 机制**：
   - 如果 MD5 不匹配，记录错误日志
   - 返回 `STATUS_NOT_SUPPORTED`
   - 提示用户添加新版本映射


**技术原理**:
```
正常 LdrLoadDll 执行流程:
┌─────────────────────────┐
│  LdrLoadDll 函数入口     │
│  - 保存现场             │
│  - 参数处理             │
│  - 加载 DLL             │
│  - 初始化 DLL           │ ← 钩子触发点（返回前）
│  - 恢复现场             │
│  - RET 指令             │ ← 返回指令位置（被钩住）
└─────────────────────────┘
       ↓
┌─────────────────────────┐
│  Trampoline 跳转        │
│  - 保存完整上下文       │
│  - 跳转到钩子回调       │
└─────────────────────────┘
       ↓
┌─────────────────────────┐
│  DllLoadMon 钩子回调    │
│  - 保存寄存器           │
│  - 读取 RDI 获取模块名  │
│  - 检查监视列表         │
│  - [如果匹配]           │
│    - 触发事件通知       │
│    - 等待释放事件       │ ← 关键：等待 UMController 处理
│  - 恢复寄存器           │
│  - 跳回原返回位置       │
└─────────────────────────┘
```

**钩子类型**: 函数返回位置钩（Return Site Hook）

**优势**:
- 不影响 LdrLoadDll 的正常执行流程
- 在 DLL 完全加载并初始化后触发
- 避免破坏调用约定和栈平衡

**实现方式（Rev4 重要变更）**：
- ⭐ **复用 HookCore 基础设施**：通过 `HookCore::ApplyHook` 函数实现钩子注入
- ⭐ **无需重新实现钩子逻辑**：使用现有的 trampoline 机制和钩子管理代码
- ⭐ **钩子常驻内存**：一旦注入，不会主动移除，保持监控能力

#### 1.3 RDI 监控逻辑

**实现步骤**:
1. **监控 RDI**：
   - 在钩子回调中，保存现场后读取 RDI
   - RDI 指向 `UNICODE_STRING` 结构（NTDLL 调用约定）
   - 提取文件名（不含后缀）

2. **与监视列表比较**：
   - 遍历注册的监视列表
   - 不区分大小写比较 DLL 名称
   - 如果匹配，触发事件通知流程

#### 1.4 事件通知与等待机制

**完整流程**:
```
1. DllLoadMon 检测到目标 DLL 加载
         ↓
2. 触发事件通知 UMController (NtSetEvent)
         ↓
3. DllLoadMon 进入等待状态 (NtWaitForSingleObject)
         ↓
4. UMController 接收到事件通知
         ↓
5. UMController 应用目标 DLL 的钩子
         ↓
6. UMController 触发释放事件 (NtSetEvent)
         ↓
7. DllLoadMon 从等待状态唤醒
         ↓
8. DllLoadMon 恢复执行，返回到被 hook 的进程
```

**关键说明**:
- **步骤 3 的等待是必需的**：防止 LdrLoadDll 立即返回导致被 hook 的进程在钩子未就绪的情况下继续执行
- **步骤 6 的释放事件由 UMController 触发**：确保所有钩子都已应用完成
- **钩子不移除**：DllLoadMon 保持在进程中，继续监控后续 DLL 加载事件

**事件名称规则**:

| 事件类型 | 命名格式 | 用途 | 触发方 | 等待方 |
|---------|---------|------|--------|--------|
| 加载通知事件 | `Global\\DelayHook_Load_{ProcessId}` | 通知 UMController 目标 DLL 已加载 | DllLoadMon | UMController |
| 释放等待事件 | `Global\\DelayHook_Release_{ProcessId}` | 通知 DllLoadMon 可以释放阻塞 | UMController | DllLoadMon |
| 钩子应用事件 | `Global\\DelayHook_HookApplied_{ProcessId}_{DllName}` | 通知 HookUI 钩子已应用 | UMController | HookUI (可选) |

**前缀说明**:
- `DelayHook_Load_*`: 用于 DLL 加载完成通知
- `DelayHook_Release_*`: 用于解除 DllLoadMon 阻塞
- `DelayHook_HookApplied_*`: 用于 UI 状态更新

---

### 2. UMController

**位置**: `controller/UMController/UMControllerDlg.cpp`

**职责**:
- 实现 `RegisterModuleWatch`（通过 `HookCore::ApplyHook` 注入 DllLoadMon.dll）
- 维护每个进程的待处理钩子列表
- 监听模块加载完成事件
- **收到通知时应用待处理的钩子**
- **通知 DllLoadMon 解除阻塞**

**实现步骤**:

#### 2.1 修改 RegisterModuleWatch

**参考代码**: [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76)

**实现逻辑**:
```cpp
NTSTATUS RegisterModuleWatch(HANDLE hProcess, const wchar_t* dllName)
{
    DWORD pid = GetProcessId(hProcess);
    
    // 1. 创建命名事件
    wchar_t eventNameLoad[64];
    wchar_t eventNameRelease[64];
    swprintf_s(eventNameLoad, L"Global\\DelayHook_Load_%lu", pid);
    swprintf_s(eventNameRelease, L"Global\\DelayHook_Release_%lu", pid);
    
    HANDLE hEventLoad = CreateEventW(NULL, TRUE, FALSE, eventNameLoad);
    HANDLE hEventRelease = CreateEventW(NULL, TRUE, FALSE, eventNameRelease);
    
    // 2. 通过 HookCore::ApplyHook 注入 DllLoadMon.dll
    // 获取 DllLoadMon.dll 的导出函数地址
    HMODULE hDllLoadMon = LoadLibrary(L"DllLoadMon.dll");
    if (!hDllLoadMon) {
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
    
    // 3. 调用 ApplyHook 注入 DllLoadMon.dll
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
    
    // 4. 调用初始化函数，传入事件句柄和监视列表
    pfnInitialize(hProcess, hEventLoad, hEventRelease);
    
    // 5. 注册要监视的模块
    // 通过共享内存或 IPC 传递给 DllLoadMon
    
    // 6. 创建事件监听线程
    CreateThread(NULL, 0, DelayHookMonitorThread, params);
    
    return STATUS_SUCCESS;
}
```

**关键说明（Rev4）**：
- ⭐ **使用 HookCore::ApplyHook**：复用现有钩子基础设施，无需重新实现
- ⭐ **钩子永久驻留**：不调用 `RemoveHook`，保持监控能力
- ⭐ **一次注入，多次使用**：同一个 DllLoadMon 实例可以处理多个 DLL 加载事件

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
  │                          │ - DelayHook_Load_{PID}     │                           │
  │                          │ - DelayHook_Release_{PID}  │                           │
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
  │                          │ (等待 DelayHook_Load_{PID})│                           │
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
  │                          │                            │ 触发 DelayHook_Load_{PID} │
  │                          │                            │──────────────────────────>│
  │                          │                            │                           │
  │                          │                            │ 等待 DelayHook_Release_{PID}
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
  │                          │ 触发 DelayHook_Release_{PID}
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

1. **用户注册延迟钩子**：HookUI 调用 UMController 注册
2. **UMController 检查模块状态**：如果未加载，准备监控
3. **调用 HookCore::ApplyHook**：⭐ 复用现有基础设施注入 DllLoadMon.dll
4. **创建事件对象**：创建加载通知事件和释放等待事件
5. **初始化监控**：调用 DllLoadMon 导出函数设置监视列表
6. **启动监听线程**：UMController 等待加载通知事件
7. **目标进程调用 LdrLoadDll**：正常加载 DLL
8. **DllLoadMon 钩子触发**：在返回指令处拦截（通过 trampoline）
9. **检测目标 DLL**：读取 RDI 获取模块名并匹配
10. **触发加载事件**：通知 UMController
11. **等待释放事件**：**防止 LdrLoadDll 立即返回** ⭐ **关键**
12. **UMController 应用钩子**：检索并应用所有待处理钩子
13. **触发释放事件**：通知 DllLoadMon 解除阻塞 ⭐ **关键**
14. **DllLoadMon 恢复执行**：跳回原返回位置
15. **LdrLoadDll 返回**：此时所有钩子已就绪
16. **更新 UI**：显示钩子状态为"活动"
17. **DllLoadMon 继续驻留**：⭐ **Rev4 新增** 不移除钩子，继续监控后续 DLL 加载

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
   - 实现 `RegisterModuleWatch`：
     - 创建两个命名事件：`DelayHook_Load_{ProcessId}` 和 `DelayHook_Release_{ProcessId}`
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
   - **无需修改**：现有 `ApplyHook` 函数已足够强大，支持 DllLoadMon 注入
   - **无需修改**：钩子管理机制完善，支持常驻钩子

7. **`controller/HookCoreLib/HookCore.h`** ⭐ **Rev4 说明**
   - **无需修改**：接口设计已经满足需求

---

## 关于 HookCore 复用的说明 ⭐ **Rev4 重点**

根据新的设计要求，**DllLoadMon 组件将完全复用现有的 HookCore 基础设施**：

### 1. 复用 ApplyHook 函数

**位置**: [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76)

**功能**:
- 验证目标地址有效性
- 注入 trampoline DLL（如果需要）
- 分配远程内存用于 trampoline 代码
- 构建 trampoline 和钩子跳转代码
- 应用钩子到目标位置

**优势**:
- ✅ **无需重新实现钩子逻辑**：直接使用成熟的钩子基础设施
- ✅ **保证稳定性**：复用经过验证的代码，降低 bug 风险
- ✅ **统一管理机制**：所有钩子使用相同的管理接口
- ✅ **简化维护**：未来钩子机制的改进自动惠及 DllLoadMon

### 2. DllLoadMon 的定位

**DllLoadMon 是一个特殊的钩子代码 DLL**：
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

**Rev4 明确要求**：
- ⭐ **不移除 LdrLoadDll 钩子**：保持永久监控能力
- ⭐ **随时响应 DLL 加载**：用户可能随时需要添加新的延迟钩子
- ⭐ **性能影响可控**：LdrLoadDll 钩子只在返回时触发，开销很小

**实现方式**:
- 调用 `HookCore::ApplyHook` 后，**不调用**`HookCore::RemoveHook`
- DllLoadMon.dll 保持在目标进程内存中
- 钩子持续有效，直到进程终止

---

## 实现注意事项

### MD5-偏移量映射表维护

1. **数据收集**：
   - 收集多个 Windows 版本的 ntdll.dll
   - 包括 32 位和 64 位版本
   - 记录每个文件的版本信息
   - **由用户负责收集和提供映射关系**

2. **偏移量测量**：
   - 使用调试器分析 LdrLoadDll 函数
   - 找到返回指令（RET）的位置
   - 记录相对于 ntdll 基址的偏移量

3. **映射表更新**：
   - 定期更新映射表以支持新版本的 Windows
   - 提供 fallback 机制（如果找不到匹配的 MD5）

### 同步和线程安全

1. **监视列表保护**：
   - 使用 SRW 锁或临界区保护监视列表
   - 注册/注销操作需要加锁
   - LdrLoadDll 钩子中读取列表也需要加锁

2. **事件处理**：
   - UMController 中每个进程一个事件等待线程
   - 避免多个线程同时处理同一进程的事件
   - 待处理钩子列表访问需要同步

3. **等待超时处理**：
   - DllLoadMon 等待释放事件时应设置超时（如 5 秒）
   - 防止 UMController 崩溃导致死锁
   - 超时后记录日志并继续执行

### 错误处理

1. **MD5 匹配失败**：
   - 如果当前 ntdll 的 MD5 不在映射表中
   - 记录日志并返回错误
   - 提示用户该场景暂不支持

2. **注入失败**：
   - ApplyHook 失败时的回滚机制
   - 清理已创建的事件对象
   - 从待处理列表中移除失败的钩子

3. **超时处理**：
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
5. 等待 - 释放机制测试

### 集成测试
1. 在 wmic.exe 中测试 fastprox.dll 的延迟钩子
2. 测试多个延迟钩子同时存在的情况
3. 测试模块卸载后重新加载的场景
4. 测试 UI 状态更新是否正确
5. 测试钩子常驻功能（多次 DLL 加载）
6. 测试超时处理机制

### 回归测试
1. 确保常规钩子功能不受影响
2. 确保 HookCore::ApplyHook 功能正常
3. 确保现有进程监控功能正常

---

## 总结

本修订方案（Rev4）的核心改进：

1. ✅ **删除了阶段 1**：基于驱动的 ModuleWatch 已经移除完成
2. ✅ **明确了 LdrLoadDll 钩取机制**：详细说明返回位置钩取原理和 MD5-偏移量映射方法
3. ✅ **引入专用组件**：创建 DllLoadMon.dll 专门处理延迟钩子监控
4. ⭐ **复用 HookCore 基础设施**：直接使用 `HookCore::ApplyHook` 函数，无需重新实现钩子逻辑
5. ✅ **明确 IPC 机制**：使用命名事件进行进程间通信
6. ✅ **完善等待 - 释放机制**：DllLoadMon 在通知后等待，UMController 处理完成后释放阻塞
7. ✅ **规范事件命名**：定义清晰的事件前缀和用途（Load/Release/HookApplied）
8. ✅ **添加超时处理**：防止死锁情况
9. ⭐ **钩子常驻策略**：LdrLoadDll 钩子永久驻留，随时响应 DLL 加载事件

### 关键技术决策（Rev4）

1. **复用而非重写**：
   - 使用 [`HookCore::ApplyHook`](file://c:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp#L76) 而非重新实现钩子逻辑
   - 降低开发成本，提高代码质量

2. **常驻钩子设计**：
   - LdrLoadDll 钩子一旦注入就不移除
   - 支持随时添加新的延迟钩子
   - 性能开销可控

3. **专用组件**：
   - DllLoadMon 专注于 DLL 加载监控
   - 与 umhh.x64 分离，职责清晰

### 下一步行动

- [ ] 创建 DllLoadMon 组件（参考 HookCodeTemplate 项目结构）
- [ ] 实现 ntdll 版本映射表（初始数据：MD5:35b03f5d9c6da76fec950a36f9d357b3 → Offset:0x16B34）
- [ ] 修改 UMController 实现事件监听和释放逻辑
- [ ] 更新 HookUI 支持延迟钩子显示
- [ ] 编写单元测试验证等待 - 释放机制
- [ ] 用户继续提供更多 ntdll 版本映射数据
- [ ] 测试 HookCore::ApplyHook 与 DllLoadMon 的集成

---

## 附录：事件命名规范速查表

| 前缀 | 完整格式 | 方向 | 用途 |
|------|---------|------|------|
| `DelayHook_Load_` | `Global\DelayHook_Load_{ProcessId}` | DllLoadMon → UMController | 通知 DLL 加载完成 |
| `DelayHook_Release_` | `Global\DelayHook_Release_{ProcessId}` | UMController → DllLoadMon | 解除 DllLoadMon 阻塞 |
| `DelayHook_HookApplied_` | `Global\DelayHook_HookApplied_{ProcessId}_{DllName}` | UMController → HookUI | UI 状态更新（可选） |

**命名规则**:
- 所有事件使用 `Global\` 前缀以实现跨会话访问
- 使用进程 ID 区分不同进程
- 使用有意义的名词（Load/Release/HookApplied）表示事件类型

---

## 附录：HookCore::ApplyHook 接口参考

**函数签名**:
```cpp
bool HookCore::ApplyHook(
    DWORD pid,                      // 目标进程 ID
    ULONGLONG address,              // 钩子目标地址（LdrLoadDll 返回位置）
    IHookServices* services,        // 服务接口（可选）
    DWORD64 hook_code_addr,         // 钩子代码地址（DllLoadMon 导出函数）
    int hook_id,                    // 钩子 ID（自定义标识）
    DWORD* out_ori_asm_code_len,    // 输出：原始汇编代码长度
    PVOID* out_trampoline_pit,      // 输出：trampoline 内存地址
    PVOID* out_ori_asm_code_addr    // 输出：原始代码备份地址
);
```

**返回值**:
- `true`: 钩子应用成功
- `false`: 钩子应用失败（检查日志获取详细信息）

**使用示例**:
```cpp
DWORD oriLen = 0;
PVOID trampPit = NULL;
PVOID oriCodeAddr = NULL;

bool success = HookCore::ApplyHook(
    pid,
    ldrLoadDllReturnAddr,
    g_services,
    (DWORD64)pfnDllLoadMonHook,
    HOOKID_DELAYLOAD_MONITOR,
    &oriLen,
    &trampPit,
    &oriCodeAddr
);

if (success) {
    // 钩子应用成功，DllLoadMon 开始监控
} else {
    // 处理失败情况
}
```
