# 延迟钩子实现方案 (修订版 3)

## 概述

本文档描述了延迟钩子（Delay Hook）功能的实现方案。延迟钩子允许在目标 DLL 加载之前注册钩子，系统会自动监控 DLL 加载并在加载完成后自动应用钩子。

**主要改进点（Rev3）**：
- ✅ 删除基于驱动的 ModuleWatch 组件（阶段 1 已移除）
- ✅ 创建专用 DllLoadMon.dll 监控组件
- ✅ 完善事件通知机制和命名规则
- ✅ 优化通知流程，确保 DllLoadMon 正确等待和释放
- ✅ 添加详细的 ntdll 版本映射机制
- ✅ 明确 IPC 通信机制

---

## 核心组件

### 1. DllLoadMon.dll（新建专用监控 DLL）

**位置**: `hook_component/DllLoadMon/`

**职责**:
- 钩住目标进程中 LdrLoadDll 函数的返回位置
- 监控特定 DLL 的加载完成事件
- 通过事件通知 UMController
- **等待 UMController 完成钩子应用后释放阻塞**

**实现细节**:

#### 1.1 ntdll 版本适配

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
    // 后续由用户添加更多版本...
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
   - 获取对应的返回指令偏移量

3. **Fallback 机制**：
   - 如果 MD5 不匹配，记录错误日志
   - 返回 `STATUS_NOT_SUPPORTED`
   - 提示用户添加新版本映射

#### 1.2 LdrLoadDll 钩取实现

**钩取位置**: LdrLoadDll 函数的返回指令处

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

#### 1.4 事件通知与等待机制 ⭐ **Rev3 重要更新**

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

**事件名称规则**: ⭐ **Rev3 新增**

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
- 实现 `RegisterModuleWatch`（通过 ApplyHook 注入 DllLoadMon.dll）
- 维护每个进程的待处理钩子列表
- 监听模块加载完成事件
- **收到通知时应用待处理的钩子**
- **通知 DllLoadMon 解除阻塞** ⭐ **Rev3 重要更新**

**实现步骤**:

#### 2.1 修改 RegisterModuleWatch

**参考代码**: `hook_component/umhh.x64\dllmain.cpp` 的 `mycode` 函数 line 545-593

**实现逻辑**:
```cpp
NTSTATUS RegisterModuleWatch(HANDLE hProcess, const wchar_t* dllName)
{
    // 1. 创建命名事件
    wchar_t eventNameLoad[64];
    wchar_t eventNameRelease[64];
    swprintf_s(eventNameLoad, L"Global\\DelayHook_Load_%lu", GetProcessId(hProcess));
    swprintf_s(eventNameRelease, L"Global\\DelayHook_Release_%lu", GetProcessId(hProcess));
    
    HANDLE hEventLoad = CreateEventW(NULL, TRUE, FALSE, eventNameLoad);
    HANDLE hEventRelease = CreateEventW(NULL, TRUE, FALSE, eventNameRelease);
    
    // 2. 通过 ApplyHook 注入 DllLoadMon.dll
    // 参考 dllmain.cpp line 545-593 的 IPC 实现机制
    
    // 3. 调用 DllLoadMonHook 初始化监控
    // 4. 调用 RegisterWatch 注册要监视的模块
    
    // 5. 创建事件监听线程
    CreateThread(NULL, 0, DelayHookMonitorThread, params);
    
    return STATUS_SUCCESS;
}
```

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
        ApplyHook(params->hProcess, hook.moduleBase, hook.hookInfo);
    }
    
    // ⭐ Rev3 关键：通知 DllLoadMon 解除阻塞
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
- 对每个钩子调用 `ApplyHook`
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

## 通信流程 ⭐ **Rev3 完善版**

### 完整时序图

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
  │                          │ 注入 DllLoadMon.dll         │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 调用 DllLoadMonHook 初始化   │                           │
  │                          │───────────────────────────>│                           │
  │                          │                            │                           │
  │                          │ 调用 RegisterWatch         │                           │
  │                          │ 注册监视模块名              │                           │
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
  │                          │ (调用 ApplyHook)           │                           │
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
```

### 流程说明

1. **用户注册延迟钩子**：HookUI 调用 UMController 注册
2. **UMController 检查模块状态**：如果未加载，准备监控
3. **注入 DllLoadMon.dll**：通过 ApplyHook 注入专用监控 DLL
4. **创建事件对象**：创建加载通知事件和释放等待事件
5. **初始化监控**：调用 DllLoadMon 导出函数设置监视列表
6. **启动监听线程**：UMController 等待加载通知事件
7. **目标进程调用 LdrLoadDll**：正常加载 DLL
8. **DllLoadMon 钩子触发**：在返回指令处拦截
9. **检测目标 DLL**：读取 RDI 获取模块名并匹配
10. **触发加载事件**：通知 UMController
11. **等待释放事件**：**防止 LdrLoadDll 立即返回** ⭐ **关键**
12. **UMController 应用钩子**：检索并应用所有待处理钩子
13. **触发释放事件**：通知 DllLoadMon 解除阻塞 ⭐ **关键**
14. **DllLoadMon 恢复执行**：跳回原返回位置
15. **LdrLoadDll 返回**：此时所有钩子已就绪
16. **更新 UI**：显示钩子状态为"活动"

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
   - LdrLoadDll 返回位置钩取实现
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
     - 通过 ApplyHook 注入 DllLoadMon.dll
     - 调用导出函数初始化和注册监视
   - 添加事件监听线程函数
   - 实现待处理钩子应用逻辑
   - **在钩子应用完成后触发释放事件** ⭐ **Rev3 新增**
   - 参考 `hook_component/umhh.x64\dllmain.cpp` line 545-593 的 IPC 实现机制

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

#### 注入的 DLL（可选修改）
6. **`hook_component/umhh.x64/dllmain.cpp`**
   - **注意**：根据修订方案，umhh.x64 不进行 LdrLoadDll 钩取
   - 仅在需要延迟钩子时才注入 DllLoadMon.dll
   - umhh.x64 保持现有功能不变
   - 如果需要，可添加辅助函数用于判断模块是否已加载

---

## 关于 umhh.x64 组件的说明

根据修订后的设计方案，**umhh.x64 组件不需要进行修改**。原因如下：

1. **职责分离**：
   - umhh.x64：负责基础注入功能和常规钩子应用
   - DllLoadMon.dll：专门负责延迟钩子场景的模块加载监控

2. **按需注入**：
   - 只有在出现延迟钩子需求时，才注入 DllLoadMon.dll
   - umhh.x64 在常规场景下注入，不负责模块监控

3. **避免过度钩取**：
   - 不在 umhh.x64 注入时就钩住 LdrLoadDll
   - 减少不必要的性能开销和潜在冲突

4. **简化架构**：
   - 专用组件负责专用功能
   - umhh.x64 保持简洁，专注于基础注入

---

## 实现注意事项

### MD5-偏移量映射表维护

1. **数据收集**：
   - 收集多个 Windows 版本的 ntdll.dll
   - 包括 32 位和 64 位版本
   - 记录每个文件的版本信息
   - **由用户负责收集和提供映射关系** ⭐

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

3. **等待超时处理**： ⭐ **Rev3 新增**
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
2. LdrLoadDll 钩取功能测试
3. RDI 读取和模块名提取测试
4. 事件通知机制测试
5. **等待 - 释放机制测试** ⭐ **Rev3 新增**

### 集成测试
1. 在 wmic.exe 中测试 fastprox.dll 的延迟钩子
2. 测试多个延迟钩子同时存在的情况
3. 测试模块卸载后重新加载的场景
4. 测试 UI 状态更新是否正确
5. **测试超时处理机制** ⭐ **Rev3 新增**

### 回归测试
1. 确保常规钩子功能不受影响
2. 确保 umhh.x64 注入功能正常
3. 确保现有进程监控功能正常

---

## 总结

本修订方案（Rev3）的核心改进：

1. ✅ **删除了阶段 1**：基于驱动的 ModuleWatch 已经移除完成
2. ✅ **明确了 LdrLoadDll 钩取机制**：详细说明返回位置钩取原理和 MD5-偏移量映射方法
3. ✅ **引入专用组件**：创建 DllLoadMon.dll 专门处理延迟钩子监控，与 umhh.x64 分离
4. ✅ **保留 umhh.x64**：umhh.x64 组件保持不变，仅在需要时注入 DllLoadMon.dll
5. ✅ **明确 IPC 机制**：使用命名事件进行进程间通信，参考现有代码实现
6. ⭐ **完善等待 - 释放机制**：DllLoadMon 在通知后等待，UMController 处理完成后释放阻塞
7. ⭐ **规范事件命名**：定义清晰的事件前缀和用途（Load/Release/HookApplied）
8. ⭐ **添加超时处理**：防止死锁情况

### 下一步行动

- [ ] 创建 DllLoadMon 组件
- [ ] 实现 ntdll 版本映射表（初始数据：MD5:35b03f5d9c6da76fec950a36f9d357b3 → Offset:0x16B34）
- [ ] 修改 UMController 实现事件监听和释放逻辑
- [ ] 更新 HookUI 支持延迟钩子显示
- [ ] 编写单元测试验证等待 - 释放机制
- [ ] 用户继续提供更多 ntdll 版本映射数据

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
