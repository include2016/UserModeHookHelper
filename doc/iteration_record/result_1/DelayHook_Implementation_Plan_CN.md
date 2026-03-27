# Delay Hook 延迟钩子机制实现文档

## 概述

本文档描述了延迟钩子（Delay Hook）机制的实现方案，该机制允许钩住尚未加载的 DLL。这解决了在钩子注册时某些 DLL 还未加载的问题，例如在调试 `wmic.exe` 进程中的 `fastprox.dll` 时遇到的场景。

## 问题陈述

当前的架构要求 DLL 必须先加载才能应用钩子。然而，某些 DLL（如 `wmic.exe` 中的 `fastprox.dll`）是根据命令行参数动态加载的，这使得使用当前方法无法钩住这些 DLL。

## 解决方案架构

### 核心组件

1. **用户模式钩子管理器** (`hook_component/umhh.x64`)
   - 监控目标进程中的 `LdrLoadDll` 调用
   - 检测被监视的模块何时加载
   - 当被监视模块加载时通知 UMController

2. **UMController** (`controller/UMController`)
   - 维护待处理钩子列表
   - 接收模块加载通知
   - 当模块加载时应用相应的钩子

3. **HookUI** (`controller/HookUI`)
   - 提供用于注册延迟钩子的用户界面
   - 在钩子序列窗口中显示待处理的钩子

### 实现策略

**阶段 1：移除基于驱动的 ModuleWatch**（错误的方法）
- 从驱动中删除 `ModuleWatch.c` 和 `ModuleWatch.h`
- 移除驱动端的模块加载监控
- 仅通过 `LdrLoadDll` 钩子在用户态进行监控

**阶段 2：实现用户模式延迟钩子机制**
- 在注入的 DLL 中钩住 `ntdll!LdrLoadDll`
- 维护要监视的模块列表
- 当被监视模块加载时，通过 ETW 或 IPC 通知 UMController
- UMController 为该模块应用待处理的钩子

**阶段 3：与现有钩子流程集成**
- 扩展 `HookServices.h` 中的 `PendingHook` 结构
- 在 HookUI 中添加延迟钩子的 UI 支持
- 与现有的钩子序列机制集成

## 详细设计

### 数据结构

#### PendingHook（已在 HookServices.h 中定义）
```cpp
struct PendingHook {
    DWORD pid;
    std::wstring module;      // 模块名称（例如 "fastprox.dll"）
    std::wstring offset;      // 偏移量字符串（例如 "0x1234"）
    std::wstring dllPath;     // 钩子代码 DLL 的完整路径
    std::wstring exportName;  // 导出函数名称
    ULONGLONG address;        // 解析后的地址（模块加载时填充）
    HookRow hookRow;          // 应用钩子的 HookRow 数据
};
```

#### ModuleWatchEntry（新建 - 在 umhh.x64 中）
```cpp
struct ModuleWatchEntry {
    std::wstring moduleName;      // 要监视的模块（不区分大小写）
    DWORD pid;                     // 目标进程 ID
    bool notified;                 // 是否已发送通知
};
```

### 组件职责

#### 1. umhh.x64（注入的 DLL）

**位置**: `hook_component/umhh.x64/dllmain.cpp`

**职责**:
- 注入后钩住 `ntdll!LdrLoadDll`
- 维护要监视的模块列表（从 UMController 接收）
- 检查每次 `LdrLoadDll` 调用是否在监视列表中
- 当被监视模块成功加载时：
  - 通过 ETW 事件或 IPC 通知 UMController
  - 在通知中包含模块基址

**实现步骤**:
1. 添加全局监视列表和同步原语
2. 注入后钩住 `LdrLoadDll`（已有基础设施）
3. 在被钩住的 `LdrLoadDll` 中：
   - 调用原始函数
   - 成功后检查加载的模块是否在监视列表中
   - 如果匹配，向 UMController 发送通知
4. 提供注册/注销模块监视的函数

#### 2. UMController

**位置**: `controller/UMController/UMControllerDlg.cpp`

**职责**:
- 实现 `RegisterModuleWatch`（替换基于驱动的实现）
- 维护每个进程的待处理钩子列表
- 监听模块加载通知
- 收到通知时应用待处理的钩子

**实现步骤**:
1. 修改 `RegisterModuleWatch` 以向注入的 DLL 发送监视请求
2. 添加模块加载通知处理器
3. 收到通知时：
   - 检索该模块的待处理钩子
   - 应用每个钩子
   - 从待处理列表中移除已应用的钩子
   - 更新 UI 以反映钩子状态

#### 3. HookUI

**位置**: `controller/HookUI/HookProcDlg.cpp`

**职责**:
- 允许用户通过 UI 注册延迟钩子
- 在钩子序列列表中显示待处理的钩子
- 区分活动钩子和待处理钩子

**实现步骤**:
1. 添加 UI 元素指示"待处理"状态
2. 当用户为未加载的模块添加钩子时：
   - 添加到待处理钩子列表
   - 注册模块监视
   - 显示"待处理"指示器
3. 当待处理钩子变为活动时更新 UI

### 通信流程

```
用户在 HookUI 中添加延迟钩子
    ↓
HookUI 调用 IHookServices::AddPendingHook()
    ↓
HookUI 调用 IHookServices::RegisterModuleWatch()
    ↓
UMController 通过 IPC/管道向注入的 DLL 发送监视请求
    ↓
[注入的 DLL 监控 LdrLoadDll 调用]
    ↓
目标模块加载 → LdrLoadDll 被调用
    ↓
被钩住的 LdrLoadDll 检测到被监视的模块
    ↓
注入的 DLL 通知 UMController（通过 ETW/IPC）
    ↓
UMController 检索待处理的钩子
    ↓
UMController 将钩子应用到已加载的模块
    ↓
UMController 移除待处理的钩子
    ↓
HookUI 更新 UI 显示活动钩子
```

## 需要修改的文件

### 需要删除的文件（基于驱动的方法）
1. `drivers/UserModeHookHelper/ModuleWatch.c` ✓ 已删除
2. `drivers/UserModeHookHelper/ModuleWatch.h` ✓ 已删除
3. 移除以下文件中的引用：
   - `drivers/UserModeHookHelper/SysCallback.c`（移除 ModuleWatch 包含和调用）✓ 已完成
   - `drivers/UserModeHookHelper/UserModeHookHelper.vcxproj`（移除 ModuleWatch.c 编译）✓ 已完成
   - `drivers/UserModeHookHelper/FltCommPort.c`（移除 Handle_RegisterModuleWatch 处理器）✓ 已完成

### 需要修改的文件

#### 共享层
1. **`Shared/HookServices.h`**
   - 已有 `PendingHook` 结构 ✓
   - 已有 `RegisterModuleWatch` 接口 ✓
   - 已有 `AddPendingHook`、`GetPendingHooks`、`RemovePendingHooks` ✓
   - 需要添加：注销模块监视的接口

#### Controller 层
2. **`controller/UMController/UMControllerDlg.cpp`**
   - 实现 `RegisterModuleWatch`（当前调用驱动）
   - 添加模块加载通知处理器
   - 实现待处理钩子应用逻辑

3. **`controller/UMController/FilterCommPort.cpp`**
   - 修改 `FLTCOMM_RegisterModuleWatch` 以与注入的 DLL 通信
   - 添加 IPC 机制向注入的 DLL 发送监视请求

4. **`controller/UMController/FilterCommPort.h`**
   - 添加新 IPC 方法的声明

#### HookUI 层
5. **`controller/HookUI/HookProcDlg.cpp`**
   - 更新 UI 以显示待处理的钩子
   - 添加延迟钩子时调用 `RegisterModuleWatch`

#### 注入的 DLL
6. **`hook_component/umhh.x64/dllmain.cpp`**
   - 添加模块监视列表管理
   - 钩住 `LdrLoadDll` 以监控模块加载
   - 添加通知机制以通知 UMController
   - 处理来自 UMController 的监视注册

### 需要创建的文件

7. **`hook_component/umhh.x64/ModuleMonitor.h`**（新建）
   - 模块监控接口
   - 监视列表管理

8. **`hook_component/umhh.x64/ModuleMonitor.cpp`**（新建）
   - 模块监控实现
   - `LdrLoadDll` 钩子逻辑

## 实现任务

### 任务 1：移除基于驱动的代码 ✓ 已完成
- [x] 删除 `ModuleWatch.c` 和 `ModuleWatch.h`
- [x] 从 `SysCallback.c` 中移除 `ModuleWatch` 引用
- [x] 从驱动 vcxproj 中移除 `ModuleWatch`
- [x] 从 `FltCommPort.c` 中移除 `Handle_RegisterModuleWatch`

### 任务 2：在注入的 DLL 中实现模块监控器
- [ ] 创建 `ModuleMonitor.h` 和 `ModuleMonitor.cpp`
- [ ] 实现带线程安全访问的监视列表
- [ ] 钩住 `LdrLoadDll`（扩展现有的钩子基础设施）
- [ ] 实现向 UMController 的通知机制

### 任务 3：更新 UMController
- [ ] 修改 `RegisterModuleWatch` 以使用 IPC 而不是驱动
- [ ] 添加模块加载通知处理器
- [ ] 实现待处理钩子应用逻辑
- [ ] 添加进程退出时的清理功能

### 任务 4：更新 HookUI
- [ ] 为待处理钩子添加 UI 指示器
- [ ] 更新钩子添加逻辑以处理未加载的模块
- [ ] 当待处理钩子变为活动时刷新 UI

### 任务 5：测试
- [ ] 使用未加载 DLL 的场景进行测试
- [ ] 验证 DLL 加载时钩子是否正确应用
- [ ] 测试同一模块的多个待处理钩子
- [ ] 测试进程退出时的清理

## 技术考虑

### 同步
- 监视列表访问必须是线程安全的（使用 SRW 锁或临界区）
- `LdrLoadDll` 钩子在目标进程上下文中执行 - 保持逻辑最小化
- 向 UMController 的通知应该是异步的

### 错误处理
- 处理被监视模块加载失败的情况
- 当目标进程退出时清理监视
- 处理 UMController 重启场景

### 安全性
- 验证模块名称以防止注入攻击
- 确保 IPC 通道安全
- 验证通知中的进程 ID

## 成功标准

1. 用户可以通过 HookUI 为未加载的 DLL 注册钩子
2. 当 DLL 加载时自动应用钩子
3. UI 更新以反映钩子状态变化（待处理 → 活动）
4. 模块加载检测不涉及驱动程序
5. 对目标进程的性能影响最小

## 时间估算

- 任务 1（移除驱动代码）：2 小时 ✓
- 任务 2（实现模块监控器）：6 小时
- 任务 3（更新 UMController）：4 小时
- 任务 4（更新 HookUI）：3 小时
- 任务 5（测试）：3 小时

**总计**：约 18 小时

---

*文档创建日期：2026 年 3 月 27 日*  
*作者：AI 助手*
