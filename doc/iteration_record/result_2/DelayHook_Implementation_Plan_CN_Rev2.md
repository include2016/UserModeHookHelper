# Delay Hook 延迟钩子机制实现文档（修订版）

## 概述

本文档描述了延迟钩子（Delay Hook）机制的实现方案，该机制允许钩住尚未加载的 DLL。这解决了在钩子注册时某些 DLL 还未加载的问题，例如在调试 `wmic.exe` 进程中的 `fastprox.dll` 时遇到的场景。

## 问题陈述

当前的架构要求 DLL 必须先加载才能应用钩子。然而，某些 DLL（如 `wmic.exe` 中的 `fastprox.dll`）是根据命令行参数动态加载的，这使得使用当前方法无法钩住这些 DLL。

## 解决方案架构

### 核心组件

1. **DllLoadMon.dll**（新建专用监控 DLL）
   - 注入到目标进程
   - 钩住 `ntdll!LdrLoadDll` 返回位置
   - 监控 RDI 寄存器（PUNICODE_STRING，DLL 文件名不含后缀）
   - 检测到目标 DLL 加载完成后，通过事件通知主程序

2. **UMController**（`controller/UMController`）
   - 维护待处理钩子列表
   - 监听模块加载完成事件
   - 当模块加载完成时应用相应的钩子

3. **HookUI**（`controller/HookUI`）
   - 提供用于注册延迟钩子的用户界面
   - 在钩子序列窗口中显示待处理的钩子

### 关键技术细节

#### LdrLoadDll 返回位置钩取原理

- **为什么钩住返回位置**：只有在 LdrLoadDll 函数执行到返回代码时，目标 DLL 才真正完成加载，此时我们才能对目标 DLL 进行钩取操作。

- **返回位置的确定**：不同版本的 ntdll.dll 中，返回位置的偏移量不同。目前采用硬编码方式：
  - 预先收集多个版本的 ntdll.dll 文件（32 位和 64 位）
  - 计算每个版本文件的 MD5 值
  - 记录每个 MD5 对应的返回位置偏移量
  - 建立 MD5-偏移量映射关系表
  - 运行时通过计算当前环境中 ntdll.dll 的 MD5 来确定对应的偏移量
  - 使用公式：`Hook 地址 = ntdll.dll 基址 + 偏移量`

- **监控机制**：
  - 在 LdrLoadDll 返回后，RDI 寄存器指向 PUNICODE_STRING 结构
  - 该结构包含加载的 DLL 文件名（不含扩展名）
  - 通过读取 RDI 内容获取刚加载的 DLL 名称
  - 与监视列表中的模块名进行比较

#### 事件通知机制

- **事件命名规则**：`Global\\DelayHook_{ProcessId}`
  - 使用进程 ID 确保唯一性
  - 便于 UMController 定位到具体进程的事件

- **通知流程**：
  1. DllLoadMon.dll 检测到目标 DLL 加载完成
  2. 触发命名事件
  3. UMController 等待并接收到事件信号
  4. UMController 应用待处理钩子

### 实现策略

**阶段 2：实现用户模式延迟钩子机制**
- 创建 DllLoadMon.dll 专用监控组件
- 实现 ntdll MD5-偏移量映射表
- 实现 LdrLoadDll 返回位置钩取
- 实现事件通知机制
- UMController 实现事件监听和待处理钩子应用

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
    std::wstring module;      // 模块名称（例如 "fastprox"，不含后缀）
    std::wstring offset;      // 偏移量字符串（例如 "0x1234"）
    std::wstring dllPath;     // 钩子代码 DLL 的完整路径
    std::wstring exportName;  // 导出函数名称
    ULONGLONG address;        // 解析后的地址（模块加载时填充）
    HookRow hookRow;          // 应用钩子的 HookRow 数据
};
```

#### NtdllVersionEntry（新建 - MD5-偏移量映射）
```cpp
struct NtdllVersionEntry {
    UCHAR md5[16];           // ntdll.dll 文件的 MD5 哈希值
    ULONG offset_x64;        // 64 位版本返回位置偏移量
    ULONG offset_x86;        // 32 位版本返回位置偏移量
    const wchar_t* version;  // 可选：Windows 版本标识
};
```

#### ModuleWatchEntry（新建 - 监视列表项）
```cpp
struct ModuleWatchEntry {
    std::wstring moduleName;  // 要监视的模块（不含后缀，不区分大小写）
    bool notified;            // 是否已发送通知
};
```

### 组件职责

#### 1. DllLoadMon.dll（专用监控 DLL）

**位置**: `hook_component/DllLoadMon/DllLoadMon.dll`（新建）

**职责**:
- 注入到目标进程后，根据当前 ntdll.dll 的 MD5 查找对应的返回位置偏移量
- 使用 ApplyHook 钩住 `ntdll!LdrLoadDll` 返回位置
- 在钩子回调中监控 RDI 寄存器获取加载的 DLL 名
- 检查加载的 DLL 是否在监视列表中
- 当匹配的 DLL 加载完成时，触发命名事件通知 UMController

**导出函数**:
```cpp
// 初始化监控
extern "C" __declspec(dllexport) 
BOOL DllLoadMonHook(DWORD dwReason, LPVOID lpReserved);

// 注册模块监视
extern "C" __declspec(dllexport)
BOOL RegisterWatch(const wchar_t* moduleName);

// 注销模块监视
extern "C" __declspec(dllexport)
BOOL UnregisterWatch(const wchar_t* moduleName);
```

**实现细节**:
1. **MD5 匹配流程**：
   - DllMain 中获取 ntdll.dll 基址
   - 读取文件内容计算 MD5
   - 在预定义的映射表中查找匹配的条目
   - 获取返回位置偏移量

2. **钩住返回位置**：
   - 计算 Hook 地址：`ntdllBase + offset`
   - 准备 ApplyHook 所需参数
   - 调用 ApplyHook 安装钩子

3. **监控 RDI**：
   - 在钩子回调中，保存现场后读取 RDI
   - RDI 指向 UNICODE_STRING 结构
   - 提取文件名（不含.wav 后缀）
   - 与监视列表比较

4. **事件通知**：
   - 事件名称格式：`Global\\DelayHook_{ProcessId}`
   - 使用 NtSetEvent 触发事件
   - UMController 等待该事件

#### 2. UMController

**位置**: `controller/UMController/UMControllerDlg.cpp`

**职责**:
- 实现 `RegisterModuleWatch`（通过 ApplyHook 注入 DllLoadMon.dll）
- 维护每个进程的待处理钩子列表
- 监听模块加载完成事件
- 收到通知时应用待处理的钩子

**实现步骤**:
1. **修改 RegisterModuleWatch**：
   - 参考 `hook_component/umhh.x64\dllmain.cpp` 的 mycode 函数 line 545-593
   - 创建命名事件：`Global\\DelayHook_{ProcessId}`
   - 通过 ApplyHook 注入 DllLoadMon.dll
   - 调用 DllLoadMonHook 初始化监控
   - 调用 RegisterWatch 注册要监视的模块

2. **添加事件监听线程**：
   - 为每个有延迟钩子的进程创建事件等待线程
   - 使用 NtWaitForSingleObject 等待事件
   - 事件触发后，检索该进程的待处理钩子

3. **应用待处理钩子**：
   - 遍历待处理钩子列表
   - 对每个钩子调用 ApplyHook
   - 从未处理列表移除已应用的钩子
   - 更新 UI 显示钩子状态

#### 3. HookUI

**位置**: `controller/HookUI/HookProcDlg.cpp`

**职责**:
- 允许用户通过 UI 注册延迟钩子
- 在钩子序列列表中显示待处理的钩子
- 区分活动钩子和待处理钩子

**实现步骤**:
1. **添加 UI 元素**：
   - 在钩子列表中添加"状态"列
   - 显示"待处理"或"活动"状态
   - 可使用不同颜色或图标区分

2. **延迟钩子注册流程**：
   - 用户添加钩子时，检查模块是否已加载
   - 如果未加载：
     - 添加到待处理钩子列表
     - 调用 RegisterModuleWatch
     - 显示"待处理"状态
   - 如果已加载：
     - 直接应用钩子
     - 显示"活动"状态

3. **UI 更新**：
   - 当待处理钩子变为活动时
   - UMController 通知 HookUI 刷新显示
   - 更新状态为"活动"

### 通信流程

```
用户在 HookUI 中添加延迟钩子
    ↓
HookUI 检查模块是否已加载
    ↓
[模块未加载]
    ↓
HookUI 调用 IHookServices::AddPendingHook()
    ↓
HookUI 调用 IHookServices::RegisterModuleWatch()
    ↓
UMController 创建命名事件：Global\\DelayHook_{ProcessId}
    ↓
UMController 通过 ApplyHook 注入 DllLoadMon.dll
    ↓
UMController 调用 DllLoadMonHook 初始化
    ↓
UMController 调用 RegisterWatch 注册监视模块
    ↓
[DllLoadMon.dll 监控 LdrLoadDll 返回]
    ↓
目标模块加载 → LdrLoadDll 被调用
    ↓
LdrLoadDll 返回，钩子被触发
    ↓
钩子回调读取 RDI 获取 DLL 名
    ↓
检测到是被监视的模块
    ↓
DllLoadMon.dll 触发命名事件
    ↓
UMController 等待线程接收到事件
    ↓
UMController 检索待处理的钩子
    ↓
UMController 将钩子应用到已加载的模块
    ↓
UMController 移除待处理的钩子
    ↓
UMController 通知 HookUI 更新状态
    ↓
HookUI 更新 UI 显示活动钩子
```

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
   - 事件通知实现
   - 监视列表管理

3. **`hook_component/DllLoadMon/DllLoadMon.vcxproj`**
   - 项目配置文件
   - 导出符号定义

4. **`hook_component/DllLoadMon/ntdll_versions.h`**
   - 预定义的 ntdll 版本映射表
   - MD5 哈希值和对应偏移量

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
     - 创建命名事件
     - 通过 ApplyHook 注入 DllLoadMon.dll
     - 调用导出函数初始化和注册监视
   - 添加事件监听线程函数
   - 实现待处理钩子应用逻辑
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

## 实现注意事项

### MD5-偏移量映射表维护

1. **数据收集**：
   - 收集多个 Windows 版本的 ntdll.dll
   - 包括 32 位和 64 位版本
   - 记录每个文件的版本信息

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

## 测试计划

### 单元测试
1. MD5 计算和匹配逻辑测试
2. LdrLoadDll 钩取功能测试
3. RDI 读取和模块名提取测试
4. 事件通知机制测试

### 集成测试
1. 在 wmic.exe 中测试 fastprox.dll 的延迟钩子
2. 测试多个延迟钩子同时存在的情况
3. 测试模块卸载后重新加载的场景
4. 测试 UI 状态更新是否正确

### 回归测试
1. 确保常规钩子功能不受影响
2. 确保 umhh.x64 注入功能正常
3. 确保现有进程监控功能正常

## 总结

本修订方案的核心改进：

1. **删除了阶段 1**：基于驱动的 ModuleWatch 已经移除完成
2. **明确了 LdrLoadDll 钩取机制**：详细说明返回位置钩取原理和 MD5-偏移量映射方法
3. **引入专用组件**：创建 DllLoadMon.dll 专门处理延迟钩子监控，与 umhh.x64 分离
4. **保留 umhh.x64**：umhh.x64 组件保持不变，仅在需要时注入 DllLoadMon.dll
5. **明确 IPC 机制**：使用命名事件进行进程间通信，参考现有代码实现

下一步行动：
- 创建 DllLoadMon 组件
- 实现 ntdll 版本映射表
- 修改 UMController 实现事件监听
- 更新 HookUI 支持延迟钩子显示
