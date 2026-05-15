# Instant Hook 功能实现计划

## Context

当前 hook 机制是在进程完全启动、所有模块加载完成后，通过 HookDialog 窗口手动指定 offset 进行 hook。用户希望实现"即时 hook"——在目标 DLL 刚加载时（进程还在启动过程中）就完成 hook，而不是等进程完全启动。

核心原则：监控和应用逻辑完全放在 UMController 端管理，不依赖 HookUI 窗口。

## 架构概览

```
UMController                         UMHH.dll (in target process)
     |                                       |
     |  1. "Set Instant Hook" 菜单项          |
     |  2. 选择 hookseq 文件                  |
     |  3. 写 C:\users\public\delay.hook.<pFnv> 文件 |
     |  4. 创建 LoadNotify 监听线程（后台）     |
     |                                       | 5. 启动目标进程，CheckSignalFile 通过
     |                                       | 6. ScanDelayHookFiles() 解析文件
     |                                       | 7. Hook LdrLoadDll
     |                                       |
     |         LoadNotify.<pFnv>.<dllFnv> <--|
     | 8. 收到通知，调用 InstantHookManager  |
     |   执行 InjectTrampoline + HookCore    |
     |                                       |
     | 9. -------- HookNotify -------->     |
     |                                       | 10. LdrLoadDll_HookHandler 继续执行
```

## 事件命名规范（每个 Target DLL 独立）

```
LoadNotify.<processFnvHash>.<dllFnvHash>
    - UMHH.dll 加载目标 DLL 时 signal
    - UMController 监听此事件

HookNotify.<processFnvHash>.<dllFnvHash>
    - UMController 完成 hook 后 signal
    - UMHH.dll LdrLoadDll_HookHandler 等待此事件
```

- `processFnvHash` = 进程 NT 路径的 FNV-1a hash（16位 hex 小写）
- `dllFnvHash` = 目标 DLL 文件名的 FNV-1a hash（16位 hex 小写）

每个目标 DLL 有独立的 LoadNotify/HookNotify 事件对。

## 文件修改清单

### 1. `hook_component/umhh.x64/dllmain.cpp`

**新增数据结构：**
```cpp
struct InstantHookTarget {
    wchar_t targetDllName[MAX_PATH];        // 目标 DLL 文件名
    unsigned long long dllFnvHash;           // DLL 文件名的 FNV hash
    HANDLE hLoadNotifyEvent;                // LoadNotify.<pFnv>.<dllFnv>
    HANDLE hHookNotifyEvent;                // HookNotify.<pFnv>.<dllFnv>
    InstantHookTarget* next;
};
static InstantHookTarget* g_InstantHookList = nullptr;
```

**事件句柄放在链表节点中，每个节点有自己的 LoadNotify/HookNotify 事件对。**

**新增宏（SharedMacroDef.h）：**
```cpp
#define LOAD_NOTIFY_EVENT_FMT L"LoadNotify.%llx.%llx"
#define HOOK_NOTIFY_EVENT_FMT L"HookNotify.%llx.%llx"
```

**新增函数：**
- `ScanDelayHookFiles()` - 在 `CheckSignalFile` 通过后，扫描 `C:\users\public\delay.hook.*`，用当前进程路径的 FNV 匹配文件名后缀，解析并加入链表
- `ParseDelayHookFile(const wchar_t* path)` - 解析 delay.hook 文件，提取所有目标 DLL，加入链表

**修改 `LdrLoadDll_HookHandler`：**
- 遍历 `g_InstantHookList`
- 对比被加载的 DLL 文件名（只用文件名，不用完整路径）与链表中的 `targetDllName`
- 匹配时：
  1. Signal `node->hLoadNotifyEvent`（LoadNotify.<pFnv>.<dllFnvHash>）
  2. Wait on `node->hHookNotifyEvent`（HookNotify.<pFnv>.<dllFnvHash>，INFINITE）
  3. 收到通知后 CloseHandle 两个事件，从链表移除（只 hook 一次）

**修改启动流程（`CheckSignalFile` 通过后）：**
```cpp
if (CheckSignalFile((UCHAR*)ntPath, len, DELAY_HOOK_SIGNAL_FILE_FMT)) {
    DWORD hook_offset = 0;
    if (GetNtdllFnvHash(fnvStr, 17)) {
        if (!GetHookOffsetFromConfig(fnvStr, &hook_offset)) {
            EtwLog(L"FNV %s not found in config\n", fnvStr);
            break;
        }
    } else {
        EtwLog(L"failed to get ntdll FNV hash\n");
        break;
    }

    // ⭐ 新增：扫描 delay.hook 文件，建立 InstantHook 链表
    if (!ScanDelayHookFiles()) {
        EtwLog(L"ScanDelayHookFiles failed\n");
		break;
    }

    // 如果有 InstantHook 目标，才安装 LdrLoadDll hook
    if (g_InstantHookList != nullptr) {
        if (!ApplyLocalHook(hookAddr, (PVOID)LdrLoadDll_HookHandler, &tramp, &oriLen)) {
            EtwLog(L"NTDLL ApplyLocalHook failed\n");
            break;
        }
        // 写入跳转指令...
    }
}
```

---

### 2. `controller/UMController/InstantHookManager.h`（新建）

```cpp
#pragma once
#include <windows.h>
#include <string>
#include <vector>

class InstantHookManager {
public:
    struct HookTarget {
        DWORD targetPid;
        std::wstring processNtPath;
        unsigned long long processFnvHash;
        std::wstring targetDllName;      // DLL 文件名
        unsigned long long dllFnvHash;
        std::wstring dllPath;             // hook DLL 路径
        std::wstring exportName;          // hook 导出名
        std::wstring module;              // 目标模块（如 ntdll）
        std::wstring offset;              // offset 字符串（hex）
    };

    InstantHookManager(IHookServices* services);
    ~InstantHookManager();

    // 添加一个 instant hook 目标
    bool AddTarget(const HookTarget& target);

    // 启动所有目标的监听线程
    void StartAllListeners();

    // 停止所有监听线程并清理
    void StopAll();

private:
    struct ListenerContext {
        InstantHookManager* mgr;
        HookTarget target;
    };

    static DWORD WINAPI ListenerThread(LPVOID lpParam);
    void ListenerThreadImpl(ListenerContext* ctx);

    // 解析 hookseq 文件
    static bool ParseHookSeqFile(const wchar_t* filePath, std::vector<HookTarget>& outTargets);

    // 计算字符串的 FNV-1a hash
    static unsigned long long ComputeFnvHash(const wchar_t* str);

    std::vector<ListenerContext*> m_Listeners;
    IHookServices* m_services;
};
```

---

### 3. `controller/UMController/InstantHookManager.cpp`（新建）

**ListenerThreadImpl 逻辑：**
1. 根据 `target.processFnvHash` 和 `target.dllFnvHash` 构造事件名，打开 `LoadNotify.<pFnv>.<dllFnv>` 和 `HookNotify.<pFnv>.<dllFnv>` 事件（SYNCHRONIZE）
2. `WaitForSingleObject(hLoadNotify, INFINITE)` 等待
3. DLL 加载通知到达后：
   - `m_services->InjectTrampoline(target.pid, target.dllPath)` - 注入 hook DLL
   - 等待 hook DLL 加载完成（轮询 `GetModuleBase`，最多 5 秒）
   - 获取 moduleBase + 解析 offset
   - `HookCore::ApplyHook(target.pid, targetAddress, m_services, hookFunctionAddress, hookId, ...)`
4. Signal `HookNotify.<pFnv>.<dllFnv>` 事件
5. CloseHandle，清理

---

### 4. `controller/UMController/UMControllerDlg.cpp`

**Resource.h 增加菜单 ID：**
```cpp
#define ID_MENU_SET_INSTANT_HOOK   400XX
```

**Context menu 新增菜单项：**
```cpp
menu.AppendMenu(MF_STRING, ID_MENU_SET_INSTANT_HOOK, L"Set Instant Hook");
```

**ON_COMMAND 映射：**
```cpp
ON_COMMAND(ID_MENU_SET_INSTANT_HOOK, &CUMControllerDlg::OnSetInstantHook)
```

**新增函数 `OnSetInstantHook()`：**
```cpp
void CUMControllerDlg::OnSetInstantHook() {
    // 1. 获取选中的 process entry 的 PID 和 NT path
    int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
    if (nItem == -1) return;
    PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
    DWORD pid = PID_FROM_ITEMDATA(packed);
    std::wstring ntPath = GetItemNtPath(nItem);

    // 2. 弹出 CFileDialog 选择 hookseq 文件
    CFileDialog dlg(TRUE, L".hookseq", NULL, OFN_HIDEREADONLY, L"HookSeq Files (*.hookseq)|*.hookseq||");
    if (dlg.DoModal() != IDOK) return;
    std::wstring hookSeqPath = dlg.GetPathName();

    // 3. 解析 hookseq 获取目标 DLL 列表
    std::vector<InstantHookManager::HookTarget> targets;
    InstantHookManager::ParseHookSeqFile(hookSeqPath.c_str(), targets);

    // 4. 计算 processFnvHash
    unsigned long long processFnvHash = InstantHookManager::ComputeFnvHash(ntPath.c_str());

    // 5. 写 C:\users\public\delay.hook.<processFnvHash> 文件
    WCHAR delayFile[MAX_PATH];
    swprintf_s(delayFile, L"C:\\users\\public\\delay.hook.%016llx", processFnvHash);
    // 复制 hookseq 内容到 delay.hook 文件

    // 6. 为每个目标 DLL 添加监听
    for (auto& t : targets) {
        t.targetPid = pid;
        t.processNtPath = ntPath;
        t.processFnvHash = processFnvHash;
        t.dllFnvHash = InstantHookManager::ComputeFnvHash(t.targetDllName.c_str());
        m_InstantHookMgr->AddTarget(t);
    }
    m_InstantHookMgr->StartAllListeners();
}
```

**新增成员变量：**
```cpp
InstantHookManager* m_InstantHookMgr = nullptr;
```

---

### 5. `Shared/SharedMacroDef.h`

```cpp
#define DELAY_HOOK_FILE_PREFIX L"C:\\users\\public\\delay.hook."
#define LOAD_NOTIFY_EVENT_FMT L"LoadNotify.%llx.%llx"
#define HOOK_NOTIFY_EVENT_FMT L"HookNotify.%llx.%llx"
```

---

### 6. `controller/UMController/UMController.vcxproj`

添加 `InstantHookManager.cpp` 到项目。

---

## delay.hook 文件格式

```
[hook]
module=ntdll
offset=418b4
dllPath=C:\Windows\System32\myhook.dll
export=MyHookExport
```

一个文件可包含多个 `[hook]` block。

文件路径：`C:\users\public\delay.hook.<processFnvHash>`
- `processFnvHash` = 进程 NT 路径的 FNV-1a hash（16位 hex 小写）

---

## 实现步骤

### 第一步：UMHH.dll 端

1. `SharedMacroDef.h` 增加 `LOAD_NOTIFY_EVENT_FMT`、`HOOK_NOTIFY_EVENT_FMT`
2. `dllmain.cpp` 增加 `InstantHookTarget` 链表和全局变量
3. 实现 `ScanDelayHookFiles()` 和 `ParseDelayHookFile()`
4. 修改 `LdrLoadDll_HookHandler` 增加 DLL 文件名匹配 + 事件 signal/wait
5. 修改启动流程：`CheckSignalFile` 通过后调用 `ScanDelayHookFiles()`，有目标则安装 LdrLoadDll hook

### 第二步：UMController 端 - InstantHookManager

1. 创建 `InstantHookManager.h` 和 `InstantHookManager.cpp`
2. 实现 `ListenerThread` - 等待 LoadNotify，执行 hook，signal HookNotify
3. 实现 `ParseHookSeqFile` - 解析 hookseq 为 `HookTarget` 列表
4. 实现 `ComputeFnvHash` - 计算字符串的 FNV-1a hash

### 第三步：UMController 端 - 集成

1. `Resource.h` 增加 `ID_MENU_SET_INSTANT_HOOK`
2. `UMControllerDlg.h` 增加 `InstantHookManager* m_InstantHookMgr`
3. `UMControllerDlg.cpp`：
   - context menu 添加 "Set Instant Hook"
   - 实现 `OnSetInstantHook()`
   - OnInitDialog 中创建 `m_InstantHookMgr`
   - OnDestroy 中 `StopAll()` 并删除

---

## 注意事项

1. **DLL 名称匹配**：`LdrLoadDll_HookHandler` 只比较文件名（不含路径），因为 `LdrLoadDll` 参数是完整路径
2. **事件生命周期**：UMHH.dll 是事件的创建方（CreateEvent），UMController 是打开方（OpenEvent with SYNCHRONIZE）
3. **多 DLL 支持**：每个 `[hook]` block 有独立的 LoadNotify/HookNotify 事件对
4. **进程路径获取**：从 `ProcessManager` 或 `m_ProcListCtrl` NT Path 列获取

---

## 验证方法

1. 编译 UMHH.dll 和 UMController
2. UMController 选择目标进程，右键 "Set Instant Hook"，选 hookseq 文件
3. 启动目标进程
4. 确认 `LdrLoadDll_HookHandler` 正确 signal LoadNotify
5. 确认 UMController 收到通知并执行 `HookCore::ApplyHook`
6. 确认目标 DLL 被正确 hook