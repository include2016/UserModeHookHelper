时序图：

```
sequenceDiagram
    participant UM as UMController
    participant HM as HookCore::ApplyHook
    participant TP as Target Process
    participant DL as DllLoadMonHook
    
    Note over UM,DL: Phase 1: Registration (RegisterModuleWatch)
    
    UM->>UM: Calculate ntdll MD5
    UM->>UM: Lookup LdrLoadDll offset from table
    UM->>UM: Load DllLoadMon.dll
    UM->>UM: Get DllLoadMonHook address
    UM->>TP: OpenProcess(PROCESS_ALL_ACCESS)
    UM->>TP: CreateEvent(Load_{PID})
    UM->>TP: CreateEvent(Release_{PID})
    UM->>TP: VirtualAllocEx(DllLoadMonSharedData)
    UM->>TP: Write shared data (events, watch list)
    UM->>HM: ApplyHook(pid, LdrLoadDllRet, DllLoadMonHook)
    HM->>TP: Install trampoline at LdrLoadDll return
    HM-->>UM: Hook installed successfully
    
    Note over UM,DL: Phase 2: Runtime (DLL Load in Target Process)
    
    TP->>TP: Application calls LoadLibrary
    TP->>TP: LdrLoadDll executes
    TP->>TP: DLL mapped into memory
    Note over TP: LdrLoadDll RETURN ADDRESS<br/>triggers DllLoadMonHook
    TP->>DL: DllLoadMonHook(ModuleBase, Events, WatchList)
    DL->>DL: Extract module name from RDI->Unicode_String
    DL->>DL: Compare with watch list (SRWLOCK)
    
    alt Module in watch list
        DL->>TP: SetEvent(hLoadEvent)
        DL->>UM: Signal: Target DLL loaded!
        Note over UM: Apply pending hooks now
        UM->>UM: ApplyPendingHooks()
        UM->>TP: SetEvent(hReleaseEvent)
        DL->>TP: WaitForSingleObject(hReleaseEvent, 5s)
        DL-->>TP: Return from hook
        TP->>TP: Continue normal execution
    else Module not in watch list
        DL-->>TP: Return immediately
        TP->>TP: Continue normal execution
    end
```

将上述代码复制到[这里](https://www.mermaidonline.live/zh/editor)查看



![image-20260328154009633](README.assets\image-20260328154009633.png)