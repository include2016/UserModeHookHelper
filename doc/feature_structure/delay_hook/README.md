[时序图在线查看](https://www.mermaidonline.live/zh/editor)

delay hook特性的总体逻辑
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



UmController和DllLoadMon组件的通信机制：
```
sequenceDiagram
    participant UM as UMController
    participant MMF as Memory-Mapped File
    participant DL as DllLoadMon (target process)
    participant KM as Kernel/Filter

    Note over UM,DL: Setup Phase
    UM->>MMF: CreateFileMapping<br/>Global\DllLoadMon_SharedData_{PID}
    UM->>MMF: MapViewOfFile()
    UM->>MMF: Populate ModuleNames[]
    UM->>MMF: Initialize events
    Note right of UM: Keep file mapping<br/>handle alive

    Note over UM,DL: Monitoring Phase
    loop LdrLoadDll calls in target process
        DL->>DL: Check if DLL in watch list
        alt DLL is watched
            DL->>UM: Signal hLoadEvent
            Note over UM: Apply pending hooks
            UM->>UM: HookCore::ApplyHook()
            UM->>UM: Wait for trampoline load
            UM->>DL: Signal hReleaseEvent
            DL->>DL: Continue execution
        else DLL not watched
            DL->>DL: Normal execution
        end
    end

    Note over UM,DL: Cleanup Phase
    alt Process terminates
        UM->>UM: OnUpdateProcess()<br/>detects exit
        UM->>MMF: CleanupWatchList()
        MMF-->>UM: Resources freed
    else Hook removed
        UM->>UM: HandleRemoveHook()
        UM->>MMF: CleanupWatchListByPid()
        MMF-->>UM: Resources freed
    end
```
