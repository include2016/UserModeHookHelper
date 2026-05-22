#pragma once
#ifndef MASTER_LOAD_EVENT_BASE 
#define MASTER_LOAD_EVENT_BASE L"MASTER_LOAD_EVENT."
#endif
#ifndef HOOK_DLL_NT_MASTER_LOAD_EVENT 
#define HOOK_DLL_NT_MASTER_LOAD_EVENT L"\\BaseNamedObjects\\" MASTER_LOAD_EVENT_BASE
#endif

#define DLL_LOAD_MON_DLL_NAME L"DllLoadMon.dll"
#define DLL_LOAD_MON_EXPORT_X64 "DllLoadMonHook_X64"
#define DLL_LOAD_MON_EXPORT_Win32 "DllLoadMonHook_Win32"

#define LUA_ENGINE_DLL_X64 L"LuaEngine.x64.dll"
#define LUA_ENGINE_DLL_Win32 L"LuaEngine.Win32.dll"


#define LUA_ENGINE_EXPORT_X64 "LuaHookDispatch_X64"
#define LUA_ENGINE_EXPORT_Win32 "LuaHookDispatch_Win32"

#define DLL_LOAD_MON_HOOK_ID 255

#ifndef USER_MODE_MASTER_LOAD_EVENT 
#define USER_MODE_MASTER_LOAD_EVENT L"Global\\" MASTER_LOAD_EVENT_BASE
#endif

#ifndef INJECTION_SIGNAL_EVENT_BASE
#define INJECTION_SIGNAL_EVENT_BASE L"INJECTION_SIGNAL."
#endif

#ifndef HOOK_DLL_NT_INJECTION_SIGNAL_EVENT
#define HOOK_DLL_NT_INJECTION_SIGNAL_EVENT L"\\BaseNamedObjects\\" INJECTION_SIGNAL_EVENT_BASE
#endif

#ifndef WAKEUP_EVENT_BASE
#define WAKEUP_EVENT_BASE L"WAKEUP."
#endif

#ifndef HOOK_DLL_NT_WAKEUP_EVENT
#define HOOK_DLL_NT_WAKEUP_EVENT L"\\BaseNamedObjects\\" WAKEUP_EVENT_BASE
#endif
#ifndef HOOK_DLL_UM_WAKEUP_EVENT
#define HOOK_DLL_UM_WAKEUP_EVENT L"Global\\" WAKEUP_EVENT_BASE
#endif
// Hook mode constants
#define HOOK_MODE_DLL  0   // hook_code_addr points to DLL export function
#define HOOK_MODE_LUA  1   // hook_code_addr points to LuaEngine dispatch

#define LUA_ENGINE_SIGNAL_EVENT_BASE    L"LUA_ENGINE_SIGNAL.%u_%d"
#define LUA_ENGINE_NT_SIGNAL_EVENT      L"\\BaseNamedObjects\\" LUA_ENGINE_SIGNAL_EVENT_BASE
#define LUA_ENGINE_UM_SIGNAL_EVENT      L"Global\\" LUA_ENGINE_SIGNAL_EVENT_BASE


// LuaEngine → Controller: signal back that script was loaded
#define LUA_ENGINE_LOADED_EVENT_BASE    L"LUA_ENGINE_LOADED.%u_%d"
#define LUA_ENGINE_NT_LOADED_EVENT      L"\\BaseNamedObjects\\" LUA_ENGINE_LOADED_EVENT_BASE
#define LUA_ENGINE_UM_LOADED_EVENT      L"Global\\" LUA_ENGINE_LOADED_EVENT_BASE


// IPC data file
#define LUA_ENGINE_IPC_FILE_FMT         L"C:\\Users\\Public\\lua_ipc.%d"
#define LUA_ENGINE_NT_IPC_FILE_FMT      L"\\??\\" LUA_ENGINE_IPC_FILE_FMT

// Separator in IPC data between script path and handler name
#define LUA_IPC_SEPARATOR L'|'

#ifndef HOOK_DLL_LOAD_MUTANT_FMT
#define HOOK_DLL_LOAD_MUTANT_FMT L"\\BaseNamedObjects\\UMHH_DLL_MUTANT.%d"
#endif

#define MASTER_LOADED_SIGNAL_BACK_EVENT_BASE L"MASTER_LOADLED_SIGNAL_BACK."
#ifndef HOOK_DLL_NT_MASTER_LOADED_SIGNAL_BACK_EVENT
#define HOOK_DLL_NT_MASTER_LOADED_SIGNAL_BACK_EVENT L"\\BaseNamedObjects\\" MASTER_LOADED_SIGNAL_BACK_EVENT_BASE
#endif

#ifndef HOOK_DLL_UM_MASTER_LOADED_SIGNAL_BACK_EVENT
#define HOOK_DLL_UM_MASTER_LOADED_SIGNAL_BACK_EVENT L"Global\\" MASTER_LOADED_SIGNAL_BACK_EVENT_BASE
#endif

#ifndef USER_MODE_INJECTION_SIGNAL_EVENT
#define USER_MODE_INJECTION_SIGNAL_EVENT L"Global\\" INJECTION_SIGNAL_EVENT_BASE
#endif


#define UM_STOP_SIGNAL_FILE_PATH L"C:\\Users\\Public\\stop_umhh_boot_start"
#define DRIVER_STOP_SIGNAL_FILE_PATH L"\\??\\" UM_STOP_SIGNAL_FILE_PATH

#define LOCATOR_SIGNAL_EVENT L"Global\\LOCATOR_SIGNAL_EVENT"
#define LOCATOR_IPC_FILE_PATH L"C:\\Users\\Public\\locator.bin"

#define HOOK_CODE_EXPORT_X86 "HookCodeWin32"
#define HOOK_CODE_EXPORT_X64 "HookCodeX64"

#define HOOK_CODE_TEMP_DIR_NAME L"hookcode_dll_temp"

#define KERNEL_32_X86 "\\Windows\\SysWOW64\\kernel32.dll"
#define KERNEL_32_X64 "\\Windows\\System32\\kernel32.dll"

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)

#define NTDLL_X86 L"\\??\\C:\\Windows\\SysWOW64\\ntdll.dll"
#define NTDLL_X64 L"\\??\\C:\\Windows\\System32\\ntdll.dll"

#ifdef _WIN64
#define NTDLL_PATH NTDLL_X64
#else
#define NTDLL_PATH NTDLL_X86
#endif


// Simple module list node returned by PhBuildModuleListWow64
typedef struct _PH_MODULE_LIST_NODE {
	struct _PH_MODULE_LIST_NODE* Next;
	void* Base;
	unsigned long Size; // SizeOfImage if known; 0 if unknown
	wchar_t* Path;      // Full NT path of module
} PH_MODULE_LIST_NODE, *PPH_MODULE_LIST_NODE;

#ifndef UMHH_OB_CALLBACK_DEVICE
#define UMHH_OB_CALLBACK_DEVICE L"\\\\.\\UMHHObCallbackCtl"
#endif


#define BS_SERVICE_NAME L"UMHH.BootStart"
#define SERVICE_NAME L"UserModeHookHelper"
#define UMHH_OB_CALLBACK_SERVICE_NAME L"UMHH.ObCallback"
// Registry persistence vendor/key definitions. Vendor name is configurable
// here so kernel and user-mode code use the same value.
#define REG_VENDOR_NAME L"GIAO"
#define REG_PERSIST_SUBKEY L"SOFTWARE\\" REG_VENDOR_NAME L"\\" SERVICE_NAME
#define REG_PERSIST_REGPATH L"\\Registry\\Machine\\" REG_PERSIST_SUBKEY

// Block list value names (REG_MULTI_SZ) under REG_PERSIST_SUBKEY
#define REG_BLOCKED_PROCESS_NAME L"BlockedProcessName"
#define REG_BLOCKED_DLL_NAME     L"BlockedDllName"
// Whitelist hash values for ObCallback (REG_MULTI_SZ of hex hashes)
#define REG_WHITELIST_HASHES     L"WhitelistHashes"
// Protected process names (final component, REG_MULTI_SZ)
#define REG_PROTECTED_PROCESS_NAME L"ProtectedProcessName"

#define LUA_ENGINE_PLACEHOLDER_EXP_FUNC "LuaEngineIPCSlot"

#define TRAMPOLINE_EXP_NUM_MAX 0x100

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define MASETER_EXP_FUNC_NAME ReadFileParsePidAndDllPath
#define MASETER_EXP_FUNC_NAME_STR STR(MASETER_EXP_FUNC_NAME)

#define IPC_DLL_PATH_END_MARK '|'


#define E9_JMP_INSTRUCTION_SIZE 0x5
#define E9_JMP_INSTRUCTION_OPCODE_SIZE 0x1
#define E9_JMP_INSTRUCTION_OPRAND_SIZE 0x4


#ifndef INJECTED_DLL_LOADED_EVENT_BASE
#define INJECTED_DLL_LOADED_EVENT_BASE L"INJECTED_DLL_LOADED."
#endif

#ifndef HOOK_DLL_NT_INJECTED_DLL_LOADED_EVENT
#define HOOK_DLL_NT_INJECTED_DLL_LOADED_EVENT L"\\BaseNamedObjects\\" INJECTED_DLL_LOADED_EVENT_BASE
#endif

#ifndef HOOK_DLL_UM_INJECTED_DLL_LOADED_EVENT
#define HOOK_DLL_UM_INJECTED_DLL_LOADED_EVENT L"Global\\" INJECTED_DLL_LOADED_EVENT_BASE
#endif


#define TRAMPOLINE_INJECTION_TIMEOUT 500

#define DLL_LOAD_MON_SHARED_DATA_FMT L"Global\\DllLoadMon_SharedData_%lu"

#define DELAY_HOOK_LOAD_EVENT_FMT L"Global\\DelayHook_Load_%lu"
#define DELAY_HOOK_RELEASE_EVENT_FMT L"Global\\DelayHook_Release_%lu"
#define DLL_LOAD_MON_DATA_ACCESS_EVENT_FMT L"Global\\DelayHook_Access_%lu"

#define DLL_LOAD_MON_DATA_ACCESS_TIMEOUT 500  // 500ms

#define UM_DELAY_HOOK_FILE_FMT L"C:\\users\\public\\delay.hook.%16llx"
#define NT_DELAY_HOOK_FILE_FMT L"\\??\\" UM_DELAY_HOOK_FILE_FMT

#define LOAD_NOTIFY_EVENT_FMT L"LoadNotify.%016llx.%016llx.%016llx"
#define NT_LOAD_NOTIFY_EVENT_FMT L"\\BaseNamedObjects\\" LOAD_NOTIFY_EVENT_FMT
#define UM_LOAD_NOTIFY_EVENT_FMT L"Global\\" LOAD_NOTIFY_EVENT_FMT

#define HOOK_NOTIFY_EVENT_FMT L"HookNotify.%016llx.%016llx.%016llx"
#define NT_HOOK_NOTIFY_EVENT_FMT L"\\BaseNamedObjects\\" HOOK_NOTIFY_EVENT_FMT
#define UM_HOOK_NOTIFY_EVENT_FMT L"Global\\" HOOK_NOTIFY_EVENT_FMT

#define UMCONTROLLER_PID_FILE L"C:\\users\\public\\umcontroller.pid"


#define UM_HOOK_EVENT_PID_FILE_FMT L"C:\\users\\public\\hookevent.%016llx.%016llx.%016llx"
#define NT_HOOK_EVENT_PID_FILE_FMT L"\\??\\" UM_HOOK_EVENT_PID_FILE_FMT

