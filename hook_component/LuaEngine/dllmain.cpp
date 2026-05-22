// LuaEngine.dll -- Main entry point
// Runs inside target process. Only uses ntdll Nt* functions so it works
// at early process startup (same constraint as umhh.dll).
//
// Architecture:
//   DllMain -- OnProcessAttach -- resolve ntdll functions, start AgentCode thread
//   AgentCode thread -- wait for IPC signal, load Lua script, bind handler
//   LuaHookDispatch_X64 / LuaHookDispatch_Win32 -- called from trampoline

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#define NTDLL_NO_INLINE_INIT_STRING

#include "LuaEngine.h"
#include "../../Shared/LogMacros.h"
#include "../../Shared/SharedMacroDef.h"
#include "../../drivers/UserModeHookHelper/UKShared.h"
#include "../controller/UMController/ETW.h"

// ---- ntdll function pointer instances ----

PNtCreateEvent          pNtCreateEvent = 0;
PNtOpenEvent            pNtOpenEvent = 0;
PNtSetEvent             pNtSetEvent = 0;
PNtResetEvent           pNtResetEvent = 0;
PNtWaitForSingleObject  pNtWaitForSingleObject = 0;
PNtClose                pNtClose = 0;
PRtlInitUnicodeString   pRtlInitUnicodeString = 0;
PLdrGetDllHandle        pLdrGetDllHandle = 0;
PLdrLoadDll             pLdrLoadDll = 0;
PRtlZeroMemory          pRtlZeroMemory = 0;


PNtReadFile             pNtReadFile = 0;
PNtWriteFile            pNtWriteFile = 0;
PNtOpenFile             pNtOpenFile = 0;
PNtDeleteFile           pNtDeleteFile = 0;
PNtDelayExecution       pNtDelay = 0;
PRtlAddRefDll           pLdrAddRefDll = 0;
typedef int(__cdecl * _snwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	...
	);
static _snwprintf_fn_t _snwprintf_ = NULL;

typedef int(__cdecl * _vsnwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	va_list args
	);

static _vsnwprintf_fn_t _vsnwprintf_ = NULL;

// ---- ETW ----
// Map Event* symbols to the standard ETW APIs provided by evntprov.h
#define EventActivityIdControl  EventActivityIdControl
#define EventEnabled            EventEnabled
#define EventProviderEnabled    EventProviderEnabled
#define EventRegister           EventRegister
#define EventSetInformation     EventSetInformation
#define EventUnregister         EventUnregister
#define EventWrite              EventWrite
#define EventWriteEndScenario   EventWriteEndScenario
#define EventWriteEx            EventWriteEx
#define EventWriteStartScenario EventWriteStartScenario
#define EventWriteString        EventWriteString
#define EventWriteTransfer      EventWriteTransfer

#include <evntprov.h>

#include <stdarg.h>

PVOID ProviderHandle = 0;
VOID Log(_In_ PCWSTR Format, ...) {
    WCHAR Buffer[1024];
    va_list args;
    va_start(args, Format);
	_vsnwprintf_(Buffer, 1024 - 1, Format, args);
    va_end(args);
    Buffer[1024 - 1] = L'\0';
    WCHAR Prefixed[1100];
    _snwprintf_(Prefixed, 1100 - 1, L"[LuaEngine]  %s", Buffer);
    Prefixed[1100 - 1] = L'\0';
    if (ProviderHandle) {
        EventWriteString((REGHANDLE)(ULONG_PTR)ProviderHandle, 0, 0, Prefixed);
    } else {
        UNICODE_STRING u;
        pRtlInitUnicodeString(&u, Prefixed);
        DbgPrint("%wZ\n", u);
    }
}
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                     \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);          \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);          \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);         \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);         \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);         \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);         \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);         \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);         \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);         \
    PVOID rdx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x58);         \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);         \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
                                                                             \
    /* original_esp can be used to access original parameters */             \
    ULONG original_esp = (esp) + 0x20;                                       \
                                                                             \
    /* original register values saved on stack */                             \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                   \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                   \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                   \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                   \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                  \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                  \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);
// ---- Lua state pool ----

LuaHookEntry g_luaHooks[LUA_ENGINE_MAX_HOOKS];

static void InitLuaHooks() {
    RtlZeroMemory(g_luaHooks, sizeof(g_luaHooks));
    for (int i = 0; i < LUA_ENGINE_MAX_HOOKS; i++) {
        g_luaHooks[i].L = 0;
        g_luaHooks[i].funcRef = LUA_NOREF;
    }
}

// ---- C binding: register table ----

// push_register_table pushes a Lua table with register values onto the stack.
// x64 version: key register values are passed as parameters.
static void push_register_table_x64(lua_State* L,
    ULONG_PTR rcx, ULONG_PTR rdx, ULONG_PTR r8, ULONG_PTR r9,
    ULONG_PTR rax, ULONG_PTR rbx, ULONG_PTR rbp,
    ULONG_PTR rsi, ULONG_PTR rdi, ULONG_PTR rsp)
{
    lua_createtable(L, 0, 10);
    lua_pushinteger(L, (lua_Integer)rcx);  lua_setfield(L, -2, "rcx");
    lua_pushinteger(L, (lua_Integer)rdx);  lua_setfield(L, -2, "rdx");
    lua_pushinteger(L, (lua_Integer)r8);   lua_setfield(L, -2, "r8");
    lua_pushinteger(L, (lua_Integer)r9);   lua_setfield(L, -2, "r9");
    lua_pushinteger(L, (lua_Integer)rax);  lua_setfield(L, -2, "rax");
    lua_pushinteger(L, (lua_Integer)rbx);  lua_setfield(L, -2, "rbx");
    lua_pushinteger(L, (lua_Integer)rbp);  lua_setfield(L, -2, "rbp");
    lua_pushinteger(L, (lua_Integer)rsi);  lua_setfield(L, -2, "rsi");
    lua_pushinteger(L, (lua_Integer)rdi);  lua_setfield(L, -2, "rdi");
    lua_pushinteger(L, (lua_Integer)rsp);  lua_setfield(L, -2, "rsp");
}

// x86 version: all registers are on the stack starting at original_esp
static void push_register_table_x86(lua_State* L, ULONG_PTR ebp, ULONG_PTR edi, ULONG_PTR esi, 
	ULONG_PTR edx, ULONG_PTR ecx, ULONG_PTR ebx, ULONG_PTR eax, ULONG_PTR esp)
{
    lua_createtable(L, 0, 8);
    // x86 registers are pushed in stage_1 order:
    // pushad saves: eax, ecx, edx, ebx, esp(original), ebp, esi, edi
    lua_pushinteger(L, (lua_Integer)edi);  lua_setfield(L, -2, "edi");
	lua_pushinteger(L, (lua_Integer)esi);  lua_setfield(L, -2, "esi");
	lua_pushinteger(L, (lua_Integer)ebp);  lua_setfield(L, -2, "ebp");
	lua_pushinteger(L, (lua_Integer)ebx);  lua_setfield(L, -2, "ebx");
	lua_pushinteger(L, (lua_Integer)edx);  lua_setfield(L, -2, "edx");
	lua_pushinteger(L, (lua_Integer)ecx);  lua_setfield(L, -2, "ecx");
	lua_pushinteger(L, (lua_Integer)eax);  lua_setfield(L, -2, "eax");
	lua_pushinteger(L, (lua_Integer)esp);  lua_setfield(L, -2, "esp");
}

// ---- C binding: mem library ----

static int mem_read_u8(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    lua_pushinteger(L, (lua_Integer)*(UINT8*)addr);
    return 1;
}
static int mem_read_u32(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    lua_pushinteger(L, (lua_Integer)*(UINT32*)addr);
    return 1;
}
static int mem_read_u64(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    lua_pushinteger(L, (lua_Integer)*(UINT64*)addr);
    return 1;
}
static int mem_write_u8(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    UINT8 val = (UINT8)lua_tointeger(L, 2);
    *(UINT8*)addr = val;
    return 0;
}
static int mem_write_u32(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    UINT32 val = (UINT32)lua_tointeger(L, 2);
    *(UINT32*)addr = val;
    return 0;
}
static int mem_write_u64(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    UINT64 val = (UINT64)lua_tointeger(L, 2);
    *(UINT64*)addr = val;
    return 0;
}
static int mem_read_wstring(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    const wchar_t* ws = (const wchar_t*)addr;
    if (!ws) { lua_pushnil(L); return 1; }
    // Convert to UTF-8 manually (no kernel32 WideCharToMultiByte in early load)
    char buf[4096];
    int i = 0;
    while (ws[i] && i < 2047) {
        // Simple ASCII-only conversion for now; non-ASCII chars become '?'
        buf[i] = (ws[i] < 0x80) ? (char)ws[i] : '?';
        i++;
    }
    buf[i] = '\0';
    lua_pushstring(L, buf);
    return 1;
}
static int mem_read_string(lua_State* L) {
    ULONG_PTR addr = (ULONG_PTR)lua_tointeger(L, 1);
    const char* s = (const char*)addr;
    if (!s) { lua_pushnil(L); return 1; }
    lua_pushstring(L, s);
    return 1;
}

// ---- C binding: log function ----

static int lua_log(lua_State* L) {
    const char* msg = lua_tostring(L, 1);
    if (msg) {
        // Convert ASCII to wchar_t for EtwLog
        WCHAR wbuf[1024];
        int i = 0;
        while (msg[i] && i < 1023) {
            wbuf[i] = (WCHAR)(unsigned char)msg[i];
            i++;
        }
        wbuf[i] = L'\0';
        Log(L"Lua: %s\n", wbuf);
    }
    return 0;
}

// ---- Register all C bindings into a lua_State ----

static void RegisterCBindingings(lua_State* L) {
    // "mem" library
    static const luaL_Reg mem_lib[] = {
        {"read_u8",      mem_read_u8},
        {"read_u32",     mem_read_u32},
        {"read_u64",     mem_read_u64},
        {"write_u8",     mem_write_u8},
        {"write_u32",    mem_write_u32},
        {"write_u64",    mem_write_u64},
        {"read_wstring", mem_read_wstring},
        {"read_string",  mem_read_string},
        {NULL, NULL}
    };
    luaL_newlib(L, mem_lib);
    lua_setglobal(L, "mem");

    // "log" function
    lua_register(L, "log", lua_log);

    // "regs" metatable with __index for register read/write
    // (used by push_register_table -- the table itself is plain,
    //  set_return is a helper on the regs table)
    // We add regs:set_return(value) which modifies the "rax" field
    lua_getglobal(L, "log"); // just to have something on stack; pop it
    lua_pop(L, 1);

    // Actually, set_return is easier as a global function
    lua_pushcfunction(L, [](lua_State* L) -> int {
        // set_return(value) -- caller should store in regs.rax before returning
        // For now, just push a helper; the trampoline will read rax from the table
        lua_pushinteger(L, (lua_Integer)0);
        return 1;
    });
    // We'll add a method on the regs table inside push_register_table instead
    lua_pop(L, 1);
}

// ---- Load a Lua script and bind handler ----

static bool LoadAndBindScript(int hook_id, const wchar_t* scriptPath, const wchar_t* handlerName) {
    if (hook_id < 0 || hook_id >= LUA_ENGINE_MAX_HOOKS) {
        Log(L"LoadAndBindScript: hook_id %d out of range\n", hook_id);
        return false;
    }

    // Convert wchar_t script path to char (ASCII only for luaL_dofile)
    char scriptPathA[MAX_PATH] = { 0 };
    int i = 0;
    while (scriptPath[i] && i < MAX_PATH - 1) {
        scriptPathA[i] = (char)(unsigned char)(scriptPath[i] & 0xFF);
        i++;
    }
    scriptPathA[i] = '\0';

    // Convert handler name to char
    char handlerNameA[256] = { 0 };
    i = 0;
    while (handlerName[i] && i < 255) {
        handlerNameA[i] = (char)(unsigned char)(handlerName[i] & 0xFF);
        i++;
    }
    handlerNameA[i] = '\0';

    // Create new lua_State for this hook
    lua_State* L = luaL_newstate();
    if (!L) {
        Log(L"luaL_newstate failed for hook_id %d\n", hook_id);
        return false;
    }

    luaL_openlibs(L);
  
    // Register our C bindings
    RegisterCBindingings(L);

    // Load and execute the script
    if (luaL_dofile(L, scriptPathA) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        WCHAR werr[512];
        int j = 0;
        while (err && err[j] && j < 511) {
            werr[j] = (WCHAR)(unsigned char)err[j];
            j++;
        }
        werr[j] = L'\0';
        Log(L"luaL_dofile failed for %s: %s\n", scriptPath, werr);
        lua_close(L);
        return false;
    }

    // Look up handler function
    lua_getglobal(L, handlerNameA);
    if (!lua_isfunction(L, -1)) {
        Log(L"handler '%s' not found in script %s\n", handlerName, scriptPath);
        lua_close(L);
        return false;
    }

    // Store function reference in registry
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Clean up old state if any
    if (g_luaHooks[hook_id].L) {
        lua_close(g_luaHooks[hook_id].L);
    }

    g_luaHooks[hook_id].L = L;
    g_luaHooks[hook_id].funcRef = ref;

    Log(L"script loaded: hook_id=%d script=%s handler=%s ref=%d\n",
        hook_id, scriptPath, handlerName, ref);
    return true;
}

// ---- Dispatch functions (called from trampoline) ----

// x64 dispatch: hook_id arrives in rdx (set by mov rdx, hook_id in stage_2)
// PROLOGX64 saves all registers; original_rsp points to stage_1 save area
extern "C" __declspec(dllexport) VOID LuaHookDispatch_X64(
    PVOID rcx, int hook_id, PVOID r8, PVOID r9, PVOID rsp)
{
	PROLOGX64(rsp);
    // Note: PROLOGX64 equivalent is handled by the hook code template
    // Here we just do the Lua dispatch

    if (hook_id < 0 || hook_id >= LUA_ENGINE_MAX_HOOKS) {
		Log(L"invalid hook id provided\n");
		return;
	}
    lua_State* L = g_luaHooks[hook_id].L;
    int ref = g_luaHooks[hook_id].funcRef;
    if (!L || ref == LUA_NOREF) return;

    // Push the handler function from registry
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);

    // Push register table as argument
    // TODO: extract actual register values from the trampoline save area
    // For Phase 1, push a basic table with the known parameters
    push_register_table_x64(L,
        (ULONG_PTR)rcx, (ULONG_PTR)rdx /* original rdx from save area */,
        (ULONG_PTR)r8, (ULONG_PTR)r9,
		(ULONG_PTR)rax, (ULONG_PTR)rbx , (ULONG_PTR)rbp ,
		(ULONG_PTR)rsi, (ULONG_PTR)rdi, (ULONG_PTR)original_rsp);

    // Call the Lua handler
    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        WCHAR werr[256];
        int i = 0;
        while (err && err[i] && i < 255) {
            werr[i] = (WCHAR)(unsigned char)err[i];
            i++;
        }
        werr[i] = L'\0';
        Log(L"lua_pcall error hook_id=%d: %s\n", hook_id, werr);
        lua_pop(L, 1);
    }
}

// x86 dispatch: hook_id is at [esp], original_esp at [esp+4]
extern "C" __declspec(dllexport) VOID LuaHookDispatch_Win32(ULONG esp)
{
	PROLOGWin32(esp);
    int hook_id = *(int*)(ULONG_PTR)esp;
    

	if (hook_id < 0 || hook_id >= LUA_ENGINE_MAX_HOOKS) {
		Log(L"invalid hook id provided\n");
		return;
	}
    lua_State* L = g_luaHooks[hook_id].L;
    int ref = g_luaHooks[hook_id].funcRef;
    if (!L || ref == LUA_NOREF) return;

    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    push_register_table_x86(L, (ULONG_PTR)ebp, (ULONG_PTR)edi, (ULONG_PTR)esi, 
		(ULONG_PTR)edx, (ULONG_PTR)ecx, (ULONG_PTR)ebx, (ULONG_PTR)eax,(ULONG_PTR)original_esp);

    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        WCHAR werr[256];
        int i = 0;
        while (err && err[i] && i < 255) {
            werr[i] = (WCHAR)(unsigned char)err[i];
            i++;
        }
        werr[i] = L'\0';
        Log(L"lua_pcall error hook_id=%d: %s\n", hook_id, werr);
        lua_pop(L, 1);
    }
}

// ---- IPC: data storage export (same trick as umhh.dll) ----
// The controller writes the script path + handler name to this function's
// code area via WriteProcessMemoryWrap, then signals the event.

extern "C" __declspec(dllexport) int LuaEngineIPCSlot(int slot_id)
{
    // This function body is used as data storage.
    // The controller writes: script_path_wchar | handler_name_wchar
    // up to MAX_PATH * 2 + 256 bytes.
    // The return value is the slot_id for identification.
	Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n"); Log(L"IPC PLACEHOLDER\n");
    return slot_id;
}

// ---- AgentCode thread: wait for IPC signals and load scripts ----

static HANDLE g_EventHandles[LUA_ENGINE_MAX_HOOKS] = { 0 };

NTSTATUS AgentCode(_In_ PVOID ThreadParameter)
{
    // Resolve ntdll functions
    UNICODE_STRING NtdllPath;
    pRtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

    ANSI_STRING RoutineName;
    HANDLE NtdllHandle;
    pLdrGetDllHandle(NULL, 0, &NtdllPath, (PVOID*)&NtdllHandle);

#define RESOLVE(name) \
    pRtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll"); \
    pLdrGetDllHandle(NULL, 0, &NtdllPath, (PVOID*)&NtdllHandle); \
    RtlInitAnsiString(&RoutineName, (PSTR)#name); \
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&p##name)

    // We already have most functions from DllMain, but re-resolve the
    // ones needed for IPC file operations
    RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateEvent);
    RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenEvent);
    RtlInitAnsiString(&RoutineName, (PSTR)"NtSetEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtSetEvent);
    RtlInitAnsiString(&RoutineName, (PSTR)"NtResetEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtResetEvent);
    RtlInitAnsiString(&RoutineName, (PSTR)"NtWaitForMultipleObjects");
    // NtWaitForMultipleObjects needs a separate pointer
    typedef NTSTATUS(NTAPI* PNtWaitForMultipleObjects)(
        ULONG Count, HANDLE* Handles, WAIT_TYPE WaitType,
        BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    PNtWaitForMultipleObjects pNtWaitForMultipleObjects = 0;
    RtlInitAnsiString(&RoutineName, (PSTR)"NtWaitForMultipleObjects");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtWaitForMultipleObjects);

#undef RESOLVE

    if (!pNtWaitForMultipleObjects) {
        Log(L"failed to resolve NtWaitForMultipleObjects\n");
        return 0;
    }

    // Create per-hook events
    for (int i = 0; i < LUA_ENGINE_MAX_HOOKS; i++) {
        WCHAR eventName[150];
		_snwprintf_(eventName, 149, LUA_ENGINE_NT_SIGNAL_EVENT,            NtCurrentProcessId(), i);

        UNICODE_STRING uName;
        pRtlInitUnicodeString(&uName, eventName);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hEvent = NULL;
        NTSTATUS st = pNtCreateEvent(&hEvent, EVENT_ALL_ACCESS,
            &oa, NotificationEvent, FALSE);
        if (NT_SUCCESS(st)) {
            g_EventHandles[i] = hEvent;
        }
        // If event already exists, try to open it
        if (!NT_SUCCESS(st)) {
			Log(L"failed to create event, Name=%s\n", eventName);
            st = pNtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);
            if (NT_SUCCESS(st)) {
                g_EventHandles[i] = hEvent;
            }
        }
    }

    Log(L"AgentCode started, monitoring %d hook slots\n", LUA_ENGINE_MAX_HOOKS);
 
    // Main loop: wait on all events, handle signaled ones
    // NtWaitForMultipleObjects supports at most MAXIMUM_WAIT_OBJECTS (64) handles,
    // so we split the 256 hook slots into groups of 64 and poll each group.
#define WAIT_GROUP_SIZE 64
#define WAIT_GROUP_COUNT ((LUA_ENGINE_MAX_HOOKS + WAIT_GROUP_SIZE - 1) / WAIT_GROUP_SIZE)

    while (true) {
        bool anySignaled = false;

        // Poll each group of events
        for (int g = 0; g < WAIT_GROUP_COUNT; g++) {
            int groupStart = g * WAIT_GROUP_SIZE;
            int groupCount = WAIT_GROUP_SIZE;
            if (groupStart + groupCount > LUA_ENGINE_MAX_HOOKS)
                groupCount = LUA_ENGINE_MAX_HOOKS - groupStart;

            // Count valid handles in this group and compact into a local array
            HANDLE groupHandles[WAIT_GROUP_SIZE] = { 0 };
            int handleIndex[WAIT_GROUP_SIZE] = { 0 }; // maps local index -> global hook_id
            int validCount = 0;
            for (int j = 0; j < groupCount; j++) {
                int hookId = groupStart + j;
                if (g_EventHandles[hookId]) {
                    groupHandles[validCount] = g_EventHandles[hookId];
                    handleIndex[validCount] = hookId;
                    validCount++;
                }
            }

            if (validCount == 0) continue;

            // Wait on this group with zero timeout (poll, don't block)
            LARGE_INTEGER zeroTimeout;
            zeroTimeout.QuadPart = 0;
            NTSTATUS st = pNtWaitForMultipleObjects(
                validCount, groupHandles,
                WaitAny, FALSE, &zeroTimeout);

            if (st >= 0 && st < validCount) {
                // One or more events in this group are signaled
                anySignaled = true;

                // Check each handle in the group for signaled state
                for (int j = 0; j < validCount; j++) {
                    st = pNtWaitForSingleObject(groupHandles[j], FALSE, &zeroTimeout);
                    if (st == 0) { // STATUS_OBJECT_WAIT_0 = signaled
                        int i = handleIndex[j];
                        pNtResetEvent(g_EventHandles[i], NULL);

                        // Read IPC data from LuaEngineIPCSlot export address
                        UCHAR* data_addr = (UCHAR*)(ULONG_PTR)&LuaEngineIPCSlot;
#ifdef _DEBUG
                        data_addr = *(DWORD*)(data_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE)
                            + data_addr + E9_JMP_INSTRUCTION_SIZE;
#endif
                        // Data format: wchar_t script_path | wchar_t handler_name  
                        // Read as wchar_t string
                        wchar_t* wdata = (wchar_t*)data_addr;
                        wchar_t scriptPath[MAX_PATH] = { 0 };
                        wchar_t handlerName[256] = { 0 };

                        int k = 0;
                        // Copy script path until separator
                        while (wdata[k] && wdata[k] != LUA_IPC_SEPARATOR && k < MAX_PATH - 1) {
                            scriptPath[k] = wdata[k];
                            k++;
                        }
                        scriptPath[k] = L'\0';

                        if (wdata[k] == LUA_IPC_SEPARATOR) {
                            k++; // skip separator
                            int m = 0;
                            while (wdata[k] && m < 255) {
                                handlerName[m] = wdata[k];
                                k++;
                                m++;
                            }
                            handlerName[m] = L'\0';
                        }
                        Log(L"IPC signal received: hook_id=%d script=%s handler=%s\n",
                            i, scriptPath, handlerName);

                        if (scriptPath[0] && handlerName[0]) {
                            bool ok = LoadAndBindScript(i, scriptPath, handlerName);

                            // Signal back to controller
                            WCHAR loadedEventName[150];
                            _snwprintf_(loadedEventName, 149,
                                LUA_ENGINE_NT_LOADED_EVENT, NtCurrentProcessId(), i);

                            UNICODE_STRING uName;
                            pRtlInitUnicodeString(&uName, loadedEventName);
                            OBJECT_ATTRIBUTES oa;
                            InitializeObjectAttributes(&oa, &uName,
                                OBJ_CASE_INSENSITIVE, NULL, NULL);

                            HANDLE hLoaded = NULL;
                            NTSTATUS lst = pNtOpenEvent(&hLoaded,
                                EVENT_MODIFY_STATE, &oa);
                            if (NT_SUCCESS(lst)) {
                                pNtSetEvent(hLoaded, NULL);
                                pNtClose(hLoaded);
                                Log(L"script loaded signal sent: hook_id=%d ok=%d\n", i, ok);
                            }
                        }
                    }
                }
            }
        }

        if (!anySignaled) {
            // No events were signaled; short sleep before next poll
            LARGE_INTEGER delay;
            delay.QuadPart = -1000000; // 100ms
            pNtDelay(FALSE, &delay);
        }
    }


    return 0;
}

// ---- DllMain ----

NTSTATUS
NTAPI
OnProcessAttach(_In_ PVOID ModuleHandle)
{
	LdrAddRefDll(LDR_ADDREF_DLL_PIN, ModuleHandle);

    // Resolve ntdll functions
    UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

    HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, (PVOID*)&NtdllHandle);

    ANSI_STRING RoutineName;

    RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_snwprintf_);

    RtlInitAnsiString(&RoutineName, (PSTR)"_vsnwprintf");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_vsnwprintf_);

    RtlInitAnsiString(&RoutineName, (PSTR)"RtlInitUnicodeString");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pRtlInitUnicodeString);

    RtlInitAnsiString(&RoutineName, (PSTR)"LdrGetDllHandle");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pLdrGetDllHandle);



    RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtDelayExecution");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDelay);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateEvent);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenEvent);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtSetEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtSetEvent);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtResetEvent");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtResetEvent);

    RtlInitAnsiString(&RoutineName, (PSTR)"NtWaitForSingleObject");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtWaitForSingleObject);

    RtlInitAnsiString(&RoutineName, (PSTR)"LdrAddRefDll");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pLdrAddRefDll);

	RtlInitAnsiString(&RoutineName, (PSTR)"_vsnwprintf");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_vsnwprintf_);

	RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_snwprintf_);

    // ETW registration
    EventRegister(&ProviderGUID, NULL, NULL, (PREGHANDLE)(ULONG_PTR)&ProviderHandle);

    // Mutex to prevent double-load
    {
        WCHAR mutant_name[100];
        _snwprintf_(mutant_name, 99, LUA_ENGINE_LOAD_MUTANT_FMT, NtCurrentProcessId());
        UNICODE_STRING Name;
        pRtlInitUnicodeString(&Name, mutant_name);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hMutant;
        NTSTATUS status = pNtCreateEvent(&hMutant, MUTANT_ALL_ACCESS, &oa, NotificationEvent, FALSE);
        // We don't actually use a mutant here; just check if we can create our signal event
        // If LuaEngine is already loaded, the events will already exist and NtCreateEvent
        // will return STATUS_OBJECT_NAME_COLLISION -- that's fine, we'll open them instead.
    }

    // Initialize Lua state pool
    InitLuaHooks();

    // Start AgentCode in a new thread
    // Use LdrLoadDll's RtlCreateUserThread equivalent or NtCreateThreadEx
    // For simplicity, use a system call to create thread
    // Note: We can't use CreateThread (kernel32) in early load
    // Use NtCreateThreadEx from ntdll
    typedef NTSTATUS(NTAPI* PNtCreateThreadEx)(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, HANDLE ProcessHandle,
        PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
        SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize,
        PVOID AttributeList);
    PNtCreateThreadEx pNtCreateThreadEx = 0;
    RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateThreadEx");
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateThreadEx);

    if (pNtCreateThreadEx) {
        HANDLE hThread = NULL;
        pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            NtCurrentProcess(), (PVOID)AgentCode, NULL, 0, 0, 0, 0, NULL);
        if (hThread) {
            pNtClose(hThread);
            Log(L"AgentCode thread created\n");
        } else {
            Log(L"NtCreateThreadEx failed\n");
        }
    } else {
        Log(L"NtCreateThreadEx not available, AgentCode not started\n");
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OnProcessAttach(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
