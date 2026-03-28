// framework.h - Framework definitions for DllLoadMon project

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Project type
#define DLLLOADMON_EXPORTS

// Platform detection
#ifdef _WIN64
    #define PLATFORM_X64
#else
    #define PLATFORM_X86
#endif
