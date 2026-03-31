// pch.h - Precompiled header for DllLoadMon

#pragma once

// Windows headers
#define WIN32_NO_STATUS
#include <windows.h>

#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <winternl.h>

// Standard C++ headers
#include <vector>
#include <string>
#include <cstring>
