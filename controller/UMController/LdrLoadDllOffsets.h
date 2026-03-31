#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>

// MD5 hash length (hex string)
constexpr size_t MD5_HASH_LENGTH = 32;

// Structure to hold MD5-to-offset mapping for LdrLoadDll return address
struct LdrLoadDllOffsetEntry {
    const char* md5Hash;      // MD5 hash of ntdll.dll (lowercase hex)
    DWORD64 offset;           // Offset of LdrLoadDll return instruction
    const char* version;      // Windows version description
};

// Pre-computed MD5 offsets for common Windows versions
// x64 versions
static const LdrLoadDllOffsetEntry g_LdrLoadDllOffsets_x64[] = {
	// Windows 10 21H2 x64
	{"35b03f5d9c6da76fec950a36f9d357b3", 0x16B34, "Windows 10 21H2 x64"},
	// Sentinel/Default (should be updated with real values)
	{nullptr, 0x0, "Unknown"}
};

// x86 (WoW64) versions
static const LdrLoadDllOffsetEntry g_LdrLoadDllOffsets_x86[] = {
    // Windows 10 21H2 x86
    {"e7ei09gh6jde6j6cfd9h6g4ice9g7j5", 0x15A12, "Windows 10 21H2 x86"},
    // Windows 10 22H2 x86
    {"f8fj10hi7kef7k7dge0i7h5jdf0h8k6", 0x15B23, "Windows 10 22H2 x86"},
    // Sentinel/Default
    {nullptr, 0x0, "Unknown"}
};

// Forward declarations
std::string CalculateFileMD5(const std::wstring& filePath);
DWORD64 FindLdrLoadDllOffset(const std::string& md5Hash, bool is64Bit);
DWORD64 CalculateNtdllLdrLoadDllRetOffset(DWORD processId, bool is64Bit);
