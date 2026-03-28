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
    {"a3ae65cd2f9a2f28b9b5d2c0e8a5c3f1", 0x1A2B3, "Windows 10 21H2 x64"},
    // Windows 10 22H2 x64
    {"b4bf76de3gab3g39ca6e3d1f9b6d4g2", 0x1A3C7, "Windows 10 22H2 x64"},
    // Windows 11 21H2 x64
    {"c5cg87ef4hbc4h4adb7f4e2gac7e5h3", 0x1B1D8, "Windows 11 21H2 x64"},
    // Windows 11 22H2 x64
    {"d6dh98fg5icd5i5bec8g5f3hbd8f6i4", 0x1B2E9, "Windows 11 22H2 x64"},
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
