#include "pch.h"
#include "LdrLoadDllOffsets.h"
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "Crypt32.lib")

/**
 * Calculate MD5 hash of a file
 * @param filePath Full path to the file
 * @return MD5 hash as lowercase hex string (32 characters), or empty string on failure
 */
std::string CalculateFileMD5(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE buffer[4096];
    DWORD bytesRead = 0;
    BYTE hashBuffer[16];
    DWORD hashLength = sizeof(hashBuffer);
    
    // Acquire cryptographic context
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    // Create hash object
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Open file
    hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Read file and update hash
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CloseHandle(hFile);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }
    
    CloseHandle(hFile);
    
    // Get final hash value
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBuffer, &hashLength, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    // Convert to hex string
    std::stringstream ss;
    for (DWORD i = 0; i < hashLength; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hashBuffer[i];
    }
    
    return ss.str();
}

/**
 * Find LdrLoadDll offset from MD5 hash
 * @param md5Hash MD5 hash of ntdll.dll
 * @param is64Bit true for x64, false for x86
 * @return Offset value, or 0 if not found
 */
DWORD64 FindLdrLoadDllOffset(const std::string& md5Hash, bool is64Bit) {
    const LdrLoadDllOffsetEntry* table = is64Bit ? g_LdrLoadDllOffsets_x64 : g_LdrLoadDllOffsets_x86;
    
    for (size_t i = 0; table[i].md5Hash != nullptr; i++) {
        if (_stricmp(table[i].md5Hash, md5Hash.c_str()) == 0) {
            return table[i].offset;
        }
    }
    
    // Not found in table
    return 0;
}

/**
 * Calculate ntdll LdrLoadDll return offset for a specific process
 * @param processId Target process ID
 * @param is64Bit true for x64 process, false for x86
 * @return Offset value, or 0 on failure
 */
DWORD64 CalculateNtdllLdrLoadDllRetOffset(DWORD processId, bool is64Bit) {
    // Construct ntdll.dll path based on architecture
    std::wstring ntdllPath;
    if (is64Bit) {
        // x64 ntdll is in System32
        ntdllPath = L"C:\\Windows\\System32\\ntdll.dll";
    } else {
        // x86 ntdll is in SysWOW64
        ntdllPath = L"C:\\Windows\\SysWOW64\\ntdll.dll";
    }
    
    // Calculate MD5
    std::string md5Hash = CalculateFileMD5(ntdllPath);
    if (md5Hash.empty()) {
        return 0;
    }
    
    // Lookup offset from table
    return FindLdrLoadDllOffset(md5Hash, is64Bit);
}
