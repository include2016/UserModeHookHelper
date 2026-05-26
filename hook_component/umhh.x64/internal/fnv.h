#pragma once

#define FNV1A_OFFSET 14695981039346656037ULL
#define FNV1A_PRIME 1099511628211ULL

static inline DWORD64 FnvInit(void) { return FNV1A_OFFSET; }

static inline DWORD64 FnvUpdate(DWORD64 h, const void* data, SIZE_T len, BOOL ci) {
	const UCHAR* p = (const UCHAR*)data;
	for (SIZE_T i = 0; i < len; ++i) {
		UCHAR b = p[i];
		if (ci && b >= 'A' && b <= 'Z') b += ('a' - 'A');
		h ^= b;
		h *= FNV1A_PRIME;
	}
	return h;
}

static inline DWORD64 FnvHashBytes(const void* data, SIZE_T len, BOOL ci) {
	return FnvUpdate(FnvInit(), data, len, ci);
}
