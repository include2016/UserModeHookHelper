#pragma once

#define BUILD_PID_EVENT_NAME(buf, fmt)                                     \
	_snwprintf_((buf), RTL_NUMBER_OF(buf) - 1, fmt L"%d",                  \
		(ULONG)(ULONG_PTR)NtCurrentProcessId())
