#pragma once

#include <ntdef.h>

#if DBG
#define SCS_DEBUG_PRINT(ComponentId, Level, ...) \
    DbgPrintEx((ComponentId), (Level), __VA_ARGS__)
#else
#define SCS_DEBUG_PRINT(ComponentId, Level, ...)
#endif