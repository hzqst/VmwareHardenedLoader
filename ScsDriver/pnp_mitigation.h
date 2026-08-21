#pragma once

#include <ntdef.h>

extern "C" {

NTSTATUS ScsInstallPnpMitigation(_In_ PDRIVER_OBJECT DriverObject);

VOID ScsRemovePnpMitigation();

} // extern "C"