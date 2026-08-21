#pragma once

#include <ntdef.h>

extern "C" {

NTSTATUS ScsInstallFirmwareMitigation(
	_In_ PVOID FirmwareTableResource,
	_In_ PVOID FirmwareTableProviderListHead);

VOID ScsRemoveFirmwareMitigation();

} // extern "C"