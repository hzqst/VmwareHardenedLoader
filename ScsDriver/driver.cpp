#include <ntddk.h>

#include "debug_util.h"
#include "firmware_mitigation.h"
#include "kernel_resolver.h"
#include "pnp_mitigation.h"
#include "registry_mitigation.h"

namespace {

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
	ScsRemovePnpMitigation();
	ScsRemoveFirmwareMitigation();
}

} // namespace

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath) {
	PAGED_CODE();

	ScsKernelResolver resolver = {};
	NTSTATUS status = ScsResolveKernelSymbols(RegistryPath, &resolver);
	if (!NT_SUCCESS(status)) {
		SCS_DEBUG_PRINT(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"SCS: kernel resolution failed: 0x%08X\n", status);
		return status;
	}

	status = ScsInstallFirmwareMitigation(
		resolver.FirmwareTableResource, resolver.FirmwareTableProviderListHead);
	if (!NT_SUCCESS(status)) {
		SCS_DEBUG_PRINT(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"SCS: firmware mitigation installation failed: 0x%08X\n", status);
		return status;
	}

	status = ScsInstallPnpMitigation(DriverObject);
	if (!NT_SUCCESS(status)) {
		SCS_DEBUG_PRINT(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"SCS: pnp mitigation installation failed: 0x%08X\n", status);
		ScsRemoveFirmwareMitigation();
		return status;
	}

	status = ScsApplyRegistryMitigation();
	if (!NT_SUCCESS(status)) {
		SCS_DEBUG_PRINT(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"SCS: registry mitigation failed: 0x%08X\n", status);
		ScsRemoveFirmwareMitigation();
		ScsRemovePnpMitigation();
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}