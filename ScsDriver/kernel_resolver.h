#pragma once

#include <ntdef.h>

typedef struct _ScsKernelResolver {
	PVOID FirmwareTableResource;
	PVOID FirmwareTableProviderListHead;
} ScsKernelResolver, *PScsKernelResolver;

extern "C" {

NTSTATUS ScsResolveKernelSymbols(
	_In_ PUNICODE_STRING RegistryPath,
	_Out_ PScsKernelResolver Resolver);

} // extern "C"