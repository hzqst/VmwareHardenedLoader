#include "registry_mitigation.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ScsApplyRegistryMitigation)
#endif

namespace {

constexpr ULONG kMemTag = 'sCSM';

PVOID AllocMem(_In_ SIZE_T Size) {
#pragma warning(push)
#pragma warning(disable : 4996)
	return ExAllocatePoolWithTag(PagedPool, Size, kMemTag);
#pragma warning(pop)
}

NTSTATUS RecursiveDelete(_In_ HANDLE KeyHandle) {
	PAGED_CODE();

	for (;;) {
		ULONG requiredLength = 0;
		NTSTATUS status = ZwEnumerateKey(
			KeyHandle, 0, KeyBasicInformation, nullptr, 0, &requiredLength);
		if (status == STATUS_NO_MORE_ENTRIES) {
			break;
		}
		if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
			return status;
		}

		auto* keyInformation = static_cast<PKEY_BASIC_INFORMATION>(
			AllocMem(requiredLength));
		if (!keyInformation) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwEnumerateKey(
			KeyHandle,
			0,
			KeyBasicInformation,
			keyInformation,
			requiredLength,
			&requiredLength);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(keyInformation, kMemTag);
			if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
				continue;
			}
			return status;
		}

		if (keyInformation->NameLength > MAXUSHORT) {
			ExFreePoolWithTag(keyInformation, kMemTag);
			return STATUS_NAME_TOO_LONG;
		}

		UNICODE_STRING childName = {};
		childName.Buffer = keyInformation->Name;
		childName.Length = static_cast<USHORT>(keyInformation->NameLength);
		childName.MaximumLength = childName.Length;

		OBJECT_ATTRIBUTES attributes;
		InitializeObjectAttributes(
			&attributes,
			&childName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			KeyHandle,
			nullptr);

		HANDLE childHandle = nullptr;
		status = ZwOpenKey(
			&childHandle, DELETE | KEY_ENUMERATE_SUB_KEYS, &attributes);
		ExFreePoolWithTag(keyInformation, kMemTag);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = RecursiveDelete(childHandle);
		ZwClose(childHandle);
		if (!NT_SUCCESS(status)) {
			return status;
		}
	}

	return ZwDeleteKey(KeyHandle);
}

} // namespace

NTSTATUS ScsApplyRegistryMitigation() {
	PAGED_CODE();

	UNICODE_STRING keyName = RTL_CONSTANT_STRING(
		L"\\Registry\\Machine\\HARDWARE\\ACPI\\DSDT\\PTLTD_");
	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(
		&attributes,
		&keyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		nullptr);

	HANDLE keyHandle = nullptr;
	NTSTATUS status = ZwOpenKey(
		&keyHandle, DELETE | KEY_ENUMERATE_SUB_KEYS, &attributes);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
		return STATUS_SUCCESS;
	}
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = RecursiveDelete(keyHandle);
	ZwClose(keyHandle);
	return status;
}