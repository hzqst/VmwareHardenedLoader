#include "firmware_mitigation.h"

namespace {

using FirmwareHandler = NTSTATUS(__cdecl*)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);

struct FIRMWARE_HANDLER_NODE {
	SYSTEM_FIRMWARE_TABLE_HANDLER SystemFWHandler;
	LIST_ENTRY ProviderListEntry;
};
using PFIRMWARE_HANDLER_NODE = FIRMWARE_HANDLER_NODE*;

FirmwareHandler g_orig_firmware = nullptr;
FirmwareHandler g_orig_acpi = nullptr;
FirmwareHandler g_orig_smbios = nullptr;
PERSOURCE g_fw_resource = nullptr;
PLIST_ENTRY g_provider_list = nullptr;
BOOLEAN g_mitigation_active = FALSE;

void PatternReplace(
	_Inout_ PVOID Buffer,
	_In_ ULONG BufferLength,
	_In_reads_bytes_(PatternLength) const char* Pattern,
	_In_reads_bytes_(PatternLength) const char* Replacement,
	_In_ SIZE_T PatternLength) {
	if (!Buffer || !Pattern || !Replacement || PatternLength == 0) {
		return;
	}
	PUCHAR cursor = static_cast<PUCHAR>(Buffer);
	SIZE_T remaining = BufferLength;
	while (remaining >= PatternLength) {
		PUCHAR match = nullptr;
		const SIZE_T searchLen = remaining - PatternLength + 1;
		for (SIZE_T i = 0; i < searchLen; ++i) {
			if (RtlCompareMemory(cursor + i, Pattern, PatternLength) == PatternLength) {
				match = cursor + i;
				break;
			}
		}
		if (!match) {
			return;
		}
		RtlCopyMemory(match, Replacement, PatternLength);
		const SIZE_T consumed = static_cast<SIZE_T>((match - cursor) + PatternLength);
		cursor = match + PatternLength;
		remaining -= consumed;
	}
}

void RemoveTableEntry(
	_Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION Info,
	_In_reads_bytes_(4) const char* Signature) {
	if (!Info || !Info->TableBuffer || !Signature) {
		return;
	}
	ULONG length = Info->TableBufferLength;
	if (length < 4 || (length & 3u) != 0) {
		return;
	}
	PUCHAR bytes = static_cast<PUCHAR>(static_cast<PVOID>(Info->TableBuffer));
	const UCHAR swapped[4] = {
		static_cast<UCHAR>(Signature[3]),
		static_cast<UCHAR>(Signature[2]),
		static_cast<UCHAR>(Signature[1]),
		static_cast<UCHAR>(Signature[0]),
	};
	ULONG dst = 0;
	for (ULONG src = 0; src < length; src += 4) {
		if (RtlCompareMemory(bytes + src, Signature, 4) == 4 ||
			RtlCompareMemory(bytes + src, swapped, 4) == 4) {
			continue;
		}
		if (dst != src) {
			bytes[dst + 0] = bytes[src + 0];
			bytes[dst + 1] = bytes[src + 1];
			bytes[dst + 2] = bytes[src + 2];
			bytes[dst + 3] = bytes[src + 3];
		}
		dst += 4;
	}
	if (dst < length) {
		RtlZeroMemory(bytes + dst, length - dst);
		Info->TableBufferLength = dst;
	}
}

BOOLEAN TableIdMatches(_In_ ULONG TableID, _In_reads_bytes_(4) const char* Signature) {
	const UCHAR swapped[4] = {
		static_cast<UCHAR>(Signature[3]),
		static_cast<UCHAR>(Signature[2]),
		static_cast<UCHAR>(Signature[1]),
		static_cast<UCHAR>(Signature[0]),
	};
	return (RtlCompareMemory(&TableID, Signature, 4) == 4 ||
		RtlCompareMemory(&TableID, swapped, 4) == 4);
}

void RecalculateAcpiChecksum(_Inout_ PVOID Buffer, _In_ ULONG BufferLength) {
	if (!Buffer || BufferLength < 36) {
		return;
	}
	PUCHAR bytes = static_cast<PUCHAR>(Buffer);
	ULONG length = 0;
	RtlCopyMemory(&length, bytes + 4, sizeof(length));
	if (length < 36 || length > BufferLength) {
		return;
	}
	bytes[9] = 0;
	UCHAR sum = 0;
	for (ULONG i = 0; i < length; ++i) {
		sum = static_cast<UCHAR>(sum + bytes[i]);
	}
	bytes[9] = static_cast<UCHAR>(0u - sum);
}

NTSTATUS __cdecl FilterFirmware(PSYSTEM_FIRMWARE_TABLE_INFORMATION info) {
	const NTSTATUS status = g_orig_firmware(info);
	if (NT_SUCCESS(status) && info && info->Action == 1) {
		PatternReplace(info->TableBuffer, info->TableBufferLength, "VMware", "Hyper-V", 6);
		PatternReplace(info->TableBuffer, info->TableBufferLength, "Virtual", "Physical", 7);
	}
	return status;
}

NTSTATUS __cdecl FilterAcpi(PSYSTEM_FIRMWARE_TABLE_INFORMATION info) {
	if (info && info->Action == 1 && TableIdMatches(info->TableID, "WAET")) {
		info->TableBufferLength = 0;
		return STATUS_NOT_FOUND;
	}

	const NTSTATUS status = g_orig_acpi(info);
	if (NT_SUCCESS(status) && info) {
		if (info->Action == 0) {
			RemoveTableEntry(info, "WAET");
		} else if (info->Action == 1) {
			PatternReplace(info->TableBuffer, info->TableBufferLength, "VMware", "Hyper-V", 6);
			PatternReplace(info->TableBuffer, info->TableBufferLength, "VMWARE", "HYPERV", 6);
			RecalculateAcpiChecksum(info->TableBuffer, info->TableBufferLength);
		}
	}
	return status;
}

NTSTATUS __cdecl FilterSmbios(PSYSTEM_FIRMWARE_TABLE_INFORMATION info) {
	const NTSTATUS status = g_orig_smbios(info);
	if (NT_SUCCESS(status) && info && info->Action == 1) {
		PatternReplace(info->TableBuffer, info->TableBufferLength, "VMware", "Hyper-V", 6);
		PatternReplace(info->TableBuffer, info->TableBufferLength, "VMWARE", "HYPERV", 6);
	}
	return status;
}

void HookHandler(
	_In_ PFIRMWARE_HANDLER_NODE Node,
	_In_ ULONG Signature,
	_In_ FirmwareHandler Replacement,
	_Out_ FirmwareHandler* Original) {
	if (Node->SystemFWHandler.ProviderSignature == Signature &&
		Node->SystemFWHandler.FirmwareTableHandler && !*Original) {
		*Original = Node->SystemFWHandler.FirmwareTableHandler;
		Node->SystemFWHandler.FirmwareTableHandler = Replacement;
	}
}

} // namespace

NTSTATUS ScsInstallFirmwareMitigation(
	_In_ PVOID FirmwareTableResource,
	_In_ PVOID FirmwareTableProviderListHead) {
	PAGED_CODE();
	if (!FirmwareTableResource || !FirmwareTableProviderListHead) {
		return STATUS_INVALID_PARAMETER;
	}
	if (g_mitigation_active) {
		return STATUS_ALREADY_REGISTERED;
	}

	g_fw_resource = static_cast<PERESOURCE>(FirmwareTableResource);
	g_provider_list = static_cast<PLIST_ENTRY>(FirmwareTableProviderListHead);
	ExAcquireResourceExclusiveLite(g_fw_resource, TRUE);

	ULONG visited = 0;
	for (PLIST_ENTRY entry = g_provider_list->Flink;
		entry && entry != g_provider_list && visited++ < 64;
		entry = entry->Flink) {
		auto* node = CONTAINING_RECORD(entry, FIRMWARE_HANDLER_NODE, ProviderListEntry);
		HookHandler(node, 'FIRM', FilterFirmware, &g_orig_firmware);
		HookHandler(node, 'ACPI', FilterAcpi, &g_orig_acpi);
		HookHandler(node, 'RSMB', FilterSmbios, &g_orig_smbios);
	}

	ExReleaseResourceLite(g_fw_resource);
	if (!g_orig_firmware && !g_orig_acpi && !g_orig_smbios) {
		g_fw_resource = nullptr;
		g_provider_list = nullptr;
		return STATUS_NOT_FOUND;
	}

	g_mitigation_active = TRUE;
	return STATUS_SUCCESS;
}

VOID ScsRemoveFirmwareMitigation() {
	PAGED_CODE();
	if (!g_mitigation_active || !g_fw_resource || !g_provider_list) {
		return;
	}

	ExAcquireResourceExclusiveLite(g_fw_resource, TRUE);
	ULONG visited = 0;
	for (PLIST_ENTRY entry = g_provider_list->Flink;
		entry && entry != g_provider_list && visited++ < 64;
		entry = entry->Flink) {
		auto* node = CONTAINING_RECORD(entry, FIRMWARE_HANDLER_NODE, ProviderListEntry);
		if (node->SystemFWHandler.ProviderSignature == 'FIRM' && g_orig_firmware) {
			node->SystemFWHandler.FirmwareTableHandler = g_orig_firmware;
		}
		if (node->SystemFWHandler.ProviderSignature == 'ACPI' && g_orig_acpi) {
			node->SystemFWHandler.FirmwareTableHandler = g_orig_acpi;
		}
		if (node->SystemFWHandler.ProviderSignature == 'RSMB' && g_orig_smbios) {
			node->SystemFWHandler.FirmwareTableHandler = g_orig_smbios;
		}
	}
	ExReleaseResourceLite(g_fw_resource);

	g_orig_firmware = nullptr;
	g_orig_acpi = nullptr;
	g_orig_smbios = nullptr;
	g_fw_resource = nullptr;
	g_provider_list = nullptr;
	g_mitigation_active = FALSE;
}