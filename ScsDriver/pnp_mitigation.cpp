#include "pnp_mitigation.h"

extern "C" {

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
	_In_ PVOID Object,
	_In_ ULONG HandleAttributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Out_ PHANDLE Handle);

extern POBJECT_TYPE* CmKeyObjectType;

} // extern "C"

namespace {

LARGE_INTEGER g_hook_cookie = { 0 };
BOOLEAN g_hook_installed = FALSE;

BOOLEAN PatternSearchCI(
	_In_reads_bytes_(HaystackBytes) PCWCH Haystack,
	_In_ ULONG HaystackBytes,
	_In_reads_bytes_(NeedleBytes) PCWCH Needle,
	_In_ ULONG NeedleBytes) {
	if (NeedleBytes == 0 || HaystackBytes < NeedleBytes) {
		return FALSE;
	}
	const ULONG hCount = HaystackBytes / sizeof(WCHAR);
	const ULONG nCount = NeedleBytes / sizeof(WCHAR);
	if (nCount == 0 || hCount < nCount) {
		return FALSE;
	}
	for (ULONG i = 0; i + nCount <= hCount; ++i) {
		BOOLEAN match = TRUE;
		for (ULONG j = 0; j < nCount; ++j) {
			if (RtlUpcaseUnicodeChar(Haystack[i + j]) !=
				RtlUpcaseUnicodeChar(Needle[j])) {
				match = FALSE;
				break;
			}
		}
		if (match) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN EndsWithCI(_In_ PCUNICODE_STRING Full, _In_ PCWSTR Tail) {
	if (!Full || !Full->Buffer || !Tail) {
		return FALSE;
	}
	UNICODE_STRING tail;
	RtlInitUnicodeString(&tail, Tail);
	if (Full->Length < tail.Length) {
		return FALSE;
	}
	PCWCH start = (PCWCH)((PUCHAR)Full->Buffer + Full->Length - tail.Length);
	UNICODE_STRING slice;
	slice.Buffer = const_cast<PWCH>(start);
	slice.Length = tail.Length;
	slice.MaximumLength = tail.Length;
	return RtlEqualUnicodeString(&slice, &tail, TRUE);
}

static const WCHAR kVendorPattern[] = L"VEN_1A2B";
static const WCHAR kProductPattern[] = L"VID_3C4D";

BOOLEAN NameMatchesTarget(_In_ PCWCH Name, _In_ ULONG NameBytes) {
	if (!Name || NameBytes == 0) {
		return FALSE;
	}
	if (PatternSearchCI(Name, NameBytes,
			kVendorPattern, sizeof(kVendorPattern) - sizeof(WCHAR))) {
		return TRUE;
	}
	if (PatternSearchCI(Name, NameBytes,
			kProductPattern, sizeof(kProductPattern) - sizeof(WCHAR))) {
		return TRUE;
	}
	return FALSE;
}

BOOLEAN ExtractKeyName(
	_In_ PVOID KeyInformation,
	_In_ KEY_INFORMATION_CLASS Class,
	_In_ ULONG BufferLength,
	_Out_ PCWCH* Name,
	_Out_ PULONG NameLength) {
	*Name = nullptr;
	*NameLength = 0;
	if (!KeyInformation) {
		return FALSE;
	}
	switch (Class) {
	case KeyBasicInformation: {
		if (BufferLength < FIELD_OFFSET(KEY_BASIC_INFORMATION, Name)) {
			return FALSE;
		}
		auto* info = reinterpret_cast<PKEY_BASIC_INFORMATION>(KeyInformation);
		ULONG maxName = BufferLength - FIELD_OFFSET(KEY_BASIC_INFORMATION, Name);
		*Name = info->Name;
		*NameLength = min(info->NameLength, maxName);
		return TRUE;
	}
	case KeyNodeInformation: {
		if (BufferLength < FIELD_OFFSET(KEY_NODE_INFORMATION, Name)) {
			return FALSE;
		}
		auto* info = reinterpret_cast<PKEY_NODE_INFORMATION>(KeyInformation);
		ULONG maxName = BufferLength - FIELD_OFFSET(KEY_NODE_INFORMATION, Name);
		*Name = info->Name;
		*NameLength = min(info->NameLength, maxName);
		return TRUE;
	}
	case KeyNameInformation: {
		if (BufferLength < FIELD_OFFSET(KEY_NAME_INFORMATION, Name)) {
			return FALSE;
		}
		auto* info = reinterpret_cast<PKEY_NAME_INFORMATION>(KeyInformation);
		ULONG maxName = BufferLength - FIELD_OFFSET(KEY_NAME_INFORMATION, Name);
		*Name = info->Name;
		*NameLength = min(info->NameLength, maxName);
		return TRUE;
	}
	default:
		return FALSE;
	}
}

BOOLEAN IsEnumBranch(_In_ PVOID KeyObject) {
	if (!KeyObject) {
		return FALSE;
	}
	PCUNICODE_STRING keyName = nullptr;
	NTSTATUS status = CmCallbackGetKeyObjectIDEx(
		&g_hook_cookie, KeyObject, nullptr, &keyName, 0);
	if (!NT_SUCCESS(status) || !keyName) {
		return FALSE;
	}
	BOOLEAN result =
		EndsWithCI(keyName, L"\\Enum\\PCI") ||
		EndsWithCI(keyName, L"\\Enum\\USB") ||
		EndsWithCI(keyName, L"\\Enum\\HDAUDIO");
	CmCallbackReleaseKeyObjectIDEx(keyName);
	return result;
}

BOOLEAN PathTargetsHidden(_In_ PCUNICODE_STRING Path) {
	if (!Path || !Path->Buffer || Path->Length == 0) {
		return FALSE;
	}
	static const struct {
		const WCHAR* branch;
		const WCHAR* pattern;
	} rules[] = {
		{ L"\\Enum\\PCI\\",     kVendorPattern },
		{ L"\\Enum\\HDAUDIO\\", kVendorPattern },
		{ L"\\Enum\\USB\\",     kProductPattern },
	};
	for (auto& rule : rules) {
		UNICODE_STRING branch;
		RtlInitUnicodeString(&branch, rule.branch);
		UNICODE_STRING pattern;
		RtlInitUnicodeString(&pattern, rule.pattern);
		if (PatternSearchCI(Path->Buffer, Path->Length,
				branch.Buffer, branch.Length) &&
			PatternSearchCI(Path->Buffer, Path->Length,
				pattern.Buffer, pattern.Length)) {
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS SkipHidden(
	_Inout_ PREG_ENUMERATE_KEY_INFORMATION PreInfo,
	_In_ ULONG StartIndex) {
	HANDLE keyHandle = nullptr;
	NTSTATUS status = ObOpenObjectByPointer(
		PreInfo->Object,
		OBJ_KERNEL_HANDLE,
		nullptr,
		KEY_ENUMERATE_SUB_KEYS,
		*CmKeyObjectType,
		KernelMode,
		&keyHandle);
	if (!NT_SUCCESS(status) || !keyHandle) {
		return STATUS_NO_MORE_ENTRIES;
	}

	NTSTATUS enumStatus = STATUS_NO_MORE_ENTRIES;
	ULONG index = StartIndex;
	for (;;) {
		enumStatus = ZwEnumerateKey(
			keyHandle,
			index,
			PreInfo->KeyInformationClass,
			PreInfo->KeyInformation,
			PreInfo->Length,
			PreInfo->ResultLength);
		if (!NT_SUCCESS(enumStatus)) {
			break;
		}
		PCWCH name = nullptr;
		ULONG nameBytes = 0;
		if (!ExtractKeyName(PreInfo->KeyInformation, PreInfo->KeyInformationClass,
				*PreInfo->ResultLength, &name, &nameBytes)) {
			break;
		}
		if (!NameMatchesTarget(name, nameBytes)) {
			break;
		}
		++index;
	}

	ZwClose(keyHandle);
	return enumStatus;
}

NTSTATUS RegistryCallback(PVOID Context, PVOID Argument1, PVOID Argument2) {
	UNREFERENCED_PARAMETER(Context);

	if (ExGetPreviousMode() != UserMode) {
		return STATUS_SUCCESS;
	}

	const REG_NOTIFY_CLASS notify =
		static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(Argument1));

	switch (notify) {
	case RegNtPostEnumerateKey: {
		auto* post = reinterpret_cast<PREG_POST_OPERATION_INFORMATION>(Argument2);
		if (!post || !NT_SUCCESS(post->Status)) {
			break;
		}
		auto* preInfo = reinterpret_cast<PREG_ENUMERATE_KEY_INFORMATION>(post->PreInformation);
		if (!preInfo || !preInfo->KeyInformation || !preInfo->ResultLength) {
			break;
		}
		if (!IsEnumBranch(preInfo->Object)) {
			break;
		}
		PCWCH name = nullptr;
		ULONG nameBytes = 0;
		if (!ExtractKeyName(preInfo->KeyInformation, preInfo->KeyInformationClass,
				*preInfo->ResultLength, &name, &nameBytes)) {
			break;
		}
		if (!NameMatchesTarget(name, nameBytes)) {
			break;
		}
		post->ReturnStatus = SkipHidden(preInfo, preInfo->Index + 1);
		break;
	}

	case RegNtPreOpenKey:
	case RegNtPreOpenKeyEx: {
		auto* info = reinterpret_cast<PREG_OPEN_KEY_INFORMATION>(Argument2);
		if (!info || !info->CompleteName) {
			break;
		}
		if (PathTargetsHidden(info->CompleteName)) {
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
		break;
	}

	default:
		break;
	}

	return STATUS_SUCCESS;
}

} // namespace

NTSTATUS ScsInstallPnpMitigation(_In_ PDRIVER_OBJECT DriverObject) {
	PAGED_CODE();
	if (g_hook_installed) {
		return STATUS_ALREADY_REGISTERED;
	}
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"388888");
	const NTSTATUS status = CmRegisterCallbackEx(
		RegistryCallback,
		&altitude,
		DriverObject,
		nullptr,
		&g_hook_cookie,
		nullptr);
	if (NT_SUCCESS(status)) {
		g_hook_installed = TRUE;
	} else {
		g_hook_cookie.QuadPart = 0;
	}
	return status;
}

VOID ScsRemovePnpMitigation() {
	PAGED_CODE();
	if (!g_hook_installed) {
		return;
	}
	CmUnRegisterCallback(g_hook_cookie);
	g_hook_installed = FALSE;
	g_hook_cookie.QuadPart = 0;
}