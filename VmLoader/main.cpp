#include <fltkernel.h>

extern "C"
{
	PVOID ACPI_DriverObject = NULL;

	typedef NTSTATUS(__cdecl *PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);

	typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER {
		ULONG       ProviderSignature;
		BOOLEAN     Register;
		PFNFTH      FirmwareTableHandler;
		PVOID       DriverObject;
	} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;

	NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

	_Use_decl_annotations_ void *UtilGetSystemProcAddress(
		const wchar_t *proc_name) {
		PAGED_CODE();

		UNICODE_STRING proc_name_U = {};
		RtlInitUnicodeString(&proc_name_U, proc_name);
		return MmGetSystemRoutineAddress(&proc_name_U);
	}

	_Use_decl_annotations_ static void DriverUnload(
		PDRIVER_OBJECT driver_object) {
		UNREFERENCED_PARAMETER(driver_object);
		PAGED_CODE();


	}



	_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
		PUNICODE_STRING registry_path) {
		UNREFERENCED_PARAMETER(registry_path);
		PAGED_CODE();

		//use following code to locate ExpFirmwareTableResource & ExpFirmwareTableProviderListHead
		//PAGE
		//41 B8 41 52 46 54                                   mov     r8d, 'TFRA'     ; Tag

		driver_object->DriverUnload = DriverUnload;

		return STATUS_SUCCESS;
	}
}