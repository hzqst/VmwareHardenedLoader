#include <fltkernel.h>

extern "C"
{
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

		auto pfnNtQuerySystemInformation = UtilGetSystemProcAddress(L"NtQuerySystemInformation");

		DbgPrint("NtQuerySystemInformation found at %p", pfnNtQuerySystemInformation);



		driver_object->DriverUnload = DriverUnload;

		return STATUS_SUCCESS;
	}
}