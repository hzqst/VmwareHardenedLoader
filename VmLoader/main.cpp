#include <fltkernel.h>

extern "C"
{
	_Use_decl_annotations_ static void DriverUnload(
		PDRIVER_OBJECT driver_object) {
		UNREFERENCED_PARAMETER(driver_object);
		PAGED_CODE();


	}

	_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
		PUNICODE_STRING registry_path) {
		UNREFERENCED_PARAMETER(registry_path);
		PAGED_CODE();

		driver_object->DriverUnload = DriverUnload;

		return STATUS_SUCCESS;
	}
}