#include "MAP.h"
#include <Windows.h>
#include "Superfetch.h"

HANDLE OpenDriver() {
	return CreateFileA(DEVICENAME, GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, 0);
}

bool DriverMapMemory(HANDLE hDriver, IoCommand* myIo) {
	DWORD read = 0;
	return DeviceIoControl(hDriver, IOCTL_MAPMEMORY, myIo, sizeof(*myIo), myIo, sizeof(*myIo), &read, 0);

}
bool DriverUnmapMemory(HANDLE hDriver, IoCommand* myIo) {
	DWORD read = 0;
	return DeviceIoControl(hDriver, IOCTL_UNMAPMEM, myIo, sizeof(*myIo), myIo, sizeof(*myIo), &read, 0);
}

bool CloseDriver(HANDLE hDriver) {
	return CloseHandle(hDriver);
}


HANDLE OpenPhysicalMemory()
{
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\device\\physicalmemory";
	NTSTATUS			status;
	HANDLE				physmem;

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	return physmem;
}

BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, PDWORD64 Address, PSIZE_T Length, PDWORD64 VirtualAddress)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	viewBase;

	*VirtualAddress = 0;
	viewBase.QuadPart = (ULONGLONG)(*Address);
	ntStatus = ZwMapViewOfSection
	(
		PhysicalMemory,
		GetCurrentProcess(),
		(PVOID *)VirtualAddress,
		0L,
		*Length,
		&viewBase,
		Length,
		ViewShare,
		0,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(ntStatus)) return false;
	*Address = viewBase.LowPart;
	return true;
}

BOOLEAN UnMapMemory(PDWORD64 Address)
{
	if (!ZwUnmapViewOfSection(GetCurrentProcess(), (PVOID)Address))
		return true;
	else
		return false;
}