#include "stdafx.h"
#include "RyuInfuser.h"
#include "MAP.h"
#include <string>
#include <stdio.h>
#include <iostream>

using namespace std;

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")

#ifndef _WIN64
#error This can only be compiled for 64bit
#endif

RyuInfuser::RyuInfuser()
{

}

RyuInfuser::~RyuInfuser()
{

}

static BOOLEAN ChangeSecurityDescriptorPhysicalMemory()
{
	EXPLICIT_ACCESS		Access;
	PACL				OldDacl = NULL, NewDacl = NULL;
	SECURITY_DESCRIPTOR security;
	ZeroMemory(&security, sizeof(SECURITY_DESCRIPTOR));

	PSECURITY_DESCRIPTOR	psecurity = &security;
	NTSTATUS				status;
	HANDLE					physmem;
	UNICODE_STRING			physmemString;
	OBJECT_ATTRIBUTES		attributes;
	WCHAR					physmemName[] = L"\\device\\physicalmemory";

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, WRITE_DAC | READ_CONTROL, &attributes);

	if (!NT_SUCCESS(status)) return false;

	GetSecurityInfo(physmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &OldDacl, NULL, 0);

	Access.grfAccessPermissions = SECTION_ALL_ACCESS;
	Access.grfAccessMode = GRANT_ACCESS;
	Access.grfInheritance = NO_INHERITANCE;
	Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	Access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	Access.Trustee.TrusteeType = TRUSTEE_IS_USER;
	Access.Trustee.ptstrName = (LPWSTR)"CURRENT_USER";

	SetEntriesInAcl(1, &Access, OldDacl, &NewDacl);

	SetSecurityInfo(physmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NewDacl, NULL);

	CloseHandle(physmem);
	return true;
};

static BOOLEAN RestoreSecurityDescriptorPhysicalMemory()
{
	EXPLICIT_ACCESS		Access;
	PACL				OldDacl = NULL, NewDacl = NULL, NewOldDacl = NULL;
	SECURITY_DESCRIPTOR security;
	ZeroMemory(&security, sizeof(SECURITY_DESCRIPTOR));

	PSECURITY_DESCRIPTOR	psecurity = &security;
	NTSTATUS				status;
	HANDLE					physmem;
	UNICODE_STRING			physmemString;
	OBJECT_ATTRIBUTES		attributes;
	WCHAR					physmemName[] = L"\\device\\physicalmemory";

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, WRITE_DAC | READ_CONTROL, &attributes);

	if (!NT_SUCCESS(status)) return false;

	Access.grfAccessPermissions = SECTION_ALL_ACCESS;
	Access.grfAccessMode = GRANT_ACCESS;
	Access.grfInheritance = NO_INHERITANCE;
	Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	Access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	Access.Trustee.TrusteeType = TRUSTEE_IS_USER;
	Access.Trustee.ptstrName = (LPWSTR)L"CURRENT_USER";


	SetEntriesInAcl(0, &Access, _globalOldDacl, &NewOldDacl);

	SetSecurityInfo(physmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NewOldDacl, NULL);

	CloseHandle(physmem);
	return true;
};

int isThisAscii(int c)
{
	return((c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') || c == 0x20 || c == '@' || c == '_' || c == '?');
}

int isThisPrintable(uint32_t uint32)
{
	if ((isThisAscii((uint32 >> 24) & 0xFF)) && (isThisAscii((uint32 >> 16) & 0xFF)) && (isThisAscii((uint32 >> 8) & 0xFF)) &&
		(isThisAscii((uint32) & 0xFF)))
		return true;
	else
		return false;
}

bool isInsidePhysicalRAM(uint64_t addr, SFMemoryInfo* mi, int nOfRange) {
	for (int i = 0; i < nOfRange; i++)
		if (mi[i].Start <= addr && addr <= mi[i].End)
			return true;
	return false;
}

bool isPoolPage(uint64_t addr, PfnList* pfnList) {
	return pfnList[(addr / 0x1000)].isPool;
}

bool cache_objhdr_address(uint64_t address)
{
	wchar_t local_path[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, local_path);
	std::wstring filename = local_path;
	filename += L"\\cache";
	HANDLE hCache = CreateFile(filename.c_str(), GENERIC_WRITE, NULL, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hCache == INVALID_HANDLE_VALUE)
		return false;
	DWORD dwWritten;
	bool success = true;
	if (!WriteFile(hCache, &address, sizeof(address), &dwWritten, nullptr) || dwWritten != sizeof(address))
		success = false;
	::CloseHandle(hCache);
	MoveFileEx(filename.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
	return true;
}

uint64_t get_physmem_object_header_physical_address()
{
	wchar_t local_path[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, local_path);
	std::wstring filename = local_path;
	filename += L"\\cache";
	HANDLE hCache = CreateFile(filename.c_str(), GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hCache == INVALID_HANDLE_VALUE)
		return 0;
	uint64_t address = 0;
	DWORD dwRead;
	if (!ReadFile(hCache, &address, sizeof(address), &dwRead, nullptr) || dwRead != sizeof(address))
		address = 0;
	::CloseHandle(hCache);
	return address;
}

void patch(bool bPatch)
{
	IoCommand myIo = { 0 };
	myIo.offset = 0x0;
	myIo.read.QuadPart = 0x2000;
	if (physmem_object_header) {

		uint64_t physmem_object_header_page = (physmem_object_header / 0x1000) * 0x1000;

		if (!isPoolPage(physmem_object_header_page, pfnTable)) {
			physmem_object_header = NULL;
			return;
		}

		myIo.offset = physmem_object_header_page;
		if (DriverMapMemory(sDriver, &myIo)) {
			auto offset = physmem_object_header - physmem_object_header_page;
			if (myIo.virtualmemory) {
				auto pPoolHeader = (PPOOL_HEADER)(myIo.virtualmemory + offset - 0x30);
				if (0x74636553 == (pPoolHeader->PoolTag & 0x7FFFFFFF)) {
					auto pObjectHeader = (POBJECT_HEADER)(myIo.virtualmemory + offset);
					if (bPatch) {
						if (pObjectHeader->KernelObject == 1 && pObjectHeader->KernelOnlyAccess == 1) {
							pObjectHeader->KernelObject = 0;
							pObjectHeader->KernelOnlyAccess = 0;
						}
						else
							physmem_object_header = NULL;
					}
					else {
						if (pObjectHeader->KernelObject == 0 && pObjectHeader->KernelOnlyAccess == 0) {
							pObjectHeader->KernelObject = 1;
							pObjectHeader->KernelOnlyAccess = 1;
						}
						else
							physmem_object_header = NULL;
					}
				}
				else
					physmem_object_header = NULL;
			}
			else
				physmem_object_header = NULL;
			DriverUnmapMemory(sDriver, &myIo);
		}
		else
			physmem_object_header = NULL;
	}
}

/*  */
int RyuInfuser:: InfuseMeDaddyKong()
{
	system("pause");

	printf("Running...\n");

	physmem_object_header = get_physmem_object_header_physical_address();

	printf("Loaded header...\n");

	sDriver = OpenDriver();

	if (!sDriver || sDriver == (HANDLE)-1) {
		printf("Driver Not Running...\n");
		system("pause");
		return 0;
	}

	if (!SFSetup()) {
		printf("You're not running with administrator privilege...\n");
		system("pause");
	}

	SFMemoryInfo myRanges[32] = { 0 };
	int nOfRange = 0;
	pfnTable = SFGetMemoryInfo(myRanges, nOfRange);

	myRanges[nOfRange - 1].End -= 0x1000;

	if (physmem_object_header)
		patch(true);

	if (physmem_object_header != NULL)
		cout << "Patched cached address." << endl;

	if (physmem_object_header == NULL)
	{
		IoCommand myIo = { 0 };
		myIo.offset = 0x0;

		myIo.read.QuadPart = 0x2000;

		bool bFound = false;
		if (DriverMapMemory(sDriver, &myIo)) {

			auto i = 0ULL;
			for (i = 0; i < myRanges[nOfRange - 1].End; i += 0x1000) {
				if (bFound) {
					DriverUnmapMemory(sDriver, &myIo);
					break;
				}
				if (!isInsidePhysicalRAM(i, myRanges, nOfRange))
					continue;
				if (!isPoolPage(i, pfnTable))
					continue;
				if (!DriverUnmapMemory(sDriver, &myIo))
					break;
				myIo.offset = i;
				if (!DriverMapMemory(sDriver, &myIo))
					break;
				uint8_t* lpCursor = (uint8_t*)(myIo.virtualmemory);
				uint32_t previousSize = 0;

				while (true) {
					auto pPoolHeader = (PPOOL_HEADER)lpCursor;
					auto blockSize = (pPoolHeader->BlockSize << 4);
					auto previousBlockSize = (pPoolHeader->PreviousSize << 4);

					if (previousBlockSize != previousSize ||
						blockSize == 0 ||
						blockSize >= 0xFFF ||
						!isThisPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF))
						break;

					previousSize = blockSize;

					if (0x74636553 == pPoolHeader->PoolTag & 0x7FFFFFFF) {
						auto pObjectHeader = (POBJECT_HEADER)(lpCursor + 0x30);
						if (pObjectHeader->HandleCount >= 0 && pObjectHeader->HandleCount <= 3 && pObjectHeader->KernelObject == 1 && pObjectHeader->Flags == 0x16 && pObjectHeader->KernelOnlyAccess == 1)
						{
							printf("Header at %p\n", lpCursor += 0x30);

							physmem_object_header = i + ((uint64_t)lpCursor - (uint64_t)myIo.virtualmemory);
							cache_objhdr_address(physmem_object_header);

							pObjectHeader->KernelObject = 0;
							pObjectHeader->KernelOnlyAccess = 0;
							bFound = true;
							break;
						}
					}

					lpCursor += blockSize;
					if ((lpCursor - ((uint8_t*)myIo.virtualmemory)) >= 0x1000)
						break;

				}
			}
		}

		if (!bFound) {
			printf("Already Running...\n", myIo.offset);

		}

		CloseDriver(sDriver);
		if (!ChangeSecurityDescriptorPhysicalMemory()) {
			printf("Failed...\n");
			system("pause");
			return 0;
		}
	}

	system("pause"); /* Press a key after opening ryuzaki */

	system("pause"); /* Press a key after opening ryuzaki */

	try
	{
		RestoreSecurityDescriptorPhysicalMemory();

		if (physmem_object_header)
			patch(false);

		CloseDriver(sDriver);
	}
	catch (const std::exception& ex)
	{

	}

	return 0;
}


extern "C"
{
	__declspec(dllexport) RyuInfuser* GetInfuser()
	{
		return new RyuInfuser();
	}
}

extern "C"
{
	__declspec(dllexport) int InfuseMe(RyuInfuser* infuser)
	{
		if (infuser != NULL)
		{
			return infuser->InfuseMeDaddyKong();
		}

		return 0;
	}
}