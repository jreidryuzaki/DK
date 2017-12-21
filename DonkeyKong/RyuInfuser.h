
#include <windows.h>
#include <winternl.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <stdint.h>
#include <stdio.h>
#include "ntdll.h"
#include "Superfetch.h"

HANDLE sDriver;
uint64_t physmem_object_header;
PfnList* pfnTable = nullptr;

class RyuInfuser
{
public:
	RyuInfuser();
	~RyuInfuser();

	int InfuseMeDaddyKong();
};


