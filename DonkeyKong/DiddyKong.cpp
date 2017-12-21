#include "DiddyKong.h"
#include "MAP.h"
#include "Superfetch.h"


DiddyKong::DiddyKong()
{
	// get system version

	// win7
	auto version = getWinVersion();
	switch (version) {
	case WINDOWS7:

		EPNameOffset = 0x2D8;
		EPPidOffset = 0x180;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x270;
		EPLinkOffset = 0x188;
		break;
	case WINDOWS8:

		EPNameOffset = 0x438;
		EPPidOffset = 0x2E0;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x3B0;
		EPLinkOffset = 0x2E8;
		break;
	case WINDOWS81:

		EPNameOffset = 0x438;
		EPPidOffset = 0x2E0;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x3B0;
		EPLinkOffset = 0x2E8;
		break;
	case WINDOWS10:

		EPNameOffset = 0x450;
		EPPidOffset = 0x02E0;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x03C0;
		EPLinkOffset = 0x02E8;
		break;
	default:

		EPNameOffset = 0x450;
		EPPidOffset = 0x02E0;
		EPDirBaseOffset = 0x0028;
		EPBaseOffset = 0x03C0;
		EPLinkOffset = 0x02E8;
		break;
	}
	SFSetup();
	SFGetMemoryInfo(mMemInfo, mInfoCount);

	mPMemHandle = OpenPhysicalMemory();

	mMemInfo[mInfoCount - 1].End -= 0x1000;
	mMemInfo[mInfoCount - 1].Size -= 0x1000;

	uint8_t* startScan = 0;

	MapPhysicalMemory(mPMemHandle, (PDWORD64)&startScan, &mMemInfo[mInfoCount - 1].End, (PDWORD64)&ramImage);
	CloseHandle(mPMemHandle);
}

DiddyKong::~DiddyKong()
{
	UnMapMemory((PDWORD64)ramImage);
}

bool DiddyKong::Skim(uint64_t address, uint8_t* buffer, int size)
{
	for (int i = 0; i < mInfoCount; i++)
	{
		if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
		{
			memcpy(buffer, (void*)(ramImage + address), size);
			return true;
		}
	}
	return false;
}

bool DiddyKong::Inscribe(uint64_t address, uint8_t* buffer, int size)
{
	for (int i = 0; i < mInfoCount; i++)
	{
		if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
		{
			memcpy((void*)(ramImage + address), buffer, size);
			return true;
		}
	}
	return false;
}

bool DiddyKong::SkimVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
{
	auto paddress = ConvertAddress(dirbase, address);
	return Skim(paddress, buffer, size);
}

bool DiddyKong::InscribeVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
{
	auto paddress = ConvertAddress(dirbase, address);
	return Inscribe(paddress, buffer, size);
}

uint64_t DiddyKong::GetProcessSupport(int pid)
{
	uint64_t base = 0;
	SkimVirtual(GetKernelDirSupport(), FiEP(pid) + EPBaseOffset, (uint8_t*)&base, sizeof(base));
	return base;
}

uint64_t DiddyKong::GetDirSupport(int pid)
{
	uint64_t cr3 = 0;
	if (SkimVirtual(GetKernelDirSupport(), FiEP(pid) + EPDirBaseOffset, (uint8_t*)&cr3, sizeof(cr3)))
		return cr3;
	return 0;
}

uint64_t DiddyKong::GetKernelDirSupport()
{
	if (mKernelDir != 0)
		return mKernelDir;

	auto result = ScanPoolTag((char*)"Proc", [&](uint64_t address) -> bool
	{
		uint64_t peprocess;
		char buffer[0xFFFF];
		if (!Skim(address, (uint8_t*)buffer, sizeof(buffer)))
			return false;
		for (char* ptr = buffer; (uint64_t)ptr - (uint64_t)buffer <= sizeof(buffer); ptr++)
			if (!strcmp(ptr, "System"))
				peprocess = address + (uint64_t)ptr - (uint64_t)buffer - EPNameOffset;

		uint64_t pid = 0;
		if (!Skim(peprocess + EPPidOffset, (uint8_t*)&pid, sizeof(pid)))
			return false;

		if (pid == 4)
		{
			if (!Skim(peprocess + EPDirBaseOffset, (uint8_t*)&mKernelDir, sizeof(mKernelDir)))
				return false;
			if (peprocess == ConvertAddress(mKernelDir, SFGetEProcess(4))) {
				return true;
			}
		}
		return false;
	});

	if (result)
		return mKernelDir;
	return 0;
}


extern "C"
{
	__declspec(dllexport) DiddyKong* GetMyHelper()
	{
		return new DiddyKong();
	}
}

extern "C"
{
	_declspec(dllexport) bool ReadMemVirtual(DiddyKong* helper, uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
	{
		if (helper != NULL)
		{
			return helper->SkimVirtual(dirbase, address, buffer, size);
		}
	}
}

extern "C"
{
	__declspec(dllexport)  uint64_t GetMyProcessBase(DiddyKong* helper, int pid)
	{
		if (helper != NULL)
		{
			return helper->GetProcessSupport(pid);
		}
	}
}

extern "C"
{
	__declspec(dllexport)  uint64_t GetMyDirBase(DiddyKong* helper, int pid)
	{
		if (helper != NULL)
		{
			return helper->GetDirSupport(pid);
		}
	}
}