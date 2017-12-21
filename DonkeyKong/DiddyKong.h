
#include <Windows.h>
#include <stdint.h>
#include <functional>
#include "Superfetch.h"
#include "GetWindowsVersion.h"
#include "MAP.h"

class DiddyKong
{
public:
	DiddyKong();

	~DiddyKong();

	bool Skim(uint64_t address, uint8_t* buffer, int size);

	bool Inscribe(uint64_t address, uint8_t* buffer, int size);

	bool SkimVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size);

	bool InscribeVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size);

	uint64_t GetProcessSupport(int pid);

	uint64_t GetDirSupport(int pid);

	uint64_t GetKernelDirSupport();

private:
	uint64_t EPNameOffset = 0;
	uint64_t EPPidOffset = 0;
	uint64_t EPDirBaseOffset = 0;
	uint64_t EPBaseOffset = 0;
	uint64_t EPLinkOffset = 0;

	uint8_t *ramImage = 0;
	HANDLE mPMemHandle;
	SFMemoryInfo mMemInfo[32];
	int mInfoCount = 0;

	uint64_t mKernelDir = 0;

	int isPrintable(uint32_t uint32)
	{
		if ((isAscii((uint32 >> 24) & 0xFF)) && (isAscii((uint32 >> 16) & 0xFF)) && (isAscii((uint32 >> 8) & 0xFF)) &&
			(isAscii((uint32) & 0xFF)))
			return true;
		else
			return false;
	}

	int isAscii(int c)
	{
		return((c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') || c == 0x20 || c == '@' || c == '_' || c == '?');
	}

	bool isInRam(uint64_t address, uint32_t len) {
		for (int j = 0; j < mInfoCount; j++)
			if ((mMemInfo[j].Start <= address) && ((address + len) <= mMemInfo[j].End))
				return true;
		return false;
	}

	bool ScanPoolTag(char* tag_char, std::function<bool(uint64_t)> scan_callback)
	{
		uint32_t tag = (
			tag_char[0] |
			tag_char[1] << 8 |
			tag_char[2] << 16 |
			tag_char[3] << 24
			);


		for (auto i = 0ULL; i< mMemInfo[mInfoCount - 1].End; i += 0x1000) {
			if (!isInRam(i, 0x1000))
				continue;


			uint8_t* lpCursor = ramImage + i;
			uint32_t previousSize = 0;
			while (true) {
				auto pPoolHeader = (PPOOL_HEADER)lpCursor;
				auto blockSize = (pPoolHeader->BlockSize << 4);
				auto previousBlockSize = (pPoolHeader->PreviousSize << 4);

				if (previousBlockSize != previousSize ||
					blockSize == 0 ||
					blockSize >= 0xFFF ||
					!isPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF))
					break;

				previousSize = blockSize;

				if (tag == pPoolHeader->PoolTag & 0x7FFFFFFF)
					if (scan_callback((uint64_t)(lpCursor - ramImage)))
						return true;
				lpCursor += blockSize;
				if ((lpCursor - (ramImage + i)) >= 0x1000)
					break;

			}
		}

		return false;
	}

	uint64_t FiEP(int pid)
	{
		_LIST_ENTRY ActiveProcessLinks;
		SkimVirtual(GetKernelDirSupport(), SFGetEProcess(4) + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks));

		while (true)
		{
			uint64_t next_pid = 0;
			uint64_t next_link = (uint64_t)(ActiveProcessLinks.Flink);
			uint64_t next = next_link - EPLinkOffset;
			SkimVirtual(GetKernelDirSupport(), next + EPPidOffset, (uint8_t*)&next_pid, sizeof(next_pid));
			SkimVirtual(GetKernelDirSupport(), next + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks));
			if (next_pid == pid)
				return next;
			if (next_pid == 4)
				return 0;
		}

		return 0;
	}

	uint64_t ConvertAddress(uint64_t directoryTableBase, uint64_t virtualAddress)
	{
		uint16_t PML4 = (uint16_t)((virtualAddress >> 39) & 0x1FF);         //<! PML4 Entry Index
		uint16_t DirectoryPtr = (uint16_t)((virtualAddress >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
		uint16_t Directory = (uint16_t)((virtualAddress >> 21) & 0x1FF);    //<! Page Directory Table Index
		uint16_t Table = (uint16_t)((virtualAddress >> 12) & 0x1FF);        //<! Page Table Index

																			// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
																			// It can be read from the CR3 register or from the kernel process object.
		uint64_t PML4E = 0;// ReadPhysicalAddress<ulong>(directoryTableBase + (ulong)PML4 * sizeof(ulong));
		Skim(directoryTableBase + (uint64_t)PML4 * sizeof(uint64_t), (uint8_t*)&PML4E, sizeof(PML4E));

		if (PML4E == 0)
			return 0;

		// The PML4E that we read is the base address of the next table on the chain,
		// the Page-Directory-Pointer Table.
		uint64_t PDPTE = 0;// ReadPhysicalAddress<ulong>((PML4E & 0xFFFF1FFFFFF000) + (ulong)DirectoryPtr * sizeof(ulong));
		Skim((PML4E & 0xFFFF1FFFFFF000) + (uint64_t)DirectoryPtr * sizeof(uint64_t), (uint8_t*)&PDPTE, sizeof(PDPTE));

		if (PDPTE == 0)
			return 0;

		//Check the PS bit
		if ((PDPTE & (1 << 7)) != 0)
		{
			// If the PDPTE¨s PS flag is 1, the PDPTE maps a 1-GByte page. The
			// final physical address is computed as follows:
			// ！ Bits 51:30 are from the PDPTE.
			// ！ Bits 29:0 are from the original va address.
			return (PDPTE & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
		}

		// PS bit was 0. That means that the PDPTE references the next table
		// on the chain, the Page Directory Table. Read it.
		uint64_t PDE = 0;// ReadPhysicalAddress<ulong>((PDPTE & 0xFFFFFFFFFF000) + (ulong)Directory * sizeof(ulong));
		Skim((PDPTE & 0xFFFFFFFFFF000) + (uint64_t)Directory * sizeof(uint64_t), (uint8_t*)&PDE, sizeof(PDE));

		if (PDE == 0)
			return 0;

		if ((PDE & (1 << 7)) != 0)
		{
			// If the PDE¨s PS flag is 1, the PDE maps a 2-MByte page. The
			// final physical address is computed as follows:
			// ！ Bits 51:21 are from the PDE.
			// ！ Bits 20:0 are from the original va address.
			return (PDE & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
		}

		// PS bit was 0. That means that the PDE references a Page Table.
		uint64_t PTE = 0;// ReadPhysicalAddress<ulong>((PDE & 0xFFFFFFFFFF000) + (ulong)Table * sizeof(ulong));
		Skim((PDE & 0xFFFFFFFFFF000) + (uint64_t)Table * sizeof(uint64_t), (uint8_t*)&PTE, sizeof(PTE));

		if (PTE == 0)
			return 0;

		// The PTE maps a 4-KByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:12 are from the PTE.
		// ！ Bits 11:0 are from the original va address.
		return (PTE & 0xFFFFFFFFFF000) + (virtualAddress & 0xFFF);
	}
};

