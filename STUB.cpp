#include <cstdint>
#include "Resolver.hpp"

#define ZYAN_NO_LIBC
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#ifdef __cplusplus
extern "C" {
#endif 
#include <Zydis/Zydis.h>
#ifdef __cplusplus
}
#endif

extern "C" intptr_t __RelocPatcher();
extern "C" intptr_t __GetKernel32BaseAdr();
extern "C" intptr_t __GetExportDirectoryTableRVA(intptr_t Kernel32dllBase);
extern "C" int64_t __STUBMAIN()
{
	__RelocPatcher();
	volatile intptr_t GetProcAddressRVAResolved = 0, LibraryARVAResolved = 0; // localrva+krnlbase
	volatile intptr_t K32dllBase = __GetKernel32BaseAdr();
	volatile intptr_t ExportTableRVA = __GetExportDirectoryTableRVA(K32dllBase);
	STUBResolver::ExportDirectoryTable STUBexprdrtable;
	STUBResolver::InitExportDirectoryTable(ExportTableRVA, STUBexprdrtable);
	volatile intptr_t GtProcLocalRVA = STUBResolver::CalcGetProcAddressRVA(K32dllBase, STUBexprdrtable);
	volatile intptr_t LibraryALocalRVA = STUBResolver::CalcLoadLibraryARVA(K32dllBase, STUBexprdrtable);


	GetProcAddressRVAResolved = K32dllBase + GtProcLocalRVA;
	LibraryARVAResolved = K32dllBase + LibraryALocalRVA;

	//Init global header values so we can use them in other calculations
	//Used assembly because compiler refusedto do the thing that I wanted
	STUBResolver::__Init64bitVar((uint64_t)&STUBResolver::LoadLibraryRVA, LibraryARVAResolved);
	STUBResolver::__Init64bitVar((uint64_t)&STUBResolver::GetProcAddressRVA, GetProcAddressRVAResolved);

	/*
	HMODULE User32DLLlModule = STUBResolver::STUBLoadLibraryA("User32.dll");
	volatile FARPROC Adr = STUBResolver::STUBGetProcAddress(User32DLLlModule, "MessageBoxA");

	typedef int8_t FakMsgFunc(HWND, LPCSTR, LPCSTR, UINT);
	FakMsgFunc* Fake = (FakMsgFunc*)static_cast<uint64_t>(Adr);
	return Fake(NULL, "Test", "Test", 0x00000000);
	*/

	int8_t Res;
	STUBResolver::CallFunctionWithADR("User32.dll", "MessageBoxA", &Res, NULL, "Test", "Test", 0x00000000);

	ZyanU8 data[] =
	{
		0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75,
		0x08, 0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F,
		0x88, 0xFC, 0xDA, 0x02, 0x00
	};


	// The runtime address (instruction pointer) was chosen arbitrarily here in order to better
	// visualize relative addressing. In your actual program, set this to e.g. the memory address
	// that the code being disassembled was read from.
	volatile ZyanU64 runtime_address = 0x007FFFFFFF400000;

	// Loop over the instructions in our buffer.
	volatile ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;


	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, data, 15, &instruction);

	while (offset != sizeof(data))
	{
		ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, data + offset, sizeof(data) - offset, &instruction);
		offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}

	/*
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		data + offset,
		sizeof(data) - offset,
		&instruction
	))) {
		printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
		offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}
	*/

	STUBResolver::DecryptionCounter();


	return 0;
}