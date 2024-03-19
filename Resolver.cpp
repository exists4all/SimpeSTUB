#include "Resolver.hpp"


namespace STUBResolver {


	int8_t InitExportDirectoryTable(intptr_t RVA, ExportDirectoryTable& ExprDrTbl)
	{
		ExprDrTbl.ExportFlags = __Read4Bytes(RVA);
		ExprDrTbl.TimeDateStamp = __Read4Bytes(RVA + 4);
		ExprDrTbl.MajorVersion = __Read2Bytes(RVA + 8);
		ExprDrTbl.MinorVersion = __Read2Bytes(RVA + 10);
		ExprDrTbl.NameRVA = __Read4Bytes(RVA + 12);
		ExprDrTbl.OrdinalBase = __Read4Bytes(RVA + 16);
		ExprDrTbl.NumberOfAddressTableEntries = __Read4Bytes(RVA + 20);
		ExprDrTbl.NumberOfNamePointers = __Read4Bytes(RVA + 24);
		ExprDrTbl.ExportAddressTableRVA = __Read4Bytes(RVA + 28);
		ExprDrTbl.NamePointerRVA = __Read4Bytes(RVA + 32);
		ExprDrTbl.OrdinalTableRVA = __Read4Bytes(RVA + 36);
		return 0;
	}
	intptr_t CalcGetProcAddressRVA(intptr_t Krnl32Base, ExportDirectoryTable& ExprDrTbl)
	{
		char FunName[] = "GetProcAddress";
		volatile intptr_t Ptr = 0;
		for (uint32_t i = 0; i < ExprDrTbl.NumberOfAddressTableEntries; i++)
		{
			Ptr = __Read4Bytes(Krnl32Base + ExprDrTbl.NamePointerRVA + 4 * i);
			volatile bool IsFound = true;
			volatile uint8_t Index = *(uint8_t*)(Krnl32Base + Ptr);
			for (uint8_t j = 0; Index != '\0'; j++)
			{
				Index = *(uint8_t*)(Krnl32Base + Ptr + j);
				if ((char)Index != FunName[j])
				{
					IsFound = false;
					break;
				}
			}
			if (IsFound == true)
				return __Read4Bytes(i * 4 + Krnl32Base + ExprDrTbl.ExportAddressTableRVA);
		}
		return 0;
	}
	intptr_t CalcLoadLibraryARVA(intptr_t Krnl32Base, ExportDirectoryTable& ExprDrTbl)
	{
		char FunName[] = "LoadLibraryA";
		volatile intptr_t Ptr = 0;
		for (uint32_t i = 0; i < ExprDrTbl.NumberOfAddressTableEntries; i++)
		{
			Ptr = __Read4Bytes(Krnl32Base + ExprDrTbl.NamePointerRVA + 4 * i);
			volatile bool IsFound = true;
			volatile uint8_t Index = *(uint8_t*)(Krnl32Base + Ptr);
			for (uint8_t j = 0; Index != '\0'; j++)
			{
				Index = *(uint8_t*)(Krnl32Base + Ptr + j);
				if ((char)Index != FunName[j])
				{
					IsFound = false;
					break;
				}
			}
			if (IsFound == true)
				return __Read4Bytes(i * 4 + Krnl32Base + ExprDrTbl.ExportAddressTableRVA);
		}
		return 0;
	}
	HMODULE STUBLoadLibraryA(LPCSTR lpLibFileName)
	{
		typedef HMODULE func(LPCSTR);
		func* FuncPtr = (func*)static_cast<uint64_t>(LoadLibraryRVA);
		return FuncPtr(lpLibFileName);
	}
	FARPROC STUBGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
	{
		typedef FARPROC func(HMODULE, LPCSTR);
		func* FuncPtr = (func*)static_cast<uint64_t>(GetProcAddressRVA);
		return FuncPtr(hModule, lpProcName);
	}


	//MSDN functions to resolve
	extern "C"
	{
		/*
		void __imp_RtlCaptureContext(PCONTEXT ContextRecord)
		{
			STUBResolver::VoidCallVoidFunctionWithADR("vcruntime140_1.dll", "__security_check_cookie", ContextRecord);
		}
		*/
		PRUNTIME_FUNCTION __imp_RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable)
		{
			PRUNTIME_FUNCTION Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "RtlLookupFunctionEntry", &Out, ControlPc, ImageBase, HistoryTable);
			return Out;
		}
		PEXCEPTION_ROUTINE __imp_RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc, PRUNTIME_FUNCTION  FunctionEntry, PCONTEXT ContextRecord, PVOID* HandlerData, PDWORD64   EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
		{
			PEXCEPTION_ROUTINE Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "RtlVirtualUnwind", &Out, HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData, EstablisherFrame, ContextPointers);
			return Out;
		}
		LONG __imp_UnhandledExceptionFilter(_EXCEPTION_POINTERS* ExceptionInfo)
		{
			LONG Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "UnhandledExceptionFilter", &Out, ExceptionInfo);
			return Out;
		}
		LPTOP_LEVEL_EXCEPTION_FILTER __imp_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
		{
			LPTOP_LEVEL_EXCEPTION_FILTER Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "SetUnhandledExceptionFilter", &Out, lpTopLevelExceptionFilter);
			return Out;
		}
		HANDLE __imp_GetCurrentProcess()
		{
			HANDLE Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "GetCurrentProcess", &Out);
			return Out;
		}
		BOOL __imp_TerminateProcess(HANDLE hProcess, UINT uExitCode)
		{
			BOOL Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "TerminateProcess", &Out, hProcess, uExitCode);
			return Out;
		}
		BOOL __imp_IsProcessorFeaturePresent(DWORD ProcessorFeature)
		{
			BOOL Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "IsProcessorFeaturePresent", &Out, ProcessorFeature);
			return Out;
		}

		void* memset(void* dest, int c, size_t count)
		{
			void* Out;
			STUBResolver::CallFunctionWithADR("VCRUNTIME140.dll", "memset", &Out, dest, c, count);
			return Out;
		}

		void* memcpy(void* dest, const void* src, size_t count)
		{
			void* Out;
			STUBResolver::CallFunctionWithADR("VCRUNTIME140.dll", "memcpy", &Out, dest, src, count);
			return Out;
		}

		int64_t __GSHandlerCheck(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord, _DISPATCHER_CONTEXT* DispatcherContext)
		{
			int64_t Out;
			STUBResolver::CallFunctionWithADR("VCRUNTIME140.dll", "__GSHandlerCheck", &Out, ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
			return Out;
		}

		void __security_check_cookie(uintptr_t StackCookie)
		{
			STUBResolver::VoidCallVoidFunctionWithADR("VCRUNTIME140.dll", "__security_check_cookie", StackCookie);
		}

		uint64_t __security_cookie()
		{
			return 0x123456;
		}

		HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
		{
			HANDLE Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "CreateFileA", &Out, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			return Out;
		}

		BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
		{
			BOOL Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "WriteFile", &Out, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
			return Out;
		}

		DWORD GetLastError()
		{
			DWORD Out;
			STUBResolver::CallFunctionWithADR("kernel32.dll", "GetLastError", &Out);
			return Out;
		}

	}


	void DecryptionCounter()
	{
		volatile intptr_t CurrentPECRBase = __GetCurrentPEVRBase();
		volatile PIMAGE_DOS_HEADER PDOSHeader = (PIMAGE_DOS_HEADER)CurrentPECRBase;
		volatile PIMAGE_NT_HEADERS PNTHeader = (PIMAGE_NT_HEADERS)((u_char*)PDOSHeader + PDOSHeader->e_lfanew);
		volatile PIMAGE_DATA_DIRECTORY PDataDirectory[16];
		for (unsigned int i = 0; i < 16; i++)
		{
			PDataDirectory[i] = (PIMAGE_DATA_DIRECTORY)((u_char*)PDOSHeader + PDOSHeader->e_lfanew + sizeof((PNTHeader->Signature)) + sizeof((PNTHeader->FileHeader)) + 112 + i * 8);
		}
		volatile PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((u_char*)PDOSHeader + PDOSHeader->e_lfanew + sizeof((PNTHeader->Signature)) + sizeof((PNTHeader->FileHeader)) + PNTHeader->FileHeader.SizeOfOptionalHeader);
		volatile PIMAGE_SECTION_HEADER SectionHeaders[16]{};
		for (unsigned int i = 0; i < PNTHeader->FileHeader.NumberOfSections; i++)
		{
			SectionHeaders[i] = SectionHeader;
			SectionHeader++;
		}
		volatile intptr_t textSectionRVA = 0;
		volatile int8_t textSectionIndex = 0;
		BYTE text[8] = { 0x2e,0x74,0x65,0x78,0x74 };
		for (unsigned int i = 0; i < PNTHeader->FileHeader.NumberOfSections; i++)
		{
			volatile bool IsFound = true;
			for (uint8_t j = 0; j < 5; j++)
			{
				if (SectionHeaders[i]->Name[j] != text[j])
				{
					IsFound = false;
					break;
				}
			}

			if (IsFound == true)
			{
				textSectionRVA = SectionHeaders[i]->VirtualAddress;
				textSectionIndex = i;
				break;
			}
		}

		
		volatile uint8_t XORedByte = 0;
		if (SectionHeaders[textSectionIndex]->Characteristics == 0xE0000020)
		{
			for (uint64_t j = 0; j < SectionHeaders[textSectionIndex]->Misc.VirtualSize; j++)
			{
				XORedByte = *(uint8_t*)(CurrentPECRBase + textSectionRVA + j);
				XORedByte ^= 0x32;
				*(uint8_t*)(CurrentPECRBase + textSectionRVA + j) = XORedByte;
			}
		}
		else
			return;
			
		

		//ZyanU8* Data = (ZyanU8*)(CurrentPECRBase + PNTHeader->OptionalHeader.AddressOfEntryPoint);
		ZyanU8* Data = (ZyanU8*)(CurrentPECRBase + textSectionRVA);
		volatile ZyanUSize Offset = 0;
		ZydisDisassembledInstruction Instruction;
		int64_t NumberOfXORInstructions = 0;

		ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, Data + Offset, SectionHeaders[textSectionIndex]->Misc.VirtualSize - Offset, &Instruction);
		HANDLE hFile = nullptr;
		hFile = CreateFileA("I:\\Result.txt", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile, Instruction.text, 32, 0, NULL);

		/*
		while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, Data + Offset, SectionHeaders[textSectionIndex]->Misc.VirtualSize - Offset, &Instruction)))
		{
			bool IsFound = true;
			char LocalXORstr[] = "xor";
			if (Instruction.info.length == 3)
			{
				for (uint8_t x = 0; x < 3; x++)
				{
					if (LocalXORstr[x] != Instruction.text[x])
					{
						IsFound = false;
						break;
					}
				}
				if (IsFound == true)
					NumberOfXORInstructions++;
			}

			Offset += Instruction.info.length;

			if (Instruction.info.length == 0)
				break;

		}
		
		int8_t index = 0;
		char buf[16]{};
		while (NumberOfXORInstructions != 0)
		{
			buf[index] = (NumberOfXORInstructions % 10) + '0';
			NumberOfXORInstructions = NumberOfXORInstructions / 10;;
			index++;
		}
		
		
		HANDLE hFile = nullptr;
		hFile = CreateFileA("I:\\Result.txt", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		volatile DWORD pp = GetLastError();
		WriteFile(hFile, buf, 6, 0, NULL);
		*/


		return;
	}



}