#ifndef PE_STUB_RESOLVER
#define	PE_STUB_RESOLVER

#define _AMD64_
#include <cstdint>
#include <basetsd.h>
#include <windef.h>
#include <winnt.h>
#include <windows.h>



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


namespace STUBResolver {

	//Global values
	volatile inline intptr_t LoadLibraryRVA = 0;
	volatile inline intptr_t GetProcAddressRVA = 0;

	template<typename T, typename ... A>
	using Invoker = T(A...);

	volatile struct ExportDirectoryTable {
		uint32_t ExportFlags = 0;
		uint32_t TimeDateStamp = 0;
		uint16_t MajorVersion = 0;
		uint16_t MinorVersion = 0;
		intptr_t NameRVA = NULL;
		uint32_t OrdinalBase = 0;
		uint32_t NumberOfAddressTableEntries = 0;
		uint32_t NumberOfNamePointers = 0;
		intptr_t ExportAddressTableRVA = NULL;
		intptr_t NamePointerRVA = NULL;
		intptr_t OrdinalTableRVA = NULL;
	};
	extern "C" uint8_t __Read1Bytes(intptr_t RVA);
	extern "C" uint16_t __Read2Bytes(intptr_t RVA);
	extern "C" uint32_t __Read4Bytes(intptr_t RVA);
	extern "C" uint64_t __Read8Bytes(intptr_t RVA);
	extern "C" void __Init64bitVar(uint64_t VarAdr, uint64_t Value);
	int8_t InitExportDirectoryTable(intptr_t RVA, ExportDirectoryTable& ExprDrTbl);
	intptr_t CalcGetProcAddressRVA(intptr_t Krnl32Base,ExportDirectoryTable& ExprDrTbl);
	intptr_t CalcLoadLibraryARVA(intptr_t Krnl32Base, ExportDirectoryTable& ExprDrTbl);
	HMODULE STUBLoadLibraryA(LPCSTR lpLibFileName);
	FARPROC STUBGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
	//For functions that do not return void
	template<typename T, typename ...A>
	bool CallFunctionWithADR(const char* DLLName, const char* ModuleName, T* ResStruct, const A ...Args)
	{
		HMODULE User32DLLlModule = STUBResolver::STUBLoadLibraryA(DLLName);
		FARPROC Adr = STUBResolver::STUBGetProcAddress(User32DLLlModule, ModuleName);
		auto* FuncPtr = reinterpret_cast<Invoker<T, A...>*>(Adr);
		*ResStruct = FuncPtr(Args...);
		return true;
	}
	//For functions that return void
	template<typename ...A>
	bool VoidCallVoidFunctionWithADR(const char* DLLName, const char* ModuleName, const A ...Args)
	{
		HMODULE User32DLLlModule = STUBResolver::STUBLoadLibraryA(DLLName);
		FARPROC Adr = STUBResolver::STUBGetProcAddress(User32DLLlModule, ModuleName);
		auto* FuncPtr = reinterpret_cast<Invoker<A...>*>(Adr);
		return true;
	}
	//MSDN functions to resolve
	extern "C" 
	{
		void __imp_RtlCaptureContext(PCONTEXT ContextRecord);
		PRUNTIME_FUNCTION __imp_RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);
		PEXCEPTION_ROUTINE __imp_RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc, PRUNTIME_FUNCTION  FunctionEntry, PCONTEXT ContextRecord, PVOID * HandlerData, PDWORD64   EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers);
		LONG __imp_UnhandledExceptionFilter(_EXCEPTION_POINTERS * ExceptionInfo);
		LPTOP_LEVEL_EXCEPTION_FILTER __imp_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
		HANDLE __imp_GetCurrentProcess();
		BOOL __imp_TerminateProcess(HANDLE hProcess, UINT uExitCode);
		BOOL __imp_IsProcessorFeaturePresent(DWORD ProcessorFeature);
		void* memset(void* dest, int c, size_t count);
		void* memcpy(void* dest, const void* src, size_t count);
		int64_t __GSHandlerCheck(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord, _DISPATCHER_CONTEXT* DispatcherContext);
		void __security_check_cookie(uintptr_t StackCookie);
		HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
		BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
		DWORD GetLastError();

		uint64_t __security_cookie();

	}

	//Decryption and instruction counter, this functionn read bytes from allocated virtual memory
	// in runtime xor the bytes with 0x32 and then count all the xor instruction then print number
	// of xors in a message box.
	extern "C" intptr_t __GetCurrentPEVRBase();
	void DecryptionCounter();
	
}

#endif