.code
	__Read1Bytes proc
	xor rax,rax
	mov al,[rcx]
	ret
	__Read1Bytes endp

	__Read2Bytes proc
	xor rax,rax
	mov ax,[rcx]
	ret
	__Read2Bytes endp

	__Read4Bytes proc
	xor rax,rax
	mov eax,[rcx]
	ret
	__Read4Bytes endp

	__Read8Bytes proc
	xor rax,rax
	mov rax,[rcx]
	ret
	__Read8Bytes endp

	__Init64bitVar proc
	mov [rcx],rdx
	__Init64bitVar endp

	__GetKernel32BaseAdr proc
	mov rax, gs:[60h] ; Put PEB location in rax
	mov rax, [rax+18h] ; Put Ldr location in rax (Notice that PEB struct differs for 64 bit OS, it is in the remark part of MSDN PEB document)
	mov rax, [rax+20h] ; Put InMemoryOrderModuleList location in rax
	mov rax, [rax] ; move to ntdll data
	mov rax, [rax] ; move to kernel32 data
	mov rax, [rax + 30h - 10h] ; get kernel32 dllbase (Do not forgot size of two PVOIDs)
	ret
	__GetKernel32BaseAdr endp

	__GetExportDirectoryTableRVA proc
	xor rax,rax
	mov al,[rcx+3ch] ;put value of e_lfanew (1 byte) in to al register
	add rax,rcx ; Calculate virtual address of e_lfanew and put it in to rax
	add rax,88h ; 4 + 20 + 112 (PE sig + FileHeader + Standardfields of optional header for PE 64 bit)
	mov rax,[rax] ; Put export table directory (8 bytes) in rax
	xor rdx,rdx ; Use a volatile register
	mov edx,eax ; Extract virtual address of data directory from lower half of rax
	add rdx,rcx ; Add Base virtual memory
	mov rax,rdx ; Get Export Directory Table RVA
	ret
	__GetExportDirectoryTableRVA endp

	__GetCurrentPEVRBase proc
	mov rax, gs:[60h] ; Put PEB location in rax
	mov rax, [rax+18h] ; Put Ldr location in rax (Notice that PEB struct differs for 64 bit OS, it is in the remark part of MSDN PEB document)
	mov rax, [rax+20h] ; Put InMemoryOrderModuleList location in rax
	mov rax, [rax + 30h - 10h] ; get current PE virtual base (Do not forgot size of two PVOIDs)
	ret
	__GetCurrentPEVRBase endp

end