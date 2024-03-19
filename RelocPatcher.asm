.code
;trying to use volatile registers only
;if we are going to use non volatile registers we save their values by push and then retrvie it by pop
;no use of variables because it make our code base dependent, instead we use stack frames to store values
; volatile registers: RAX, RCX, RDX, R8, R9, R10, R11
	__RelocPatcher	proc

	;Create new stack fram
	push rbp
	mov rbp,rsp
	sub rsp,200h ;memory alocation for local variables that we need to keep in stack
	xor rax,rax


	;local variables
	mov [rbp - 8h],rax; PE virtual base
	mov [rbp - 10h],rax; elf_anew virtual base
	mov [rbp - 18h],rax; size of optional header
	mov [rbp - 20h],rax; offset of section headers
	mov [rbp - 28h],rax; number of sections
	mov [rbp - 30h],rax; virtual address of STUB section (called .text during dev)
	mov [rbp - 38h],rax; virtual address of SRlc section (called .reloc during dev)
	mov [rbp - 40h],rax; virtual size of SRlc section (called .reloc during dev)
	mov [rbp - 48h],rax; difference between desired location and loaded location


	;get PE base so we can parse its data to find .reloc and .text data and patch .text
	mov rax, gs:[60h] ; Put PEB location in rax
	mov rax, [rax+18h] ; Put Ldr location in rax (Notice that PEB struct differs for 64 bit OS, it is in the remark part of MSDN PEB document)
	mov rax, [rax+20h] ; Put InMemoryOrderModuleList location in rax
	mov rax, [rax + 30h - 10h] ; get current PE virtual base (Do not forgot size of two PVOIDs)
	mov [rbp - 08h],rax; store it as variable

	;get elf_anew and save it
	xor rcx,rcx
	mov cl,[rax + 3ch]
	mov [rbp - 10h],rcx

	;move to the NtHeader to get size of optional header
	add rax,rcx
	xor rcx,rcx
	mov cl,[rax + 14h]; Size of optional header
	mov [rbp - 18h],cl; save it as variable

	;Get Numberofsections
	xor rcx,rcx
	mov cl,[rax + 6h]
	mov [rbp - 28h],rcx

	;move to section headers
	add rax,18h; size of data in PE
	add rax,[rbp - 18h]
	mov [rbp - 20h],rax; save offset as variable



	mov rcx,[rbp - 28h]; get number of sections as index in rcx register
	;find .STUB section offset
	FindSTUBSection:
	xor r8,r8
	mov r8b,[rax]
	cmp r8b,2eh; 2eh = .
	jne Nextsection
	mov r8b,[rax + 1h]
	cmp r8b,53h; 53h = S
	jne Nextsection
	mov r8b,[rax + 2h]
	cmp r8b,54h; 54h = T
	jne Nextsection
	mov r8b,[rax + 3h]
	cmp r8b,55h; 55h = U
	jne Nextsection
	mov r8b,[rax + 4h]
	cmp r8b,42h; 42h = B
	jne Nextsection
	jmp STUBSectionFound; if section found we will reach here (clearly we should check untill NULL termination I just kept it simple)

	Nextsection:
	cmp rcx,0
	je ErrorNoSTUBSection
	dec rcx; one section header checked move to next
	add rax,28h
	jmp FindSTUBSection

	ErrorNoSTUBSection:
	hlt

	;store .text section data
	STUBSectionFound:
	mov ecx,[rax + 0ch]
	mov [rbp - 30h],rcx


	mov rcx,[rbp - 28h]; get number of sections as index in rcx register
	FindSTUBRelocSection:
	xor r8,r8
	mov r8b,[rax]
	cmp r8b,2eh; 2eh = .
	jne Nextsection_a
	mov r8b,[rax + 1h]
	cmp r8b,52h; 52h = R
	jne Nextsection_a
	mov r8b,[rax + 2h]
	cmp r8b,4ch; 4ch = L
	jne Nextsection_a
	mov r8b,[rax + 3h]
	cmp r8b,43h; 43h = C
	jne Nextsection_a
	mov r8b,[rax + 4h]
	cmp r8b,53h; 53h = S
	jne Nextsection_a
	mov r8b,[rax + 5h]
	cmp r8b,54h; 54h = T
	jne Nextsection_a
	jmp RelocSectionFound; if section found we will reach here (clearly we should check untill NULL termination I just kept it simple)

	Nextsection_a:
	cmp rcx,0
	je ErrorNoSTUBSection
	dec rcx; one section header checked move to next
	add rax,28h
	jmp FindSTUBRelocSection


	RelocSectionFound:
	mov ecx,[rax + 0ch]
	mov [rbp - 38h],rcx; virtual address
	mov ecx,[rax + 8h]
	mov [rbp - 40h],rcx; virtual size



	;the amount of difference that we should add depend on the offset that STUB compiled with
	;in our case this is ImageBase = 0x140000000 in SimpleSTUB.exe so we have to find the difference between ImageBase that PE loaded
	;and the ImageBase of STUB, But also keep in mind linker assumed .text section will be in 0x1000 virtual address
	;but when we added our stub as new section this is changed so we need to also add the diference of original VR and added VR
	;(the new VR when you add section in CFF)
	mov rax,[rbp - 8h]
	mov r10,140000000h; Check inside your compiled STUB to find images base
	sub rax,r10
	cmp rax,0
	je	PatchEnd; we loaded in desired location no need for patch
	mov [rbp - 48h],rax

	;mov rax,2000h; fake instruction for testing purpose
	;mov [rbp - 48h],rax; fake instruction for testing purpose


	;move to the reloc section data
	mov rax,[rbp - 8h]
	add rax,[rbp - 38h]


	;Start patching
	push r12; save volatile register value
	mov r10,rax
	add r10,[rbp - 40h]; r10 contains end of relocation section address
	RelocPatch_BlockHeadInit:
	mov r12d,[rax]; Page RVA
	mov r8d,[rax + 4h]; Block Size (include the Page RVA + Block Size)
	mov r9,rax
	add r9,r8; r9 contain end location of relocation block
	mov rdx,rax
	add rdx, 8h; rdx is iterator index over block entries

	RelocPatch_BlockEntriesParse:
	;patch bytes
	mov r11w,[rdx]; move entries in to r11 register for processing
	and r11,0fffh
	add r11,r12
	sub r11,1000h; 0x1000 is the compiled RVA of STUB
	add r11,[rbp - 8h]
	add r11,[rbp - 30h]; location of bytes that should be patched in memory (imagebase + NewSTUBRVA - OldSTUBRVA + HardOffsetofBytes)

	push rax
	mov rax,[rbp - 48h]
	add [r11],rax
	mov rax,[rbp - 30h]
	sub rax,1000h
	add [r11],rax; we moved section as well we need to consider that aswell (NewImageBase - OriginalImageBase + NewSTUBRVA - OriginalSTUBRVA)
	pop rax


	add rdx,2h; move to next entry
	cmp rdx,r9; check if we reached end of block
	jne RelocPatch_BlockEntriesParse
	jmp RelocPatch_NextBlockProc


	RelocPatch_NextBlockProc:
	cmp r9,r10; check if we reached end of section
	je PatchEnd
	mov rax,r9; otherwise move to next block and apply patches accordingly
	jmp RelocPatch_BlockHeadInit
	
	PatchEnd:

	;restore stack as it was before getting inside this function
	pop r12; restore volatile register value
	add rsp,200h
	pop rbp

	ret
	__RelocPatcher endp

end