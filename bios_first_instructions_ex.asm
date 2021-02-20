;microwave89-hv, 9/2016
;microwave89-hv, 2/2021
;SRC: https://www.onlinedisassembler.com/odaweb/Ex80S0qh/0
;++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;Prerequisites
;++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;How find earliest (Then statements valuable for blackhats likely haven't been removed from the manual yet) Intel SDM volumes for a particular processor?


;1.) Identify processor model number by "$ dmesg | grep CPU0" which leads for example to "Intel(R) Core(TM)2 Duo CPU     T9600", so number is "T9600".

;2.) Look up processor family in Wikipedia which leads to a page similar to "https://en.wikipedia.org/wiki/List_of_Intel_Core_2_microprocessors". Retrieve the release date for the model number, in this case it is "July 2008" based on the entry "Core 2 Duo T9600	SLB43 (C0)   SLGEM (E0)  2.8 GHz	6 MB	1066 MT/s	10.5×	1.050–1.162 V	35 W     FCBGA6    July 2008	AV80576GH0726M     $530".

;3.) Start searching the web for SDM volumes with (release date + 6 months) as you make sure your and earlier processors are covered: For the T9600 model search for "NetBurst" "Core" "Duo" "January 2009" filetype:pdf.

;4.) Always click on "repeat the search with the omitted results included." If you cannot find many titles containing "Vol", "Volume", "Intel", "Software", "Developer", "Manual", or "Programming" then decrease the month bias by one and repeat "3.)". For example neither "January 2009" nor "December 2008" give clear results but "November 2008" gives.

;5.) Check the first page of downloaded pdf for Order Numbers of further volumes from this set. If on first page there aren't references to minimum 2 further volumes download another pdf. If you can't find a suitable pdf after ~5 attempts decrease the month bias and repeat "3.)". In the example the first pdf was "Volume 3B" of Intel SDM with "November 2008" date, so everything is fine.

;6.) If you haven't downloaded the very first volume or volume part search for Order Number of the first volume referenced and plug the "revision number" in as well. The example document is "253669-029US" but the first volume is "253665". Enter "253665-029US" "NetBurst" "Duo" filetype:pdf.

;7.) If you know the model number search the pdf for the number series. For the Core 2 Duo CPU it is "T9...", possibly "T9000".

;8.) Keep decreasing the "revision number" while maintaining the first volume Order Number and an identifying CPU name or number until you cannot find any earlier pdfs covering your CPU. In the example the first search is "253665 028US" "NetBurst" "T9000" filetype:pdf which is from September 2008 and still covers the example CPU. Same holds true with 027US from April 2008. 026US and earlier haven't references to T9000.

;9.) Use the list of volumes in the set to search for missing Order Numbers with earliest "revision number" possible. Note that in the following parts the covered processors section may be missing. With the Core 2 Duo processor in this example enter "(Order Number) 027US" "NetBurst" filetype:pdf where (Order Number) can be read to 253665, 253666, 253667, 253668, or 253669.

;The found SDM parts or volumes with the smallest "revision number" make up to the earliest possible complete Intel "Software Developer's Manual" covering your processor. Feature descriptions later abused by blackhats and subsequently erased while they still might hold true for your processor model are likely to be unaffected.
;(Variation of search phrase: "intel" "june 2010" "volume 1" -"documentation changes" filetype:pdf)

;+++++Hence, the following analysis is based on 253665-027US, 253666-027US, and 253667-027US from April 2008 as well as 253668-027US and 253669-027US both from July 2008.+++++



;Initial GDT at 0xfffffe10, access not shown:
;0   0000 0000 00 00 00 00       base 00000000 segment limit 0
;8   ffff 0000 00 92 CF 00       base 00000000 segment limit ffffffff
;10  ffff 0000 00 9b cf 00       base 00000000 segment limit ffffffff
;18  ffff 0000 00 93 cf 00       base 00000000 segment limit ffffffff
;20  ffff 0000 00 9a cf 00       base 00000000 segment limit ffffffff
;28  ffff 0000 0f 9b 00 00       base 000f0000 segment limit ffffffff
;30  ffff 0000 00 93 00 00       base 00000000 segment limit ffffffff
;38  0000 0000 00 00 00 00       base 00000000 segment limit 0

;Index of Segment descriptor:
;(Bits 3 through 15) — Selects one of 8192 descriptors in the GDT or LDT. The processor multiplies the index value by 8 (the number of bytes in a segment descriptor) and adds the result to the base address of the GDT or LDT (from the GDTR or LDTR register, respectively). But what happens to bits 0-2???!! Bit 2 is Table indicator (0 --> GDT, 1 --> LDT), 1 and 0 is RPL (Requested Privilege Level, is it what privilege does code need to access the segment??)


Protected_switch_0xfffffad0_real32:
	mov ebp, eax                        ;0xfffffad0: 66 8b e8
	mov esi, 0xfffffe50                 ;0xfffffad3: 66 be 50 fe ff ff
	lgdt cs:[si]                        ;0xfffffad9: 66 2e 0f 01 14         (size = 0x3f at 0xfffffe50, location = 0xfffffe10 at 0xfffffe52, A better explanation follows. It was retrieved on 10/15/2016 from "http://www.osdever.net/bkerndev/Docs/gdt.htm" and is quoted without modification:
	;"To tell the processor where our new GDT table is, we use the assembly opcode 'lgdt'. 'lgdt' needs to be given a pointer to a special 48-bit structure. This special 48-bit structure is made up of 16-bits for the limit of the GDT (again, needed for protection so the processor can immediately create a General Protection Fault if we want a segment whose offset doesn't exist in the GDT), and 32-bits for the address of the GDT itself.")
	mov eax, cr0                        ;0xfffffade: 0f 20 c0
	or eax, 0x3                         ;0xfffffae1: 66 83 c8 03            (set bit 0 (protected mode enable) and 1 (Monitor co-processor(??)))
	mov cr0, eax                        ;0xfffffae5: 0f 22 c0
	mov eax, cr4                        ;0xfffffae8: 0f 20 e0
	or eax, 0x600                       ;0xfffffaeb: 66 0d 00 06 00 00      (set bit 9 (Operating system support for FXSAVE and FXRSTOR instructions) and 10 (Operating System Support for Unmasked SIMD Floating-Point Exceptions))
	mov cr4, eax                        ;0xfffffaf1: 0f 22 e0
	mov ax, 0x18                        ;0xfffffaf4: b8 18 00
	mov ds, ax                          ;0xfffffaf7: 8e d8
	mov es, ax                          ;0xfffffaf9: 8e c0
	mov fs, ax                          ;0xfffffafb: 8e e0
	mov gs, ax                          ;0xfffffafd: 8e e8
	mov ss, ax                          ;0xfffffaff: 8e d0
	mov esi, 0xfffffe8e                 ;0xfffffb01: 66 be 8e fe ff ff
	jmp FWORD PTR cs:[si]               ;0xffffff07: 66 2e ff 2c            (This first retrieves both a pointer and a limit at address 0xfffffe8e. The offset is 0xfb10 and selector(limit) is 0xffff. (Quote from "stackoverflow" site: "In a 32-bit code segment: —Moves 32 bits from a 32-bit register to memory using a 32-bit effective address. —If preceded by an operand-size prefix, moves 16 bits from a 16-bit register to memory using a 32-bit effective address") (66h = operand-size prefix))
    
Bios_entry_0xfffffb10_protected32: 
	nop                                 ;0xfffffb10: 90                     (alignment for some critical instructions following below??)
	mov eax, 0xef1c0de                  ;0xfffffb11: b8 de c0 f1 0e         (like wtf?! some pwd?? Refer to Apples use of "Specialis Revelio" and "SMC the place to be, definitely!")
	out 0x80, eax                       ;0xfffffb16: e7 80                  (I/O port DMA controller range)
	mov ebx, 0xa0000078                 ;0xfffffb18: bb 78 00 00 a0         (Value to be written at B0/D0/F0/0x88 as shown in PCI dumps, EFFECT UNKNOWN??)
	mov eax, 0x80000088                 ;0xfffffb1d: b8 88 00 00 80         (PCI Configuration transaction at Bus 0/Device 0/Function 0/Register 0x88)
	mov dx, 0xcf8                       ;0xfffffb22: 66 ba f8 0c            (I/O port PCI CONFIG_ADDRESS)
	out dx, eax                         ;0xfffffb26: ef
	mov eax, ebx                        ;0xfffffb27: 8b c3
	mov dx, 0xcfc                       ;0xfffffb29: 66 ba fc 0c            (I/O port PCI CONFIG_DATA)
	out dx, eax                         ;0xfffffb2d: ef
	mov ebx, 0xff                       ;0xfffffb2e: bb ff 00 00 00         (Value to be written at B0/D3/F0/0x8c as shown in PCI dumps, EFFECT UNKNOWN??)
	mov eax, 0x8000188c                 ;0xfffffb33: b8 8c 18 00 80         (PCI Configuration transaction at Bus 0/Device 3/Function 0/Register 0x8c)
	;8000188c
	;     8           0        |     0           0       |     1            8       |     8           c
	;1   |0  0  0  0  0  0  0    0  0  0  0  0  0  0  0   0  0  0  1  1    0  0  0    1  0  0  0  1  1  0  0
	;31   30 29 28 27 26 25 24   23 22 21 20 19 18 17 16  15 14 13 12 11   10 9  8    7  6  5  4  3  2  1  0    
	;CFG?|  RESERVED: 24-30    |       BUS: 16-23        | DEVICE: 11-15 |FUNC: 8-10|     REGISTER: 0-7
	;YES            0                      B0                    D3           F0                8C
	mov dx, 0xcf8                       ;0xfffffb38: 66 ba f8 0c            (I/O port PCI CONFIG_ADDRESS)
	out dx, eax                         ;0xfffffb3c: ef
	mov eax, ebx                        ;0xfffffb3d: 8b c3
	mov dx, 0xcfc                       ;0xfffffb3f: 66 ba fc 0c            (I/O port PCI CONFIG_DATA)
	out dx, eax                         ;0xfffffb43: ef
	mov ebx, 0x2affffff                 ;0xfffffb44: bb ff ff ff 2a         (Value to be written at B0/D3/F0/0x94 as NOT shown in PCI dumps (shown is 000fffff ??, EFFECT UNKNOWN??)
	mov eax, 0x80001894                 ;0xfffffb49: b8 94 18 00 80         (PCI Configuration transaction at Bus 0/Device 3/Function 0/Register 0x94)
	mov dx, 0xcf8                       ;0xfffffb4e: 66 ba f8 0c            (I/O port PCI CONFIG_ADDRESS)
	out dx, eax                         ;0xfffffb52: ef
	mov eax, ebx                        ;0xfffffb53: 8b c3
	mov dx, 0xcfc                       ;0xfffffb55: 66 ba fc 0c            (I/O port PCI CONFIG_DATA)
	out dx, eax                         ;0xfffffb59: ef
	;********************************************************************;
	;Set up Cache-As-RAM (CAR)
	;********************************************************************;
	mov eax, cr0                        ;0xfffffb5a: 0f 20 c0
	or eax, 0x60000000                  ;0xfffffb5d: 0d 00 00 00 60         (set bit 29 (Not Write-Through) and 30 (Cache Disable) in order to enter no-fill mode for using Cache-as-RAM. (Read hits access the cache, read misses are ignored && write hits update cache, write misses access system memory.))
	wbinvd                              ;0xfffffb62: 0f 09                  (flush undefined cache values before setting cache as RAM)
	mov cr0, eax                        ;0xfffffb64: 0f 22 c0
	;********************************************************************;
	;Prepare and trigger microcode update. As of now there are 2 update series each of two 4 KiB and one 8 KiB package spaced by loads of FFs. First series starts at ffca8100 and second series starts at ffcae100. Any update package from the first series has the same mmddyyyy hex date (little endian) as an equal positioned update from the second series. No checks are performed whether an update was successful.
	;********************************************************************;
	mov ecx, 0x17                       ;0xfffffb67: b9 17 00 00 00         (MSR number 0x17, IA32_PLATFORM_ID, Retrieves the Processor Flags data)
	rdmsr                               ;0xfffffb6c: 0f 32                  (MSR given by ecx, lower 32 bits returned in eax, higher ones (if applicable) in edx)
	shr edx, 0x12                       ;0xfffffb6e: c1 ea 12               (Bits 50-52 in edx:eax are interesting, shift higher 32 bits by 18 to have bit 50 at position 32 in edx:eax, thus resembling "0...7" in edx.)
	and edx, 0x7                        ;0xfffffb71: 83 e2 07               (Then mask out unneeded bits to retrieve Platform Id Bits (Processor Flag 0-7). This is necessary for loading correct microcode update version.)
	mov ecx, edx                        ;0xfffffb74: 8b ca
	mov ebx, 0x1                        ;0xfffffb76: bb 01 00 00 00
	;  0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  1
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	shl ebx, cl                         ;0xfffffb7b: d3 e3                  (In ecx is platform ID 0-7 but it was encoded to save space in MSR 0x17. It must be decoded by 3-to-8 decoder to later match it against a list of supported platform IDs in update header. After decoding in ebx there is 0x1 << n | n [0, 7], Example shown below with n = 7)
	;  X  X  X  X  X  X  X  X    X  X  X  X  X  X  X  X    X  X  X  X  X  X  X  X    X  X  X  X  X  1  1  1
	;------------------------------------------------------------------------------------------------------
	;  0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    1  0  0  0  0  0  0  0
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	mov esi, ebx                        ;0xfffffb7d: 8b f3
	mov eax, 0x1                        ;0xfffffb7f: b8 01 00 00 00         (Retrieve generic version information)
	cpuid                               ;0xfffffb84: 0f a2                  (cpuid input given in eax and rarely in ecx, information may be returned in eax, ebx, ecx, edx)
	and eax, 0xfff3fff                  ;0xfffffb86: 25 ff 3f ff 0f
	;  0  0  0  0  1  1  1  1    1  1  1  1  1  1  1  1    0  0  1  1  1  1  1  1    1  1  1  1  1  1  1  1
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	; (bits 0-13 interesting, as well as bits 16-27. Other bits are reserved and must not be used. eax returns thus bits 0-3: stepping ID, 4-7: model, 8-11: family ID, 12-13: Processor type, 16-19: extended model ID, 20-27: extended family ID, together forming the Processor Signature)
	; Update 2021: A selection of processor id numbers can be found in the beginning of the MSR tables in the Volume 3C of the System Programming Guide, Part 3 (326019-044US).
	; These are encoded in the DisplayFamily_DisplayModel format, which in the core2duo case (target processor of this BIOS) does NOT constitute just the family and the model but also encompasses the extended family and model fields.
	; In the core2duo case the DisplayFamily_DisplayModel can be obtained by DisplayModel = ((extended model >> 16) & 0xf << 4) + ((model >> 4) & 0xf), and DisplayFamily = family.
	mov edx, esi                        ;0xfffffb8b: 8b d6                  (Feature information in edx not used (ebx and ecx not used either))
	mov edi, 0xffca8100                 ;0xfffffb8d: bf 00 81 ca ff         (Linear address of first ucode update package)
	mov esi, edi                        ;0xfffffb92: 8b f7
	mov ecx, esi                        ;0xfffffb94: 8b ce
	add ecx, 0x5f00                     ;0xfffffb96: 81 c1 00 5f 00 00      (ecx = ffca8100 + 5f00 = ffcae000, end of spacing FFs, 5f00 = maximum update size??)

	add ecx, DWORD PTR [esi+edi*0x4-0x62]
loc_fffffb9c:                           ;Start parsing the next update package header.
	mov ebx, DWORD PTR [edi+0xc]        ;0xfffffb9c: 8b 5f 0c               (Read processor signature from update header. (Why can we access what looks like RAM before configuring it, or writing to our cache? Because all accesses >= 0xffc00000 go straight away to high ffc00000-mapped 4 MiB BIOS flash!))
	cmp eax, ebx                        ;0xfffffb9f: 3b c3                  (Compare required processor signature with signature read by cpuid (0x1), if not equal, this particular update package cannot be applied.)
	; Update 2021: When simulating with modified unicorn engine it can be seen that core2duo (extended model, family, model, stepping) = (0, 6, f, b).
	; However the update packages expect (1, 6, 7, 4), or (1, 6, 7, 6), or (1, 6, 7, a), which can be calculated back to the
	; DisplayFamily_DisplayModel (note how the stepping vanishes) "6_17", that is the "Intel Xeon Processor 3100, 3300, 5200, 5400 series, Intel Core 2 Quad processors 8000, 9000 series", according to the 326019-044US SDM.
	; Consequently, none of the contained ucode updates are applicable to an Intel (R) Core 2 Duo processor.
	; Even if it were, it also had to match the stepping (refer to the plain comparison "cmp eax, ebx"!).
	; From this one might conclude that the same BIOS (or its build environment) is used with different processors, and that at least some of those "6_17" processors
	; must have such notable flaws that might the processors prevent even successfully reach the first boot loader!
	jne loc_fffffbba                    ;0xfffffba1: 75 17
	mov ebx, DWORD PTR [edi+0x18]       ;0xfffffba3: 8b 5f 18               (Read required processor flags from header)
	and ebx, edx                        ;0xfffffba6: 23 da                  (Compare supported processor flags (platform IDs) with flag (platform ID) of processor which should be updated, below example with processor flag = 0x80 (n = 7))
	;  0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    1  0  0  0  0  0  0  0
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
    
	;  0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    1  0  0  0  1  0  0  0
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	;-------------------------------------------------------------------------------------------------------
	;  0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    0  0  0  0  0  0  0  0    1  0  0  0  0  0  0  0
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	;Example update supports another and this example processor as ebx != 0, therefore update load may continue. 
	je loc_fffffbba                     ;0xfffffba8: 74 10
	mov ecx, 0x79                       ;0xfffffbaa: b9 79 00 00 00         (MSR number 0x79, IA32_BIOS_UPDT_TRIG)
	mov eax, edi                        ;0xfffffbaf: 8b c7                  (ucode update requires linear address of update data within update package (0xffca8100 + 0x30 = 0xffca8130) in eax)
	add eax, 0x30                       ;0xfffffbb1: 83 c0 30
	xor edx, edx                        ;0xfffffbb4: 33 d2                  (edx required to be zero)
	wrmsr                               ;0xfffffbb6: 0f 30                  (Trigger microcode update. wrmsr usage: MSR given by ecx, provide lower 32 bits in eax, higher ones (if applicable) in edx.)
	jmp loc_fffffbec                    ;0xfffffbb8: eb 32

loc_fffffbba:                           ;The update does not support the signature of this processor. An attempt is made to load alternative packages.
	mov ebx, 0x800                      ;0xfffffbba: bb 00 08 00 00
	cmp DWORD PTR [edi+0x20], 0x0       ;0xfffffbbf: 83 7f 20 00            (Check if the total update size is 0, if yes, according to Vol3 part 2, 253668-027US, Page 3-38, its size is 2000 (2 KiB) (Erratum in manual or in code found??))
	je loc_fffffbc8                     ;0xfffffbc3: 74 03
	mov ebx, DWORD PTR [edi+0x20]       ;0xfffffbc5: 8b 5f 20               (Get update size as given)

loc_fffffbc8:                           ;Total update size is now known by all means.
	add edi, ebx                        ;0xfffffbc8: 03 fb                  (Retrieve address of new update)
	cmp DWORD PTR [edi], 0xffffffff     ;0xfffffbca: 83 3f ff               (Check if there is even an update after this one. End of update is marked by a bunch of FFs.)
	je loc_fffffbd3                     ;0xfffffbcd: 74 04                  (The update just parsed was the last update.)
	cmp edi, ecx                        ;0xfffffbcf: 3b f9                  (Check if maximum update size has been reached
	jb loc_fffffb9c                     ;0xfffffbd1: 72 c9                  (There was next update, parse its header.)

loc_fffffbd3:                           ;No update of this series supports this processor. Continue with the next series of updates.
	cmp esi, 0xffcae100                 ;0xfffffbd3: 81 fe 00 e1 ca ff      (Hardcoded: Has the 2nd update been parsed?)
	je loc_fffffbec                     ;0xfffffbd9: 74 11                  (If yes, continue with LAPIC setup without further update checks/attempts.)
	mov edi, 0xffcae100                 ;0xfffffbdb: bf 00 e1 ca ff         (Hardcode start address of 2nd update series)
	mov esi, edi                        ;0xfffffbe0: 8b f7
	mov ecx, esi                        ;0xfffffbe2: 8b ce
	add ecx, 0x5f00                     ;0xfffffbe4: 81 c1 00 5f 00 00      (ecx = ffcae100 + 5f00 = ffcb4000, end of spacing FFs, 5f00 = maximum update size??)
	jmp loc_fffffb9c                    ;0xfffffbea: eb b0                  (Start over with next update series)
	;********************************************************************;
	;Performs an init of all further processors by INITing them by the boot processor's Local APIC all at once.
	;********************************************************************;
loc_fffffbec:
	mov edi, fee00300                   ;0xfffffbec: bf 00 03 e0 fe         (Local APIC per default mapped at 0xfee00000, so this is a valid address with length of 1 page.)
	mov eax, 0xc4500                    ;0xfffffbf1: b8 00 45 0c 00         (Also see binary encoding below. When written to lower half of Interrupt Command Register (ICR), configures the following for IPIs: Vector Number (0-7) = 0x0 (INIT Delivery Mode requires the vector 0x0 according to Intel SDM), Delivery Mode (8-10) = 0x5 (INIT, Delivers an INIT interrupt to one or more processors and makes them perform it), Destination Mode (11) = 0x0 (Physical, destination processor specified by LAPIC ID), Delivery Status (12) = 0x0 (This is RO bit but since after platform reset the LAPIC registers 0x300-0x308 have all 0s in it, it is always safe to set this bit to 0 (Idle) too.), Reserved (13) = 0x0 (Previous statement holds true for 13 as well.), Level (14) = 0x1 (Assert, must be 0x1 for INIT delivery mode (and for all delivery modes except INIT level de-assert).), Trigger Mode (15) = 0x0 (Edge, do-not-care bit in all delivery modes except INIT level de-assert (can then be Level as well)), Reserved (16-17) = 0x0 (Was 0, should be 0), Destination Shorthand (18-19) = 0x3 (All Excluding Self, sends this IPI to all other processors except to it self because the Bootstrap Processor (BSP) already had have its INIT at reset. Using this shorthand allows for omitting the destination in Destination Field (bits 56-63, via higher half of ICR) and thus an additional write to [ICR+4]. The APIC sets the field automatically to 0xF or 0xFF which means broadcast to all processors.).)
	;  0  0  0  0  0  0  0  0    0  0  0  0  1  1  0  0    0  1  0  0  0  1  0  1    0  0  0  0  0  0  0  0
	; 31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10  9  8    7  6  5  4  3  2  1  0
	mov DWORD PTR [edi], eax            ;0xfffffbf6: 89 07                  (Write 0xc4500 at 300 (Interrupt Command Register bits 0-31) in LAPIC, Forces the other processors to do an INIT.)

	;********************************************************************;
	;Enhances (or makes work??) CAR
	;********************************************************************;
	mov ecx, 0x1a0                      ;0xfffffbf8: b9 a0 01 00 00         (MSR number 0x1a0, IA32_MISC_ENABLE, allows to check which miscellaneous processor features are enabled, but here used for proper read-modify-write as reserved bits are in undefined state yet must not be changed.)
	rdmsr                               ;0xfffffbfd: 0f 32
	or eax, 0x80200                     ;0xfffffbff: 0d 00 02 08 00         (Set bits 9 (Hardware Prefetcher Disable, disables the hardware prefetcher operation on streams of data) and 19 (Adjacent Cache Line Prefetch Disable, makes all processors fetch only the cache line that contains data required by themselves and ignore data important to other processors??) to enhance CAR function??)
	or edx, 0xa0                        ;0xfffffc04: 81 ca a0 00 00 00      (Set bits 5+32 = 37 (Data Cache Unit (DCU) Prefetcher Disable, disables the DCU L1 data cache prefetcher to not prefetch the next line into L1 from L2 or memory if multiple loads on the same line are done within a certain time. (Oh.. ??!)) and 7+32 = 39 (IP Prefetcher Disable, disables the IP Prefetcher so the IP Prefetcher does not look into sequential load history (based on instruction pointer of previous loads) and does not prefetch the next expected data into L1 from L2 or memory. (Erm ..??!!)) for enhancing CAR function even more (or make it work in the first place, because otherwise it is undefined what gets written where in the CAR??))
	wrmsr                               ;0xfffffc0a: 0f 30                  (Do adjustment of cache settings now.)
	;********************************************************************;
	;Disable the MTRRs (to prevent caching??)
	;********************************************************************;
	mov esi, 0xfffffe56                 ;0xfffffc0c: be 56 fe ff ff         (Address of MSRs to zero out, range is BIOS flash)
	mov edi, 0x1c                       ;0xfffffc11: bf 1c 00 00 00         (There are 27 iterations of the loop.)
	xor eax, eax                        ;0xfffffc16: 33 c0                  (Zero out the MTRR.)
	xor edx, edx                        ;0xfffffc18: 33 d2                  (With 36 bits addresses there are more than 32 bits, so the high 32 bits must be taken into respect too.)

loc_fffffc1a:			;(Loop is executed 27 times. At beginning of last execution edi has 1 and esi points to 27*0x2+0xfffffe56 = 0xfffffe8c.) 
	movzx ecx, WORD PTR [esi]           ;0xfffffc1a: 0f b7 0e               (Read the number of 28 MTRR setup related MSRs to zero out. They must have a defined initial state before setup of the memory map later on. Intel recommends UC memory type (0x0) for inital state. Paragraph 10.5.3 in SDM Vol. 3 also suggests that the reset of MTRRs is about preventing caching. As for now the DRAM isn't initialized yet and there is no physical memory to cache in L1-L3. The MSR numbers (0x200, 0x201, 0x202, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208, 0x209, 0x20a, 0x20b, 0x20c, 0x20d, 0x20e, 0x20f, 0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f, 0x2ff) are stored as words for space reasons but wrmsr expects a dword. Some words about the ordering: First MSR zeroed out is the IA32_MTRR_DEF_TYPE which disables the MTRR. Then the fixed range MTRR are set to 0x0. At the end mask and base of the variable range MTRRs are zeroed out.)
	wrmsr                               ;0xfffffc1d: 0f 30
	add esi, 0x2			    ;esi is word
	dec edi
	jne loc_fffffc1a	
	mov ecx, 0x2ff		;(MSR number 0x2ff = IA32_MTRR_DEF_TYPE)
	rdmsr
	and eax, 0xfffff300	;(Disabling the MTRRs a second time has to the best of current knowledge no effect. Still some notes about it: MTRRs are disabled by performing a read-modify-write with the IA32_MTRR_DEF_TYPE MSR. This clears bits 0-7 (Type field, 0 = UC Uncachable, to follow Intel recommendations), 10 (FE, Fixed-range MTRRs enable/disable, to disable fixed-range MTRRs), and 11 (E, MTRR enable/disable, to completely disable MTRRs). All other bits are reserved and are zero.)
	wrmsr
	mov ebx, 0x20000	;(??)
	mov esi, 0xffae0000	;(??)
	mov edx, 0x4000		;(??!)
	mov esp, edx		;(Stack pointer now at 0x4000, --> 16 KiB reserved for stack?)
	cmp ebx, edx		;(Comparison that is known in advance??!)
	jb loc_fffffc54		;(Jump never taken..?)
	bsf ecx, ebx		;(Searches ebx for the least significant 1 bit and stores bit position in ecx. Position of first 1 in ebx is 17.)

LOC_FFFFFC4B:
	je			;(disasm fail, hex is 74 fe, similar to eb fe = infinite loop)
	bsf eax, esi

loc_fffffc50:
	je			;(same here, cloaked eb fe)
	cmp eax, ecx

loc_fffffc54:
	
    
Reset_vector_0xfffffff0_real32:         ;Due to compatibility reasons all Intel CPUs start execution in unreal mode at 0xfffffff0.
	wbinvd                              ;0xfffffff0: 0f 09
	jmp Bios_entry_0xfffffad0           ;0xfffffff2: e9 db fa
    

    
    
    
    
