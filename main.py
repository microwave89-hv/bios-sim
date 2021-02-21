#!/usr/bin/python
# microwave89-hv
# January, 2021
# Based on python unicorn sample

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import capstone
import sys

#ins_count = 120
ins_count = 25
def hook_mem_fetch_invalid(uc, access, address, size, value, user_data):
    global ins_count
    print(">>> Missing memory is being fetched at 0x%x" %address)
    print("ins_count = %d" % ins_count)
    return False
    
def hook_mem_read_invalid(uc, access, address, size, value, user_data):
    global ins_count
    print(">>> Missing memory is being read at 0x%x" %address)
    print("ins_count = %d" % ins_count)
    return False
    
def hook_mem_write_invalid(uc, access, address, size, value, user_data):
    global ins_count
    print(">>> Missing memory is being written at 0x%x" %address)
    print("ins_count = %d" % ins_count)
    return False
    
def hook_ins_out(uc, port, size, value, data):
    print(">>> hook_ins_out: port = 0x%04x, datasize = %d, value = 0x%08x, data = %d" % (port, size, value, 0))
    return True
    
def hook_ins_in(uc, port, size, value, data):
    print(">>> hook_ins_in: port = 0x%04x, datasize = %d, value = 0x%08x, data = %d" % (port, size, value, 0))
    return True
    
def hook_ins_tst(uc, port, size, value, data):
    print(">>> hook_ins_: port = 0x%04x, datasize = %d, value = 0x%08x, data = %d" % (port, size, value, 0))
    return True
    
rom_contents = {}
with open("./biosdump4.bin", mode='rb') as rom_file: # b is important -> binary
    rom_contents = rom_file.read()
    
if len(rom_contents) < 0x1000:
    sys.exit()
    
print("%08x" % len(rom_contents))

BASE_ADDRESS = 0x0
#ins 300
RESET_ADDRESS = 0xfffffff0 # Intel(R) doc 253668 (System Programming Guide, Part 1), 9-2
CS_BASE_INIT = 0xffff0000 # ' '

rom_size = len(rom_contents)
rom_start = 0xffffffff - rom_size + 1
print("Simulating BIOS with size 0x%x, ROM start @ 0x%x" % (rom_size, rom_start))
print("Emulate 8086 code")
try:
    # Initialize emulator in X86-16bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32);
    
    # # map 8 MiB memory for this emulation
    #mu.mem_map(0xff800000, 0x800000)
    mu.mem_map(rom_start, rom_size)
    
    # # write machine code to be emulated to memory
    #mu.mem_write(0xfffff000, EFIROM_EXCERPT)
    mu.mem_write(rom_start, rom_contents)
    mu.mem_map(0x100000000, 0x1000) # Against over-reading
    mu.mem_map(0xfee00000, 0x1000) # LAPIC
    #mu.mem_map(0x0000, 0x10000) # Against over-reading
    
    mu.hook_add(UC_HOOK_MEM_FETCH_INVALID, hook_mem_fetch_invalid)
    mu.hook_add(UC_HOOK_MEM_READ_INVALID, hook_mem_read_invalid)
    mu.hook_add(UC_HOOK_MEM_WRITE_INVALID, hook_mem_write_invalid)
    mu.hook_add(UC_HOOK_INSN, hook_ins_in, None, 1, 0, UC_X86_INS_IN)
    mu.hook_add(UC_HOOK_INSN, hook_ins_out, None, 1, 0, UC_X86_INS_OUT)
    #mu.hook_add(UC_HOOK_INSN, hook_ins_tst, None, 1, 0, UC_X86_INS_WRMSR)

    cs_base = CS_BASE_INIT
    MAX_INS_LEN = 15
    
    REAL_MODE = 0
    PROTECTED_MODE = 1
    LONG_MODE = 2
    
    cpu_mode = REAL_MODE
    eip = 0
    cs_sel = 0
    cs_full = 0
    fetch_eip = 0
    rw_eip = 0
    
    #mu.reg_write(UC_X86_REG_CS, 0x10)
    mu.reg_write(UC_X86_REG_EIP, 0xfffffb10)
    
    #ins_count = 0
    
    mu.emu_start(0xfffffb10, 0, 0, ins_count + 1)
    
    while True:
        eip = mu.reg_read(UC_X86_REG_EIP)
        if eip > 0xffff: # Should normally(!) (see "unreal mode") only be possible if CPU in protected or long mode
            cpu_mode = PROTECTED_MODE
        
        if cpu_mode == REAL_MODE:
            print("REAL_MODE")
            cs_sel = mu.reg_read(UC_X86_REG_CS)
            print("cs_sel = %04x" % cs_sel)
            cs_full = cs_sel + cs_base
            print("cs_full = %08x" % cs_full)
            fetch_eip = (cs_full * 0x10 & 0xffffffff) + eip # only 16 bit addressing mode!
            print("fetch_eip = %08x" % fetch_eip)
            rw_eip = fetch_eip
            print("rw_eip = %08x" % rw_eip)
            cs.mode = capstone.CS_MODE_16

        else:
            print("PROTECTED_MODE")
            #cs_base = 0
            #cs_sel = mu.reg_read(UC_X86_REG_CS)
            #print("cs_sel = %04x" % cs_sel)
            #cs_full = cs_sel + cs_base
            #print("cs_full = %08x" % cs_full)
            #fetch_eip = eip
            #print("fetch_eip = %08x" % fetch_eip)
            #rw_eip = (cs_full * 0x10 & 0xffffffff) + eip # wrong?
            #print("rw_eip = %08x" % rw_eip)
            #if eip == 0xfffffa10:
            #    mu.reg_write(UC_X86_REG_CS, 0x10)
            #    eip = 0xfffffb10
                
            print("eip = %08x" % eip)
            rw_eip = eip
            cs.mode = capstone.CS_MODE_32
        
        b = {}
        #b = raw_input()
        #print("Attempt read mem 0x%08x (raw eip = 0x%08x, fetch_eip = 0x%08x)" % (rw_eip, eip, fetch_eip))
        print("Attempt read mem 0x%08x (raw eip = 0x%08x)" % (rw_eip, eip))
        curr_code = mu.mem_read(rw_eip, MAX_INS_LEN)
        ins = cs.disasm(curr_code, rw_eip, 1)
        mnemonic = {}
        op_str = {}
        for curr_ins in ins:
            mnemonic = curr_ins.mnemonic
            op_str = curr_ins.op_str
        
        print("\n\nHit enter to execute instruction below")
        print("0x%08x:\t%s\t%s" % (rw_eip, mnemonic, op_str))
        b = raw_input()
        #
        # if total_eip != 0xfffffb01:
        print("1 step")
        #mu.reg_write(UC_X86_REG_EIP, rw_eip)
        mu.emu_start(rw_eip, 0, 0, 1) # Fetch 15 bytes since the longest x86 instruction is 15 bytes {citation}, and then emulate one instruction (1) in infinite time (0).
        ins_count += 1
        # else:
        #     steps = 3
        #     print("%d steps" % steps)
        #     mu.emu_start(total_eip, total_eip + MAX_INS_LEN * steps, 0, steps) # Fetch 15 bytes since the longest x86 instruction is 15 bytes {citation}, and then emulate one instruction (1) in infinite time (0).
        #3print(mu.query(1))
        #mu.emu_start(0xfffffff0, 0, 0, 60)
        #help(mu)
        #print(mu.query(1))
        
        print("Calculation done. Below is the result")
        print("EAX:         %08x" % mu.reg_read(UC_X86_REG_EAX))
        print("EBX:         %08x" % mu.reg_read(UC_X86_REG_EBX))
        print("ECX:         %08x" % mu.reg_read(UC_X86_REG_ECX))
        print("EDX:         %08x" % mu.reg_read(UC_X86_REG_EDX))
        print("EBP:         %08x" % mu.reg_read(UC_X86_REG_EBP))
        print("ESI:         %08x" % mu.reg_read(UC_X86_REG_ESI))
        print("EDI:         %08x" % mu.reg_read(UC_X86_REG_EDI))
        print("CS:EIP: %04x:%08x" % (mu.reg_read(UC_X86_REG_CS), mu.reg_read(UC_X86_REG_EIP)))
        print("RIP: %x" % mu.reg_read(UC_X86_REG_RIP))
        print("SS:ESP: %04x:%08x" % (mu.reg_read(UC_X86_REG_SS), mu.reg_read(UC_X86_REG_ESP)))
        print("DS:              %04x" % mu.reg_read(UC_X86_REG_DS))
        print("ES:              %04x" % mu.reg_read(UC_X86_REG_ES))
        print("FS:              %04x" % mu.reg_read(UC_X86_REG_FS))
        print("GS:              %04x" % mu.reg_read(UC_X86_REG_GS))
        print("CR0:         %08x" % mu.reg_read(UC_X86_REG_CR0))
        print("CR2:         %08x" % mu.reg_read(UC_X86_REG_CR2))
        print("CR3:         %08x" % mu.reg_read(UC_X86_REG_CR3))
        print("CR4:         %08x" % mu.reg_read(UC_X86_REG_CR4))
        print("EFLAGS:      %08x" % mu.reg_read(UC_X86_REG_EFLAGS))
        print("ins_count = %d" % ins_count)

except UcError as e:
    print("ERROR: %s" % e)

