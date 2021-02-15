# Prepare Unicorn
1. Download Unicorn 1.0.2 Tag src
2. (Optional) Tailor to x86 only, see COMPILE.NIX
3. Comment line "" in file "" to prevent override of the x86 reset state (BIOS simulation requires the CPU to start with the very values stated in the Intel SDMs!)
4. Make and install as described in the COMPILE.NIX

# Handy to know
* Unicorn "core" func: *disas_insn()*
