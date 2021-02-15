# Prepare Unicorn
1. Download Unicorn 1.0.2 Tag src
1a. (Optional) Tailor to x86 only, see COMPILE.NIX
2. Comment line "" in file "" to prevent override of the x86 reset state (BIOS simulation requires the CPU to start with the very values stated in the Intel SDMs!)
3. Make and install as described in the COMPILE.NIX

# Handy to know
* Unicorn "core" func: *disas_insn()*
