# Prepare Unicorn
1. Download Unicorn 1.0.2 Tag src
2. (Optional) Tailor to x86 only, see COMPILE.NIX
3. Make and install as described in the COMPILE.NIX
4. Run the sample tests (not unit tests) to make sure the installation is fine
5. In the file *<unicorn>/uc.c* comment the code as below to prevent override of the x86 reset state (BIOS simulation requires the CPU to start with the very values stated in the Intel SDMs!)
  ```
  /*if (uc->reg_reset)
     uc->reg_reset(uc);*/
  ```
6. Make and install as described in the COMPILE.NIX

# Handy to know
* Unicorn "core" func: *disas_insn()*
