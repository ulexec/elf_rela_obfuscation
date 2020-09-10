A small POC of EPO obfuscation using Rela relocations for ELF64 PIE binaries.
The dynamic linker enforces relocations before it passes control flow to the main binary.
If the CODE segment is writable relocations can be done in code, therefore patching code JIT.
This POC patches offset 0 of the code segment to a relative jmp to the OEP.
