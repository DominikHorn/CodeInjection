#include <elf.h>

#define true 1
#define false 0

#define EXIT_SUCCESS 0
#define EXIT_INVALIDPARAM -1
#define EXIT_NOVICTIM -2
#define EXIT_ERRORFORK -3
#define EXIT_ERRORPTRACE -4

#define ELF_HEADER 0x400000

#if UNITPTR_MAX == 0xffffffff
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Dyn Elf32_Dyn
#define Elf_Word Elf32_Word

#define ELF_ST_TYPE ELF32_ST_TYPE

#define SYM_LENGTH 32
#else
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Word Elf64_Word

#define ELF_ST_TYPE ELF64_ST_TYPE

#define SYM_LENGTH 64
#endif
