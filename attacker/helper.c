#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <elf.h>
#include <link.h>

#include "helper.h"
#include "def.h"

// Globals
unsigned long symtab = -1;
unsigned long strtab = -1;
int nchains = -1;

char* getLastPathComponent(char* path) {
   int lastComponentStartIndex = 0;

   // Find start index of lastPathComponent
   for (int i = strlen(path) - 2; i >= 0; i--) { 
      char charAtIndex = path[i];
      if (charAtIndex == '/') {
         lastComponentStartIndex = i+1;
         break;
      }
   }

   // Extract lastPathComponent into new char*
   return path + lastComponentStartIndex;
}

/* continue exection */
void ptrace_cont(pid_t pid) {
   int status = 0;

   if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
      fprintf(stderr, "could not cont exec with ptrace!\n");
      exit(EXIT_ERRORPTRACE);
   }

   while (!WIFSTOPPED(status)) waitpid(pid, &status, WNOHANG);
}

void ptrace_detach(pid_t pid) {
   if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
      fprintf(stderr, "could not detach with ptrace!\n");
      exit(EXIT_ERRORPTRACE);
   }
}

void* read_data(pid_t pid, unsigned long addr, void *vptr, int len) {
   int i, count;
   long word;
   unsigned long* ptr = (unsigned long*)vptr;
   count = i = 0;
   while (count < len) {
      word = ptrace(PTRACE_PEEKTEXT, pid, addr+count, NULL);
      count += 4;
      ptr[i++] = word;
   }
}

char* read_str(int pid, unsigned long addr, int len) {
   char* ret = calloc(len, sizeof(char));
   read_data(pid, addr, ret, len);
   return ret;
}

void write_data(pid_t pid, unsigned long addr, void *vptr, int len) {
   int i, count;
   long word;
   i = count = 0;

   while (count < len) {
      memcpy(&word, vptr+count, sizeof(word));
      word = ptrace(PTRACE_POKETEXT, pid, addr+count, word);
      count += 4;
   }
}

struct link_map* locate_linkmap(int pid) {
   Elf_Ehdr* ehdr = malloc(sizeof(Elf_Ehdr));
   Elf_Phdr* phdr = malloc(sizeof(Elf_Phdr));
   Elf_Dyn* dyn = malloc(sizeof(Elf_Dyn));
   Elf_Word got;
   struct link_map* l = malloc(sizeof(struct link_map));
   unsigned long phdr_addr, dyn_addr, map_addr;

   // Get program header table offset from elf header

   read_data(pid, ELF_HEADER, ehdr, sizeof(Elf_Ehdr));

   phdr_addr = 0x400000 + ehdr->e_phoff;
   printf("program header at %p\n", phdr_addr);

   // Locate PT_DYNAMIC

   read_data(pid, phdr_addr, phdr, sizeof(Elf_Phdr));

   while (phdr->p_type != PT_DYNAMIC) {
      read_data(pid, phdr_addr += sizeof(Elf_Phdr), phdr, sizeof(Elf_Phdr));
   }

  // Go through dynamic section to find adress of the GOT
  dyn_addr = phdr->p_vaddr;
  read_data(pid, dyn_addr, dyn, sizeof(Elf_Dyn));

   while (dyn->d_tag != DT_PLTGOT) {
      read_data(pid, dyn_addr += sizeof(Elf_Dyn), dyn, sizeof(Elf_Dyn));
   }

   got = (Elf_Word) dyn->d_un.d_ptr;
   got += sizeof(Elf_Word); // Get the second GOT entry (Symbol table)

   // read first link_map item and return it
   read_data(pid, (unsigned long) got, &map_addr, sizeof(Elf_Word));
   read_data(pid, map_addr, l, sizeof(struct link_map));

   free(ehdr);
   free(phdr);
   free(dyn);

   return l;
}

void resolv_tables(int pid, struct link_map* map) {
   Elf_Dyn* dyn = malloc(sizeof(Elf_Dyn));
   unsigned long addr;

   addr = (unsigned long) map->l_ld;

   read_data(pid, addr, dyn, sizeof(Elf_Dyn));

   while (dyn->d_tag) {
      switch(dyn->d_tag) {
         case DT_HASH:
            read_data(pid, dyn->d_un.d_ptr + map->l_addr+4, &nchains, sizeof(nchains));
            break;

         case DT_STRTAB:
            strtab = dyn->d_un.d_ptr;
            break;

         case DT_SYMTAB:
            symtab = dyn->d_un.d_ptr;
            break;
         
         default:
            break;
      }

      addr += sizeof(Elf_Dyn);
      read_data(pid, addr, dyn, sizeof(Elf_Dyn));
   }

   free(dyn);
}

unsigned long find_sym_in_tables(int pid, struct link_map* map, char* sym_name) {
   Elf_Sym* sym = malloc(sizeof(Elf_Sym));
   char* str;
   int i = 0;

   while (i < nchains) {
      read_data(pid, symtab+(i*sizeof(Elf_Sym)), sym, sizeof(Elf_Sym));
      i++;
      
      if (ELF_ST_TYPE(sym->st_info) != STT_FUNC) continue;

      /* read symbol name from string table */
      str = read_str(pid, strtab + sym->st_name, SYM_LENGTH);
      
      if(strncmp(str, sym_name, strlen(sym_name)) == 0)
         return (map->l_addr+sym->st_value);
   }

   /* symbol not found */
   return 0;
}

























































































