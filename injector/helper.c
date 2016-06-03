#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>

#include "helper.h"
#include "def.h"

// Globals
unsigned long symtab = -1;
unsigned long strtab = -1;
int nchains = -1;

/* retrieve last path component of string */
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

/* attach to tracee */
void ptrace_attach(pid_t pid) {
   if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
      fprintf(stderr, "could not attach with ptrace!\n");
      exit(EXIT_ERRORPTRACE);
   }
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

/* detach from tracee */
void ptrace_detach(pid_t pid) {
   if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
      fprintf(stderr, "could not detach with ptrace!\n");
      exit(EXIT_ERRORPTRACE);
   }
}

void ptrace_getregs(pid_t pid, struct user_regs_struct* regs) {
   if (ptrace(PTRACE_GETREGS,pid, NULL, regs) == -1) {
      fprintf(stderr, "PTRACE could not get regs for pid: %d\n", pid);
      exit(EXIT_ERRORPTRACE);
   }
}

void ptrace_setregs(pid_t pid, struct user_regs_struct* regs) {
   if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
      fprintf(stderr, "PTRACE could not set regs for pid: %d\n", pid);
      exit(EXIT_ERRORPTRACE);
   }
}

/* set ptrace options so that the tracee will not live on after injector/loader exits */
void ptrace_kill_on_parent_exit(pid_t pid) {
   ptrace(PTRACE_SETOPTIONS, pid, PTRACE_O_TRACEEXEC, NULL);
}

/* read data from remote process' space*/
void read_data(pid_t pid, unsigned long addr, void *vptr, int len) {
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

/* read a string from the remote process' space */
char* read_str(int pid, unsigned long addr, int len) {
   char* ret = calloc(len, sizeof(char));
   read_data(pid, addr, ret, len);
   return ret;
}

/* write data to remote process' space */
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

/* locates and extracts the linkmap inside the remote process */
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

/* resolves tables inside link_map */
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

/* searches tables for specific symbol */
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

/* Addr resolving (Find a librarys address in a specified process).
 * Since ASLR does not change symbol offsets inside of libraries we can still find the desired    
 * REMOTE_ADDRESS by adding our locally calculated symbold offset to the remote library base adress
 */
unsigned long find_library(const char *library, pid_t remote_pid) {
   char filename[0xFF] = {0}, buffer[1024] = {0};
   FILE* fp = NULL;
   unsigned long address = 0;
   sprintf(filename, "/proc/%d/maps", remote_pid);
   
   fp = fopen(filename, "rt");
   if (fp == NULL) {
      fprintf(stderr, "Could not open procs file %s\n", filename);
      exit(EXIT_ERRORPROCS);
   }
   
   while (fgets(buffer, sizeof(buffer), fp)) {
      if (strstr(buffer, library)) {
         address = (unsigned long)strtoul(buffer, NULL, 16);
         break;
      }
   }
   
   if (fp)
      fclose(fp);
      
   return address;
}

/* get address of a libc function */
unsigned long find_libc_function(const char* func_name) {
   void* self = dlopen("libc.so.6", RTLD_LAZY);
   return (unsigned long)dlsym(self, func_name);
}

/* Addr resolving (find actual function in remote process) */
unsigned long find_remote_function(const char* library, unsigned long local_addr, pid_t remote_pid) {
   unsigned long local_handle, remote_handle;

   local_handle = find_library(library, getpid());
   remote_handle = find_library(library, remote_pid);
   
   return (unsigned long)((unsigned long)remote_handle + local_addr -(unsigned long)local_handle);
}

unsigned long find_free_space_addr(pid_t remote_pid) {
   FILE* fp;
   char filename[30];
   char line[850];
   unsigned long addr;
   char str[20];
   char perms[5];
   sprintf(filename, "/proc/%d/maps", remote_pid);
   fp = fopen(filename, "r");
   if (fp == NULL)
      exit(EXIT_ERRORPROCS);
     
   while (fgets(line, 850, fp) != NULL) {
      sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);
      
      if (strstr(perms, "x") != NULL) {
         break;
      }
   }
   
   fclose(fp);
   return addr;
}
