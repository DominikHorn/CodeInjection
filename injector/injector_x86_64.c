#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>

#include "injector_x86_64.h"
#include "helper.h"
#include "def.h"

struct user_regs_struct _regs_backup;
struct user_regs_struct _regs_fiddle;

void reset_regs_fiddle() {
   // Copy into fiddle regs for us to fiddle with fresh copy
   memcpy(&_regs_fiddle, &_regs_backup, sizeof(struct user_regs_struct));
}

/* PARAMETERS:
 *
 * - Size of area to malloc inside RBX
 * - malloc addr inside RAX
 */
void malloc_stub() {
  /* __asm__(
      "push %rbx\n"
      "call *%rax\n"
      "add $0x4, %rsp\n"
      "int $0x3\n"
   );*/
   
   __asm__
   (
      "mov  rax, 1\n"
      "mov  rdi, 1\n"
      "mov  rsi, message\n"
      "mov  rdx, length\n"
      "syscall\n"
      "mov  rax, 60\n"
      "mov  rdi, 0\n"
      "syscall\n"
      
      "message: db 'Hello, world!',0x0a\n"
      "length: equ $-message\n"
   );
}

void malloc_stub_end() {
   // Used to calculate malloc_stub()'s length
}

void restore_remote(pid_t pid) {
   ptrace_setregs(pid, &_regs_backup);

#ifndef DEBUG
   if (_launcher_mode)
      // Detach and let injected child continue orphanaged
      ptrace_detach(victim_pid);
#endif
}

void gain_code_exec(pid_t remote_pid) {
   malloc_stub();

   ptrace_detach(remote_pid);
   exit(1);
 
   int status;

   // Find remote function adresses for malloc, free, __libc_dlopen_mode
   unsigned long remote_malloc_addr = find_remote_function("libc", find_libc_function("malloc"), remote_pid);
   unsigned long remote_free_addr = find_remote_function("libc", find_libc_function("free"), remote_pid);
   unsigned long remote_dlopen_addr = find_remote_function("libc", find_libc_function("__libc_dlopen_mode"), remote_pid);
   
   // Initialize global regs structs variables
   memset(&_regs_backup, 0, sizeof(struct user_regs_struct));
   memset(&_regs_fiddle, 0, sizeof(struct user_regs_struct));
   ptrace_getregs(remote_pid, &_regs_backup);
   reset_regs_fiddle();

   // Get Addr to write our initial stub to:
   unsigned long free_space_addr = find_free_space_addr(remote_pid);
   
   // Set RIP to addr start (2 byte long start instruction)
   _regs_fiddle.rip = free_space_addr + 2;
   
   // TODO TMP
   // Setup parameters in registers (see malloc_stub definition)
   _regs_fiddle.rbx = 1073741824; // exactly one GB
   _regs_fiddle.rax = remote_malloc_addr;
   
   // Upload registers
   printf("Uploading payload regs\n");
   ptrace_setregs(remote_pid, &_regs_fiddle);
   
   // Figure out stub size
   size_t stub_size = (intptr_t)malloc_stub_end - (intptr_t)malloc_stub;
   
   // Create buffer holdig our stub
   printf("Crafting payload stub\n");
   char* stub_code = malloc(stub_size * sizeof(char));
   memset(stub_code, 0, stub_size * sizeof(char));
   memcpy(stub_code, malloc_stub, stub_size);

   // Backup everything that we'll overwrite in target location
   printf("Backing up data\n");
   char* backup = malloc(stub_size * sizeof(char));
   read_data(remote_pid, free_space_addr, backup, stub_size);
   
   // Write our code to target location
   printf("Uploading payload\n");
   write_data(remote_pid, free_space_addr, stub_code, stub_size);
   
   // Continue execution and wait for int3
   printf("Code injection successfull, executing\n"); 
   ptrace_cont(remote_pid);
   sleep(1);
   printf("Pid returned ... probably\n");
   
   // Reupload old data
   printf("Reuploading old data\n");
   write_data(remote_pid, free_space_addr, backup, stub_size);
   ptrace_setregs(remote_pid, &_regs_backup);
   printf("Reset execution flow, continuing execution");
   
   ptrace_cont(remote_pid);
   
   free(backup);
   free(stub_code);
   
   printf("TMP; HALTING FOR 30 seconds\n");
   sleep(30);
}
