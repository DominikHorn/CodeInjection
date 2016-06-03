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

void setup_malloc_stub(pid_t pid, void* malloc_addr, size_t size) {
  // Make sure we got fresh regs to fiddle
  reset_regs_fiddle();
  
  // push parameters into registers
  _regs_fiddle.rbx = (long) size;
  _regs_fiddle.rax = (long) malloc_addr;
  ptrace(PTRACE_SETREGS, pid, NULL, &_regs_fiddle);
}

void malloc_stub() {
   __asm__(
      "push %rbx\n"
      "call *%rax\n"
      "add $0x4, %rsp\n"
      "int $0x3\n"
   );
}

void malloc_stub_end() {
   // Used to calculate malloc_stub()'s length
}

void restore_remote(pid_t pid) {
   ptrace(PTRACE_SETREGS, pid, NULL, _regs_backup);

#ifndef DEBUG
   if (_launcher_mode)
      // Detach and let injected child continue orphanaged
      ptrace_detach(victim_pid);
#endif
}

void gain_code_exec(pid_t pid) {
   // Find remote function adresses for malloc, free, etc
   void* (*local_malloc)(size_t size) = &malloc;
   void (*local_free)(void* ptr) = &free;
   
   printf("malloc is @ %p\nfree is @ %p\n", local_malloc, local_free);
   
   // Method 2 to find those functions
   long malloc_addr = 0;
   void* self = dlopen("libc.so.6", RTLD_LAZY);
   void* funcAddr = dlsym(self, "malloc");
   malloc_addr = (long)funcAddr;
   printf("malloc is @ %p according to method 2\n", malloc_addr);
   
   // Initialize global regs structs variables
   memset(&_regs_backup, 0, sizeof(struct user_regs_struct));
   memset(&_regs_fiddle, 0, sizeof(struct user_regs_struct));
   ptrace(PTRACE_GETREGS, pid, NULL, &_regs_backup);

   printf("TMP; HALTING FOR 5 seconds\n");
   sleep(5);
}
