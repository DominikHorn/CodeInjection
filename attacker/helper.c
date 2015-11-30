#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "helper.h"
#include "def.h"

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
