#define _POSIX_SOURCE
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "helper.h"
#include "def.h"

short _launcher_mode = false;

void wrong_usage(char* prog_name) {
   fprintf(stderr, "Invalid arguments.\nUse: %s -l <PATH> or %s -a <PID>\n", prog_name, prog_name);
   exit(EXIT_INVALIDPARAM);
}

// loads the victim and returns pid
pid_t launch_victim_and_trace(char* victimPath) {
   pid_t pid = fork();
   if (pid == false) {
      // Prep for ptrace
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);

      // Load Victim
      char* argv[] = {getLastPathComponent(victimPath), NULL};
      execv(victimPath, argv);
      fprintf(stderr, "Could not load victim (%s)!\n", victimPath);
      exit(EXIT_NOVICTIM);
   } else if (pid == -1) {
      fprintf(stderr, "Could not fork!\n");
      exit(EXIT_ERRORFORK);
   }

   return pid;
}

void gain_code_exec(pid_t pid) {
   // Find remote function adresses for malloc, free, etc

   // Load stub code into process space of tracee

   // Continue child
   ptrace_cont(pid);
}

int main(int argc, char* argv[]) {
   int status = -1;
   pid_t victim_pid = 0;

   if (argc != 3) {
      wrong_usage(argv[0]);
   }
   
   // launch victim and trace  
   if (strcmp(argv[1], "-l") == 0) {
      _launcher_mode = true;
      victim_pid = launch_victim_and_trace(argv[2]);
 
      printf("main(): Done launching. (Binary: %s, PID: %d)\n", argv[2], victim_pid);
   } else if (strcmp(argv[1], "-a") == 0) {
      // get pid and attach
      victim_pid = atoi(argv[2]);
      ptrace_attach(victim_pid);
      
      printf("main(): Done attaching to Process with PID %d)\n", victim_pid);    
   } else {
      wrong_usage(argv[0]);
   }
  
   // Wait for Tracee to stop
   waitpid(victim_pid, &status, 0); 
  
   // Gain code execution inside victim process
   gain_code_exec(victim_pid);

#ifndef DEBUG
   if (_launcher_mode)
      // Detach and let injected child continue orphanaged
      ptrace_detach(victim_pid);
#endif

   exit(EXIT_SUCCESS);
}
