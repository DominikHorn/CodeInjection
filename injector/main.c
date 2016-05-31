#define _POSIX_SOURCE
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#include "helper.h"
#include "def.h"

short _launcher_mode = false;

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

void wrong_usage() {
   fprintf(stderr, "Invalid arguments.\nUse: %s -l <PATH> or %s -a <PID>\n", argv[0], argv[0]);
   exit(EXIT_INVALIDPARAM);
}

int main(int argc, char* argv[]) {
   int status = -1;

   if (argc != 3) {
      wrong_usage();
   }
   
   // launch victim and trace  
   if (strcmp(argv[1], "-l") == 0) {
      launcher_mode = true;
      victim_pid = launch_victim_and_trace(argv[2]);
 
      printf("main(): Done launching. (Binary: %s, PID: %d)\n", argv[2], victim_pid);

#ifdef DEBUG
      // Set Option: Kill Tracee when Tracer exits
      ptrace_kill_on_parent_exit(victim_pid);
#endif
      
   } else if (strcmp(argv[1], "-a") == 0) {
      ptrace_attach(atoi(argv[2]));
      
      printf("main(): Done attaching to Process with PID %d)\n", atoi(argv[2]));
   } else {
      wrong_usage();
   }
  
   // Gain code execution inside victim process

#ifndef DEBUG
   if (_launcher_mode)
      // Detach and let injected child continue orphanaged
      ptrace_detach(victim_pid);
#endif

   exit(EXIT_SUCCESS);
}
