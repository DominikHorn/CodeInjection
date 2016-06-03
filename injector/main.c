#define _POSIX_SOURCE
#include <stdio.h>
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
#include "injector_x86_64.h"

short _launcher_mode = false;

void wrong_usage(char* prog_name) {
   fprintf(stderr, "Invalid arguments.\nUse: %s -l <PATH> or %s -a <PID>\n", prog_name, prog_name);
   exit(EXIT_INVALIDPARAM);
}

// loads the remote and returns pid
pid_t launch_remote_and_trace(char* remote_path) {
   pid_t pid = fork();
   if (pid == false) {
      // Prep for ptrace
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);

      // Load remote
      char* argv[] = {getLastPathComponent(remote_path), NULL};
      execv(remote_path, argv);
      fprintf(stderr, "Could not load remote (%s)!\n", remote_path);
      exit(EXIT_NOREMOTE);
   } else if (pid == -1) {
      fprintf(stderr, "Could not fork!\n");
      exit(EXIT_ERRORFORK);
   }

   return pid;
}

int main(int argc, char* argv[]) {
   int status = -1;
   pid_t remote_pid = 0;

   if (argc != 3) {
      wrong_usage(argv[0]);
   }
   
   // launch remote and trace  
   if (strcmp(argv[1], "-l") == 0) {
      _launcher_mode = true;
      remote_pid = launch_remote_and_trace(argv[2]);
 
      printf("main(): Done launching. (Binary: %s, PID: %d)\n", argv[2], remote_pid);
   } else if (strcmp(argv[1], "-a") == 0) {
      // get pid and attach
      remote_pid = atoi(argv[2]);
      ptrace_attach(remote_pid);
      
      printf("main(): Done attaching to Process with PID %d)\n", remote_pid);
   } else {
      wrong_usage(argv[0]);
   }
  
   // Wait for Tracee to stop
   waitpid(remote_pid, &status, 0);
   
   // Gain code execution inside remote process
   gain_code_exec(remote_pid);
   
   // Restore remote process and continue
   restore_remote(remote_pid);
   
   exit(EXIT_SUCCESS);
}
