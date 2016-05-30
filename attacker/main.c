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

// TODO: tmp (maybe)
pid_t victimPid = -1;

// TODO: tmp
void killChild() {
   if (victimPid != -1) {
      ptrace(PTRACE_DETACH, victimPid, NULL, NULL);
      kill(victimPid, SIGINT);
   }
}

// loads the victim and returns pid
pid_t loadVictim(char* victimPath) {
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

int main(int argc, char* argv[]) {
   if (argc != 2) {
      fprintf(stderr, "Invalid arguments.\nUse: %s <pathToVictim>\n", argv[0]);
      exit(EXIT_INVALIDPARAM);
   }

   signal(SIGINT, killChild);

   victimPid = loadVictim(argv[1]);
   printf("main(): done loading victim (PID: %d)\n", victimPid);
   // TODO: tmp
   while (true) {
      sleep(1);
   }

   killChild(); // TODO: tmp
   exit(EXIT_SUCCESS);
}
