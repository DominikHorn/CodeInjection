#include <stdio.h>
#include <unistd.h>

#define true 1
#define false 0

void lefunction() {
   static int counter = 0;
   printf("I AM LE INVICIBLE: %d\n", counter++);
}

int main(int argc, char* argv[]) {
   while (true) {
      lefunction();
      sleep(1);
   }
}
