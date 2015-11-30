#include <stdio.h>
#include <unistd.h>

#define true 1
#define false 0

void lefunction() {
   printf("I AM LE INVICIBLE\n");
}

int main(int argc, char* argv[]) {
   while (true) {
      lefunction();
      sleep(2);
   }
}
