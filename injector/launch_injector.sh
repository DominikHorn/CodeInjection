#!/bin/bash

trap "trap - SIGTERM && kill -- -$$; rm injector" SIGINT SIGTERM EXIT

$(gcc -o injector -std=c99 main.c helper.c)
if [[ $? != 0 ]]; then
   echo "An error occured compiling. Exiting..."
   exit
else
   ./injector $1 $2
fi
