#!/bin/bash

trap "rm injector; trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

$(gcc -o injector -std=c99 -ldl main.c helper.c injector_x86_64.c)
if [[ $? != 0 ]]; then
   echo "An error occured compiling. Exiting..."
   exit
else
   ./injector $1 $2
fi
