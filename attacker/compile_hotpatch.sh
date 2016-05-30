#!/bin/bash
nasm -f elf64 -o hotpatch.o hotpatch.asm
ld -o hotpatch hotpatch.o

