@echo off
rm msgsh.exe
nasm -f win64 -o msgsh.o msgsh.asm
ld -s -o msgsh.exe msgsh.o
