@echo off
rm mycalc.exe
nasm -f win64 -o mycalc.o mycalc.asm
ld -s -o mycalc.exe mycalc.o
