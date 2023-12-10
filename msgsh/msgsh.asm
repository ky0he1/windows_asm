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

; "LoadLibraryA" to resolve addresses
    xor rcx, rcx
    add cl, 0x7                 ; String length for compare string
    mov rax, 0x7262694C64616F4C ; rbiLdaoL
    lea rsi, [rax]              ; RSI = "LoadLibr"
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
    mov r13, rax                ; R13 = Kernel32.LoadLibraryA Address


; "GetProcAddress" to resolve addresses
    xor rcx, rcx
    add cl, 0x7                 ; String length for compare string
    mov rax, 0x41636f7250746547 ; rbiLdaoL
    lea rsi, [rax]              ; RSI = "AcorPteG"
    xor rax, rax                ; Setup Counter for resolving the API Address after finding the name string
    loop2:
    xor rcx, rcx
    add cl, 0x7                 ; String length for compare string
    xor rdi,rdi             ; Clear RDI for setting up string name retrieval
    mov edi, [r11+rax*4]    ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
    add rdi, r8             ; RDI = &NameString    = RVA NameString + &kernel32.dll
    mov rdi, [rdi]
    cmp rsi, rdi            ; if RDX == RDI { jmp resolveraddr }
    je resolveaddr2
    inc rax
    jmp short loop2

resolveaddr2:
    mov ax, [r12+rax*2]
    mov eax, [r10+rax*4]
    add rax, r8
    mov r14, rax                ; R14 = Kernel32.GetProcAddress Address

; HMODULE LoadLibraryA(
;   [in] LPCSTR lpLibFileName
; );
    mov rcx, 0x6c6c             ; ll
    push rcx
    mov rcx, 0x642e323372657375 ; .23resu
    push rcx
    mov rcx, rsp                ; lpLibFileName(RCX) = user32.dll
    sub rsp, 0x18
    call r13                    ; Call LoadLibraryA

    add rsp, 0x18               ; LoadLibraryA 用のスタック分
    add rsp, 0x10               ; 文字列用のスタック分
    mov r15, rax                ; R15 = Base address of user32.dll


; FARPROC GetProcAddress(
;   [in] HMODULE hModule,       <- RCX
;   [in] LPCSTR  lpProcName     <- RDX
; );
    mov rcx, 0x41786f           ; Axo
    push rcx
    mov rcx, 0x426567617373654d   ; BegasseM
    push rcx
    mov rdx, rsp                ; lpProcName(RDX) = MessageBoxA
    mov rcx, r15                ; hHodule(RCX) = user32.dll
    sub rsp, 0x28
    call r14                    ; Call GetProcAddress

    add rsp, 0x28
    add rsp, 0x10
    mov r12, rax                ; R12 = MessageBoxA

; int MessageBoxA(
;   [in, optional] HWND   hWnd,         <- RCX
;   [in, optional] LPCSTR lpText,       <- RDX
;   [in, optional] LPCSTR lpCaption,    <- R8
;   [in]           UINT   uType         <- R9
; );
    sub rsp, 0x8
    xor r9, r9                  ; R8 = 0
    mov r8, 0x656c746954        ; eltiT
    push r8
    mov r8, rsp
    mov rdx, 0x6f6c6c6548       ; olleH
    push rdx
    mov rdx, rsp
    xor rcx, rcx                ; RCX = NULL
    call r12
