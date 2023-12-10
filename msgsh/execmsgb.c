#include <windows.h>
#include <stdio.h>

typedef int(WINAPI* MsgBoxPtr)(HWND, LPCSTR, LPCSTR, UINT);

int
main() {
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (user32 != NULL) {
        MsgBoxPtr MessageBoxA = (MsgBoxPtr)GetProcAddress(user32, "MessageBoxA");
        if (MessageBoxA != NULL) {
            MessageBoxA(NULL, "Hello, World!", "MessageBox Example", MB_OK);
        } else {
            printf("MessageBoxA function not found!\n");
        }
        FreeLibrary(user32);
    } else {
        printf("user32.dll not found!\n");
    }

    return 0;
}
