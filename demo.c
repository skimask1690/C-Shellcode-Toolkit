// Build: x86_64-w64-mingw32-gcc -s demo.c -nostdlib -nostartfiles -ffreestanding -fno-ident -Wl,-subsystem,windows -e _start -Os -fPIC -fno-asynchronous-unwind-tables -T linker.ld -o demo.exe

#include "winapi_loader.h"

// -------------------- Function pointer type --------------------
typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

// -------------------- Strings --------------------
STRING(user32_dll, "user32.dll")
STRING(messageboxa, "MessageBoxA")
STRING(hello_msg, "Hello from shellcode!")
STRING(title_msg, "C Shellcode Demo")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hUser32 = myLoadLibraryA(user32_dll);
    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)myGetProcAddress(hUser32, messageboxa);
    pMessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
}
