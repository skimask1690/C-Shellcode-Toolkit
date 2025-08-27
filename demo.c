// Build: x86_64-w64-mingw32-gcc -s demo.c -nostdlib -nostartfiles -ffreestanding -fno-ident -Wl,-subsystem,windows -e _start -Os -fPIC -fno-asynchronous-unwind-tables -T linker.ld -o demo.exe

#define DLL_NAME_MAX_LENGTH 17 // aligned stack

#include "winapi_loader.h"

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

__attribute__((section(".text"))) static char user32_dll[]  = "user32.dll";
__attribute__((section(".text"))) static char messageboxa[] = "MessageBoxA";
__attribute__((section(".text"))) static char hello_msg[]   = "Hello from shellcode!";
__attribute__((section(".text"))) static char title_msg[]   = "C Shellcode Demo";

__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hUser32 = customLoadLibraryA(user32_dll);
    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)customGetProcAddress(hUser32, messageboxa);
    pMessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
}
