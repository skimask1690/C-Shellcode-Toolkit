# ⚙️ C Shellcode Toolkit

This project demonstrates a **minimal Windows loader** that dynamically resolves DLLs and functions **without using the C runtime or static imports**. It shows how to:

- Access the Windows **PEB (Process Environment Block)** to enumerate loaded modules.
- Implement custom versions of `GetModuleHandleA` and `GetProcAddress`.
- Load additional DLLs (`LdrLoadDll`) at runtime.
- Call functions (like `MessageBoxA`) dynamically.

---

## 🔹 Features

### WinAPI Loader
- Manual module resolution through the PEB.
- Manual export resolution from PE export tables.
- Dynamic `LoadLibraryA` / `GetProcAddress` usage without static imports.
- Freestanding (no CRT / no standard startup files).
- Minimal, lightweight shellcode.

### Shellcode Loader
- Loads shellcode from disk.
- Allocates memory and sets it executable (`VirtualAlloc` / `VirtualProtect`).
- Jumps to the entry point in memory.
- Cleans up memory after execution.

---

## 🔹 Build Instructions

Requires `gcc` targeting 64-bit Windows

Build the demo:
```bash
x86_64-w64-mingw32-gcc -s demo.c -nostdlib -nostartfiles -ffreestanding -fno-ident -Wl,-subsystem,windows -e _start -Os -fPIC -fno-asynchronous-unwind-tables -T linker.ld -o demo.exe
```

Extract shellcode from .text:
```bash
objcopy -O binary --only-section=.text demo.exe shellcode.bin
```

Build the shellcode loader:
```bash
x86_64-w64-mingw32-gcc shellcode_loader.c -o loader.exe
```

## 🔹 Usage
Run the loader and pass the shellcode as an argument:
```bash
loader.exe shellcode.bin
```
This will load the shellcode into memory and execute it.

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

## 📜 License

This project is released under the [MIT License](LICENSE).







