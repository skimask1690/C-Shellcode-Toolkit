import os
import sys
import subprocess

def compile_to_shellcode(input_c, output_bin, use_xor=False):
    output_exe = "temp_compile.exe"
    
    compile_cmd = [
        "x86_64-w64-mingw32-gcc",
        "-s", input_c,
        "-nostdlib", "-nostartfiles", "-ffreestanding",
        "-fno-ident", "-Wl,-subsystem,windows", "-e", "_start",
        "-Os", "-fPIC", "-fno-asynchronous-unwind-tables", 
        "-T", "linker.ld",
        "-o", output_exe
    ]
    
    if use_xor:
        compile_cmd.append("-DXOR")
    
    objcopy_cmd = [
        "objcopy",
        "-O", "binary",
        "--only-section=.text",
        output_exe,
        output_bin
    ]

    try:
        subprocess.run(compile_cmd, check=True)
        subprocess.run(objcopy_cmd, check=True)

        print("[+] Shellcode generated: " + output_bin)
        os.remove(output_exe)

    except subprocess.CalledProcessError:
        sys.exit(1)

if len(sys.argv) < 3:
    print(f"Usage: {os.path.basename(sys.argv[0])} <input.c> <output.bin> [-xor]")
    sys.exit(1)
    
input_c = sys.argv[1]
output_bin = sys.argv[2]
use_xor = "-xor" in sys.argv[3:]
    
compile_to_shellcode(input_c, output_bin, use_xor)
