#include <windows.h>

// -------------------- PEB structs --------------------
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

// -------------------- Module lookup --------------------
HMODULE myGetModuleHandleA(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ent = (LDR_DATA_TABLE_ENTRY*)((BYTE*)cur - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        SIZE_T len = ent->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;
        for (i = 0; i < len; ++i) {
            if (((char)(ent->BaseDllName.Buffer[i] | 0x20)) != (char)(name[i] | 0x20))
                break;
        }
        if (i == len && name[i] == 0) return (HMODULE)ent->DllBase;
    }
    return NULL;
}

// -------------------- Function lookup --------------------
FARPROC myGetProcAddress(HMODULE hMod, const char* fnName) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nameInExport = (const char*)(base + names[i]);
        const char* targetName = fnName;
        int match = 1;
        while (*nameInExport && *targetName) {
            if ((*nameInExport | 0x20) != (*targetName | 0x20)) {
                match = 0;
                break;
            }
            ++nameInExport;
            ++targetName;
        }
        if (match && *targetName == 0)
            return (FARPROC)(base + (SIZE_T)funcs[ords[i]]);
    }
    return NULL;
}

// -------------------- ASCII to Unicode helper --------------------
static void AsciiToWideChar(const char* ascii, UNICODE_STRING* ustr, wchar_t* buf, SIZE_T bufCount) {
    SIZE_T i = 0;
    while (ascii[i] && i < bufCount - 1) {
        buf[i] = (wchar_t)ascii[i];
        i++;
    }
    buf[i] = 0;

    ustr->Length = (USHORT)(i * sizeof(wchar_t));
    ustr->MaximumLength = (USHORT)((i + 1) * sizeof(wchar_t));
    ustr->Buffer = buf;
}

// -------------------- LdrLoadDll wrapper --------------------
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
    PWSTR PathToFile,
    ULONG Flags,
    UNICODE_STRING* ModuleFileName,
    PHANDLE ModuleHandle
);

HMODULE myLoadLibraryA(const char* dllNameA) {
    unsigned char stackbuf[21];
    char* ntdll_dll   = (char*)&stackbuf[0];   // 10 bytes
    char* ldrloaddll  = (char*)&stackbuf[10];  // 11 bytes

    ntdll_dll[0] = 'n'; ntdll_dll[1] = 't'; ntdll_dll[2] = 'd';
    ntdll_dll[3] = 'l'; ntdll_dll[4] = 'l'; ntdll_dll[5] = '.';
    ntdll_dll[6] = 'd'; ntdll_dll[7] = 'l'; ntdll_dll[8] = 'l';
    ntdll_dll[9] = 0;

    ldrloaddll[0] = 'L'; ldrloaddll[1] = 'd'; ldrloaddll[2] = 'r';
    ldrloaddll[3] = 'L'; ldrloaddll[4] = 'o'; ldrloaddll[5] = 'a';
    ldrloaddll[6] = 'd'; ldrloaddll[7] = 'D'; ldrloaddll[8] = 'l';
    ldrloaddll[9] = 'l'; ldrloaddll[10] = 0;

    wchar_t buf[17]; // aligned stack
    UNICODE_STRING ustr;
    AsciiToWideChar(dllNameA, &ustr, buf, sizeof(buf)/sizeof(buf[0]));

    HMODULE hModule = NULL;

    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);
    LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)myGetProcAddress(hNtdll, ldrloaddll);

    pLdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hModule);

    return hModule;
}
