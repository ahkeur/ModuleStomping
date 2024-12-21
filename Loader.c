#include <windows.h>

// Simple DLL loader

BOOL LoadMyLibrary() {
    HMODULE hModule = LoadLibrary("C:\\Windows\\System32\\amsi.dll");
    if (hModule == NULL) {
        printf("Failed to load library\n");
        return FALSE;
    }
    return TRUE;
}

void main() {
    HMODULE hModule = LoadLibrary("stomp.dll");
    if (hModule == NULL) {
        printf("Failed to load library\n");
        return;
    }
    printf("Library loaded\n");
    typedef void (*StartWFunc)();
    StartWFunc StartW = (StartWFunc)GetProcAddress(hModule, "StartW");
    if (StartW == NULL) {
        printf("Failed to find StartW function\n");
        return;
    }
    StartW();
}