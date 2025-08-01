
#include "framework.h"

// Use only NTDLL/kernel32/kernelbase APIs because HiJack uses LdrGetDllHandle instead of LdrLoadDll

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            AllocConsole();

            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            if (!hConsole || (hConsole == INVALID_HANDLE_VALUE)) {
                return FALSE;
            }

            DWORD unWritten = 0;
            WriteConsoleA(hConsole, "Hello, World!\n", 14, &unWritten, nullptr);

            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
