
#include "framework.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			AllocConsole();

			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			if (!hConsole || (hConsole == INVALID_HANDLE_VALUE)) {
				return FALSE;
			}

			DWORD unWritten = 0;
			WriteConsoleA(hConsole, "[DLL_PROCESS_ATTACH] Hello, World!\n", 35, &unWritten, nullptr);

			break;
		}
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH: {
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			if (!hConsole || (hConsole == INVALID_HANDLE_VALUE)) {
				return TRUE;
			}

			DWORD unWritten = 0;
			WriteConsoleA(hConsole, "[DLL_PROCESS_DETACH] Hello, World!\n", 35, &unWritten, nullptr);

			break;
		}
	}

	return TRUE;
}
