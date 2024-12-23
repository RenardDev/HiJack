
// Default
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>

// C
#include <io.h>
#include <fcntl.h>
#include <conio.h>

// C++
#include <clocale>

// STL
#include <string>
#include <unordered_map>
#include <memory>
#include <deque>
#include <algorithm>
#include <cwctype>
#include <cctype>

// Pragmas
#pragma comment(lib, "ntdll")
#pragma comment(lib, "psapi")

// Types
using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;

// General definitions
#define ProcessDebugFlags static_cast<PROCESSINFOCLASS>(0x1F)
#define SafeCloseHandle(x) if ((x) && (x != INVALID_HANDLE_VALUE)) { CloseHandle(x); }

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);

std::unordered_map<DWORD, HANDLE> g_Processes;
bool g_bContinueDebugging = true;

HANDLE g_hStdInput = nullptr;
HANDLE g_hStdOutput = nullptr;
HANDLE g_hStdError = nullptr;

bool EnableDebugPrivilege(HANDLE hProcess, bool bEnable) {
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		_tprintf_s(_T("ERROR: OpenProcessToken (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	LUID luid = {};
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		_tprintf_s(_T("ERROR: LookupPrivilegeValue (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hToken);
		return false;
	}

	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: AdjustTokenPrivileges (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}

tstring GetProcessPath(HANDLE hProcess) {
	TCHAR szProcessPath[MAX_PATH + 1] = {};
	if (!GetProcessImageFileName(hProcess, szProcessPath, _countof(szProcessPath))) {
		return _T("");
	}

	TCHAR szTemp[MAX_PATH * 2] = {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] = {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				size_t unNameLen = _tcslen(szName);

				if (unNameLen < MAX_PATH) {
					bFound = (_tcsnicmp(szProcessPath, szName, unNameLen) == 0) && (*(szProcessPath + unNameLen) == _T('\\'));
					if (bFound) {
						TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szProcessPath + unNameLen);
						StringCchCopyN(szProcessPath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
					}
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	return szProcessPath;
}

tstring GetProcessDirectory(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (ProcessPath.empty()) {
		return _T("");
	}

	TCHAR szDrive[_MAX_DRIVE] = {}, szDir[_MAX_DIR] = {};
	if (_tsplitpath_s(ProcessPath.c_str(), szDrive, _countof(szDrive), szDir, _countof(szDir), nullptr, 0, nullptr, 0) != 0) {
		return _T("");
	}

	TCHAR szProcessDirectory[MAX_PATH] = {};
	if (_stprintf_s(szProcessDirectory, _countof(szProcessDirectory), _T("%s%s"), szDrive, szDir) < 0) {
		return _T("");
	}

	return szProcessDirectory;
}

tstring GetProcessName(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (ProcessPath.empty()) {
		return _T("");
	}

	TCHAR szName[_MAX_DRIVE] = {}, szExt[_MAX_DIR] = {};
	if (_tsplitpath_s(ProcessPath.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt)) != 0) {
		return _T("");
	}

	TCHAR szProcessName[MAX_PATH] = {};
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s%s"), szName, szExt) < 0) {
		return _T("");
	}

	return szProcessName;
}

tstring GetFileNameFromHandle(HANDLE hFile) {
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
	if ((dwFileSizeLo == 0) && (dwFileSizeHi == 0)) {
		return _T("");
	}

	HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 1, nullptr);
	if (!hFileMap || (hFileMap == INVALID_HANDLE_VALUE)) {
		return _T("");
	}

	void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
	if (!pMem) {
		CloseHandle(hFileMap);
		return _T("");
	}

	TCHAR szFileName[MAX_PATH + 1] = {};
	if (!GetMappedFileName(GetCurrentProcess(), pMem, szFileName, _countof(szFileName))) {
		UnmapViewOfFile(pMem);
		CloseHandle(hFileMap);
		return _T("");
	}

	TCHAR szTemp[MAX_PATH * 2] = {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] = {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				size_t unNameLen = _tcslen(szName);

				if (unNameLen < MAX_PATH) {
					bFound = (_tcsnicmp(szFileName, szName, unNameLen) == 0) && (*(szFileName + unNameLen) == _T('\\'));
					if (bFound) {
						TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szFileName + unNameLen);
						StringCchCopyN(szFileName, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
					}
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	TCHAR szName[_MAX_FNAME] = {}, szExt[_MAX_EXT] = {};
	if (_tsplitpath_s(szFileName, nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt)) != 0) {
		return _T("");
	}

	TCHAR szResultFileName[MAX_PATH] = {};
	if (_stprintf_s(szResultFileName, _countof(szResultFileName), _T("%s%s"), szName, szExt) < 0) {
		return _T("");
	}

	tstring result = szResultFileName;

	std::transform(result.begin(), result.end(), result.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return result;
}

tstring GetProcessHiJackLibraryName(HANDLE hProcess) {
	auto ProcessName = GetProcessPath(hProcess);
	if (ProcessName.empty()) {
		return _T("");
	}

	TCHAR szName[_MAX_DRIVE] = {};
	if (_tsplitpath_s(ProcessName.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), nullptr, 0) != 0) {
		return _T("");
	}

	TCHAR szProcessName[MAX_PATH] = {};
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s_hijack.dll"), szName) < 0) {
		return _T("");
	}

	return szProcessName;
}


bool CreateStandardProcess(const TCHAR* szFileName, PTCHAR szCommandLine, PROCESS_INFORMATION& pi) {
	STARTUPINFO si = {};
	si.cb = sizeof(si);

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS | NORMAL_PRIORITY_CLASS, nullptr, nullptr, &si, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool CreateProcessWithParent(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hParentProcess, PROCESS_INFORMATION& pi) {
	STARTUPINFOEX si = {};
	si.StartupInfo.cb = sizeof(si);

	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
	si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attrSize));
	if (!si.lpAttributeList || !InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize) || !UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: Failed to set up process attributes (Error = 0x%08X)\n"), GetLastError());
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS | NORMAL_PRIORITY_CLASS | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, reinterpret_cast<STARTUPINFO*>(&si), &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}

	DeleteProcThreadAttributeList(si.lpAttributeList);
	HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	return true;
}

void CloseHandles(PROCESS_INFORMATION& pi) {
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	pi.hThread = nullptr;
	pi.hProcess = nullptr;
}

bool CreateDebugProcess(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hJob, PPROCESS_INFORMATION pProcessInfo) {
	if (!szFileName) {
		return false;
	}

	PROCESS_BASIC_INFORMATION pbi = {};
	if (!NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3)));
	if (hParentProcess == INVALID_HANDLE_VALUE) {
		hParentProcess = nullptr;
	}

	if (hParentProcess && (GetProcessName(hParentProcess) == _T("explorer.exe"))) {
		CloseHandle(hParentProcess);
		hParentProcess = nullptr;
	}

	PROCESS_INFORMATION pi = {};
	if (!hParentProcess) {
		if (!CreateStandardProcess(szFileName, szCommandLine, pi)) {
			return false;
		}
	} else {
		if (!CreateProcessWithParent(szFileName, szCommandLine, hParentProcess, pi)) {
			return false;
		}

		CloseHandle(hParentProcess);
	}

	if (!pi.hProcess || !pi.hThread) {
		return false;
	}

	if (hJob && (hJob != INVALID_HANDLE_VALUE)) {
		if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandles(pi);
			return false;
		}
	}

	if (SuspendThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		CloseHandles(pi);
		return false;
	}

	if (!NT_SUCCESS(NtResumeProcess(pi.hProcess))) {
		_tprintf_s(_T("ERROR: NtResumeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandles(pi);
		return false;
	}

	if (pProcessInfo) {
		*pProcessInfo = pi;
	}

	return true;
}

void OnCreateProcessEvent(DWORD ProcessId) {
	_tprintf_s(_T("PROCESS CREATE: %lu\n"), ProcessId);
}

void OnExitProcessEvent(DWORD ProcessId) {
	_tprintf_s(_T("PROCESS EXIT: %lu\n"), ProcessId);
}

void OnCreateThreadEvent(DWORD ProcessId, DWORD ThreadId) {
	_tprintf_s(_T("THREAD CREATE: %lu\n"), ThreadId);
}

void OnExitThreadEvent(DWORD ProcessId, DWORD ThreadId) {
	_tprintf_s(_T("THREAD EXIT: %lu\n"), ThreadId);
}

void OnLoadModuleEvent(DWORD ProcessId, LPVOID ImageBase, HANDLE hFile) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

	auto ModuleFileName = GetFileNameFromHandle(hFile);

#ifdef _WIN64
	_tprintf_s(_T("MODULE LOAD: 0x%016llX - %s\n"), reinterpret_cast<size_t>(ImageBase), ModuleFileName.c_str());
#else
	_tprintf_s(_T("MODULE LOAD: 0x%08X - %s\n"), reinterpret_cast<size_t>(ImageBase), ModuleFileName.c_str());
#endif

	if (ModuleFileName == _T("kernelbase.dll")) {
		g_bContinueDebugging = false;

		auto ProcessInjectLibraryName = GetProcessHiJackLibraryName(Process->second);
		if (ProcessInjectLibraryName.empty()) {
			return;
		}

		auto ProcessHiJackLibraryPath = GetProcessDirectory(Process->second) + ProcessInjectLibraryName;
		if (ProcessHiJackLibraryPath.empty()) {
			return;
		}

		DWORD dwAttrib = GetFileAttributes(ProcessHiJackLibraryPath.c_str());
		if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
			return; // Not exist file
		}

		HANDLE hProcessFile = CreateFile(ProcessHiJackLibraryPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!hProcessFile || (hProcessFile == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		HANDLE hMapFile = CreateFileMapping(hProcessFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hProcessFile);
			return;
		}

		void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
		if (!pMap) {
			_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}

		PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
		PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
		if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
			_tprintf_s(_T("ERROR: Invalid PE header!\n"));
			UnmapViewOfFile(pMap);
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}

#ifdef _WIN64
		if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
			_tprintf_s(_T("ERROR: This library cannot be loaded in 64 bit!\n"));
			UnmapViewOfFile(pMap);
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}

		PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
		if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			_tprintf_s(_T("ERROR: Invalid PE header!\n"));
			UnmapViewOfFile(pMap);
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}
#else
		if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
			_tprintf_s(_T("ERROR: This library cannot be loaded in 32 bit!\n"));
			UnmapViewOfFile(pMap);
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}

		PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
		if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			_tprintf_s(_T("ERROR: Invalid PE header!\n"));
			UnmapViewOfFile(pMap);
			CloseHandle(hMapFile);
			CloseHandle(hProcessFile);
			return;
		}
#endif

		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);

		const size_t unProcessDirectoryLength = ProcessHiJackLibraryPath.length() + 1;

		void* pAddress = VirtualAllocEx(Process->second, nullptr, unProcessDirectoryLength * sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pAddress) {
			_tprintf_s(_T("ERROR: VirtualAllocEx (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		if (!WriteProcessMemory(Process->second, pAddress, ProcessHiJackLibraryPath.c_str(), unProcessDirectoryLength * sizeof(TCHAR), nullptr)) {
			_tprintf_s(_T("ERROR: WriteProcessMemory (Error = 0x%08X)\n"), GetLastError());
			return;
		}

#ifdef _UNICODE
		using fnLoadLibraryW = HMODULE(WINAPI*)(LPCWSTR lpLibFileName);
		fnLoadLibraryW pLoadLibraryW = reinterpret_cast<fnLoadLibraryW>(GetProcAddress(reinterpret_cast<HMODULE>(ImageBase), "LoadLibraryW"));
		if (!pLoadLibraryW) {
			_tprintf_s(_T("ERROR: GetProcAddress (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		HANDLE hThread = CreateRemoteThread(Process->second, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), pAddress, 0, nullptr);
		if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateRemoteThread (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		CloseHandle(hThread);
#else
		using fnLoadLibraryA = HMODULE(WINAPI*)(LPCSTR lpLibFileName);
		fnLoadLibraryA pLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(reinterpret_cast<HMODULE>(ImageBase), "LoadLibraryA"));
		if (!pLoadLibraryA) {
			_tprintf_s(_T("ERROR: GetProcAddress (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		HANDLE hThread = CreateRemoteThread(Process->second, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryA), pAddress, 0, nullptr);
		if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateRemoteThread (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		CloseHandle(hThread);
#endif
	}
}

void OnUnloadModuleEvent(DWORD ProcessId, LPVOID ImageBase) {
#ifdef _WIN64
	_tprintf_s(_T("MODULE UNLOAD: 0x%016llX\n"), reinterpret_cast<size_t>(ImageBase));
#else
	_tprintf_s(_T("MODULE UNLOAD: 0x%08X\n"), reinterpret_cast<size_t>(ImageBase));
#endif
}

void OnExceptionEvent(DWORD ProcessId, DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Info) {
	_tprintf_s(_T("EXCEPTION (%s)\n"), Info.dwFirstChance ? _T("first-chance") : _T("second-chance"));
	_tprintf_s(_T("  CODE:       0x%08X\n"), Info.ExceptionRecord.ExceptionCode);
#ifdef _WIN64
	_tprintf_s(_T("  ADDRESS:    0x%016llX\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#else
	_tprintf_s(_T("  ADDRESS:    0x%08X\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#endif
	_tprintf_s(_T("  THREAD ID:  %lu\n"), ThreadId);
	_tprintf_s(_T("  FLAGS:      0x%08X\n"), Info.ExceptionRecord.ExceptionFlags);
	_tprintf_s(_T("  PARAMETERS: %lu\n"), Info.ExceptionRecord.NumberParameters);

	DWORD NumberParameters = Info.ExceptionRecord.NumberParameters;
	if (NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS) {
		NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
	}

	for (DWORD i = 0; i < NumberParameters; ++i) {
#ifdef _WIN64
		_tprintf_s(_T("    PARAM[%d]: 0x%016llX\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#else
		_tprintf_s(_T("    PARAM[%d]: 0x%08X\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#endif
	}
}

void OnDebugStringEvent(DWORD ProcessId, DWORD ThreadId, const OUTPUT_DEBUG_STRING_INFO& Info) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

	if ((Info.lpDebugStringData == 0) || (Info.nDebugStringLength == 0)) {
		return;
	}

	const SIZE_T cMaxChars = 8192;

	if (Info.fUnicode) {
		static WCHAR Buffer[cMaxChars + 1] = {};

		SIZE_T CharsToRead = Info.nDebugStringLength;

		if (CharsToRead > cMaxChars) {
			CharsToRead = cMaxChars;
		}

		SIZE_T BytesRead = 0;

		if (!ReadProcessMemory(Process->second, Info.lpDebugStringData, Buffer, CharsToRead * sizeof(WCHAR), &BytesRead) || (BytesRead == 0)) {
			return;
		}

		wprintf(L"ODS(%u): %s\n", ThreadId, Buffer);
	}
	else {
		static CHAR Buffer[cMaxChars + 1] = {};

		SIZE_T CharsToRead = Info.nDebugStringLength;

		if (CharsToRead > cMaxChars) {
			CharsToRead = cMaxChars;
		}

		SIZE_T BytesRead = 0;

		if (!ReadProcessMemory(Process->second, Info.lpDebugStringData, Buffer, CharsToRead * sizeof(CHAR), &BytesRead) || (BytesRead == 0)) {
			return;
		}

		printf("ODS(%u): %s\n", ThreadId, Buffer);
	}
}

void OnTimeout() {
	_tprintf_s(_T("TIMEOUT!\n"));
}

bool DebugProcess(DWORD unTimeout, bool* pbContinue, bool* pbStopped) {
	if (!pbContinue) {
		return false;
	}

	DEBUG_EVENT DebugEvent;
	bool bSeenInitialBreakpoint = false;

	while (*pbContinue) {
		if (WaitForDebugEvent(&DebugEvent, unTimeout)) {
			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:
					g_Processes[DebugEvent.dwProcessId] = DebugEvent.u.CreateProcessInfo.hProcess;
					OnCreateProcessEvent(DebugEvent.dwProcessId);
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage, DebugEvent.u.CreateProcessInfo.hFile);
					SafeCloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
					break;

				case EXIT_PROCESS_DEBUG_EVENT:
					OnExitProcessEvent(DebugEvent.dwProcessId);
					g_Processes.erase(DebugEvent.dwProcessId);
					if (g_Processes.empty()) {
						*pbContinue = false;
						*pbStopped = true;
					}

					break;

				case CREATE_THREAD_DEBUG_EVENT:
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					break;

				case EXIT_THREAD_DEBUG_EVENT:
					OnExitThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					break;

				case LOAD_DLL_DEBUG_EVENT:
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.LoadDll.lpBaseOfDll, DebugEvent.u.LoadDll.hFile);
					SafeCloseHandle(DebugEvent.u.LoadDll.hFile);
					break;

				case UNLOAD_DLL_DEBUG_EVENT:
					OnUnloadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.UnloadDll.lpBaseOfDll);
					break;

				case OUTPUT_DEBUG_STRING_EVENT:
					OnDebugStringEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.DebugString);
					break;

				case RIP_EVENT:
					break;

				case EXCEPTION_DEBUG_EVENT:
					OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception);
					ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
					if (!bSeenInitialBreakpoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {
						ContinueStatus = DBG_CONTINUE;
						bSeenInitialBreakpoint = true;
					}

					break;
			}

			if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus)) {
				return false;
			}
		} else {
			if (GetLastError() == ERROR_SEM_TIMEOUT) {
				OnTimeout();
			} else {
				return false;
			}
		}
	}

	return true;
}

int _tmain(int argc, PTCHAR argv[], PTCHAR envp[]) {
	_tprintf_s(_T("HiJack [Version 1.0.0]\n\n"));

	if (argc < 2) {
		_tprintf_s(_T("Usage variations:\n"));
		_tprintf_s(_T("  <Path> <Arguments>\n"));
		_tprintf_s(_T("  /add <Filename>\n"));
		_tprintf_s(_T("  /remove <Filename>\n"));
		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/add")) == 0) {
		if (argc < 3) {
			_tprintf_s(_T("Usage variations:\n"));
			_tprintf_s(_T("  <Path> <Arguments>\n"));
			_tprintf_s(_T("  /add <Filename>\n"));
			_tprintf_s(_T("  /remove <Filename>\n"));
			return EXIT_SUCCESS;
		}

		TCHAR szKey[MAX_PATH] = {};
		if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), argv[2]) < 0) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		HKEY hKey = nullptr;
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		auto ProcessPath = GetProcessPath(GetCurrentProcess());
		if (ProcessPath.empty()) {
			return EXIT_FAILURE;
		}

		if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(ProcessPath.c_str()), (static_cast<DWORD>(ProcessPath.length()) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegSetValueEx (Error = 0x%08X)\n"), GetLastError());
			RegCloseKey(hKey);
			return EXIT_FAILURE;
		}

		_tprintf_s(_T("ADDED!\n"));

		RegCloseKey(hKey);
		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/remove")) == 0) {
		if (argc < 3) {
			_tprintf_s(_T("Usage variations:\n"));
			_tprintf_s(_T("  <Path> <Arguments>\n"));
			_tprintf_s(_T("  /add <Filename>\n"));
			_tprintf_s(_T("  /remove <Filename>\n"));
			return EXIT_SUCCESS;
		}

		TCHAR szKey[MAX_PATH] = {};
		if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), argv[2]) < 0) {
			return EXIT_FAILURE;
		}

		HKEY hKey = nullptr;
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_READ | KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		RegDeleteValue(hKey, _T("Debugger"));

		DWORD unKeysCount = 0;
		if (RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, &unKeysCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegQueryInfoKey (Error = 0x%08X)\n"), GetLastError());
			RegCloseKey(hKey);
			return EXIT_SUCCESS;
		}

		RegCloseKey(hKey);

		if (!unKeysCount) {
			if (RegDeleteKey(HKEY_LOCAL_MACHINE, szKey) != ERROR_SUCCESS) {
				_tprintf_s(_T("WARNING: RegDeleteKey (Error = 0x%08X)\n"), GetLastError());
			}
		}

		_tprintf_s(_T("REMOVED!\n"));
		return EXIT_SUCCESS;
	}

	TCHAR szResultPath[MAX_PATH] = {};
	DWORD unPathLength = SearchPath(nullptr, argv[1], nullptr, MAX_PATH, szResultPath, nullptr);
	if (!((unPathLength > 0) && (unPathLength < MAX_PATH))) {
		TCHAR szExecutableName[MAX_PATH] = {};
		if (_stprintf_s(szExecutableName, _countof(szExecutableName), _T("%s.exe"), argv[1]) < 0) {
			return EXIT_FAILURE;
		}

		memset(szResultPath, 0, sizeof(szResultPath));

		unPathLength = SearchPath(nullptr, szExecutableName, nullptr, MAX_PATH, szResultPath, nullptr);
		if (!((unPathLength > 0) && (unPathLength < MAX_PATH))) {
			_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}
	}

	HANDLE hProcessFile = CreateFile(szResultPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hProcessFile || (hProcessFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	HANDLE hMapFile = CreateFileMapping(hProcessFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This process cannot be run in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}
#else
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This process cannot be run in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		return EXIT_FAILURE;
	}
#endif

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hProcessFile);

	HANDLE hJob = CreateJobObject(nullptr, nullptr);
	if (!hJob || (hJob == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateJobObject (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION joli = {};
	joli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &joli, sizeof(joli))) {
		_tprintf_s(_T("ERROR: SetInformationJobObject (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	tstring CommandLine = _T("");
	for (int i = 1; i < argc; ++i) {
		if (i != 1) {
			CommandLine += argv[i];
		}
		else {
			CommandLine += _T('"');
			CommandLine += argv[i];
			CommandLine += _T('"');
		}

		if (i + 1 < argc) {
			CommandLine += _T(' ');
		}
	}

	auto pCommandLine = std::make_unique<TCHAR[]>(CommandLine.size() + 1);
	if (!pCommandLine) {
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	std::copy(CommandLine.begin(), CommandLine.end(), pCommandLine.get());

	pCommandLine[CommandLine.size()] = _T('\0');

	PROCESS_INFORMATION pi = {};
	if (!CreateDebugProcess(szResultPath, pCommandLine.get(), hJob, &pi)) {
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (ResumeThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	bool bStopped = false;
	if (!DebugProcess(INFINITE, &g_bContinueDebugging, &bStopped)) {
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (bStopped) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (SuspendThread(pi.hThread) != 0) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unDebugFlags = 0;
	if (!NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags), nullptr))) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	unDebugFlags = 1;

	if (!NT_SUCCESS(NtSetInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags)))) {
		_tprintf_s(_T("ERROR: NtSetInformationProcess (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (!DebugActiveProcessStop(pi.dwProcessId)) {
		_tprintf_s(_T("ERROR: DebugActiveProcessStop (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (!EnableDebugPrivilege(GetCurrentProcess(), false)) {
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (ResumeThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unExitCode = EXIT_FAILURE;
	if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	return unExitCode;
}
