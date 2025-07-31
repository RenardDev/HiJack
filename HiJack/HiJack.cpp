
// Default
#include <Windows.h>
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
#include <array>
#include <string>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <cwctype>
#include <cctype>

// Pragmas
#pragma comment(lib, "ntdll")
#pragma comment(lib, "psapi")

// Types
using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
using tstring_optional = std::pair<bool, tstring>;

// General definitions

#define HIJACK_VERSION "1.4.3"

#define ProcessDebugObjectHandle static_cast<PROCESSINFOCLASS>(0x1E)
#define ProcessDebugFlags static_cast<PROCESSINFOCLASS>(0x1F)
#define SafeCloseHandle(x) if ((x) && (x != INVALID_HANDLE_VALUE)) { CloseHandle(x); }
#define FileStandardInformation static_cast<FILE_INFORMATION_CLASS>(5)

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);

// [{
//     PID: (HANDLE, START ADDRESS)
// }]
std::unordered_map<DWORD, std::pair<HANDLE, LPVOID>> g_Processes;

// [{
//     PID: ORIGINAL BYTES
// }]
std::unordered_map<DWORD, std::vector<unsigned char>> g_ProcessesOriginalEntryPointByte;


// [{
//     PID: [{
//         TID: (HANDLE, START ADDRESS)
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, std::pair<HANDLE, LPVOID>>> g_Threads;

// [{
//     PID: [{
//         BASE ADDRESS: FULL MODULE PATH
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, tstring_optional>> g_Modules;

bool g_bContinueDebugging = true;

bool IsRunningAsAdmin() {
	SID_IDENTIFIER_AUTHORITY NT_AUTHORITY = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup = nullptr;
	if (!AllocateAndInitializeSid(&NT_AUTHORITY, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
		_tprintf_s(_T("ERROR: AllocateAndInitializeSid (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	BOOL bIsAdmin = FALSE;
	if (!CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin)) {
		_tprintf_s(_T("ERROR: CheckTokenMembership (Error = 0x%08X)\n"), GetLastError());
		FreeSid(AdministratorsGroup);
		return false;
	}

	return bIsAdmin;
}

bool ReLaunchAsAdmin(bool bAllowCancel = false) {
	TCHAR szPath[MAX_PATH];
	if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
		return false;
	}

	LPCTSTR szCommandLine = GetCommandLine();
	LPCTSTR szArguments = _tcsstr(szCommandLine, _T(" "));
	if (!szArguments) {
		_tprintf_s(_T("ERROR: _tcsstr\n"));
		return false;
	}

	SHELLEXECUTEINFO sei {};
	sei.cbSize = sizeof(sei);
	sei.lpVerb = _T("runas");
	sei.lpFile = szPath;
	sei.lpParameters = szArguments;
	sei.nShow = SW_NORMAL;

	if (!ShellExecuteEx(&sei)) {
		if (bAllowCancel && (GetLastError() == ERROR_CANCELLED)) {
			return true;
		}

		_tprintf_s(_T("ERROR: ShellExecuteEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool EnableDebugPrivilege(HANDLE hProcess, bool bEnable) {
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		_tprintf_s(_T("ERROR: OpenProcessToken (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	LUID luid {};
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		_tprintf_s(_T("ERROR: LookupPrivilegeValue (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hToken);
		return false;
	}

	TOKEN_PRIVILEGES tp {};
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

tstring_optional GetProcessPath(HANDLE hProcess) {
	TCHAR szProcessPath[MAX_PATH + 1] {};
	if (!GetProcessImageFileName(hProcess, szProcessPath, _countof(szProcessPath))) {
		_tprintf_s(_T("ERROR: GetProcessImageFileName (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	TCHAR szTemp[MAX_PATH * 2] {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				size_t unNameLength = _tcslen(szName);

				if (unNameLength < MAX_PATH) {
					bFound = (_tcsnicmp(szProcessPath, szName, unNameLength) == 0) && (*(szProcessPath + unNameLength) == _T('\\'));
					if (bFound) {
						TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szProcessPath + unNameLength);
						StringCchCopyN(szProcessPath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
					}
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	return { true, szProcessPath };
}

tstring_optional GetProcessDirectory(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (!ProcessPath.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(ProcessPath.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szProcessDirectory[MAX_PATH] {};
	if (_stprintf_s(szProcessDirectory, _countof(szProcessDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szProcessDirectory };
}

tstring_optional GetProcessName(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (!ProcessPath.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(ProcessPath.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szProcessName[MAX_PATH] {};
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring ProcessName = szProcessName;

	std::transform(ProcessName.begin(), ProcessName.end(), ProcessName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, ProcessName };
}

tstring_optional GetFilePath(HANDLE hFile) {
	HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 1, nullptr);
	if (!hFileMap || (hFileMap == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
	if (!pMem) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFileMap);
		return { false, _T("") };
	}

	TCHAR szFilePath[MAX_PATH + 1] {};
	if (!GetMappedFileName(GetCurrentProcess(), pMem, szFilePath, _countof(szFilePath))) {
		_tprintf_s(_T("ERROR: GetMappedFileName (Error = 0x%08X)\n"), GetLastError());
		UnmapViewOfFile(pMem);
		CloseHandle(hFileMap);
		return { false, _T("") };
	}

	UnmapViewOfFile(pMem);
	CloseHandle(hFileMap);

	TCHAR szTemp[MAX_PATH * 2] {};
	if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
		TCHAR szName[MAX_PATH] {};
		TCHAR szDrive[3] = _T(" :");
		bool bFound = false;
		PTCHAR p = szTemp;

		do {
			*szDrive = *p;

			if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
				size_t unNameLength = _tcslen(szName);

				if (unNameLength < MAX_PATH) {
					bFound = (_tcsnicmp(szFilePath, szName, unNameLength) == 0) && (*(szFilePath + unNameLength) == _T('\\'));
					if (bFound) {
						TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szFilePath + unNameLength);
						StringCchCopyN(szFilePath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
					}
				}
			}

			while (*p++);
		} while (!bFound && *p);
	}

	return { true, szFilePath };
}

tstring_optional GetFileDirectory(HANDLE hFile) {
	auto FilePath = GetFilePath(hFile);
	if (!FilePath.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(FilePath.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileDirectory[MAX_PATH] {};
	if (_stprintf_s(szFileDirectory, _countof(szFileDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szFileDirectory };
}

tstring_optional GetFileName(HANDLE hFile) {
	auto FilePath = GetFilePath(hFile);
	if (!FilePath.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(FilePath.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileName[MAX_PATH] {};
	if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring FileName = szFileName;

	std::transform(FileName.begin(), FileName.end(), FileName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, FileName };
}

bool CreateStandardProcess(const TCHAR* szFileName, PTCHAR szCommandLine, PROCESS_INFORMATION& pi) {
	STARTUPINFO si {};
	si.cb = sizeof(si);

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool CreateProcessWithParent(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hParentProcess, PROCESS_INFORMATION& pi) {
	STARTUPINFOEX si {};
	si.StartupInfo.cb = sizeof(si);

	/* FIXME: Changing parent is unstable and currently impossible to redirect stdin/stdout in right way
	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, 2, 0, &attrSize);
	si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attrSize));
	if (!si.lpAttributeList ||
		!InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attrSize) ||
		!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: Failed to set up process attributes (Error = 0x%08X)\n"), GetLastError());
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}
	*/

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		//DeleteProcThreadAttributeList(si.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
		return false;
	}

	//DeleteProcThreadAttributeList(si.lpAttributeList);
	//HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	return true;
}

bool CreateDebugProcess(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hJob, PPROCESS_INFORMATION pProcessInfo) {
	if (!szFileName) {
		return false;
	}

	PROCESS_BASIC_INFORMATION pbi {};
	if (!NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HANDLE hParentProcess = nullptr;

	DWORD unParentPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3));
	if (unParentPID) {
		hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unParentPID);
		if (hParentProcess == INVALID_HANDLE_VALUE) {
			hParentProcess = nullptr;
		}
	}

	auto ProcessName = GetProcessName(hParentProcess);
	if (ProcessName.second == _T("wininit.exe")) {
		_tprintf_s(_T("ERROR: Parent process is `wininit.exe`!\n"));
		return false;
	}

	if (hParentProcess && ProcessName.first && ((ProcessName.second == _T("services.exe")) || (ProcessName.second == _T("explorer.exe")))) {
		CloseHandle(hParentProcess);
		hParentProcess = nullptr;
	}

	PROCESS_INFORMATION pi {};
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
			_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return false;
		}
	}

	if (SuspendThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	if (!NT_SUCCESS(NtResumeProcess(pi.hProcess))) {
		_tprintf_s(_T("ERROR: NtResumeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	if (pProcessInfo) {
		*pProcessInfo = pi;
	}

	return true;
}

HANDLE GetDebugProcess(DWORD unProcessID, LPVOID* ppStartAddress = nullptr) {
	auto Process = g_Processes.find(unProcessID);
	if (Process == g_Processes.end()) {
		return nullptr;
	}

	if (ppStartAddress) {
		*ppStartAddress = Process->second.second;
	}

	return Process->second.first;
}

HANDLE GetDebugThread(DWORD unProcessID, DWORD unThreadID, LPVOID* ppStartAddress = nullptr) {
	auto ProcessThreads = g_Threads.find(unProcessID);
	if (ProcessThreads == g_Threads.end()) {
		return nullptr;
	}

	auto Thread = ProcessThreads->second.find(unThreadID);
	if (Thread == ProcessThreads->second.end()) {
		return nullptr;
	}

	if (ppStartAddress) {
		*ppStartAddress = Thread->second.second;
	}

	return Thread->second.first;
}

tstring_optional GetDebugModulePath(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	return Module->second;
}

tstring_optional GetDebugModuleDirectory(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {};
	errno_t err = _tsplitpath_s(Module->second.second.c_str(), szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileDirectory[MAX_PATH] {};
	if (_stprintf_s(szFileDirectory, _countof(szFileDirectory), _T("%s%s"), szDrive, szDirectory) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	return { true, szFileDirectory };
}

tstring_optional GetDebugModuleName(DWORD unProcessID, LPVOID pImageBase) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return { false, _T("") };
	}

	auto Module = ProcessModules->second.find(pImageBase);
	if (Module == ProcessModules->second.end()) {
		return { false, _T("") };
	}

	if (!Module->second.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
	errno_t err = _tsplitpath_s(Module->second.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szFileName[MAX_PATH] {};
	if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring FileName = szFileName;

	std::transform(FileName.begin(), FileName.end(), FileName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, FileName };
}

LPVOID GetDebugModuleAddress(DWORD unProcessID, tstring ModuleName) {
	auto ProcessModules = g_Modules.find(unProcessID);
	if (ProcessModules == g_Modules.end()) {
		return nullptr;
	}

	tstring LowerModuleName = ModuleName;
	std::transform(LowerModuleName.begin(), LowerModuleName.end(), LowerModuleName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	for (const auto& Module : ProcessModules->second) {
		if (!Module.second.first) {
			continue;
		}

		TCHAR szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
		if (_tsplitpath_s(Module.second.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt)) != 0) {
			continue;
		}

		TCHAR szFileName[MAX_PATH] {};
		if (_stprintf_s(szFileName, _countof(szFileName), _T("%s%s"), szName, szExt) < 0) {
			continue;
		}

		tstring CurrentModuleName = szFileName;
		std::transform(CurrentModuleName.begin(), CurrentModuleName.end(), CurrentModuleName.begin(), [](TCHAR c) {
#ifdef _UNICODE
			return std::towlower(c);
#else
			return std::tolower(static_cast<unsigned char>(c));
#endif
		});

		if (CurrentModuleName == LowerModuleName) {
			return Module.first;
		}
	}

	return nullptr;
}

void OnCreateProcessEvent(DWORD unProcessID) {
#ifdef _DEBUG
	_tprintf_s(_T("PROCESSCREATE: %lu\n"), unProcessID);
#endif // _DEBUG
}

void OnExitProcessEvent(DWORD unProcessID, DWORD unExitCode) {
#ifdef _DEBUG
	_tprintf_s(_T("PROCESSEXIT(%lu): %lu\n"), unProcessID, unExitCode);
#endif // _DEBUG
}

void OnCreateThreadEvent(DWORD unProcessID, DWORD unThreadID) {
#ifdef _DEBUG
	_tprintf_s(_T("THREADCREATE(%lu): %lu\n"), unProcessID, unThreadID);
#endif // _DEBUG
}

void OnExitThreadEvent(DWORD unProcessID, DWORD unThreadID, DWORD unExitCode) {
#ifdef _DEBUG
	_tprintf_s(_T("THREADEXIT(%lu, %lu): %lu\n"), unProcessID, unThreadID, unExitCode);
#endif // _DEBUG
}

void OnLoadModuleEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pImageBase) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);
	if (!ModuleFileName.first) {
		return;
	}

#ifdef _WIN64
	_tprintf_s(_T("MODULELOAD(0x%016llX): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#else
	_tprintf_s(_T("MODULELOAD(0x%08X): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#endif
#endif // _DEBUG
}

void OnUnloadModuleEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pImageBase) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);
	if (!ModuleFileName.first) {
		return;
	}

#ifdef _WIN64
	_tprintf_s(_T("MODULEUNLOAD(0x%016llX): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#else
	_tprintf_s(_T("MODULEUNLOAD(0x%08X): %s\n"), reinterpret_cast<size_t>(pImageBase), ModuleFileName.second.c_str());
#endif
#endif // _DEBUG
}

void OnDebugStringEvent(DWORD unProcessID, DWORD unThreadID, const OUTPUT_DEBUG_STRING_INFO& Info) {
#ifdef _DEBUG
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	if ((Info.lpDebugStringData == 0) || (Info.nDebugStringLength == 0)) {
		return;
	}

	const SIZE_T cMaxChars = 8192; // 8 KiB

	if (Info.fUnicode) {
		static WCHAR szBuffer[cMaxChars + 1] {};
		memset(szBuffer, 0, sizeof(szBuffer));

		SIZE_T unCharsToRead = Info.nDebugStringLength;

		if (unCharsToRead > cMaxChars) {
			unCharsToRead = cMaxChars;
		}

		SIZE_T unBytesRead = 0;

		if (!ReadProcessMemory(Process, Info.lpDebugStringData, szBuffer, unCharsToRead * sizeof(WCHAR), &unBytesRead) || (unBytesRead == 0)) {
			return;
		}

		wprintf(L"ONDEBUGSTRING(%lu, %lu): \"%s\"\n", unProcessID, unThreadID, szBuffer);
	} else {
		static CHAR Buffer[cMaxChars + 1] {};
		memset(Buffer, 0, sizeof(Buffer));

		SIZE_T unCharsToRead = Info.nDebugStringLength;

		if (unCharsToRead > cMaxChars) {
			unCharsToRead = cMaxChars;
		}

		SIZE_T unBytesRead = 0;

		if (!ReadProcessMemory(Process, Info.lpDebugStringData, Buffer, unCharsToRead * sizeof(CHAR), &unBytesRead) || (unBytesRead == 0)) {
			return;
		}

		printf("ONDEBUGSTRING(%lu, %lu): \"%s\"\n", unProcessID, unThreadID, Buffer);
	}
#endif // _DEBUG
}

void OnRIPEvent(DWORD unProcessID, DWORD unThreadID, DWORD unError, DWORD unType) {
#ifdef _DEBUG
	_tprintf_s(_T("RIPEVENT(%lu, %lu): 0x%08X, 0x%08X\n"), unProcessID, unThreadID, unError, unType);
#endif // !_DEBUG
}

void OnExceptionEvent(DWORD unProcessID, DWORD unThreadID, const EXCEPTION_DEBUG_INFO& Info, bool bInitialBreakPoint, bool* pHandledException) {
#ifdef _DEBUG
	_tprintf_s(_T("ONEXCEPTION (%s)\n"), Info.dwFirstChance ? _T("First-Chance") : _T("Second-Chance"));
	_tprintf_s(_T("  CODE:       0x%08X\n"), Info.ExceptionRecord.ExceptionCode);
#ifdef _WIN64
	_tprintf_s(_T("  ADDRESS:    0x%016llX\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#else
	_tprintf_s(_T("  ADDRESS:    0x%08X\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress));
#endif
	_tprintf_s(_T("  THREADID:   %lu\n"), unThreadID);
	_tprintf_s(_T("  FLAGS:      0x%08X\n"), Info.ExceptionRecord.ExceptionFlags);
	_tprintf_s(_T("  PARAMETERS: %lu\n"), Info.ExceptionRecord.NumberParameters);

	DWORD NumberParameters = Info.ExceptionRecord.NumberParameters;
	if (NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS) {
		NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
	}

	for (DWORD i = 0; i < NumberParameters; ++i) {
#ifdef _WIN64
		_tprintf_s(_T("    PARAM[%lu]: 0x%016llX\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#else
		_tprintf_s(_T("    PARAM[%lu]: 0x%08X\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#endif
	}
#endif // _DEBUG
}

void OnEntryPoint(DWORD unProcessID, DWORD unThreadID) {
#ifdef _DEBUG
	_tprintf_s(_T("ONENTRYPOINT(%lu): %lu\n"), unProcessID, unThreadID);
#endif // !_DEBUG

	g_bContinueDebugging = false; // There is no point in debugging further
}

void OnTimeout() {
#ifdef _DEBUG
	_tprintf_s(_T("ONTIMEOUT!\n"));
#endif // _DEBUG
}

bool DebugProcess(DWORD unTimeout, bool* pbContinue, bool* pbStopped) {
	if (!pbContinue) {
		return false;
	}

	DEBUG_EVENT DebugEvent;
	bool bSeenInitialBreakPoint = false;

	std::vector<unsigned char> vecBreakPointBytes = { 0xCC };
	std::vector<unsigned char> vecBreakPointOriginalBytes(vecBreakPointBytes.size());

	while (*pbContinue) {
		if (WaitForDebugEvent(&DebugEvent, unTimeout)) {
			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:

					// Setting breakpoint for entrypoint

					if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, vecBreakPointOriginalBytes.data(), vecBreakPointOriginalBytes.size(), nullptr)) {
						break;
					}

					if (!WriteProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, vecBreakPointBytes.data(), vecBreakPointBytes.size(), nullptr)) {
						break;
					}

					FlushInstructionCache(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, vecBreakPointBytes.size());

					// Other stuff

					g_Processes[DebugEvent.dwProcessId] = { DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId] = vecBreakPointOriginalBytes;
					g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = { DebugEvent.u.CreateProcessInfo.hThread, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_Modules[DebugEvent.dwProcessId][DebugEvent.u.CreateProcessInfo.lpBaseOfImage] = GetFilePath(DebugEvent.u.CreateProcessInfo.hFile);

					OnCreateProcessEvent(DebugEvent.dwProcessId);
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage);

					SafeCloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
					break;

				case EXIT_PROCESS_DEBUG_EVENT:
					OnExitProcessEvent(DebugEvent.dwProcessId, DebugEvent.u.ExitProcess.dwExitCode);

					g_Modules.erase(DebugEvent.dwProcessId);
					g_Threads.erase(DebugEvent.dwProcessId);
					g_ProcessesOriginalEntryPointByte.erase(DebugEvent.dwProcessId);
					g_Processes.erase(DebugEvent.dwProcessId);

					if (g_Processes.empty()) {
						*pbContinue = false;
						*pbStopped = true;
					}

					break;

				case CREATE_THREAD_DEBUG_EVENT:
					g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = { DebugEvent.u.CreateThread.hThread, DebugEvent.u.CreateThread.lpStartAddress };
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					break;

				case EXIT_THREAD_DEBUG_EVENT:
					OnExitThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.ExitThread.dwExitCode);

					g_Threads[DebugEvent.dwProcessId].erase(DebugEvent.dwThreadId);
					if (g_Threads[DebugEvent.dwProcessId].empty()) {
						g_Threads.erase(DebugEvent.dwProcessId);
					}

					break;

				case LOAD_DLL_DEBUG_EVENT:
					g_Modules[DebugEvent.dwProcessId][DebugEvent.u.LoadDll.lpBaseOfDll] = GetFilePath(DebugEvent.u.LoadDll.hFile);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.LoadDll.lpBaseOfDll);
					SafeCloseHandle(DebugEvent.u.LoadDll.hFile);
					break;

				case UNLOAD_DLL_DEBUG_EVENT:
					OnUnloadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.UnloadDll.lpBaseOfDll);

					g_Modules[DebugEvent.dwProcessId].erase(DebugEvent.u.UnloadDll.lpBaseOfDll);
					if (g_Modules[DebugEvent.dwProcessId].empty()) {
						g_Modules.erase(DebugEvent.dwProcessId);
					}

					break;

				case OUTPUT_DEBUG_STRING_EVENT:
					OnDebugStringEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.DebugString);
					break;

				case RIP_EVENT:
					OnRIPEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.RipInfo.dwError, DebugEvent.u.RipInfo.dwType);
					break;

				case EXCEPTION_DEBUG_EVENT:
					bool bHandledException = false;
					OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, !bSeenInitialBreakPoint, &bHandledException);

					ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

					if (bSeenInitialBreakPoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == g_Processes[DebugEvent.dwProcessId].second) && (g_ProcessesOriginalEntryPointByte.find(DebugEvent.dwProcessId) != g_ProcessesOriginalEntryPointByte.end())) {
						if (!WriteProcessMemory(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId].data(), g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId].size(), nullptr)) {
							break;
						}

						FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId].size());

						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
#ifdef _WIN64
							ctx.Rip = reinterpret_cast<DWORD64>(g_Processes[DebugEvent.dwProcessId].second);
#else
							ctx.Eip = reinterpret_cast<DWORD>(g_Processes[DebugEvent.dwProcessId].second);
#endif
							SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx);
						}

						OnEntryPoint(DebugEvent.dwProcessId, DebugEvent.dwThreadId);

						ContinueStatus = DBG_EXCEPTION_HANDLED;
					}

					if (bSeenInitialBreakPoint && bHandledException) {
						ContinueStatus = DBG_EXCEPTION_HANDLED;
					}

					if (!bSeenInitialBreakPoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {
						ContinueStatus = DBG_CONTINUE;
						bSeenInitialBreakPoint = true;
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

void ShowHelp() {
	_tprintf_s(_T("Usage variations:\n"));
	_tprintf_s(_T("  /list\n"));
	_tprintf_s(_T("  /add <File Name>\n"));
	_tprintf_s(_T("  /remove <File Name>\n"));
}

bool HiJackList() {
	HKEY hKey = nullptr;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegOpenKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unIndex = 0;
	TCHAR szSubKeyName[MAX_PATH] {};
	DWORD unSubKeyNameSize = MAX_PATH;
	while (RegEnumKeyEx(hKey, unIndex, szSubKeyName, &unSubKeyNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
		HKEY hSubKey = nullptr;
		if (RegOpenKeyEx(hKey, szSubKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
			DWORD unType = 0;
			TCHAR szDebuggerValue[MAX_PATH] {};
			DWORD unDebuggerValueSize = sizeof(szDebuggerValue);
			if ((RegQueryValueEx(hSubKey, _T("Debugger"), nullptr, &unType, reinterpret_cast<LPBYTE>(szDebuggerValue), &unDebuggerValueSize) == ERROR_SUCCESS) && (unType == REG_SZ) && (unDebuggerValueSize > sizeof(TCHAR))) {
				_tprintf_s(_T("> %s: %s\n"), szSubKeyName, szDebuggerValue);
			}

			RegCloseKey(hSubKey);
		}

		++unIndex;
		unSubKeyNameSize = MAX_PATH;
	}

	RegCloseKey(hKey);
	return true;
}

bool HiJackAdd(const TCHAR* szFileName) {
	if (!szFileName) {
		return false;
	}

	TCHAR szKey[MAX_PATH] {};
	if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), szFileName) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HKEY hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
	if (!szSelfProcessPath) {
		_tprintf_s(_T("ERROR: PEB\n"));
		return false;
	}

#ifndef _UNICODE
	UNICODE_STRING us {};
	RtlInitUnicodeString(&us, szSelfProcessPath);

	ANSI_STRING as {};
	NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
		return false;
	}
#endif // !_UNICODE

#ifdef _UNICODE
	if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(szSelfProcessPath), (static_cast<DWORD>(_tcslen(szSelfProcessPath)) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
#else
	if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(as.Buffer), as.Length + 1) != ERROR_SUCCESS) {
#endif
		_tprintf_s(_T("ERROR: RegSetValueEx (Error = 0x%08X)\n"), GetLastError());
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

bool HiJackRemove(const TCHAR* szFileName) {
	if (!szFileName) {
		return false;
	}

	TCHAR szKey[MAX_PATH] {};
	if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), szFileName) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	HKEY hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	RegDeleteValue(hKey, _T("Debugger"));
	RegCloseKey(hKey);

	hKey = nullptr;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	DWORD unValuesCount = 0;
	if (RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &unValuesCount, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegQueryInfoKey (Error = 0x%08X)\n"), GetLastError());
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);

	if (!unValuesCount) {
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, szKey) != ERROR_SUCCESS) {
			_tprintf_s(_T("WARNING: RegDeleteKey (Error = 0x%08X)\n"), GetLastError());
		}
	}

	return true;
}

bool FindExecutablePath(const TCHAR* szFileName, LPTSTR pResultPath, DWORD dwBufferSize) {
	if (!szFileName || !pResultPath || !dwBufferSize) {
		return false;
	}

	memset(pResultPath, 0, dwBufferSize * sizeof(TCHAR));

	DWORD unPathLength = SearchPath(nullptr, szFileName, nullptr, dwBufferSize, pResultPath, nullptr);
	if (!((unPathLength > 0) && (unPathLength < dwBufferSize))) {
		TCHAR szExecutableName[MAX_PATH] {};

		if (_stprintf_s(szExecutableName, _countof(szExecutableName), _T("%s.exe"), szFileName) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			return false;
		}

		memset(pResultPath, 0, dwBufferSize * sizeof(TCHAR));

		unPathLength = SearchPath(nullptr, szExecutableName, nullptr, dwBufferSize, pResultPath, nullptr);
		if (!((unPathLength > 0) && (unPathLength < dwBufferSize))) {
			_tprintf_s(_T("ERROR: Unable to locate executable '%s' (Error = 0x%08X)\n"), szFileName, GetLastError());
			return false;
		}
	}

	return true;
}

int _tmain(int argc, PTCHAR argv[], PTCHAR envp[]) {
#ifdef _DEBUG
#ifdef _WIN64
	_tprintf_s(_T("HiJack [Version " HIJACK_VERSION "]\n\n"));
#else
	_tprintf_s(_T("HiJack32 [Version " HIJACK_VERSION "]\n\n"));
#endif
#endif // _DEBUG

	if (argc < 2) {
		ShowHelp();
		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/list")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("HiJack [Version " HIJACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("HiJack32 [Version " HIJACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (!HiJackList()) {
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/add")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("HiJack [Version " HIJACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("HiJack32 [Version " HIJACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (argc < 3) {
			ShowHelp();
			return EXIT_SUCCESS;
		}

		if (!IsRunningAsAdmin()) {
			if (!ReLaunchAsAdmin()) {
				return EXIT_FAILURE;
			}

			_tprintf_s(_T("SUCCESS!\n"));
			return EXIT_SUCCESS;
		}

		if (!HiJackAdd(argv[2])) {
			return EXIT_FAILURE;
		}

		_tprintf_s(_T("SUCCESS!\n"));
		return EXIT_SUCCESS;
	}

	if (_tcscmp(argv[1], _T("/remove")) == 0) {
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("HiJack [Version " HIJACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("HiJack32 [Version " HIJACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

		if (argc < 3) {
			ShowHelp();
			return EXIT_SUCCESS;
		}

		if (!IsRunningAsAdmin()) {
			if (!ReLaunchAsAdmin()) {
				return EXIT_FAILURE;
			}

			_tprintf_s(_T("SUCCESS!\n"));
			return EXIT_SUCCESS;
		}

		if (!HiJackRemove(argv[2])) {
			return EXIT_FAILURE;
		}

		_tprintf_s(_T("SUCCESS!\n"));
		return EXIT_SUCCESS;
	}

	TCHAR szResultPath[MAX_PATH] {};
	if (!FindExecutablePath(argv[1], szResultPath, MAX_PATH)) {
		return EXIT_FAILURE;
	}

	HANDLE hFile = CreateFile(szResultPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	HANDLE hMapFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	HANDLE hJob = CreateJobObject(nullptr, nullptr);
	if (!hJob || (hJob == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateJobObject (Error = 0x%08X)\n"), GetLastError());
		return EXIT_FAILURE;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION joli{};
	joli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &joli, sizeof(joli))) {
		_tprintf_s(_T("ERROR: SetInformationJobObject (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {}, szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#endif
		if (err != 0) {
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		TCHAR szProcessPath[MAX_PATH] {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s32%s"), szDrive, szDirectory, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD dwAttrib = GetFileAttributes(szProcessPath);
		if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
			_tprintf_s(_T("ERROR: This process cannot be run!\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si {};
		PROCESS_INFORMATION pi {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (hJob && (hJob != INVALID_HANDLE_VALUE)) {
			if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
				_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
				TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				CloseHandle(hJob);
				return EXIT_FAILURE;
			}
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This process cannot be run in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#else
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] {}, szDirectory[_MAX_DIR] {}, szName[_MAX_FNAME] {}, szExt[_MAX_EXT] {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDirectory, _countof(szDirectory), szName, _countof(szName), szExt, _countof(szExt));
#endif
		if (err != 0) {
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		PTCHAR szSubString = _tcsstr(szName, _T("32"));
		if (szSubString) {
			size_t unRemainingLength = _tcslen(szSubString + 2);
			std::memmove(szSubString, szSubString + 2, unRemainingLength + 1);
		}

		TCHAR szProcessPath[MAX_PATH] {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s%s"), szDrive, szDirectory, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD dwAttrib = GetFileAttributes(szProcessPath);
		if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
			_tprintf_s(_T("ERROR: This process cannot be run!\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si {};
		PROCESS_INFORMATION pi {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (hJob && (hJob != INVALID_HANDLE_VALUE)) {
			if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
				_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
				TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				CloseHandle(hJob);
				return EXIT_FAILURE;
			}
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This process cannot be run in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#endif

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	tstring CommandLine = _T("");
	for (int i = 1; i < argc; ++i) {

		if ((i == 1) || _tcschr(argv[i], _T(' '))) {
			CommandLine += _T('"');
			CommandLine += argv[i];
			CommandLine += _T('"');
		} else {
			CommandLine += argv[i];
		}

		if (i + 1 < argc) {
			CommandLine += _T(' ');
		}
	}

	auto pCommandLine = std::make_unique<TCHAR[]>(CommandLine.size() + 1);
	if (!pCommandLine) {
		_tprintf_s(_T("ERROR: Not enough memory for new command line! (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	std::copy(CommandLine.begin(), CommandLine.end(), pCommandLine.get());

	pCommandLine[CommandLine.size()] = _T('\0');

	if (!EnableDebugPrivilege(GetCurrentProcess(), true)) {
		return EXIT_FAILURE;
	}

	PROCESS_INFORMATION pi {};
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
	NTSTATUS nStatus = NtQueryInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags), nullptr);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	unDebugFlags = 0x00000001;

	nStatus = NtSetInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags));
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtSetInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	HANDLE hDebug = nullptr;
	nStatus = NtQueryInformationProcess(pi.hProcess, ProcessDebugObjectHandle, &hDebug, sizeof(HANDLE), nullptr);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	nStatus = NtRemoveProcessDebug(pi.hProcess, hDebug);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtRemoveProcessDebug (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	CloseHandle(hDebug);

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
		_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
		TerminateThread(pi.hThread, EXIT_FAILURE);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unExitCode = EXIT_FAILURE;
	if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
		_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	return unExitCode;
}
