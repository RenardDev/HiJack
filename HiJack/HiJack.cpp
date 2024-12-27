
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

// General definitions

#define HIJACK_VERSION "1.1.2"

#define ProcessDebugFlags static_cast<PROCESSINFOCLASS>(0x1F)
#define SafeCloseHandle(x) if ((x) && (x != INVALID_HANDLE_VALUE)) { CloseHandle(x); }

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);

std::unordered_map<DWORD, HANDLE> g_Processes;
std::unordered_map<DWORD, std::unordered_map<DWORD, HANDLE>> g_Threads;
std::unordered_map<DWORD, std::unordered_map<LPVOID, tstring>> g_Modules;
std::unordered_map<DWORD, std::pair<void*, HANDLE>> g_InjectedModules;
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

	SHELLEXECUTEINFO sei = {};
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
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
		_tprintf_s(_T("ERROR: GetProcessImageFileName (Error = 0x%08X)\n"), GetLastError());
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
	errno_t err = _tsplitpath_s(ProcessPath.c_str(), szDrive, _countof(szDrive), szDir, _countof(szDir), nullptr, 0, nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return _T("");
	}

	TCHAR szProcessDirectory[MAX_PATH] = {};
	if (_stprintf_s(szProcessDirectory, _countof(szProcessDirectory), _T("%s%s"), szDrive, szDir) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return _T("");
	}

	return szProcessDirectory;
}

tstring GetProcessName(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (ProcessPath.empty()) {
		return _T("");
	}

	TCHAR szName[_MAX_FNAME] = {}, szExt[_MAX_EXT] = {};
	errno_t err = _tsplitpath_s(ProcessPath.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return _T("");
	}

	TCHAR szProcessName[MAX_PATH] = {};
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return _T("");
	}

	return szProcessName;
}

tstring GetFileNameFromHandle(HANDLE hFile) {
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
	if ((dwFileSizeLo == 0) && (dwFileSizeHi == 0)) {
		_tprintf_s(_T("ERROR: GetFileSize (Error = 0x%08X)\n"), GetLastError());
		return _T("");
	}

	HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 1, nullptr);
	if (!hFileMap || (hFileMap == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		return _T("");
	}

	void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
	if (!pMem) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFileMap);
		return _T("");
	}

	TCHAR szFileName[MAX_PATH + 1] = {};
	if (!GetMappedFileName(GetCurrentProcess(), pMem, szFileName, _countof(szFileName))) {
		_tprintf_s(_T("ERROR: GetMappedFileName (Error = 0x%08X)\n"), GetLastError());
		UnmapViewOfFile(pMem);
		CloseHandle(hFileMap);
		return _T("");
	}

	UnmapViewOfFile(pMem);
	CloseHandle(hFileMap);

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
	errno_t err = _tsplitpath_s(szFileName, nullptr, 0, nullptr, 0, szName, _countof(szName), szExt, _countof(szExt));
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return _T("");
	}

	TCHAR szResultFileName[MAX_PATH] = {};
	if (_stprintf_s(szResultFileName, _countof(szResultFileName), _T("%s%s"), szName, szExt) < 0) {
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
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

/*
bool SetHardwareBreakPoint(HANDLE hThread, LPVOID pAddress) {
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (SuspendThread(hThread) == static_cast<DWORD>(-1)) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	if (!GetThreadContext(hThread, &CTX)) {
		_tprintf_s(_T("ERROR: GetThreadContext (Error = 0x%08X)\n"), GetLastError());
		ResumeThread(hThread);
		return false;
	}

	CTX.Dr0 = reinterpret_cast<DWORD_PTR>(pAddress);
	CTX.Dr7 = 0x00000001;

	if (!SetThreadContext(hThread, &CTX)) {
		_tprintf_s(_T("ERROR: SetThreadContext (Error = 0x%08X)\n"), GetLastError());
		ResumeThread(hThread);
		return false;
	}

	if (ResumeThread(hThread) == static_cast<DWORD>(-1)) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool SetBreakPointAtEntryPoint(HANDLE hProcess, LPVOID pBaseAddress, HANDLE hThread) {
	BYTE Buffer[0x1000];
	SIZE_T unBytesRead = 0;
	if (!ReadProcessMemory(hProcess, pBaseAddress, Buffer, sizeof(Buffer), &unBytesRead)) {
		_tprintf_s(_T("ERROR: ReadProcessMemory (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(Buffer);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(Buffer) + pDH->e_lfanew);

	DWORD unEntryPointRVA = pNTHs->OptionalHeader.AddressOfEntryPoint;
	if (!unEntryPointRVA) {
		_tprintf_s(_T("ERROR: Process without entrypoint!\n"));
		return false;
	}

	LPVOID pEntryPointAddress = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(pBaseAddress) + unEntryPointRVA);
	if (!SetHardwareBreakPoint(hThread, pEntryPointAddress)) {
		return false;
	}

	return true;
}

void SetBreakPointsAtTLSCallbacks(HANDLE hProcess, LPVOID pBaseAddress, HANDLE hThread) {
	BYTE Buffer[0x1000];
	SIZE_T unBytesRead = 0;
	if (!ReadProcessMemory(hProcess, pBaseAddress, Buffer, sizeof(Buffer), &unBytesRead)) {
		_tprintf_s(_T("WARNING: ReadProcessMemory (Error = 0x%08X)\n"), GetLastError());
		return;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(Buffer);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(Buffer) + pDH->e_lfanew);

	DWORD TLSDirectoryRVA = pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	if (!TLSDirectoryRVA) {
		return;
	}

	IMAGE_TLS_DIRECTORY TLSDirectory;
	unBytesRead = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<void*>(reinterpret_cast<char*>(pBaseAddress) + TLSDirectoryRVA), &TLSDirectory, sizeof(TLSDirectory), &unBytesRead)) {
		_tprintf_s(_T("ERROR: ReadProcessMemory (Error = 0x%08X)\n"), GetLastError());
		return;
	}

	void** TLSCallbacks = reinterpret_cast<void**>(TLSDirectory.AddressOfCallBacks);
	while (true) {
		PVOID pCallBack = nullptr;
		unBytesRead = 0;
		if (!ReadProcessMemory(hProcess, TLSCallbacks, &pCallBack, sizeof(pCallBack), &unBytesRead) || !pCallBack) {
			_tprintf_s(_T("WARNING: ReadProcessMemory (Error = 0x%08X)\n"), GetLastError());
			break;
		}

		if (!SetHardwareBreakPoint(hThread, pCallBack)) {
			break;
		}

		++TLSCallbacks;
	}
}
*/

tstring GetProcessHiJackLibraryName(HANDLE hProcess) {
	auto ProcessName = GetProcessPath(hProcess);
	if (ProcessName.empty()) {
		return _T("");
	}

	TCHAR szName[_MAX_FNAME] = {};
	errno_t err = _tsplitpath_s(ProcessName.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return _T("");
	}

	TCHAR szProcessName[MAX_PATH] = {};
#ifdef _WIN64
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s_hijack.dll"), szName) < 0) {
#else
	if (_stprintf_s(szProcessName, _countof(szProcessName), _T("%s_hijack32.dll"), szName) < 0) {
#endif
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return _T("");
	}

	return szProcessName;
}

bool CreateStandardProcess(const TCHAR* szFileName, PTCHAR szCommandLine, PROCESS_INFORMATION& pi) {
	STARTUPINFO si = {};
	si.cb = sizeof(si);

	if (!CreateProcess(szFileName, szCommandLine, nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		_tprintf_s(_T("ERROR: CreateProcess (Error = 0x%08X)\n"), GetLastError());
		return false;
	}

	return true;
}

bool CreateProcessWithParent(const TCHAR* szFileName, PTCHAR szCommandLine, HANDLE hParentProcess, PROCESS_INFORMATION& pi) {
	STARTUPINFOEX si = {};
	si.StartupInfo.cb = sizeof(si);

	/* Change parent (unstable and currently impossible to redirect stdin/stdout in right way)
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

	HANDLE hParentProcess = nullptr;

	DWORD unParentPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3));
	if (unParentPID) {
		hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unParentPID);
		if (hParentProcess == INVALID_HANDLE_VALUE) {
			hParentProcess = nullptr;
		}

		if (!hParentProcess) {
			_tprintf_s(_T("ERROR: OpenProcess (Error = 0x%08X)\n"), GetLastError());
			return false;
		}
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
			_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
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
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
	_tprintf_s(_T("PROCESS CREATE: %lu\n"), ProcessId);
#endif // _DEBUG
}

void OnExitProcessEvent(DWORD ProcessId) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
	_tprintf_s(_T("PROCESS EXIT: %lu\n"), ProcessId);
#endif // _DEBUG
}

void OnCreateThreadEvent(DWORD ProcessId, DWORD ThreadId) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
	_tprintf_s(_T("THREAD CREATE: %lu\n"), ThreadId);
#endif // _DEBUG
}

void OnExitThreadEvent(DWORD ProcessId, DWORD ThreadId) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
	_tprintf_s(_T("THREAD EXIT: %lu\n"), ThreadId);
#endif // _DEBUG
}

void OnLoadModuleEvent(DWORD ProcessId, LPVOID ImageBase, HANDLE hFile) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

	auto Modules = g_Modules.find(ProcessId);
	if (Modules == g_Modules.end()) {
		return;
	}

	auto Module = Modules->second.find(ImageBase);
	if (Module == Modules->second.end()) {
		return;
	}

	auto& ModuleFileName = Module->second;

#ifdef _DEBUG
#ifdef _WIN64
	_tprintf_s(_T("MODULE LOAD: 0x%016llX - %s\n"), reinterpret_cast<size_t>(ImageBase), ModuleFileName.c_str());
#else
	_tprintf_s(_T("MODULE LOAD: 0x%08X - %s\n"), reinterpret_cast<size_t>(ImageBase), ModuleFileName.c_str());
#endif
#endif // _DEBUG

	auto InjectedModules = g_InjectedModules.find(ProcessId);
	if ((InjectedModules == g_InjectedModules.end()) && (ModuleFileName == _T("kernelbase.dll"))) {
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
			return; // File not exist
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

		void* pAddress = VirtualAllocEx(Process->second, nullptr, (ProcessHiJackLibraryPath.length() + 1) * sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pAddress) {
			_tprintf_s(_T("ERROR: VirtualAllocEx (Error = 0x%08X)\n"), GetLastError());
			return;
		}

		if (!WriteProcessMemory(Process->second, pAddress, ProcessHiJackLibraryPath.c_str(), (ProcessHiJackLibraryPath.length() + 1) * sizeof(TCHAR), nullptr)) {
			_tprintf_s(_T("ERROR: WriteProcessMemory (Error = 0x%08X)\n"), GetLastError());
			VirtualFreeEx(Process->second, pAddress, 0, MEM_RELEASE);
			return;
		}

#ifdef _UNICODE
		using fnLoadLibraryW = HMODULE(WINAPI*)(LPCWSTR lpLibFileName);
		fnLoadLibraryW pLoadLibraryW = reinterpret_cast<fnLoadLibraryW>(GetProcAddress(reinterpret_cast<HMODULE>(ImageBase), "LoadLibraryW"));
		if (!pLoadLibraryW) {
			_tprintf_s(_T("ERROR: GetProcAddress (Error = 0x%08X)\n"), GetLastError());
			VirtualFreeEx(Process->second, pAddress, 0, MEM_RELEASE);
			return;
		}

		HANDLE hThread = CreateRemoteThread(Process->second, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), pAddress, 0, nullptr);
		if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateRemoteThread (Error = 0x%08X)\n"), GetLastError());
			VirtualFreeEx(Process->second, pAddress, 0, MEM_RELEASE);
			return;
		}

		g_InjectedModules[ProcessId] = std::make_pair(pAddress, hThread);
#else
		using fnLoadLibraryA = HMODULE(WINAPI*)(LPCSTR lpLibFileName);
		fnLoadLibraryA pLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(reinterpret_cast<HMODULE>(ImageBase), "LoadLibraryA"));
		if (!pLoadLibraryA) {
			_tprintf_s(_T("ERROR: GetProcAddress (Error = 0x%08X)\n"), GetLastError());
			VirtualFreeEx(Process->second, pAddress, 0, MEM_RELEASE);
			return;
		}

		HANDLE hThread = CreateRemoteThread(Process->second, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryA), pAddress, 0, nullptr);
		if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("ERROR: CreateRemoteThread (Error = 0x%08X)\n"), GetLastError());
			VirtualFreeEx(Process->second, pAddress, 0, MEM_RELEASE);
			return;
		}

		g_InjectedModules[ProcessId] = std::make_pair(pAddress, hThread);
#endif

#ifdef _DEBUG
		_tprintf_s(_T("INJECTED!\n"));
#endif // _DEBUG
	}
}

void OnUnloadModuleEvent(DWORD ProcessId, LPVOID ImageBase) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
#ifdef _WIN64
	_tprintf_s(_T("MODULE UNLOAD: 0x%016llX\n"), reinterpret_cast<size_t>(ImageBase));
#else
	_tprintf_s(_T("MODULE UNLOAD: 0x%08X\n"), reinterpret_cast<size_t>(ImageBase));
#endif
#endif // _DEBUG
}

void OnExceptionEvent(DWORD ProcessId, DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Info, bool bInitialBreakPoint) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
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
#endif // _DEBUG

	if (bInitialBreakPoint) {
		g_bContinueDebugging = false;
	}

	auto InjectedModules = g_InjectedModules.find(ProcessId);
	if (bInitialBreakPoint && (InjectedModules != g_InjectedModules.end())) {
#ifdef _DEBUG
		_tprintf_s(_T("POST-INJECTED!\n"));
#endif // _DEBUG
	}
}

void OnDebugStringEvent(DWORD ProcessId, DWORD ThreadId, const OUTPUT_DEBUG_STRING_INFO& Info) {
	auto Process = g_Processes.find(ProcessId);
	if (Process == g_Processes.end()) {
		return;
	}

#ifdef _DEBUG
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
	} else {
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
#endif // _DEBUG
}

void OnTimeout() {
#ifdef _DEBUG
	_tprintf_s(_T("TIMEOUT!\n"));
#endif // _DEBUG
}

bool DebugProcess(DWORD unTimeout, bool* pbContinue, bool* pbStopped) {
	if (!pbContinue) {
		return false;
	}

	DEBUG_EVENT DebugEvent;
	bool bSeenInitialBreakPoint = false;

	while (*pbContinue) {
		if (WaitForDebugEvent(&DebugEvent, unTimeout)) {
			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:
					g_Processes[DebugEvent.dwProcessId] = DebugEvent.u.CreateProcessInfo.hProcess;
					{
						if (g_Threads.find(DebugEvent.dwProcessId) == g_Threads.end()) {
							g_Threads[DebugEvent.dwProcessId] = std::unordered_map<DWORD, HANDLE>();
						}

						g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = DebugEvent.u.CreateProcessInfo.hThread;
					}
					{
						if (g_Modules.find(DebugEvent.dwProcessId) == g_Modules.end()) {
							g_Modules[DebugEvent.dwProcessId] = std::unordered_map<LPVOID, tstring>();
						}

						g_Modules[DebugEvent.dwProcessId][DebugEvent.u.LoadDll.lpBaseOfDll] = GetFileNameFromHandle(DebugEvent.u.CreateProcessInfo.hThread);
					}

					OnCreateProcessEvent(DebugEvent.dwProcessId);
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage, DebugEvent.u.CreateProcessInfo.hFile);

					SafeCloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
					break;

				case EXIT_PROCESS_DEBUG_EVENT:
					OnExitProcessEvent(DebugEvent.dwProcessId);
					g_Modules.erase(DebugEvent.dwProcessId);
					g_Threads.erase(DebugEvent.dwProcessId);
					g_Processes.erase(DebugEvent.dwProcessId);
					if (g_Processes.empty()) {
						*pbContinue = false;
						*pbStopped = true;
					}

					break;

				case CREATE_THREAD_DEBUG_EVENT:
					{
						if (g_Threads.find(DebugEvent.dwProcessId) == g_Threads.end()) {
							g_Threads[DebugEvent.dwProcessId] = std::unordered_map<DWORD, HANDLE>();
						}

						g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = DebugEvent.u.CreateThread.hThread;
					}
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					break;

				case EXIT_THREAD_DEBUG_EVENT:
					OnExitThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					{
						auto Process = g_Threads.find(DebugEvent.dwProcessId);
						if (Process != g_Threads.end()) {
							auto& Threads = Process->second;
							auto Thread = Threads.find(DebugEvent.dwThreadId);
							if (Thread != Threads.end()) {
								Threads.erase(Thread);
								if (Threads.empty()) {
									g_Threads.erase(Process);
								}
							}
						}
					}

					break;

				case LOAD_DLL_DEBUG_EVENT:
					{
						if (g_Modules.find(DebugEvent.dwProcessId) == g_Modules.end()) {
							g_Modules[DebugEvent.dwProcessId] = std::unordered_map<LPVOID, tstring>();
						}

						g_Modules[DebugEvent.dwProcessId][DebugEvent.u.LoadDll.lpBaseOfDll] = GetFileNameFromHandle(DebugEvent.u.CreateThread.hThread);
					}
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.LoadDll.lpBaseOfDll, DebugEvent.u.LoadDll.hFile);
					SafeCloseHandle(DebugEvent.u.LoadDll.hFile);
					break;

				case UNLOAD_DLL_DEBUG_EVENT:
					OnUnloadModuleEvent(DebugEvent.dwProcessId, DebugEvent.u.UnloadDll.lpBaseOfDll);
					{
						auto Process = g_Modules.find(DebugEvent.dwProcessId);
						if (Process != g_Modules.end()) {
							auto& Modules = Process->second;
							auto Module = Modules.find(DebugEvent.u.LoadDll.lpBaseOfDll);
							if (Module != Modules.end()) {
								Modules.erase(Module);
								if (Modules.empty()) {
									g_Modules.erase(Process);
								}
							}
						}
					}

					break;

				case OUTPUT_DEBUG_STRING_EVENT:
					OnDebugStringEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.DebugString);
					break;

				case RIP_EVENT:
					break;

				case EXCEPTION_DEBUG_EVENT:
					OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, !bSeenInitialBreakPoint);
					ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
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
	_tprintf_s(_T("  <Path> <Arguments>\n"));
	_tprintf_s(_T("  /list\n"));
	_tprintf_s(_T("  /add <File Name>\n"));
	_tprintf_s(_T("  /remove <File Name>\n"));
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

		HKEY hKey = nullptr;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegOpenKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		DWORD unIndex = 0;
		TCHAR szSubKeyName[MAX_PATH] = {};
		DWORD unSubKeyNameSize = MAX_PATH;
		while (RegEnumKeyEx(hKey, unIndex, szSubKeyName, &unSubKeyNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
			HKEY hSubKey = nullptr;
			if (RegOpenKeyEx(hKey, szSubKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
				DWORD unType = 0;
				TCHAR szDebuggerValue[MAX_PATH] = {};
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

		TCHAR szKey[MAX_PATH] = {};
		if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), argv[2]) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		HKEY hKey = nullptr;
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us = {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as = {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

#ifdef _UNICODE
		if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(szSelfProcessPath), (static_cast<DWORD>(_tcslen(szSelfProcessPath)) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
#else
		if (RegSetValueEx(hKey, _T("Debugger"), 0, REG_SZ, reinterpret_cast<const BYTE*>(as.Buffer), as.Length + 1) != ERROR_SUCCESS) {
#endif
			_tprintf_s(_T("ERROR: RegSetValueEx (Error = 0x%08X)\n"), GetLastError());
			RegCloseKey(hKey);
			return EXIT_FAILURE;
		}

		RegCloseKey(hKey);

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

		TCHAR szKey[MAX_PATH] = {};
		if (_stprintf_s(szKey, _countof(szKey), _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s"), argv[2]) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		HKEY hKey = nullptr;
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		RegDeleteValue(hKey, _T("Debugger"));
		RegCloseKey(hKey);

		hKey = nullptr;
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, NULL, nullptr, NULL, KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegCreateKeyEx (Error = 0x%08X)\n"), GetLastError());
			return EXIT_FAILURE;
		}

		DWORD unValuesCount = 0;
		if (RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &unValuesCount, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
			_tprintf_s(_T("ERROR: RegQueryInfoKey (Error = 0x%08X)\n"), GetLastError());
			RegCloseKey(hKey);
			return EXIT_SUCCESS;
		}

		RegCloseKey(hKey);

		if (!unValuesCount) {
			if (RegDeleteKey(HKEY_LOCAL_MACHINE, szKey) != ERROR_SUCCESS) {
				_tprintf_s(_T("WARNING: RegDeleteKey (Error = 0x%08X)\n"), GetLastError());
			}
		}

		_tprintf_s(_T("SUCCESS!\n"));
		return EXIT_SUCCESS;
	}

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

	TCHAR szResultPath[MAX_PATH] = {};
	DWORD unPathLength = SearchPath(nullptr, argv[1], nullptr, MAX_PATH, szResultPath, nullptr);
	if (!((unPathLength > 0) && (unPathLength < MAX_PATH))) {
		TCHAR szExecutableName[MAX_PATH] = {};
		if (_stprintf_s(szExecutableName, _countof(szExecutableName), _T("%s.exe"), argv[1]) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		memset(szResultPath, 0, sizeof(szResultPath));

		unPathLength = SearchPath(nullptr, szExecutableName, nullptr, MAX_PATH, szResultPath, nullptr);
		if (!((unPathLength > 0) && (unPathLength < MAX_PATH))) {
			_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
	}

	HANDLE hProcessFile = CreateFile(szResultPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hProcessFile || (hProcessFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	HANDLE hMapFile = CreateFileMapping(hProcessFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us = {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as = {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] = {}, szDir[_MAX_DIR] = {}, szName[_MAX_FNAME] = {}, szExt[_MAX_EXT] = {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDir, _countof(szDir), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDir, _countof(szDir), szName, _countof(szName), szExt, _countof(szExt));
#endif
		if (err != 0) {
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		TCHAR szProcessPath[MAX_PATH] = {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s32%s"), szDrive, szDir, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD dwAttrib = GetFileAttributes(szProcessPath);
		if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
			_tprintf_s(_T("ERROR: This process cannot be run in 64 bit!\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si = {};
		PROCESS_INFORMATION pi = {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandles(pi);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandles(pi);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This process cannot be run in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#else
	if (pTempNTHs->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);

		PWSTR szSelfProcessPath = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
		if (!szSelfProcessPath) {
			_tprintf_s(_T("ERROR: PEB\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		UNICODE_STRING us = {};
		RtlInitUnicodeString(&us, szSelfProcessPath);

		ANSI_STRING as = {};
		NTSTATUS nStatus = RtlUnicodeStringToAnsiString(&as, &us, TRUE);
		if (!NT_SUCCESS(nStatus)) {
			_tprintf_s(_T("ERROR: RtlUnicodeStringToAnsiString (Error = 0x%08X)\n"), nStatus);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}
#endif // !_UNICODE

		TCHAR szDrive[_MAX_DRIVE] = {}, szDir[_MAX_DIR] = {}, szName[_MAX_FNAME] = {}, szExt[_MAX_EXT] = {};
#ifdef _UNICODE
		errno_t err = _tsplitpath_s(szSelfProcessPath, szDrive, _countof(szDrive), szDir, _countof(szDir), szName, _countof(szName), szExt, _countof(szExt));
#else
		errno_t err = _tsplitpath_s(as.Buffer, szDrive, _countof(szDrive), szDir, _countof(szDir), szName, _countof(szName), szExt, _countof(szExt));
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

		TCHAR szProcessPath[MAX_PATH] = {};
		if (_stprintf_s(szProcessPath, _countof(szProcessPath), _T("%s%s%s%s"), szDrive, szDir, szName, szExt) < 0) {
			_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD dwAttrib = GetFileAttributes(szProcessPath);
		if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) {
			_tprintf_s(_T("ERROR: This process cannot be run in 32 bit!\n"));
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		STARTUPINFO si = {};
		PROCESS_INFORMATION pi = {};
		si.cb = sizeof(si);

		if (!CreateProcess(szProcessPath, GetCommandLine(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
			_tprintf_s(_T("ERROR: Failed to launch 64-bit version (Error = 0x%08X)\n"), GetLastError());
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
			_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
			CloseHandles(pi);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		DWORD unExitCode = EXIT_FAILURE;
		if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
			_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
			CloseHandles(pi);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

		return unExitCode;
	}

	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This process cannot be run in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hProcessFile);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}
#endif

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hProcessFile);

	tstring CommandLine = _T("");
	for (int i = 1; i < argc; ++i) {
		if (i != 1) {
			CommandLine += argv[i];
		} else {
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
		_tprintf_s(_T("ERROR: Not enough memory for new command line! (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	std::copy(CommandLine.begin(), CommandLine.end(), pCommandLine.get());

	pCommandLine[CommandLine.size()] = _T('\0');

	if (!EnableDebugPrivilege(GetCurrentProcess(), true)) {
		return EXIT_FAILURE;
	}

	PROCESS_INFORMATION pi = {};
	if (!CreateDebugProcess(szResultPath, pCommandLine.get(), hJob, &pi)) {
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (ResumeThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	bool bStopped = false;
	if (!DebugProcess(INFINITE, &g_bContinueDebugging, &bStopped)) {
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (bStopped) {
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (SuspendThread(pi.hThread) != 0) {
		_tprintf_s(_T("ERROR: SuspendThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unDebugFlags = 0;
	NTSTATUS nStatus = NtQueryInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags), nullptr);
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtQueryInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	unDebugFlags = 1;

	nStatus = NtSetInformationProcess(pi.hProcess, ProcessDebugFlags, &unDebugFlags, sizeof(unDebugFlags));
	if (!NT_SUCCESS(nStatus)) {
		_tprintf_s(_T("ERROR: NtSetInformationProcess (Error = 0x%08X)\n"), nStatus);
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (!DebugActiveProcessStop(pi.dwProcessId)) {
		_tprintf_s(_T("ERROR: DebugActiveProcessStop (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (!EnableDebugPrivilege(GetCurrentProcess(), false)) {
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	if (ResumeThread(pi.hThread) != 1) {
		_tprintf_s(_T("ERROR: ResumeThread (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	for (auto&& InjectedModule : g_InjectedModules) {
		auto Process = g_Processes.find(InjectedModule.first);
		if (Process == g_Processes.end()) {
			continue;
		}

		if (WaitForSingleObject(InjectedModule.second.second, INFINITE) != WAIT_OBJECT_0) {
			TerminateThread(InjectedModule.second.second, EXIT_SUCCESS);
			_tprintf_s(_T("WARNING: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
		}

		CloseHandle(InjectedModule.second.second);

		HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, Process->first);
		if (!hProcess || (hProcess == INVALID_HANDLE_VALUE)) {
			_tprintf_s(_T("WARNING: OpenProcess (Error = 0x%08X)\n"), GetLastError());
			continue;
		}

		if (!VirtualFreeEx(hProcess, InjectedModule.second.first, 0, MEM_RELEASE)) {
			_tprintf_s(_T("WARNING: VirtualFreeEx (Error = 0x%08X)\n"), GetLastError());
		}

#ifdef _DEBUG
		_tprintf_s(_T("RELEASED RESOURCES FOR INJECTED!\n"));
#endif // _DEBUG
	}

	g_InjectedModules.clear();

	if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
		_tprintf_s(_T("ERROR: WaitForSingleObject (Error = 0x%08X)\n"), GetLastError());
		TerminateProcess(pi.hProcess, EXIT_FAILURE);
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	DWORD unExitCode = EXIT_FAILURE;
	if (!GetExitCodeProcess(pi.hProcess, &unExitCode)) {
		_tprintf_s(_T("ERROR: GetExitCodeProcess (Error = 0x%08X)\n"), GetLastError());
		CloseHandles(pi);
		CloseHandle(hJob);
		return EXIT_FAILURE;
	}

	return unExitCode;
}
