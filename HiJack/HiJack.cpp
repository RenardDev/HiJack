
// Default
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbghelp.h>

// C
#include <io.h>
#include <fcntl.h>
#include <conio.h>

// C++
#include <clocale>

// STL
#include <type_traits>
#include <array>
#include <string>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <cwctype>
#include <cctype>

// Detours
#include "Detours.h"

// CompileStackString
#include "CompileStackString.h"

// Types
using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
using tstring_optional = std::pair<bool, tstring>;

using fnDbgPrint = ULONG(NTAPI*)(PCSTR Format, ...);

using fnRtlDosPathNameToNtPathName_U = BOOLEAN(NTAPI*)(PCWSTR DosName, PUNICODE_STRING NtName, PCWSTR* DosFilePath, PUNICODE_STRING NtFilePath);

using fnRtlFreeUnicodeString = void(NTAPI*)(PUNICODE_STRING UnicodeString);
using fnRtlFreeAnsiString = void(NTAPI*)(PANSI_STRING AnsiString);

using fnRtlInitUnicodeString = void(NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
using fnRtlInitAnsiString = void(NTAPI*)(PANSI_STRING DestinationString, PCSZ SourceString);
using fnRtlUnicodeStringToAnsiString = NTSTATUS(NTAPI*)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
using fnRtlAnsiStringToUnicodeString = NTSTATUS(NTAPI*)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);

using fnRtlAllocateHeap = PVOID(NTAPI*)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
using fnRtlFreeHeap = BOOLEAN(NTAPI*)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

using fnNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using fnNtFreeVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
using fnNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
using fnNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

using fnNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
using fnNtFlushInstructionCache = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);

using fnLdrLoadDll = NTSTATUS(NTAPI*)(PWSTR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
using fnLdrGetDllHandle = NTSTATUS(NTAPI*)(PWORD pwPath, PVOID Unused, PUNICODE_STRING ModuleFileName, PHANDLE pHModule);
using fnLdrGetProcedureAddress = NTSTATUS(NTAPI*)(PVOID ModuleHandle, PANSI_STRING ProcedureName, ULONG Ordinal, PVOID* ProcedureAddress);

using fnRtlHashUnicodeString = NTSTATUS(NTAPI*)(PUNICODE_STRING, BOOLEAN, ULONG, PULONG);
using fnRtlRbInsertNodeEx = VOID(NTAPI*)(Detours::PRTL_RB_TREE, Detours::PRTL_BALANCED_NODE, BOOLEAN, Detours::PRTL_BALANCED_NODE);
using fnRtlRbRemoveNode = VOID(NTAPI*)(Detours::PRTL_RB_TREE, Detours::PRTL_BALANCED_NODE);

using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

enum HIJACK_FLAGS : unsigned char {
	HIJACK_FLAG_NONE = 0,
	HIJACK_FLAG_IMMEDIATELY_UNLOAD = 1,
	HIJACK_FLAG_LDR_LINKING = 2
};

typedef struct _LOADER_DATA {
	HIJACK_FLAGS m_unFlags;

	void* m_pImageAddress;

	HMODULE m_hNTDLL;

	fnDbgPrint m_pDbgPrint;

	fnRtlDosPathNameToNtPathName_U m_pRtlDosPathNameToNtPathName_U;
	fnRtlFreeUnicodeString m_pRtlFreeUnicodeString;
	fnRtlFreeAnsiString m_pRtlFreeAnsiString;
	fnRtlInitUnicodeString m_pRtlInitUnicodeString;
	fnRtlInitAnsiString m_pRtlInitAnsiString;
	fnRtlUnicodeStringToAnsiString m_pRtlUnicodeStringToAnsiString;
	fnRtlAnsiStringToUnicodeString m_pRtlAnsiStringToUnicodeString;
	fnRtlAllocateHeap m_pRtlAllocateHeap;
	fnRtlFreeHeap m_pRtlFreeHeap;
	fnNtAllocateVirtualMemory m_pNtAllocateVirtualMemory;
	fnNtFreeVirtualMemory m_pNtFreeVirtualMemory;
	fnNtReadVirtualMemory m_pNtReadVirtualMemory;
	fnNtWriteVirtualMemory m_pNtWriteVirtualMemory;
	fnNtProtectVirtualMemory m_pNtProtectVirtualMemory;
	fnNtFlushInstructionCache m_pNtFlushInstructionCache;
	fnLdrLoadDll m_pLdrLoadDll;
	fnLdrGetDllHandle m_pLdrGetDllHandle;
	fnLdrGetProcedureAddress m_pLdrGetProcedureAddress;
	fnRtlHashUnicodeString m_pRtlHashUnicodeString;
	fnRtlRbInsertNodeEx m_pRtlRbInsertNodeEx;
	fnRtlRbRemoveNode m_pRtlRbRemoveNode;

	wchar_t m_szImageName[MAX_PATH];
} LOADER_DATA, *PLOADER_DATA;

struct IFT_HDR_MIN {
	ULONG Count;
	ULONG MaxCount;
};

struct IFT_HDR_FULL {
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	ULONG Overflow;
};

#ifdef _WIN64
struct IFT_ENTRY64 {
	PVOID pImageBase;
	ULONG unSizeOfImage;
	ULONG unSizeOfTable;
	ULONG_PTR unExceptionDirectory;
};

using IFT_ENTRY = IFT_ENTRY64;
#elif _WIN32
struct IFT_ENTRY32 {
	PVOID pImageBase;
	ULONG unSizeOfImage;
	ULONG unExceptionDirectory;
	ULONG unExceptionDirectorySize;
};

using IFT_ENTRY = IFT_ENTRY32;
#endif

struct IFT_VIEW {
	BYTE* pBase = nullptr;

	ULONG unCountOff = 0;
	ULONG unMaxCountOff = 0;
	ULONG unEpochOff = 0;
	ULONG unOverflowOff = 0;
	ULONG unEntriesOff = 0;

	volatile ULONG* pCount = nullptr;
	volatile ULONG* pMaxCount = nullptr;
	volatile ULONG* pEpoch = nullptr;
	volatile BYTE* pOverflow = nullptr;
	IFT_ENTRY* pEntries = nullptr;

	ULONG unCount = 0;
	ULONG unMaxCount = 0;

	PVOID pProtectionBase = nullptr;
	SIZE_T unProtectionSize = 0;
	ULONG unOldProtection = 0;
	bool bProtectionActive = false;
};

// General definitions

#define HIJACK_VERSION "4.1.3"

#define ProcessDebugObjectHandle static_cast<PROCESSINFOCLASS>(0x1E)
#define ProcessDebugFlags static_cast<PROCESSINFOCLASS>(0x1F)
#define SafeCloseHandle(X)                    \
	if ((X) && (X != INVALID_HANDLE_VALUE)) { \
		CloseHandle(X);                       \
	}
#define FileStandardInformation static_cast<FILE_INFORMATION_CLASS>(5)

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);

DEFINE_SECTION(".load", SECTION_READWRITE)

// [{
//     PID: (HANDLE, START ADDRESS)
// }]
std::unordered_map<DWORD, std::pair<HANDLE, LPVOID>> g_Processes;

// [{
//     PID: STUB ADDRESS
// }]
std::unordered_map<DWORD, LPVOID> g_Stub;

// [{
//     PID: [{
//         TID: CALLBACK ADDRESS
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, LPVOID>> g_TLSReArm;

// [{
//     PID: [{
//         CALLBACK ADDRESS: ORIGINAL BYTES
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, BYTE>> g_TLSOriginalByte;

// [{
//     PID: [{
//         CALLBACK ADDRESS: MODULE BASE
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, LPVOID>> g_TLSCallBackOwner;

// [{
//     PID: [{
//         ENTRYPOINT: ORIGINAL BYTES
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, BYTE>> g_DLLEntryPointOriginalByte;

// [{
//     PID: [{
//         ENTRYPOINT: MODULE_BASE
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<LPVOID, LPVOID>> g_DLLEntryPointOwner;

// [{
//     PID: [{
//         TID: ENTRYPOINT
//     }]
// }]
std::unordered_map<DWORD, std::unordered_map<DWORD, LPVOID>> g_DLLEntryPointReArm;

// [{
//     PID: ORIGINAL BYTES
// }]
std::unordered_map<DWORD, BYTE> g_ProcessesOriginalEntryPointByte;

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

// [{
//     PID: [
//         HANDLE
//     ]
// }]
std::unordered_map<DWORD, HANDLE> g_ProcessSuspendedMainThreads;

// [{
//     PID: (BASE ADDRESS, SIZE)
// }]
std::unordered_map<DWORD, std::pair<LPVOID, size_t>> g_RemoteLoaderSection;

// [{
//     PID: [
//         HANDLE
//     ]
// }]
std::unordered_map<DWORD, HANDLE> g_ProcessInjectionThreads;

bool g_bContinueDebugging = true;
HIJACK_FLAGS g_unHiJackFlags = HIJACK_FLAG_NONE;
bool g_bGlobalDisableThreadLibraryCalls = false;

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

	FreeSid(AdministratorsGroup);
	return bIsAdmin;
}

bool ReLaunchAsAdmin(bool bAllowCancel = false) {
	TCHAR szPath[MAX_PATH];
	if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
		return false;
	}

	LPCTSTR szCommandLine = GetCommandLine();
	LPCTSTR szArguments = _tcschr(szCommandLine, _T(' '));
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
				const size_t unNameLength = _tcslen(szName);

				bFound = (_tcsnicmp(szProcessPath, szName, unNameLength) == 0) && (*(szProcessPath + unNameLength) == _T('\\'));
				if (bFound) {
					TCHAR szTempFile[MAX_PATH];
					StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szProcessPath + unNameLength);
					StringCchCopyN(szProcessPath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
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
				const size_t unNameLength = _tcslen(szName);

				bFound = (_tcsnicmp(szFilePath, szName, unNameLength) == 0) && (*(szFilePath + unNameLength) == _T('\\'));
				if (bFound) {
					TCHAR szTempFile[MAX_PATH];
					StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, szFilePath + unNameLength);
					StringCchCopyN(szFilePath, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
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

LPVOID EnsureStub(DWORD unProcessID, HANDLE hProcess) {
	auto it = g_Stub.find(unProcessID);
	if (it != g_Stub.end()) {
		return it->second;
	}

#ifdef _WIN64
	BYTE pStub[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xC3                          // ret
	};
#else
	BYTE pStub[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xC2, 0x0C, 0x00              // ret 0x0C   ; DllMain/TLS __stdcall: 3 args = 12 bytes
	};
#endif

	LPVOID pMemory = VirtualAllocEx(hProcess, nullptr, sizeof(pStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMemory) {
		return nullptr;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pMemory, pStub, sizeof(pStub), &unWritten) || (unWritten != sizeof(pStub))) {
		VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
		return nullptr;
	}

	FlushInstructionCache(hProcess, pMemory, sizeof(pStub));

	g_Stub[unProcessID] = pMemory;

	return pMemory;
}

bool EnumTLSCallBacks(HANDLE hProcess, LPVOID lpBaseOfImage, std::vector<LPVOID>& vecCallBacks) {
	IMAGE_DOS_HEADER dh {};
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, lpBaseOfImage, &dh, sizeof(dh), &unReadden) || (unReadden != sizeof(dh))) {
		return false;
	}

	if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS nths {};
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(lpBaseOfImage) + dh.e_lfanew, &nths, sizeof(nths), &unReadden) || (unReadden != sizeof(nths))) {
		return false;
	}

	if (nths.Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	const auto& TLSDD = nths.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (!TLSDD.VirtualAddress || !TLSDD.Size) {
		return false;
	}

#ifdef _WIN64
	IMAGE_TLS_DIRECTORY64 TLSDirectory {};
#else
	IMAGE_TLS_DIRECTORY32 TLSDirectory {};
#endif
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(lpBaseOfImage) + TLSDD.VirtualAddress, &TLSDirectory, sizeof(TLSDirectory), &unReadden) || (unReadden != sizeof(TLSDirectory))) {
		return false;
	}

	if (!TLSDirectory.AddressOfCallBacks) {
		return false;
	}

	LPVOID pArray = reinterpret_cast<LPVOID>(TLSDirectory.AddressOfCallBacks);
	while (true) {
		LPVOID pCallBack = nullptr;
		unReadden = 0;
		if (!ReadProcessMemory(hProcess, pArray, &pCallBack, sizeof(pCallBack), &unReadden) || (unReadden != sizeof(pCallBack))) {
			break;
		}

		if (!pCallBack) {
			break;
		}

		vecCallBacks.push_back(pCallBack);

		pArray = reinterpret_cast<PBYTE>(pArray) + sizeof(LPVOID);
	}

	if (vecCallBacks.empty()) {
		return false;
	}

	return true;
}

bool WriteByte(HANDLE hProcess, LPVOID pAddress, BYTE unValue, BYTE* pPreviousByte = nullptr) {
	BYTE unOldByte = 0;
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, pAddress, &unOldByte, 1, &unReadden) || (unReadden != 1)) {
		return false;
	}

	if (pPreviousByte) {
		*pPreviousByte = unOldByte;
	}

	MEMORY_BASIC_INFORMATION mbi {};
	if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi))) {
		return false;
	}

	DWORD unOldProtection = 0;
	if (!VirtualProtectEx(hProcess, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
		return false;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pAddress, &unValue, 1, &unWritten) || (unWritten != 1)) {
		FlushInstructionCache(hProcess, pAddress, 1);

		DWORD unDummy = 0;
		VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);

		return false;
	}

	FlushInstructionCache(hProcess, pAddress, 1);

	DWORD unDummy = 0;
	VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);
	return true;
}

bool RestoreByte(HANDLE hProcess, LPVOID pAddress, BYTE unOriginal) {
	MEMORY_BASIC_INFORMATION mbi {};
	if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi))) {
		return false;
	}

	DWORD unOldProtection = 0;
	if (!VirtualProtectEx(hProcess, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
		return false;
	}

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(hProcess, pAddress, &unOriginal, 1, &unWritten) || (unWritten != 1)) {
		FlushInstructionCache(hProcess, pAddress, 1);

		DWORD unDummy = 0;
		VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);

		return false;
	}

	FlushInstructionCache(hProcess, pAddress, 1);

	DWORD unDummy = 0;
	VirtualProtectEx(hProcess, mbi.BaseAddress, 1, unOldProtection, &unDummy);
	return true;
}

bool SetTLSBreakPointsForModule(DWORD unProcessID, HANDLE hProcess, LPVOID pModuleBase) {
	std::vector<LPVOID> vecCallBacks;
	if (!EnumTLSCallBacks(hProcess, pModuleBase, vecCallBacks)) {
		return true;
	}

	for (auto& pCallBack : vecCallBacks) {
		if (g_TLSOriginalByte[unProcessID].count(pCallBack)) {
			continue;
		}

		BYTE unOriginal = 0;
		if (!WriteByte(hProcess, pCallBack, 0xCC, &unOriginal)) {
			continue;
		}

		g_TLSOriginalByte[unProcessID][pCallBack] = unOriginal;
		g_TLSCallBackOwner[unProcessID][pCallBack] = pModuleBase;
	}

	return true;
}

bool SetDLLEntryBreakPointForModule(DWORD unProcessID, HANDLE hProcess, LPVOID pMmoduleBase) {
	IMAGE_DOS_HEADER dh {};
	SIZE_T unReadden = 0;
	if (!ReadProcessMemory(hProcess, pMmoduleBase, &dh, sizeof(dh), &unReadden) || (unReadden != sizeof(dh))) {
		return false;
	}

	if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS nths {};
	unReadden = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<BYTE*>(pMmoduleBase) + dh.e_lfanew, &nths, sizeof(nths), &unReadden) || (unReadden != sizeof(nths))) {
		return false;
	}

	if (nths.Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	if (!(nths.FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		return true;
	}

	DWORD unEntryPoint = nths.OptionalHeader.AddressOfEntryPoint;
	if (!unEntryPoint) {
		return true;
	}

	LPVOID pEntryPoint = reinterpret_cast<BYTE*>(pMmoduleBase) + unEntryPoint;

	if (g_DLLEntryPointOriginalByte[unProcessID].count(pEntryPoint)) {
		return true;
	}

	BYTE unOriginal = 0;
	if (!WriteByte(hProcess, pEntryPoint, 0xCC, &unOriginal)) {
		return false;
	}

	g_DLLEntryPointOriginalByte[unProcessID][pEntryPoint] = unOriginal;
	g_DLLEntryPointOwner[unProcessID][pEntryPoint] = pMmoduleBase;

	return true;
}

void RestoreAllProcessBreakPoints(DWORD unProcessID) {
	LPVOID pStartAddress = nullptr;
	auto Process = GetDebugProcess(unProcessID, &pStartAddress);
	if (!Process) {
		return;
	}

	auto itEntryPointOriginalByte = g_ProcessesOriginalEntryPointByte.find(unProcessID);
	if (itEntryPointOriginalByte != g_ProcessesOriginalEntryPointByte.end()) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQueryEx(Process, pStartAddress, &mbi, sizeof(mbi))) {
			DWORD unOldProtection = 0;
			if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
				SIZE_T unWritten = 0;
				WriteProcessMemory(Process, pStartAddress, &itEntryPointOriginalByte->second, 1, &unWritten);
				FlushInstructionCache(Process, pStartAddress, 1);
				DWORD unDummy = 0;
				VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
			}
		}

		g_ProcessesOriginalEntryPointByte.erase(itEntryPointOriginalByte);
	}

	auto itTLSOriginalByte = g_TLSOriginalByte.find(unProcessID);
	if (itTLSOriginalByte != g_TLSOriginalByte.end()) {
		for (const auto& rec : itTLSOriginalByte->second) {
			if (!rec.first) {
				continue;
			}

			MEMORY_BASIC_INFORMATION mbi {};
			if (VirtualQueryEx(Process, rec.first, &mbi, sizeof(mbi))) {
				DWORD unOldProtection = 0;
				if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
					SIZE_T unWritten = 0;
					WriteProcessMemory(Process, rec.first, &rec.second, 1, &unWritten);
					FlushInstructionCache(Process, rec.first, 1);
					DWORD unDummy = 0;
					VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
				}
			}
		}

		g_TLSOriginalByte.erase(itTLSOriginalByte);
		g_TLSCallBackOwner.erase(unProcessID);
	}

	g_TLSReArm.erase(unProcessID);

	if (g_Stub.count(unProcessID)) {
		VirtualFreeEx(Process, g_Stub[unProcessID], 0, MEM_RELEASE);
		g_Stub.erase(unProcessID);
	}

	auto itDLLOriginalByte = g_DLLEntryPointOriginalByte.find(unProcessID);
	if (itDLLOriginalByte != g_DLLEntryPointOriginalByte.end()) {
		for (const auto& rec : itDLLOriginalByte->second) {
			if (!rec.first) {
				continue;
			}

			MEMORY_BASIC_INFORMATION mbi {};
			if (VirtualQueryEx(Process, rec.first, &mbi, sizeof(mbi))) {
				DWORD unOldProtection = 0;
				if (VirtualProtectEx(Process, mbi.BaseAddress, 1, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
					SIZE_T unWritten = 0;
					WriteProcessMemory(Process, rec.first, &rec.second, 1, &unWritten);
					FlushInstructionCache(Process, rec.first, 1);
					DWORD unDummy = 0;
					VirtualProtectEx(Process, mbi.BaseAddress, 1, unOldProtection, &unDummy);
				}
			}
		}

		g_DLLEntryPointOriginalByte.erase(itDLLOriginalByte);
		g_DLLEntryPointOwner.erase(unProcessID);
	}

	g_DLLEntryPointReArm.erase(unProcessID);
}

tstring_optional GetProcessHiJackLibraryName(HANDLE hProcess) {
	auto ProcessPath = GetProcessPath(hProcess);
	if (!ProcessPath.first) {
		return { false, _T("") };
	}

	TCHAR szName[_MAX_FNAME] {};
	errno_t err = _tsplitpath_s(ProcessPath.second.c_str(), nullptr, 0, nullptr, 0, szName, _countof(szName), nullptr, 0);
	if (err != 0) {
		_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
		return { false, _T("") };
	}

	TCHAR szLibraryName[MAX_PATH] {};
#ifdef _WIN64
	if (_stprintf_s(szLibraryName, _countof(szLibraryName), _T("%s_hijack.dll"), szName) < 0) {
#else
	if (_stprintf_s(szLibraryName, _countof(szLibraryName), _T("%s_hijack32.dll"), szName) < 0) {
#endif
		_tprintf_s(_T("ERROR: _stprintf_s (Error = 0x%08X)\n"), GetLastError());
		return { false, _T("") };
	}

	tstring LibraryName = szLibraryName;

	std::transform(LibraryName.begin(), LibraryName.end(), LibraryName.begin(), [](TCHAR c) {
#ifdef _UNICODE
		return std::towlower(c);
#else
		return std::tolower(static_cast<unsigned char>(c));
#endif
	});

	return { true, LibraryName };
}

bool GetRemoteModuleHandle(HANDLE hProcess, const TCHAR* szModuleName, HMODULE* phModule) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !szModuleName) {
		return false;
	}

	const size_t unModuleNameLength = _tcsclen(szModuleName);

	HMODULE hModules[1024] {};
	DWORD cbNeeded = 0;

	if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			TCHAR szName[MAX_PATH] {};
			if (GetModuleFileNameEx(hProcess, hModules[i], szName, MAX_PATH)) {
				if (_tcsicmp(szName + _tcsclen(szName) - unModuleNameLength, szModuleName) == 0) {

					if (phModule) {
						*phModule = hModules[i];
					}

					return true;
				}
			}
		}
	}

	return false;
}

template <typename T>
bool GetRemoteProcAddress(HANDLE hProcess, const TCHAR* szModuleName, const char* szProcName, T* pFunc) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !szModuleName || !szProcName) {
		return false;
	}

	HMODULE hModule = GetModuleHandle(szModuleName);
	if (!hModule) {
		return false;
	}

	HMODULE hRemoteModule = nullptr;
	if (!GetRemoteModuleHandle(hProcess, szModuleName, &hRemoteModule)) {
		return false;
	}

	T pLocalProcAddress = reinterpret_cast<T>(GetProcAddress(hModule, szProcName));
	if (!pLocalProcAddress) {
		return false;
	}

	const uintptr_t unOffset = reinterpret_cast<uintptr_t>(pLocalProcAddress) - reinterpret_cast<uintptr_t>(hModule);

	if (pFunc) {
		*pFunc = reinterpret_cast<T>(reinterpret_cast<uintptr_t>(hRemoteModule) + unOffset);
	}

	return true;
}

bool FillLoaderData(HANDLE hProcess, PLOADER_DATA pLoaderData) {
	if (!hProcess || (hProcess == INVALID_HANDLE_VALUE) || !pLoaderData) {
		return false;
	}

	if (!GetRemoteModuleHandle(hProcess, _T("ntdll.dll"), &pLoaderData->m_hNTDLL)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "DbgPrint", &pLoaderData->m_pDbgPrint)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlDosPathNameToNtPathName_U", &pLoaderData->m_pRtlDosPathNameToNtPathName_U)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeUnicodeString", &pLoaderData->m_pRtlFreeUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeAnsiString", &pLoaderData->m_pRtlFreeAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlInitUnicodeString", &pLoaderData->m_pRtlInitUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlInitAnsiString", &pLoaderData->m_pRtlInitAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlUnicodeStringToAnsiString", &pLoaderData->m_pRtlUnicodeStringToAnsiString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlAnsiStringToUnicodeString", &pLoaderData->m_pRtlAnsiStringToUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlAllocateHeap", &pLoaderData->m_pRtlAllocateHeap)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlFreeHeap", &pLoaderData->m_pRtlFreeHeap)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtAllocateVirtualMemory", &pLoaderData->m_pNtAllocateVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtFreeVirtualMemory", &pLoaderData->m_pNtFreeVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtReadVirtualMemory", &pLoaderData->m_pNtReadVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtWriteVirtualMemory", &pLoaderData->m_pNtWriteVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtProtectVirtualMemory", &pLoaderData->m_pNtProtectVirtualMemory)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "NtFlushInstructionCache", &pLoaderData->m_pNtFlushInstructionCache)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrLoadDll", &pLoaderData->m_pLdrLoadDll)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrGetDllHandle", &pLoaderData->m_pLdrGetDllHandle)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "LdrGetProcedureAddress", &pLoaderData->m_pLdrGetProcedureAddress)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlHashUnicodeString", &pLoaderData->m_pRtlHashUnicodeString)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlRbInsertNodeEx", &pLoaderData->m_pRtlRbInsertNodeEx)) {
		return false;
	}

	if (!GetRemoteProcAddress(hProcess, _T("ntdll.dll"), "RtlRbRemoveNode", &pLoaderData->m_pRtlRbRemoveNode)) {
		return false;
	}

	return true;
}

DEFINE_DATA_IN_SECTION(".load") LOADER_DATA LoaderData;

DEFINE_CODE_IN_SECTION(".load") SIZE_T __align_up(SIZE_T v, SIZE_T a) {
	return (v + a - 1) & ~(a - 1);
}

DEFINE_CODE_IN_SECTION(".load") bool MapImage(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));

	PVOID pDesiredBase = reinterpret_cast<PVOID>(pNTHs->OptionalHeader.ImageBase);
	SIZE_T unSizeOfImage = pNTHs->OptionalHeader.SizeOfImage;

	if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, 0, &unSizeOfImage, MEM_RESERVE, PAGE_READWRITE))) {
		pDesiredBase = nullptr;

		if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, 0, &unSizeOfImage, MEM_RESERVE, PAGE_READWRITE))) {
			return false;
		}
	}

	PVOID pHeaders = pDesiredBase;
	SIZE_T unSizeOfHeaders = __align_up(pNTHs->OptionalHeader.SizeOfHeaders, 0x1000);
	if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pHeaders, 0, &unSizeOfHeaders, MEM_COMMIT, PAGE_READWRITE))) {
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
		return false;
	}

	if (!NT_SUCCESS(pLD->m_pNtWriteVirtualMemory(reinterpret_cast<HANDLE>(-1), pDesiredBase, pDH, pNTHs->OptionalHeader.SizeOfHeaders, nullptr))) {
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
		return false;
	}

	auto pFirstSection = IMAGE_FIRST_SECTION(pNTHs);
	for (WORD i = 0; i < pNTHs->FileHeader.NumberOfSections; ++i) {
		SIZE_T unCommitSize = pFirstSection[i].Misc.VirtualSize ? pFirstSection[i].Misc.VirtualSize : pFirstSection[i].SizeOfRawData;
		if (!unCommitSize) {
			continue;
		}

		unCommitSize = __align_up(unCommitSize, 0x1000);

		PVOID pSectionAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(pDesiredBase) + pFirstSection[i].VirtualAddress);
		if (!NT_SUCCESS(pLD->m_pNtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pSectionAddress, 0, &unCommitSize, MEM_COMMIT, PAGE_READWRITE))) {
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
			return false;
		}

		ULONG unToCopy = pFirstSection[i].SizeOfRawData;
		if (unToCopy) {
			PVOID pSectionData = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(pDH) + pFirstSection[i].PointerToRawData);
			if (!NT_SUCCESS(pLD->m_pNtWriteVirtualMemory(reinterpret_cast<HANDLE>(-1), pSectionAddress, pSectionData, unToCopy, nullptr))) {
				pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pDesiredBase, &unSizeOfImage, MEM_RELEASE);
				return false;
			}
		}
	}

	SIZE_T unZero = 0;
	pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unZero, MEM_RELEASE);
	pLD->m_pImageAddress = pDesiredBase;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool FixRelocations(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));

	const DWORD_PTR unDelta = reinterpret_cast<DWORD_PTR>(pDH) - pNTHs->OptionalHeader.ImageBase;
	if (!unDelta) {
		return true;
	}

	if (pNTHs->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
		return false;
	}

	auto pDD = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pDD->VirtualAddress || !pDD->Size) {
		return true;
	}

	const WORD unMachine = pNTHs->FileHeader.Machine;

	auto pRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<char*>(pDH) + pDD->VirtualAddress));
	while (pRelocation->VirtualAddress && pRelocation->SizeOfBlock) {
		DWORD_PTR unBase = reinterpret_cast<DWORD_PTR>(pDH) + pRelocation->VirtualAddress;
		DWORD unCount = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD pEntries = reinterpret_cast<PWORD>(pRelocation + 1);

		for (DWORD i = 0; i < unCount; ++i) {
			WORD unEntry = pEntries[i];
			BYTE unType = unEntry >> 12;
			WORD unOffset = unEntry & 0x0FFF;
			DWORD_PTR unPatch = unBase + unOffset;

			switch (unType) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				case IMAGE_REL_BASED_HIGH:
					*reinterpret_cast<WORD*>(unPatch) += HIWORD(static_cast<DWORD>(unDelta));
					break;

				case IMAGE_REL_BASED_LOW:
					*reinterpret_cast<WORD*>(unPatch) += LOWORD(static_cast<DWORD>(unDelta));
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*reinterpret_cast<DWORD*>(unPatch) += static_cast<DWORD>(unDelta);
					break;

				case IMAGE_REL_BASED_HIGHADJ: {
					if (i + 1 >= unCount) {
						return false;
					}

					SHORT unAddend = static_cast<SHORT>(pEntries[++i]);
					LONG unHigh = *reinterpret_cast<SHORT*>(unPatch);
					LONG unTemp = (unHigh << 16) + unAddend + static_cast<LONG>(unDelta);
					*reinterpret_cast<WORD*>(unPatch) = HIWORD(unTemp);

					break;
				}

				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<ULONGLONG*>(unPatch) += static_cast<ULONGLONG>(unDelta);
					break;

				case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
					switch (unMachine) {
						case IMAGE_FILE_MACHINE_ARMNT:
						case IMAGE_FILE_MACHINE_THUMB:
							*reinterpret_cast<DWORD*>(unPatch) += static_cast<DWORD>(unDelta);
							break;

						case IMAGE_FILE_MACHINE_MIPS16:
						case IMAGE_FILE_MACHINE_MIPSFPU:
						case IMAGE_FILE_MACHINE_MIPSFPU16: {
							DWORD ins = *reinterpret_cast<DWORD*>(unPatch);
							ins = (ins & ~0x03FFFFFF) | ((((ins & 0x03FFFFFF) << 2) + static_cast<DWORD>(unDelta)) >> 2);
							*reinterpret_cast<DWORD*>(unPatch) = ins;
							break;
						}

						default:
							return false;
					}

					break;

				case IMAGE_REL_BASED_THUMB_MOV32:
					if (unMachine == IMAGE_FILE_MACHINE_ARMNT) {
						*reinterpret_cast<DWORD*>(unPatch) += static_cast<DWORD>(unDelta);
					} else {
						return false;
					}

					break;

				case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
					switch (unMachine) {
						case IMAGE_FILE_MACHINE_IA64:
							*reinterpret_cast<ULONGLONG*>(unPatch) += static_cast<ULONGLONG>(unDelta);
							break;

						case IMAGE_FILE_MACHINE_MIPS16:
						case IMAGE_FILE_MACHINE_MIPSFPU:
						case IMAGE_FILE_MACHINE_MIPSFPU16: {
							WORD ins = *reinterpret_cast<WORD*>(unPatch);
							ins = (ins & ~0xFFFF) | ((((ins & 0xFFFF) << 2) + static_cast<WORD>(unDelta)) >> 2);
							*reinterpret_cast<WORD*>(unPatch) = ins;
							break;
						}

						default:
							return false;
					}

					break;

				default:
					return false;
			}
		}

		pRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<char*>(pRelocation) + pRelocation->SizeOfBlock));
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ResolveImports(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));

	auto pDD = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!pDD->VirtualAddress) {
		return true;
	}

	auto pIID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((reinterpret_cast<char*>(pDH) + pDD->VirtualAddress));
	while (pIID->Name) {
		const char* szModuleName = reinterpret_cast<const char*>((reinterpret_cast<char*>(pDH) + pIID->Name));

		ANSI_STRING as {};
		UNICODE_STRING us {};
		pLD->m_pRtlInitAnsiString(&as, szModuleName);
		if (!NT_SUCCESS(pLD->m_pRtlAnsiStringToUnicodeString(&us, &as, TRUE))) {
			return false;
		}

		HMODULE hModule = nullptr;
		if (!NT_SUCCESS(pLD->m_pLdrLoadDll(NULL, 0, &us, reinterpret_cast<PHANDLE>(&hModule)))) {
			pLD->m_pRtlFreeUnicodeString(&us);
			return false;
		}

		pLD->m_pRtlFreeUnicodeString(&us);

		PIMAGE_THUNK_DATA pThunk = (pIID->OriginalFirstThunk != 0)
		                               ? reinterpret_cast<PIMAGE_THUNK_DATA>((reinterpret_cast<char*>(pDH) + pIID->OriginalFirstThunk))
		                               : reinterpret_cast<PIMAGE_THUNK_DATA>((reinterpret_cast<char*>(pDH) + pIID->FirstThunk));
		PIMAGE_THUNK_DATA pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((reinterpret_cast<char*>(pDH) + pIID->FirstThunk));

		while (pThunk->u1.AddressOfData) {
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				ULONG unOrdinal = IMAGE_ORDINAL(pThunk->u1.Ordinal);

				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, NULL, unOrdinal, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);

			} else {
				auto pIBN = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((reinterpret_cast<char*>(pDH) + pThunk->u1.AddressOfData));

				ANSI_STRING asn {};
				pLD->m_pRtlInitAnsiString(&asn, pIBN->Name);

				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, &asn, 0, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);
			}

			++pThunk;
			++pIAT;
		}

		++pIID;
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ResolveDelayedImports(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));

	auto pDD = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (!pDD->VirtualAddress) {
		return true;
	}

	auto pDLD = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>((reinterpret_cast<char*>(pDH) + pDD->VirtualAddress));
	while (pDLD->DllNameRVA) {
		const char* szModule = reinterpret_cast<const char*>((reinterpret_cast<char*>(pDH) + pDLD->DllNameRVA));

		ANSI_STRING as {};
		UNICODE_STRING us {};
		pLD->m_pRtlInitAnsiString(&as, szModule);
		if (!NT_SUCCESS(pLD->m_pRtlAnsiStringToUnicodeString(&us, &as, TRUE))) {
			return false;
		}

		HMODULE hModule = nullptr;
		if (!NT_SUCCESS(pLD->m_pLdrLoadDll(NULL, 0, &us, reinterpret_cast<PHANDLE>(&hModule)))) {
			pLD->m_pRtlFreeUnicodeString(&us);
			return false;
		}

		pLD->m_pRtlFreeUnicodeString(&us);

		auto pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>((reinterpret_cast<char*>(pDH) + pDLD->ImportAddressTableRVA));
		auto pINT = reinterpret_cast<PIMAGE_THUNK_DATA>((reinterpret_cast<char*>(pDH) + pDLD->ImportNameTableRVA));

		while (pINT->u1.Ordinal) {
			if (pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				ULONG unOrdinal = IMAGE_ORDINAL(pINT->u1.Ordinal);

				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, NULL, unOrdinal, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);
			} else {
				auto pIBN = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((reinterpret_cast<char*>(pDH) + pINT->u1.AddressOfData));

				ANSI_STRING asn {};
				pLD->m_pRtlInitAnsiString(&asn, pIBN->Name);

				PVOID pProcedure = nullptr;
				if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(hModule, &asn, 0, &pProcedure))) {
					return false;
				}

				pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(pProcedure);
			}

			++pIAT;
			++pINT;
		}

		++pDLD;
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ProtectSections(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));

	auto pFirstSection = IMAGE_FIRST_SECTION(pNTHs);
	for (WORD i = 0; i < pNTHs->FileHeader.NumberOfSections; ++i) {
		DWORD unCharacteristics = pFirstSection[i].Characteristics;
		DWORD unProtection = (unCharacteristics & IMAGE_SCN_MEM_EXECUTE) ? ((unCharacteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : (unCharacteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE
		                                                                                                                                                                                       : (unCharacteristics & IMAGE_SCN_MEM_READ ? PAGE_READONLY : PAGE_NOACCESS);
		PVOID unAddress = reinterpret_cast<PVOID>((reinterpret_cast<char*>(pDH) + pFirstSection[i].VirtualAddress));
		SIZE_T unSize = pFirstSection[i].Misc.VirtualSize ? pFirstSection[i].Misc.VirtualSize : pFirstSection[i].SizeOfRawData;
		if (!unSize) {
			continue;
		}

		unSize = __align_up(unSize, 0x1000);

		ULONG unOldProtection = 0;
		if (!NT_SUCCESS(pLD->m_pNtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &unAddress, &unSize, unProtection, &unOldProtection))) {
			return false;
		}

		if (unCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
			pLD->m_pNtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), nullptr, 0);
		}
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PPEB GetPEB() {
#ifdef _M_X64
	return reinterpret_cast<Detours::PPEB>(__readgsqword(0x60));
#elif _M_IX86
	return reinterpret_cast<Detours::PPEB>(__readfsdword(0x30));
#endif
}

DEFINE_CODE_IN_SECTION(".load") PLIST_ENTRY FindModuleListEntry(void* pBaseAddress) {
	if (!pBaseAddress) {
		return nullptr;
	}

	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->Ldr) {
		return nullptr;
	}

	auto pHead = &pPEB->Ldr->InLoadOrderModuleList;
	for (auto pEntry = pHead->Flink; pEntry != pHead; pEntry = pEntry->Flink) {
		auto pDTE = CONTAINING_RECORD(pEntry, Detours::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pDTE->DllBase == pBaseAddress) {
			return pEntry;
		}
	}

	return nullptr;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PLDR_DATA_TABLE_ENTRY FindModuleDataTableEntry(void* pBaseAddress) {
	if (!pBaseAddress) {
		return nullptr;
	}

	auto pEntry = FindModuleListEntry(pBaseAddress);
	if (!pEntry) {
		return nullptr;
	}

	return CONTAINING_RECORD(pEntry, Detours::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

DEFINE_CODE_IN_SECTION(".load") const wchar_t* __wbasename(const wchar_t* szFullPath) {
	if (!szFullPath) {
		return nullptr;
	}

	const wchar_t* b = szFullPath;

	for (const wchar_t* p = szFullPath; *p; ++p) {
		if ((*p == L'\\') || (*p == L'/')) {
			b = p + 1;
		}
	}

	return b;
}

DEFINE_CODE_IN_SECTION(".load") SIZE_T __wstrlen(const wchar_t* szString) {
	if (!szString) {
		return 0;
	}

	const wchar_t* p = szString;
	while (*p) {
		++p;
	}

	return static_cast<SIZE_T>(p - szString);
}

DEFINE_CODE_IN_SECTION(".load") void __wcopy(wchar_t* szDestionation, const wchar_t* szSource, SIZE_T unSize) {
	if (!szDestionation || !szSource || !unSize) {
		return;
	}

	for (SIZE_T i = 0; i < unSize; ++i) {
		if (!szSource[i]) {
			return;
		}

		szDestionation[i] = szSource[i];
	}
}

DEFINE_CODE_IN_SECTION(".load") bool __MakeHeapUnicodeString(PLOADER_DATA pLD, const wchar_t* szSource, UNICODE_STRING& usOut) {
	usOut.Buffer = nullptr;
	usOut.Length = usOut.MaximumLength = 0;

	if (!pLD || !szSource) {
		return false;
	}

	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->ProcessHeap) {
		return false;
	}

	const SIZE_T unChars = __wstrlen(szSource);
	const SIZE_T unBytes = (unChars + 1) * sizeof(wchar_t);

	wchar_t* szBuffer = reinterpret_cast<wchar_t*>(pLD->m_pRtlAllocateHeap(pPEB->ProcessHeap, HEAP_ZERO_MEMORY, unBytes));
	if (!szBuffer) {
		return false;
	}

	__wcopy(szBuffer, szSource, unChars);
	szBuffer[unChars] = L'\0';

	usOut.Buffer = szBuffer;
	usOut.Length = static_cast<USHORT>(unChars * sizeof(wchar_t));
	usOut.MaximumLength = static_cast<USHORT>(unBytes);

	return true;
}

DEFINE_CODE_IN_SECTION(".load") ULONG HashBaseDllName(PLOADER_DATA pLD, Detours::LDR_DATA_TABLE_ENTRY* pDTE) {
	if (pDTE->BaseDllName.Buffer && pDTE->BaseDllName.Length) {
		ULONG unHash = 0;
		if (NT_SUCCESS(pLD->m_pRtlHashUnicodeString(reinterpret_cast<PUNICODE_STRING>(&pDTE->BaseDllName), TRUE, 0, &unHash))) {
			return unHash;
		}
	}

	if (pDTE->FullDllName.Buffer && pDTE->FullDllName.Length) {
		const PWCHAR szBuffer = pDTE->FullDllName.Buffer;
		const SIZE_T unLength = pDTE->FullDllName.Length / sizeof(WCHAR);
		const WCHAR* szEnd = szBuffer + unLength;

		const WCHAR* s = szEnd;
		while ((s > szBuffer) && (s[-1] != L'\\') && (s[-1] != L'/')) {
			--s;
		}

		Detours::UNICODE_STRING us {};
		us.Buffer = const_cast<PWCH>(s);
		us.Length = static_cast<USHORT>((szEnd - s) * sizeof(WCHAR));
		us.MaximumLength = us.Length;

		ULONG unHash = 0;
		if (NT_SUCCESS(pLD->m_pRtlHashUnicodeString(reinterpret_cast<PUNICODE_STRING>(&us), TRUE, 0, &unHash))) {
			return unHash;
		}
	}

	return 0;
}

DEFINE_CODE_IN_SECTION(".load") void InitializeListHead(PLIST_ENTRY pHead) {
	pHead->Flink = pHead->Blink = pHead;
}

DEFINE_CODE_IN_SECTION(".load") void InsertTailList(PLIST_ENTRY pHead, PLIST_ENTRY pEntry) {
	auto pPrevious = pHead->Blink;
	pEntry->Flink = pHead;
	pEntry->Blink = pPrevious;
	pPrevious->Flink = pEntry;
	pHead->Blink = pEntry;
}

DEFINE_CODE_IN_SECTION(".load") bool AttachDdagNode(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pLD || !pDTE) {
		return false;
	}

	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->ProcessHeap) {
		return false;
	}

	auto pNode = reinterpret_cast<Detours::PLDR_DDAG_NODE>(pLD->m_pRtlAllocateHeap(pPEB->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(Detours::LDR_DDAG_NODE)));
	if (!pNode) {
		return false;
	}

	InitializeListHead(&pNode->Modules);

	pNode->ServiceTagList = nullptr;
	pNode->LoadCount = 1;
	pNode->IncomingDependencies.Tail = nullptr;
	pNode->State = Detours::LDR_DDAG_STATE::LdrModulesReadyToRun;
	pNode->PreorderNumber = 1;
	pNode->LowestLink = 1;

	pDTE->DdagNode = pNode;

	InitializeListHead(&pDTE->NodeModuleLink);
	InsertTailList(&pNode->Modules, &pDTE->NodeModuleLink);

	pDTE->ImageDll = 1;
	pDTE->EntryProcessed = 1;
	pDTE->ProcessAttachCalled = 1;
	pDTE->InLegacyLists = 1;
	pDTE->LoadReason = Detours::LoadReasonDynamicLoad;
	pDTE->ReferenceCount = 1;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") void NormalizeAllLinks(Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	InitializeListHead(&pDTE->InLoadOrderLinks);
	InitializeListHead(&pDTE->InInitializationOrderLinks);
	InitializeListHead(&pDTE->InMemoryOrderLinks);
	InitializeListHead(&pDTE->HashLinks);
	InitializeListHead(&pDTE->NodeModuleLink);
}

DEFINE_CODE_IN_SECTION(".load") WCHAR __towupper(WCHAR c) {
	return ((c >= L'a') && (c <= L'z')) ? (c - (L'a' - L'A')) : c;
}

DEFINE_CODE_IN_SECTION(".load") bool __us_equal_icase(const Detours::UNICODE_STRING& us, const wchar_t* szLit) {
	if (!us.Buffer || !szLit) {
		return false;
	}

	const SIZE_T unLength = __wstrlen(szLit);
	if (us.Length != (unLength * sizeof(wchar_t))) {
		return false;
	}

	for (SIZE_T i = 0; i < unLength; ++i) {
		if (__towupper(us.Buffer[i]) != __towupper(szLit[i])) {
			return false;
		}
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PLDR_DATA_TABLE_ENTRY __FindDTEByBaseName(const wchar_t* szBaseName) {
	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->Ldr) {
		return nullptr;
	}

	auto pHeadEntry = &pPEB->Ldr->InLoadOrderModuleList;
	for (auto pEntry = pHeadEntry->Flink; pEntry != pHeadEntry; pEntry = pEntry->Flink) {
		auto pDTE = CONTAINING_RECORD(pEntry, Detours::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pDTE->BaseDllName.Buffer && pDTE->BaseDllName.Length) {
			if (__us_equal_icase(pDTE->BaseDllName, szBaseName)) {
				return pDTE;
			}
		}
	}

	return nullptr;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PLDR_DATA_TABLE_ENTRY GetNTDLLDTE() {
	auto NTDLL = STACKSTRING(L"ntdll.dll");
	return __FindDTEByBaseName(NTDLL.c_str());
}

DEFINE_CODE_IN_SECTION(".load") bool PointerInModule(const void* pPointer, const Detours::LDR_DATA_TABLE_ENTRY* pDTE) {
	auto unPointer = reinterpret_cast<uintptr_t>(pPointer);
	auto pBase = reinterpret_cast<uintptr_t>(pDTE->DllBase);
	return (unPointer >= pBase) && (unPointer < (pBase + pDTE->SizeOfImage));
}

DEFINE_CODE_IN_SECTION(".load") PLIST_ENTRY FindLdrpHashTableBaseEx(PLOADER_DATA pLD) {
	auto pDTE = GetNTDLLDTE();
	if (!pDTE) {
		return nullptr;
	}

	auto pSelfEntry = &pDTE->HashLinks;
	for (auto pEntry = pSelfEntry->Flink; pEntry && (pEntry != reinterpret_cast<void*>(-1)) && (pEntry != pSelfEntry); pEntry = pEntry->Flink) {
		if (PointerInModule(pEntry, pDTE)) {
			const ULONG unIndex = HashBaseDllName(pLD, pDTE) & 0x1F;
			auto pBase = reinterpret_cast<BYTE*>(pEntry) - unIndex * sizeof(LIST_ENTRY);
			return reinterpret_cast<PLIST_ENTRY>(pBase);
		}
	}

	return nullptr;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PRTL_BALANCED_NODE AscendToRoot(Detours::PRTL_BALANCED_NODE pNode) {
	if (!pNode) {
		return nullptr;
	}

	for (;;) {
		ULONG_PTR unParentValue = pNode->ParentValue;
		if (!unParentValue) {
			break;
		}

#ifdef _WIN64
		pNode = reinterpret_cast<Detours::PRTL_BALANCED_NODE>(unParentValue & ~ULONG_PTR(7));
#else
		pNode = reinterpret_cast<Detours::PRTL_BALANCED_NODE>(unParentValue & ~ULONG_PTR(3));
#endif
	}

	return pNode;
}

DEFINE_CODE_IN_SECTION(".load") bool __secname_eq_nocase8(const BYTE szName[8], const char* szLit) {
	for (int i = 0; i < 8; ++i) {
		char c = szLit[i];
		char n = static_cast<char>(szName[i]);

		if (c == '\0') {
			return n == 0;
		}

		if ((n >= 'a') && (n <= 'z')) {
			n -= 32;
		}

		if ((c >= 'a') && (c <= 'z')) {
			c -= 32;
		}

		if (n != c) {
			return false;
		}
	}

	return szLit[8] == 0;
}

DEFINE_CODE_IN_SECTION(".load") bool FindSection(HMODULE hModule, const char* szName, BYTE*& pBase, SIZE_T& unSize) {
	pBase = nullptr;
	unSize = 0;

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (!pDH || (pDH->e_magic != IMAGE_DOS_SIGNATURE)) {
		return false;
	}

	auto pNTHs = (PIMAGE_NT_HEADERS)(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (!pNTHs || (pNTHs->Signature != IMAGE_NT_SIGNATURE)) {
		return false;
	}

	auto pFirstSection = IMAGE_FIRST_SECTION(pNTHs);
	for (WORD i = 0; i < pNTHs->FileHeader.NumberOfSections; ++i) {
		if (__secname_eq_nocase8(pFirstSection[i].Name, szName)) {
			pBase = reinterpret_cast<BYTE*>(hModule) + pFirstSection[i].VirtualAddress;
			unSize = pFirstSection[i].Misc.VirtualSize;
			return true;
		}
	}

	return false;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PRTL_RB_TREE LocateGlobalTreeByRoot(Detours::PRTL_BALANCED_NODE pRoot) {
	if (!pRoot) {
		return nullptr;
	}

	auto pDTE = GetNTDLLDTE();
	if (!pDTE) {
		return nullptr;
	}

	HMODULE hNTDLL = reinterpret_cast<HMODULE>(pDTE->DllBase);

	auto MRDATA = STACKSTRING(".mrdata");
	auto DATA = STACKSTRING(".data");

	const char* pSections[] = { MRDATA.c_str(), DATA.c_str() };

	for (int nSection = 0; nSection < _countof(pSections); ++nSection) {
		BYTE* pBase = nullptr;
		SIZE_T unSize = 0;
		if (!FindSection(hNTDLL, pSections[nSection], pBase, unSize)) {
			continue;
		}

		void** pWords = reinterpret_cast<void**>(pBase);
		SIZE_T unCount = unSize / sizeof(void*);

		for (SIZE_T i = 0; i < unCount; ++i) {
			if (pWords[i] == reinterpret_cast<void*>(pRoot)) {
				auto pTree = reinterpret_cast<Detours::PRTL_RB_TREE>(&pWords[i]);
				if (pTree->Root == pRoot) {
					return pTree;
				}
			}
		}
	}

	return nullptr;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PRTL_RB_TREE GetLdrpModuleIndexBase() {
	auto pDTE = GetNTDLLDTE();
	if (!pDTE) {
		return nullptr;
	}

	auto pRoot = AscendToRoot(reinterpret_cast<Detours::PRTL_BALANCED_NODE>(&pDTE->BaseAddressIndexNode));
	return LocateGlobalTreeByRoot(pRoot);
}

DEFINE_CODE_IN_SECTION(".load") void __set_parent_raw(Detours::PRTL_BALANCED_NODE n, Detours::PRTL_BALANCED_NODE p) {
	if (!n) {
		return;
	}

#ifdef _WIN64
	const ULONG_PTR unColor = n->ParentValue & 7;
#else
	const ULONG_PTR unColor = n->ParentValue & 3;
#endif

	n->ParentValue = reinterpret_cast<ULONG_PTR>(p) | unColor;
}

DEFINE_CODE_IN_SECTION(".load") bool LinkBaseAddressIndex(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pDTE) {
		return true;
	}

	auto pTree = GetLdrpModuleIndexBase();
	if (!pTree) {
		return true;
	}

	auto pNode = reinterpret_cast<Detours::PRTL_BALANCED_NODE>(&pDTE->BaseAddressIndexNode);

	pNode->Left = pNode->Right = nullptr;
	pNode->ParentValue = 0;

	if (!pTree->Root) {
		if (pLD && pLD->m_pRtlRbInsertNodeEx) {
			pLD->m_pRtlRbInsertNodeEx(pTree, nullptr, FALSE, pNode);
			return true;
		}

		pTree->Root = pNode;
		return true;
	}

	auto pCurrent = pTree->Root;
	Detours::PRTL_BALANCED_NODE pParent = nullptr;
	BOOLEAN bRight = FALSE;

	for (;;) {
		auto pCurrentDTE = CONTAINING_RECORD(pCurrent, Detours::LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
		if (pDTE->DllBase < pCurrentDTE->DllBase) {
			if (pCurrent->Left) {
				pCurrent = pCurrent->Left;
				continue;
			}

			pParent = pCurrent;
			bRight = FALSE;
			break;

		} else if (pDTE->DllBase > pCurrentDTE->DllBase) {
			if (pCurrent->Right) {
				pCurrent = pCurrent->Right;
				continue;
			}

			pParent = pCurrent;
			bRight = TRUE;
			break;

		} else {
			return true;
		}
	}

	if (pLD && pLD->m_pRtlRbInsertNodeEx) {
		pLD->m_pRtlRbInsertNodeEx(pTree, pParent, bRight, pNode);
		return true;
	}

	if (!bRight) {
		pParent->Left = pNode;
		__set_parent_raw(pNode, pParent);

	} else {
		pParent->Right = pNode;
		__set_parent_raw(pNode, pParent);
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool LinkModule(PLOADER_DATA pLD, const Detours::LDR::LINK_DATA& LinkData) {
	if (!LinkData.m_pDTE) {
		return false;
	}

	auto pDTE = LinkData.m_pDTE;
	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->Ldr) {
		return false;
	}

	NormalizeAllLinks(pDTE);

	auto pHeadLoad = LinkData.m_pSavedInLoadOrderLinks ? LinkData.m_pSavedInLoadOrderLinks : &pPEB->Ldr->InLoadOrderModuleList;
	auto pHeadInitialization = LinkData.m_pSavedInInitializationOrderLinks ? LinkData.m_pSavedInInitializationOrderLinks : &pPEB->Ldr->InInitializationOrderModuleList;
	auto pHeadMemory = LinkData.m_pSavedInMemoryOrderLinks ? LinkData.m_pSavedInMemoryOrderLinks : &pPEB->Ldr->InMemoryOrderModuleList;

	InsertTailList(pHeadLoad, &pDTE->InLoadOrderLinks);
	InsertTailList(pHeadInitialization, &pDTE->InInitializationOrderLinks);
	InsertTailList(pHeadMemory, &pDTE->InMemoryOrderLinks);

	PLIST_ENTRY pHashHead = LinkData.m_pSavedHashLinks;
	if (!pHashHead) {
		if (auto pBase = FindLdrpHashTableBaseEx(pLD)) {
			const ULONG unIndex = (HashBaseDllName(pLD, pDTE) & 0x1F);
			pHashHead = &pBase[unIndex];
		}

	} else {
		InsertTailList(pHashHead, &pDTE->HashLinks);
	}

	LinkBaseAddressIndex(pLD, pDTE);

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool LinkModule(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pDTE) {
		return false;
	}

	Detours::LDR::LINK_DATA ld {};
	ld.m_pDTE = pDTE;

	return LinkModule(pLD, ld);
}

DEFINE_CODE_IN_SECTION(".load") bool AddToLDR(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	if (FindModuleDataTableEntry(pLD->m_pImageAddress)) {
		return true;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (!pDH || (pDH->e_magic != IMAGE_DOS_SIGNATURE) || !pNTHs || (pNTHs->Signature != IMAGE_NT_SIGNATURE)) {
		return false;
	}

	const wchar_t* szFullName = pLD->m_szImageName[0] ? pLD->m_szImageName : nullptr;
	const wchar_t* szBaseName = __wbasename(szFullName);

	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->ProcessHeap) {
		return false;
	}

	auto pDTE = reinterpret_cast<Detours::PLDR_DATA_TABLE_ENTRY>(pLD->m_pRtlAllocateHeap(pPEB->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(Detours::LDR_DATA_TABLE_ENTRY)));
	if (!pDTE) {
		return false;
	}

	pDTE->DllBase = pLD->m_pImageAddress;
	pDTE->SizeOfImage = pNTHs->OptionalHeader.SizeOfImage;
	pDTE->EntryPoint = pNTHs->OptionalHeader.AddressOfEntryPoint ? reinterpret_cast<Detours::PLDR_INIT_ROUTINE>(reinterpret_cast<char*>(pDH) + pNTHs->OptionalHeader.AddressOfEntryPoint) : nullptr;

	UNICODE_STRING usFullName {};
	if (!__MakeHeapUnicodeString(pLD, szFullName, usFullName)) {
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE);
		return false;
	}

	UNICODE_STRING usBaseName {};
	if (!__MakeHeapUnicodeString(pLD, szBaseName, usBaseName)) {
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, usFullName.Buffer);
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE);
		return false;
	}

	pDTE->FullDllName = *reinterpret_cast<Detours::PUNICODE_STRING>(&usFullName);
	pDTE->BaseDllName = *reinterpret_cast<Detours::PUNICODE_STRING>(&usBaseName);
	pDTE->TimeDateStamp = pNTHs->FileHeader.TimeDateStamp;
	pDTE->BaseNameHashValue = HashBaseDllName(pLD, pDTE);

	if (!AttachDdagNode(pLD, pDTE)) {
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->BaseDllName.Buffer);
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->FullDllName.Buffer);
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE);
		return false;
	}

	if (!LinkModule(pLD, pDTE)) {
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->BaseDllName.Buffer);
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->FullDllName.Buffer);
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE);
		return false;
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") void RemoveEntryList(PLIST_ENTRY pEntry) {
	if (!pEntry) {
		return;
	}

	auto pFlink = pEntry->Flink;
	auto pBlink = pEntry->Blink;

	if (!pFlink || !pBlink) {
		pEntry->Flink = pEntry->Blink = pEntry;
		return;
	}

	pBlink->Flink = pFlink;
	pFlink->Blink = pBlink;
	pEntry->Flink = pEntry->Blink = pEntry;
}

DEFINE_CODE_IN_SECTION(".load") bool DetachDdagNode(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pLD || !pDTE || !pDTE->DdagNode) {
		return true;
	}

	auto pNode = pDTE->DdagNode;

	RemoveEntryList(&pDTE->NodeModuleLink);
	InitializeListHead(&pDTE->NodeModuleLink);

	pDTE->DdagNode = nullptr;

	auto pPEB = GetPEB();
	if (pPEB && pPEB->ProcessHeap) {
		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pNode);
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") void __memzero(void* pBuffer, SIZE_T unSize) {
	BYTE* b = reinterpret_cast<BYTE*>(pBuffer);
	for (SIZE_T i = 0; i < unSize; ++i) {
		b[i] = 0;
	}
}

DEFINE_CODE_IN_SECTION(".load") Detours::PRTL_BALANCED_NODE __parent_of(Detours::PRTL_BALANCED_NODE n) {
#ifdef _WIN64
	return reinterpret_cast<Detours::PRTL_BALANCED_NODE>(n->ParentValue & ~ULONG_PTR(7));
#else
	return reinterpret_cast<Detours::PRTL_BALANCED_NODE>(n->ParentValue & ~ULONG_PTR(3));
#endif
}

DEFINE_CODE_IN_SECTION(".load") bool UnlinkBaseAddressIndex(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pDTE) {
		return true;
	}

	auto pTree = GetLdrpModuleIndexBase();
	if (!pTree) {
		return true;
	}

	auto pNode = reinterpret_cast<Detours::PRTL_BALANCED_NODE>(&pDTE->BaseAddressIndexNode);

	if (pLD && pLD->m_pRtlRbRemoveNode) {
		pLD->m_pRtlRbRemoveNode(pTree, pNode);
		return true;
	}

	auto parent = __parent_of(pNode);
	if (pTree->Root == pNode) {
		if (!pNode->Left && !pNode->Right) {
			pTree->Root = nullptr;

		} else if (pNode->Left && !pNode->Right) {
			pTree->Root = pNode->Left;
			__set_parent_raw(pTree->Root, nullptr);

		} else if (pNode->Right && !pNode->Left) {
			pTree->Root = pNode->Right;
			__set_parent_raw(pTree->Root, nullptr);

		} else {
			auto r = pNode->Right;
			auto lm = r;

			while (lm->Left) {
				lm = lm->Left;
			}

			lm->Left = pNode->Left;
			__set_parent_raw(pNode->Left, lm);

			pTree->Root = r;
			__set_parent_raw(r, nullptr);
		}

	} else {
		if (parent) {
			if (parent->Left == pNode) {
				parent->Left = nullptr;
			}

			if (parent->Right == pNode) {
				parent->Right = nullptr;
			}
		}
	}

	pNode->Left = pNode->Right = nullptr;
	pNode->ParentValue = 0;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") Detours::PRTL_RB_TREE GetLdrpMappingInfoIndex() {
	auto pDTE = GetNTDLLDTE();
	if (!pDTE) {
		return nullptr;
	}

	auto pRoot = AscendToRoot(reinterpret_cast<Detours::PRTL_BALANCED_NODE>(&pDTE->MappingInfoIndexNode));
	return LocateGlobalTreeByRoot(pRoot);
}

DEFINE_CODE_IN_SECTION(".load") bool UnlinkMappingInfoIndex(Detours::PLDR_DATA_TABLE_ENTRY pDTE) {
	if (!pDTE) {
		return true;
	}

	auto pTree = GetLdrpMappingInfoIndex();
	if (!pTree) {
		return true;
	}

	auto pNode = reinterpret_cast<Detours::PRTL_BALANCED_NODE>(&pDTE->MappingInfoIndexNode);
	auto pParent = __parent_of(pNode);

	if (pTree->Root == pNode) {
		if (!pNode->Left && !pNode->Right) {
			pTree->Root = nullptr;

		} else if (pNode->Left && !pNode->Right) {
			pTree->Root = pNode->Left;
			__set_parent_raw(pTree->Root, nullptr);

		} else if (pNode->Right && !pNode->Left) {
			pTree->Root = pNode->Right;
			__set_parent_raw(pTree->Root, nullptr);

		} else {
			auto r = pNode->Right;
			auto lm = r;

			while (lm->Left) {
				lm = lm->Left;
			}

			lm->Left = pNode->Left;
			__set_parent_raw(pNode->Left, lm);

			pTree->Root = r;
			__set_parent_raw(r, nullptr);
		}

	} else {
		if (pParent) {
			if (pParent->Left == pNode) {
				pParent->Left = nullptr;
			}

			if (pParent->Right == pNode) {
				pParent->Right = nullptr;
			}
		}
	}

	pNode->Left = pNode->Right = nullptr;
	pNode->ParentValue = 0;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool UnLinkModule(PLOADER_DATA pLD, Detours::PLDR_DATA_TABLE_ENTRY pDTE, Detours::LDR::PLINK_DATA pLinkData) {
	if (!pDTE || !pLinkData) {
		return false;
	}

	__memzero(pLinkData, sizeof(Detours::LDR::LINK_DATA));

	pLinkData->m_pDTE = pDTE;

	auto pPEB = GetPEB();
	if (!pPEB || !pPEB->Ldr) {
		return false;
	}

	pLinkData->m_pSavedInLoadOrderLinks = &pPEB->Ldr->InLoadOrderModuleList;
	pLinkData->m_pSavedInInitializationOrderLinks = &pPEB->Ldr->InInitializationOrderModuleList;
	pLinkData->m_pSavedInMemoryOrderLinks = &pPEB->Ldr->InMemoryOrderModuleList;

	if (auto pBase = FindLdrpHashTableBaseEx(pLD)) {
		const ULONG unIndex = (HashBaseDllName(pLD, pDTE) & 0x1F);
		pLinkData->m_pSavedHashLinks = &pBase[unIndex];
	}

	RemoveEntryList(&pDTE->InLoadOrderLinks);
	RemoveEntryList(&pDTE->InInitializationOrderLinks);
	RemoveEntryList(&pDTE->InMemoryOrderLinks);
	RemoveEntryList(&pDTE->HashLinks);
	RemoveEntryList(&pDTE->NodeModuleLink);

	UnlinkBaseAddressIndex(pLD, pDTE);
	UnlinkMappingInfoIndex(pDTE);

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool RemoveFromLDR(PLOADER_DATA pLD) {
	if (!pLD || !pLD->m_pImageAddress) {
		return false;
	}

	auto pDTE = FindModuleDataTableEntry(pLD->m_pImageAddress);
	if (!pDTE) {
		return true;
	}

	DetachDdagNode(pLD, pDTE);

	Detours::LDR::LINK_DATA ld {};
	UnLinkModule(pLD, pDTE, &ld);

	auto pPEB = GetPEB();
	if (pPEB && pPEB->ProcessHeap) {
		if (pDTE->BaseDllName.Buffer) {
			pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->BaseDllName.Buffer);
		}

		if (pDTE->FullDllName.Buffer) {
			pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE->FullDllName.Buffer);
		}

		pLD->m_pRtlFreeHeap(pPEB->ProcessHeap, 0, pDTE);
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") void* GetIFTBase(PLOADER_DATA pLD) {
	if (!pLD) {
		return nullptr;
	}

#if defined(_M_X64)
	if (!pLD->m_hNTDLL) {
		return nullptr;
	}

	auto ProcedureName = STACKSTRING("KiUserInvertedFunctionTable");

	ANSI_STRING as {};
	pLD->m_pRtlInitAnsiString(&as, ProcedureName.c_str());

	PVOID pAddress = nullptr;
	if (!NT_SUCCESS(pLD->m_pLdrGetProcedureAddress(pLD->m_hNTDLL, &as, 0, &pAddress))) {
		return nullptr;
	}

	return pAddress;
#else
	return nullptr;
#endif
}

DEFINE_CODE_IN_SECTION(".load") bool IFT_OpenView(PLOADER_DATA pLD, IFT_VIEW& v) {
	v.pBase = reinterpret_cast<BYTE*>(GetIFTBase(pLD));
	if (!v.pBase) {
		return false;
	}

#ifdef _WIN64
	v.unCountOff = 0x00;
	v.unMaxCountOff = 0x04;
	v.unEpochOff = 0x08;
	v.unOverflowOff = 0x0C;
	v.unEntriesOff = 0x30;
#elif _WIN32
	v.unCountOff = 0x00;
	v.unMaxCountOff = 0x04;
	v.unEpochOff = 0x08;
	v.unOverflowOff = 0x0C;
	v.unEntriesOff = 0x20;
#endif

	v.pCount = reinterpret_cast<volatile ULONG*>(v.pBase + v.unCountOff);
	v.pMaxCount = reinterpret_cast<volatile ULONG*>(v.pBase + v.unMaxCountOff);
	v.pEpoch = v.unEpochOff ? reinterpret_cast<volatile ULONG*>(v.pBase + v.unEpochOff) : nullptr;
	v.pOverflow = v.unOverflowOff ? reinterpret_cast<volatile BYTE*>(v.pBase + v.unOverflowOff) : nullptr;
	v.pEntries = reinterpret_cast<IFT_ENTRY*>(v.pBase + v.unEntriesOff);

	v.unCount = *v.pCount;
	v.unMaxCount = *v.pMaxCount;

	if ((v.unMaxCount < 16) || (v.unMaxCount > 4096) || (v.unCount > v.unMaxCount)) {
		return false;
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool IFT_QueryImageInfo(
    PVOID pImageBase, ULONG& unSizeOfImage,
#ifdef _WIN64
    ULONG& unSizeOfTable, ULONG_PTR& unExceptionDirectory
#elif _WIN32
    ULONG& unExceptionDirectory, ULONG& unExceptionDirectorySize
#endif
) {
	if (!pImageBase) {
		return false;
	}

	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
	if (!pDH || (pDH->e_magic != IMAGE_DOS_SIGNATURE)) {
		return false;
	}

	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pImageBase) + pDH->e_lfanew);
	if (!pNTHs || (pNTHs->Signature != IMAGE_NT_SIGNATURE)) {
		return false;
	}

	unSizeOfImage = pNTHs->OptionalHeader.SizeOfImage;

	auto pDD = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	DWORD unRVA = pDD->VirtualAddress;
	DWORD unSize = pDD->Size;

#ifdef _WIN64
	if (!unRVA || !unSize) {
		unSizeOfTable = 0;
		unExceptionDirectory = 0;

	} else {
		unSizeOfTable = unSize / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		unExceptionDirectory = reinterpret_cast<ULONG_PTR>(reinterpret_cast<char*>(pImageBase) + unRVA);
	}

#elif _WIN32
	if (!unRVA || !unSize) {
		unExceptionDirectory = 0;
		unExceptionDirectorySize = 0;

	} else {
		unExceptionDirectory = reinterpret_cast<ULONG_PTR>(reinterpret_cast<char*>(pImageBase) + unRVA);
		unExceptionDirectorySize = unSize;
	}
#endif

	return true;
}

DEFINE_CODE_IN_SECTION(".load") ULONG IFT_LowerBound(const IFT_ENTRY* pEntry, ULONG unCount, PVOID pImageBase) {
	ULONG unLow = 0;
	ULONG unHigh = unCount;
	ULONG_PTR unKey = reinterpret_cast<ULONG_PTR>(pImageBase);

	while (unLow < unHigh) {
		ULONG unMiddle = unLow + (unHigh - unLow) / 2;
		ULONG_PTR unCurrent = reinterpret_cast<ULONG_PTR>(pEntry[unMiddle].pImageBase);

		if (unCurrent < unKey) {
			unLow = unMiddle + 1;

		} else {
			unHigh = unMiddle;
		}
	}

	return unLow;
}

DEFINE_CODE_IN_SECTION(".load") SIZE_T IFT_RegionBytes(const IFT_VIEW& v) {
	return static_cast<SIZE_T>(v.unEntriesOff) + static_cast<SIZE_T>(v.unMaxCount) * sizeof(IFT_ENTRY);
}

DEFINE_CODE_IN_SECTION(".load") bool IFT_ProtectBegin(PLOADER_DATA pLD, IFT_VIEW& v) {
	if (!pLD) {
		return false;
	}

	PVOID pBase = v.pBase;
	SIZE_T unSize = IFT_RegionBytes(v);
	ULONG unOldProrection = 0;
	if (!NT_SUCCESS(pLD->m_pNtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &pBase, &unSize, PAGE_READWRITE, &unOldProrection))) {
		return false;
	}

	v.pProtectionBase = pBase;
	v.unProtectionSize = unSize;
	v.unOldProtection = unOldProrection;
	v.bProtectionActive = true;

	return true;
}

DEFINE_CODE_IN_SECTION(".load") void IFT_BeginWrite(IFT_VIEW& v) {
	if (v.pEpoch) {
		InterlockedIncrement(reinterpret_cast<volatile LONG*>(v.pEpoch));
	}
}

DEFINE_CODE_IN_SECTION(".load") void* __memmove(void* pDestination, const void* pSource, SIZE_T unSize) {
	if (!pDestination || !pSource || !unSize) {
		return pDestination;
	}

	unsigned char* pDst = reinterpret_cast<unsigned char*>(pDestination);
	const unsigned char* pSrc = reinterpret_cast<const unsigned char*>(pSource);

	if (pDst == pSrc) {
		return pDst;
	}

	if (pDst < pSrc) {
		for (SIZE_T i = 0; i < unSize; ++i) {
			pDst[i] = pSrc[i];
		}

	} else {
		for (SIZE_T i = unSize; i; --i) {
			pDst[i - 1] = pSrc[i - 1];
		}
	}

	return pDst;
}

DEFINE_CODE_IN_SECTION(".load") void IFT_EndWrite(IFT_VIEW& v) {
	if (v.pEpoch) {
		InterlockedIncrement(reinterpret_cast<volatile LONG*>(v.pEpoch));
	}
}

DEFINE_CODE_IN_SECTION(".load") void IFT_ProtectEnd(PLOADER_DATA pLD, IFT_VIEW& v) {
	if (!pLD || !v.bProtectionActive) {
		return;
	}

	PVOID pBase = v.pProtectionBase;
	SIZE_T unSize = v.unProtectionSize;
	ULONG unTemp = 0;
	pLD->m_pNtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &pBase, &unSize, v.unOldProtection, &unTemp);
	v.bProtectionActive = false;
}

DEFINE_CODE_IN_SECTION(".load") bool IFT_InsertForImage(PLOADER_DATA pLD, PVOID pImageBase) {
	if (!pLD || !pImageBase) {
		return false;
	}

	IFT_VIEW v {};
	if (!IFT_OpenView(pLD, v)) {
		return true;
	}

#ifdef _WIN64
	ULONG unSizeOfImage = 0;
	ULONG unSizeOfTable = 0;
	ULONG_PTR unExceptionDirectory = 0;
	if (!IFT_QueryImageInfo(pImageBase, unSizeOfImage, unSizeOfTable, unExceptionDirectory)) {
		return false;
	}

	if (!unSizeOfTable || !unExceptionDirectory) {
		return true;
	}

	IFT_ENTRY ins {};
	ins.pImageBase = pImageBase;
	ins.unSizeOfImage = unSizeOfImage;
	ins.unSizeOfTable = unSizeOfTable;
	ins.unExceptionDirectory = unExceptionDirectory;
#elif _WIN32
	ULONG unSizeOfImage = 0;
	ULONG_PTR unExceptionDirectory = 0;
	ULONG_PTR unExceptionDirectorySize = 0;
	if (!IFT_QueryImageInfo(pImageBase, unSizeOfImage, unExceptionDirectory, unExceptionDirectorySize)) {
		return false;
	}

	IFT_ENTRY ins {};
	ins.pImageBase = pImageBase;
	ins.unSizeOfImage = unSizeOfImage;
	ins.unExceptionDirectory = unExceptionDirectory;
	ins.unExceptionDirectorySize = unExceptionDirectorySize;
#endif

	if (v.unCount == v.unMaxCount) {
		if (v.pOverflow) {
			*v.pOverflow = 1;
		}

		return false;
	}

	ULONG unIndex = IFT_LowerBound(v.pEntries, v.unCount, pImageBase);
	if ((unIndex < v.unCount) && (v.pEntries[unIndex].pImageBase == pImageBase)) {
		return true;
	}

	if (!IFT_ProtectBegin(pLD, v)) {
		return false;
	}

	IFT_BeginWrite(v);

	if (v.unCount > unIndex) {
		__memmove(&v.pEntries[unIndex + 1], &v.pEntries[unIndex], static_cast<SIZE_T>(v.unCount - unIndex) * sizeof(IFT_ENTRY));
	}

	v.pEntries[unIndex] = ins;

	InterlockedExchange(reinterpret_cast<volatile LONG*>(v.pCount), static_cast<LONG>(v.unCount + 1));

	IFT_EndWrite(v);
	IFT_ProtectEnd(pLD, v);

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool IFT_RemoveForImage(PLOADER_DATA pLD, PVOID pImageBase) {
	if (!pLD || !pImageBase) {
		return false;
	}

	IFT_VIEW v {};
	if (!IFT_OpenView(pLD, v)) {
		return true;
	}

	if (!v.unCount) {
		return true;
	}

	ULONG unIndex = IFT_LowerBound(v.pEntries, v.unCount, pImageBase);
	if ((unIndex >= v.unCount) || (v.pEntries[unIndex].pImageBase != pImageBase)) {
		return true;
	}

	if (!IFT_ProtectBegin(pLD, v)) {
		return false;
	}

	IFT_BeginWrite(v);

	if ((unIndex + 1) < v.unCount) {
		__memmove(&v.pEntries[unIndex], &v.pEntries[unIndex + 1], static_cast<SIZE_T>(v.unCount - unIndex - 1) * sizeof(IFT_ENTRY));
	}

	InterlockedExchange(reinterpret_cast<volatile LONG*>(v.pCount), static_cast<LONG>(v.unCount - 1));

	IFT_EndWrite(v);
	IFT_ProtectEnd(pLD, v);

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool ExecuteTLS(PLOADER_DATA pLD, DWORD unReason) {
	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pDH + pDH->e_lfanew);

	auto pDD = &pNTHs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (!pDD->VirtualAddress) {
		return true;
	}

	auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(reinterpret_cast<char*>(pDH) + pDD->VirtualAddress);
	auto pCallbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

	if (pCallbacks) {
		while (*pCallbacks) {
			(*pCallbacks)(pDH, unReason, nullptr);
			++pCallbacks;
		}
	}

	return true;
}

DEFINE_CODE_IN_SECTION(".load") bool CallDllMain(PLOADER_DATA pLD, DWORD unReason) {
	auto pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pLD->m_pImageAddress);
	auto pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<char*>(pDH) + pDH->e_lfanew));
	if (!pNTHs->OptionalHeader.AddressOfEntryPoint) {
		return true;
	}

	fnDllMain pEntryPoint = reinterpret_cast<fnDllMain>((reinterpret_cast<char*>(pDH) + pNTHs->OptionalHeader.AddressOfEntryPoint));

	return pEntryPoint(reinterpret_cast<HINSTANCE>(pDH), unReason, nullptr) == TRUE;
}

DEFINE_CODE_IN_SECTION(".load") DWORD WINAPI Loader(LPVOID lpParameter) {
	SELF_INCLUDE;

	PLOADER_DATA pLD = reinterpret_cast<PLOADER_DATA>(lpParameter);
	if (!pLD) {
		return EXIT_FAILURE;
	}

	if (!pLD->m_hNTDLL || !pLD->m_pImageAddress) {
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Initializing image mapping").c_str());
#endif

	if (!MapImage(pLD)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Image mapping failed").c_str());
#endif
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Applying base relocations").c_str());
#endif

	if (!FixRelocations(pLD)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to apply base relocations").c_str());
#endif
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Resolving import table").c_str());
#endif

	if (!ResolveImports(pLD)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to resolve import table").c_str());
#endif
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Resolving delayed imports").c_str());
#endif

	if (!ResolveDelayedImports(pLD)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to resolve delayed imports").c_str());
#endif
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Applying section memory protections").c_str());
#endif

	if (!ProtectSections(pLD)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to apply section protections").c_str());
#endif
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (pLD->m_unFlags & HIJACK_FLAGS::HIJACK_FLAG_LDR_LINKING) {

#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Linking image into loader structures").c_str());
#endif

		if (!AddToLDR(pLD)) {
#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to link image into loader").c_str());
#endif
			SIZE_T unSize = 0;
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
			return EXIT_FAILURE;
		}

#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Registering image in inverted function table").c_str());
#endif

		if (!IFT_InsertForImage(pLD, pLD->m_pImageAddress)) {
#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to register image in inverted function table").c_str());
#endif
			SIZE_T unSize = 0;
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
			return EXIT_FAILURE;
		}
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Executing TLS callbacks (PROCESS_ATTACH)").c_str());
#endif

	if (!ExecuteTLS(pLD, DLL_PROCESS_ATTACH)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: TLS callback execution failed").c_str());
#endif
		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	pLD->m_pDbgPrint(STACKSTRING("LOADER: Invoking DllMain (PROCESS_ATTACH)").c_str());
#endif

	if (!CallDllMain(pLD, DLL_PROCESS_ATTACH)) {
#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: DllMain returned failure").c_str());
#endif

		CallDllMain(pLD, DLL_PROCESS_DETACH);
		ExecuteTLS(pLD, DLL_PROCESS_DETACH);

		if (pLD->m_unFlags & HIJACK_FLAGS::HIJACK_FLAG_LDR_LINKING) {
			IFT_RemoveForImage(pLD, pLD->m_pImageAddress);
			RemoveFromLDR(pLD);
		}

		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	if (pLD->m_unFlags & HIJACK_FLAGS::HIJACK_FLAG_IMMEDIATELY_UNLOAD) {

#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Immediate unload requested").c_str());
#endif

#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Invoking DllMain (PROCESS_DETACH)").c_str());
#endif

		if (!CallDllMain(pLD, DLL_PROCESS_DETACH)) {
#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: DllMain detach failed").c_str());
#endif
			SIZE_T unSize = 0;
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
			return EXIT_FAILURE;
		}

#ifdef _DEBUG
		pLD->m_pDbgPrint(STACKSTRING("LOADER: Executing TLS callbacks (PROCESS_DETACH)").c_str());
#endif

		if (!ExecuteTLS(pLD, DLL_PROCESS_DETACH)) {
#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: TLS callback execution failed").c_str());
#endif
			SIZE_T unSize = 0;
			pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
			return EXIT_FAILURE;
		}

		if (pLD->m_unFlags & HIJACK_FLAGS::HIJACK_FLAG_LDR_LINKING) {

#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: Unregistering image from inverted function table").c_str());
#endif

			if (!IFT_RemoveForImage(pLD, pLD->m_pImageAddress)) {
#ifdef _DEBUG
				pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to unregister image from inverted function table").c_str());
#endif
				SIZE_T unSize = 0;
				pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
				return EXIT_FAILURE;
			}

#ifdef _DEBUG
			pLD->m_pDbgPrint(STACKSTRING("LOADER: Unlinking image from loader structures").c_str());
#endif

			if (!RemoveFromLDR(pLD)) {
#ifdef _DEBUG
				pLD->m_pDbgPrint(STACKSTRING("LOADER: Failed to unlink image from loader").c_str());
#endif
				SIZE_T unSize = 0;
				pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
				return EXIT_FAILURE;
			}
		}

		SIZE_T unSize = 0;
		pLD->m_pNtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pLD->m_pImageAddress, &unSize, MEM_RELEASE);
	}

	return EXIT_SUCCESS;
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

	if ((g_ProcessInjectionThreads.find(unProcessID) != g_ProcessInjectionThreads.end()) && (g_ProcessSuspendedMainThreads.find(unProcessID) != g_ProcessSuspendedMainThreads.end())) {
		if (GetThreadId(g_ProcessInjectionThreads[unProcessID]) == unThreadID) {
			if (!unExitCode) {
#ifdef _DEBUG
				_tprintf_s(_T("INJECTED!\n"));
#endif

				RestoreAllProcessBreakPoints(unProcessID);

				g_bGlobalDisableThreadLibraryCalls = false;
				g_bContinueDebugging = false;
			}

			auto sit = g_RemoteLoaderSection.find(unProcessID);
			if (sit != g_RemoteLoaderSection.end()) {
				auto Process = GetDebugProcess(unProcessID);
				if (Process) {
					VirtualFreeEx(Process, sit->second.first, 0, MEM_RELEASE);
				}

				g_RemoteLoaderSection.erase(sit);
			}

			ResumeThread(g_ProcessSuspendedMainThreads[unProcessID]);
			CloseHandle(g_ProcessInjectionThreads[unProcessID]);
			g_ProcessSuspendedMainThreads.erase(unProcessID);
			g_ProcessInjectionThreads.erase(unProcessID);
			return;
		}
	}
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

void OnDebugStringEvent(DWORD unProcessID, DWORD unThreadID, const OUTPUT_DEBUG_STRING_INFO Info) {
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

void WriteMiniDump(DWORD unProcessID, DWORD unThreadID, HANDLE hProcess, HANDLE hThread, const EXCEPTION_DEBUG_INFO& info, LPCTSTR szTag, MINIDUMP_TYPE nDumpType) {
	auto ProcessDirectory = GetProcessDirectory(hProcess);
	if (!ProcessDirectory.first) {
		return;
	}

	SYSTEMTIME st {};
	GetLocalTime(&st);

	TCHAR szDumpPath[MAX_PATH] {};
	StringCchPrintf(szDumpPath, _countof(szDumpPath), _T("%s%s_%lu_%lu_0x%08X_%04u%02u%02u_%02u%02u%02u.dmp"), ProcessDirectory.second.c_str(), (szTag ? szTag : _T("DUMP")), unProcessID, unThreadID, info.ExceptionRecord.ExceptionCode, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	HANDLE hFile = CreateFile(szDumpPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return;
	}

	EXCEPTION_POINTERS ep {};
	MINIDUMP_EXCEPTION_INFORMATION mei {};
	EXCEPTION_RECORD exr = info.ExceptionRecord;
	CONTEXT ctx {};

	bool bHaveExceptionInfo = false;

	if (hThread) {
		ctx.ContextFlags = CONTEXT_ALL;

		if (GetThreadContext(hThread, &ctx)) {
			ep.ExceptionRecord = &exr;
			ep.ContextRecord = &ctx;

			mei.ThreadId = unThreadID;
			mei.ExceptionPointers = &ep;
			mei.ClientPointers = FALSE;

			bHaveExceptionInfo = true;
		} else {
			_tprintf_s(_T("ERROR: GetThreadContext (Error = 0x%08X)\n"), GetLastError());
		}
	}

	if (!MiniDumpWriteDump(hProcess, unProcessID, hFile, nDumpType, bHaveExceptionInfo ? &mei : nullptr, nullptr, nullptr)) {
		_tprintf_s(_T("ERROR: MiniDumpWriteDump (Error = 0x%08X)\n"), GetLastError());
	} else {
		_tprintf_s(_T("INFO: Dump: %s\n"), szDumpPath);
	}

	CloseHandle(hFile);
}

void OnExceptionEvent(DWORD unProcessID, DWORD unThreadID, const EXCEPTION_DEBUG_INFO& Info, bool bInitialBreakPoint, bool* pHandledException) {
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return;
	}

	const DWORD unCode = Info.ExceptionRecord.ExceptionCode;

	bool bInternalException = false;

	if ((unCode == EXCEPTION_BREAKPOINT) || (unCode == EXCEPTION_SINGLE_STEP)) {
		if (pHandledException && *pHandledException) {
			bInternalException = true;
		} else if (unCode == EXCEPTION_BREAKPOINT) {
			auto itProc = g_Processes.find(unProcessID);
			auto itEntry = g_ProcessesOriginalEntryPointByte.find(unProcessID);
			if ((itProc != g_Processes.end()) && (itEntry != g_ProcessesOriginalEntryPointByte.end())) {
				if (Info.ExceptionRecord.ExceptionAddress == itProc->second.second) {
					bInternalException = true;
				}
			}
		}
	}

	if (bInternalException) {
		return;
	}

	auto it = g_RemoteLoaderSection.find(unProcessID);
	if (it != g_RemoteLoaderSection.end()) {
		size_t unBase = reinterpret_cast<size_t>(it->second.first);
		size_t unSize = it->second.second;
		size_t unAddress = reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress);

		if ((unAddress >= unBase) && (unAddress < (unBase + unSize))) {
			size_t unRVA = unAddress - unBase;

			if (!bInitialBreakPoint) {
				const MINIDUMP_TYPE nDumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithDataSegs | MiniDumpWithProcessThreadData | MiniDumpWithFullMemoryInfo);
				WriteMiniDump(unProcessID, unThreadID, Process, Thread, Info, _T("LOADER"), nDumpType);
			}

			_tprintf_s(_T("LOADER EXCEPTION (%s)\n"), Info.dwFirstChance ? _T("First-Chance") : _T("Second-Chance"));
			_tprintf_s(_T("  CODE:       0x%08X\n"), Info.ExceptionRecord.ExceptionCode);
#ifdef _WIN64
			_tprintf_s(_T("  ADDRESS:    0x%016llX (RVA: 0x%016llX)\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress), unRVA);
#else
			_tprintf_s(_T("  ADDRESS:    0x%08X (RVA: 0x%08X)\n"), reinterpret_cast<size_t>(Info.ExceptionRecord.ExceptionAddress), unRVA);
#endif
			_tprintf_s(_T("  THREADID:   %lu\n"), unThreadID);
			_tprintf_s(_T("  FLAGS:      0x%08X\n"), Info.ExceptionRecord.ExceptionFlags);
			_tprintf_s(_T("  PARAMETERS: %lu\n"), Info.ExceptionRecord.NumberParameters);

			DWORD unNumberParameters = Info.ExceptionRecord.NumberParameters;
			if (unNumberParameters > EXCEPTION_MAXIMUM_PARAMETERS) {
				unNumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
			}

			for (DWORD i = 0; i < unNumberParameters; ++i) {
#ifdef _WIN64
				_tprintf_s(_T("    PARAM[%lu]: 0x%016llX\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#else
				_tprintf_s(_T("    PARAM[%lu]: 0x%08X\n"), i, Info.ExceptionRecord.ExceptionInformation[i]);
#endif
			}

			return;
		}
	}

	if (!bInitialBreakPoint && !Info.dwFirstChance) {
		const MINIDUMP_TYPE nDumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithDataSegs | MiniDumpWithProcessThreadData | MiniDumpWithFullMemoryInfo);
		WriteMiniDump(unProcessID, unThreadID, Process, Thread, Info, _T("EXCEPTION"), nDumpType);
	}

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

bool OnTLSCallBackEvent(DWORD unProcessID, DWORD unThreadID, LPVOID pCallback, LPVOID pModuleBase, DWORD unReason) {
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return false;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return false;
	}

	bool bRedirected = false;

	if (g_bGlobalDisableThreadLibraryCalls && ((unReason == 2) || (unReason == 3))) {
		LPVOID pStub = EnsureStub(unProcessID, Process);
		if (pStub) {
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(Thread, &ctx)) {
#ifdef _WIN64
				ctx.Rip = reinterpret_cast<DWORD64>(pStub);
#else
				ctx.Eip = reinterpret_cast<DWORD64>(pStub);
#endif

				if (SetThreadContext(Thread, &ctx)) {
					bRedirected = true;
				}
			}
		}
	}

#ifdef _DEBUG
	auto ModuleName = GetDebugModuleName(unProcessID, pModuleBase);
#ifdef _WIN64
	_tprintf_s(_T("ONTLSCALLBACK(%lu, %lu): CALLBACK: 0x%016llX, REASON: %lu, MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pCallback), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#else
	_tprintf_s(_T("ONTLSCALLBACK(%lu, %lu): CALLBACK: 0x%08X, REASON: %lu, MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pCallback), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#endif
#endif

	return bRedirected;
}

bool OnDLLEntryPoint(DWORD unProcessID, DWORD unThreadID, LPVOID pEntryPoint, LPVOID pModuleBase, DWORD unReason) {
	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return false;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return false;
	}

	bool bRedirected = false;

	if (g_bGlobalDisableThreadLibraryCalls && ((unReason == 2) || (unReason == 3))) {
		LPVOID pStub = EnsureStub(unProcessID, Process);
		if (pStub) {
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(Thread, &ctx)) {
#ifdef _WIN64
				ctx.Rip = reinterpret_cast<DWORD64>(pStub);
#else
				ctx.Eip = reinterpret_cast<DWORD64>(pStub);
#endif

				if (SetThreadContext(Thread, &ctx)) {
					bRedirected = true;
				}
			}
		}
	}

#ifdef _DEBUG
	auto ModuleName = GetDebugModuleName(unProcessID, pModuleBase);
#ifdef _WIN64
	_tprintf_s(_T("ONDLLENTRYPOINT(%lu, %lu): ENTRYPOINT: 0x%016llX REASON: %lu MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pEntryPoint), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#else
	_tprintf_s(_T("ONDLLENTRYPOINT(%lu, %lu): ENTRYPOINT: 0x%08X REASON: %lu MODULE: %s%s\n"), unProcessID, unThreadID, reinterpret_cast<size_t>(pEntryPoint), unReason, ModuleName.first ? ModuleName.second.c_str() : _T("<unknown>"), bRedirected ? _T(" --> STUB") : _T(""));
#endif
#endif

	return bRedirected;
}

void OnEntryPoint(DWORD unProcessID, DWORD unThreadID) {
#ifdef _DEBUG
	_tprintf_s(_T("ONENTRYPOINT(%lu): %lu\n"), unProcessID, unThreadID);
#endif // !_DEBUG

	auto Process = GetDebugProcess(unProcessID);
	if (!Process) {
		return;
	}

	auto Thread = GetDebugThread(unProcessID, unThreadID);
	if (!Thread) {
		return;
	}

	auto ProcessDirectory = GetProcessDirectory(Process);
	if (!ProcessDirectory.first) {
		return;
	}

	auto ProcessInjectLibraryName = GetProcessHiJackLibraryName(Process);
	if (!ProcessInjectLibraryName.first) {
		return;
	}

	auto ProcessHiJackLibraryPath = ProcessDirectory.second + ProcessInjectLibraryName.second;

	DWORD dwAttrib = GetFileAttributes(ProcessHiJackLibraryPath.c_str());
	if (!((dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))) { // File not exist
		RestoreAllProcessBreakPoints(unProcessID);
		g_bContinueDebugging = false;
		return;
	}

	HANDLE hFile = CreateFile(ProcessHiJackLibraryPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFile (Error = 0x%08X)\n"), GetLastError());
		return;
	}

	HANDLE hMapFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapFile || (hMapFile == INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("ERROR: CreateFileMapping (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hFile);
		return;
	}

	void* pMap = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		_tprintf_s(_T("ERROR: MapViewOfFile (Error = 0x%08X)\n"), GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS pTempNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	if (pTempNTHs->Signature != IMAGE_NT_SIGNATURE) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

#ifdef _WIN64
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		_tprintf_s(_T("ERROR: This library cannot be loaded in 64 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}
#else
	if (pTempNTHs->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		_tprintf_s(_T("ERROR: This library cannot be loaded in 32 bit!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(pTempNTHs);
	if (pNTHs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		_tprintf_s(_T("ERROR: Invalid PE header!\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}
#endif

	LARGE_INTEGER FileSize {};
	if (!GetFileSizeEx(hFile, &FileSize)) {
		_tprintf_s(_T("ERROR: GetFileSizeEx failed (Error = 0x%08X)\n"), GetLastError());
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	if (FileSize.QuadPart <= 0) {
		_tprintf_s(_T("ERROR: Invalid file size\n"));
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	const size_t unFileSize = static_cast<size_t>(FileSize.QuadPart);

	LPVOID pImageAddress = VirtualAllocEx(Process, nullptr, unFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pImageAddress) {
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	SIZE_T unBytesWritten = 0;
	if (!WriteProcessMemory(Process, pImageAddress, pMap, unFileSize, &unBytesWritten)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		UnmapViewOfFile(pMap);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return;
	}

	UnmapViewOfFile(pMap);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	void* pSection = nullptr;
	size_t unSectionSize = 0;
	if (!Detours::Scan::FindSection(GetModuleHandle(nullptr), { '.', 'l', 'o', 'a', 'd', 0, 0, 0 }, &pSection, &unSectionSize)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	LoaderData.m_unFlags = g_unHiJackFlags;
	LoaderData.m_pImageAddress = pImageAddress;

	if (!FillLoaderData(Process, &LoaderData)) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	memset(LoaderData.m_szImageName, 0, sizeof(LoaderData.m_szImageName));

#ifdef _UNICODE
#ifdef _WIN64
	wcscpy_s(LoaderData.m_szImageName, _countof(LoaderData.m_szImageName) - 1, (LR"(C:\Windows\System32\)" + ProcessInjectLibraryName.second).c_str());
#else
	wcscpy_s(LoaderData.m_szImageName, _countof(LoaderData.m_szImageName) - 1, (LR"(C:\Windows\SysWOW64\)" + ProcessInjectLibraryName.second).c_str());
#endif
#else
#ifdef _WIN64
	MultiByteToWideChar(CP_UTF8, 0, (R"(C:\Windows\System32\)" + ProcessInjectLibraryName.second).c_str(), -1, LoaderData.m_szImageName, _countof(LoaderData.m_szImageName) - 1);
#else
	MultiByteToWideChar(CP_UTF8, 0, (R"(C:\Windows\SysWOW64\)" + ProcessInjectLibraryName.second).c_str(), -1, LoaderData.m_szImageName, _countof(LoaderData.m_szImageName) - 1);
#endif
#endif

	const size_t unLoaderDataOffset = reinterpret_cast<size_t>(&LoaderData) - reinterpret_cast<size_t>(pSection);
	const size_t unLoaderOffset = reinterpret_cast<size_t>(&Loader) - reinterpret_cast<size_t>(pSection);

	void* pRemoteSection = VirtualAllocEx(Process, nullptr, unSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteSection) {
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	g_RemoteLoaderSection[unProcessID] = { pRemoteSection, unSectionSize };

	SIZE_T unWritten = 0;
	if (!WriteProcessMemory(Process, pRemoteSection, pSection, unSectionSize, &unWritten) || (unWritten != unSectionSize)) {
		VirtualFreeEx(Process, pRemoteSection, 0, MEM_RELEASE);
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	NtFlushInstructionCache(Process, nullptr, 0);

	void* pRemoteLoaderData = reinterpret_cast<void*>(reinterpret_cast<size_t>(pRemoteSection) + unLoaderDataOffset);
	void* pRemoteLoader = reinterpret_cast<void*>(reinterpret_cast<size_t>(pRemoteSection) + unLoaderOffset);

	if (SuspendThread(Thread) != 0) {
		VirtualFreeEx(Process, pRemoteSection, 0, MEM_RELEASE);
		VirtualFreeEx(Process, pImageAddress, 0, MEM_RELEASE);
		return;
	}

	g_ProcessSuspendedMainThreads[unProcessID] = Thread;

	HANDLE hThread = CreateRemoteThread(Process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteLoader), pRemoteLoaderData, 0, nullptr);
	if (hThread && (hThread != INVALID_HANDLE_VALUE)) {
		g_bGlobalDisableThreadLibraryCalls = true;
		g_ProcessInjectionThreads[unProcessID] = hThread;
	}
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

	DEBUG_EVENT DebugEvent {};
	bool bSeenInitialBreakPoint = false;

	const BYTE unBreakPointByte = 0xCC;
	BYTE unOriginalEntryByte = 0;

	while (*pbContinue) {
		if (WaitForDebugEvent(&DebugEvent, unTimeout)) {
			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:
					if (!EnsureStub(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.hProcess)) {
						*pbContinue = false;
						break;
					}

					// Setting breakpoint for TLS

					if (!SetTLSBreakPointsForModule(DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpBaseOfImage)) {
						*pbContinue = false;
						break;
					}

					// Setting breakpoint for entrypoint

					if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, &unOriginalEntryByte, 1, nullptr)) {
						*pbContinue = false;
						break;
					}

					if (!WriteProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, &unBreakPointByte, 1, nullptr)) {
						*pbContinue = false;
						break;
					}

					FlushInstructionCache(DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, 1);

					// Other stuff

					g_Processes[DebugEvent.dwProcessId] = { DebugEvent.u.CreateProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId] = unOriginalEntryByte;
					g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = { DebugEvent.u.CreateProcessInfo.hThread, DebugEvent.u.CreateProcessInfo.lpStartAddress };
					g_Modules[DebugEvent.dwProcessId][DebugEvent.u.CreateProcessInfo.lpBaseOfImage] = GetFilePath(DebugEvent.u.CreateProcessInfo.hFile);

					OnCreateProcessEvent(DebugEvent.dwProcessId);
					OnCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId);
					OnLoadModuleEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage);

					SafeCloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
					break;

				case EXIT_PROCESS_DEBUG_EVENT:
					OnExitProcessEvent(DebugEvent.dwProcessId, DebugEvent.u.ExitProcess.dwExitCode);

					{
						auto sit = g_RemoteLoaderSection.find(DebugEvent.dwProcessId);
						if (sit != g_RemoteLoaderSection.end()) {
							g_RemoteLoaderSection.erase(sit);
						}
					}

					g_ProcessSuspendedMainThreads.erase(DebugEvent.dwProcessId);

					{
						auto iit = g_ProcessInjectionThreads.find(DebugEvent.dwProcessId);
						if (iit != g_ProcessInjectionThreads.end()) {
							SafeCloseHandle(iit->second);
							g_ProcessInjectionThreads.erase(iit);
						}
					}

					g_Modules.erase(DebugEvent.dwProcessId);

					{
						auto tit = g_Threads.find(DebugEvent.dwProcessId);
						if (tit != g_Threads.end()) {
							for (auto& kv : tit->second) {
								SafeCloseHandle(kv.second.first);
							}

							g_Threads.erase(tit);
						}
					}

					g_ProcessesOriginalEntryPointByte.erase(DebugEvent.dwProcessId);

					{
						auto pit = g_Processes.find(DebugEvent.dwProcessId);
						if (pit != g_Processes.end()) {
							SafeCloseHandle(pit->second.first);
							g_Processes.erase(pit);
						}
					}

					g_DLLEntryPointOwner.erase(DebugEvent.dwProcessId);
					g_DLLEntryPointOriginalByte.erase(DebugEvent.dwProcessId);
					g_DLLEntryPointReArm.erase(DebugEvent.dwProcessId);
					g_TLSCallBackOwner.erase(DebugEvent.dwProcessId);
					g_TLSOriginalByte.erase(DebugEvent.dwProcessId);
					g_TLSReArm.erase(DebugEvent.dwProcessId);
					g_Stub.erase(DebugEvent.dwProcessId);

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

					{
						auto pit = g_Threads.find(DebugEvent.dwProcessId);
						if (pit != g_Threads.end()) {
							auto tit = pit->second.find(DebugEvent.dwThreadId);
							if (tit != pit->second.end()) {
								SafeCloseHandle(tit->second.first);
								pit->second.erase(tit);
							}

							if (pit->second.empty()) {
								g_Threads.erase(pit);
							}
						}
					}

					g_TLSReArm[DebugEvent.dwProcessId].erase(DebugEvent.dwThreadId);
					if (g_TLSReArm[DebugEvent.dwProcessId].empty()) {
						g_TLSReArm.erase(DebugEvent.dwProcessId);
					}

					break;

				case LOAD_DLL_DEBUG_EVENT:
					if (!SetTLSBreakPointsForModule(DebugEvent.dwProcessId, g_Processes[DebugEvent.dwProcessId].first, DebugEvent.u.LoadDll.lpBaseOfDll)) {
						*pbContinue = false;
						break;
					}

					if (!SetDLLEntryBreakPointForModule(DebugEvent.dwProcessId, g_Processes[DebugEvent.dwProcessId].first, DebugEvent.u.LoadDll.lpBaseOfDll)) {
						*pbContinue = false;
						break;
					}

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

					if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
						auto itTLSReArm = g_TLSReArm.find(DebugEvent.dwProcessId);
						if (itTLSReArm != g_TLSReArm.end()) {
							auto& TLSThreadsRecord = itTLSReArm->second;
							auto itTLSReArmThread = TLSThreadsRecord.find(DebugEvent.dwThreadId);
							if (itTLSReArmThread != TLSThreadsRecord.end()) {
								auto Process = g_Processes[DebugEvent.dwProcessId].first;
								if (!WriteByte(Process, itTLSReArmThread->second, 0xCC)) {
									*pbContinue = false;
									break;
								}

								FlushInstructionCache(Process, itTLSReArmThread->second, 1);

								TLSThreadsRecord.erase(itTLSReArmThread);
								if (TLSThreadsRecord.empty()) {
									g_TLSReArm.erase(itTLSReArm);
								}

								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}
						}

						auto itDLLReArm = g_DLLEntryPointReArm.find(DebugEvent.dwProcessId);
						if (itDLLReArm != g_DLLEntryPointReArm.end()) {
							auto& DLLThreadsRecord = itDLLReArm->second;
							auto itDLLReArmThread = DLLThreadsRecord.find(DebugEvent.dwThreadId);
							if (itDLLReArmThread != DLLThreadsRecord.end()) {
								auto Process = g_Processes[DebugEvent.dwProcessId].first;
								if (!WriteByte(Process, itDLLReArmThread->second, 0xCC)) {
									*pbContinue = false;
									break;
								}

								FlushInstructionCache(Process, itDLLReArmThread->second, 1);

								DLLThreadsRecord.erase(itDLLReArmThread);
								if (DLLThreadsRecord.empty()) {
									g_DLLEntryPointReArm.erase(itDLLReArm);
								}

								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}
						}
					}

					auto itTLSOriginalByte = g_TLSOriginalByte.find(DebugEvent.dwProcessId);
					if ((itTLSOriginalByte != g_TLSOriginalByte.end()) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {

						LPVOID pAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
						auto itBP = itTLSOriginalByte->second.find(pAddress);
						if (itBP != itTLSOriginalByte->second.end()) {

							DWORD unReason = 0xFFFFFFFF;
							CONTEXT ctx {};

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							unReason = static_cast<DWORD>(ctx.Rdx & 0xFFFFFFFFull);
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							// [RET][DllHandle][Reason][Reserved]
							SIZE_T unReadden = 0;
							if (!ReadProcessMemory(g_Processes[DebugEvent.dwProcessId].first, reinterpret_cast<LPCVOID>(ctx.Esp + 8), &unReason, sizeof(unReason), &unReadden) || (unReadden != sizeof(unReason))) {
								*pbContinue = false;
								break;
							}
#endif

							LPVOID pOwnerBase = nullptr;
							auto itOwner = g_TLSCallBackOwner[DebugEvent.dwProcessId].find(pAddress);
							if (itOwner != g_TLSCallBackOwner[DebugEvent.dwProcessId].end()) {
								pOwnerBase = itOwner->second;
							}

							if (OnTLSCallBackEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, pAddress, pOwnerBase, unReason)) {
								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}

							if (!WriteByte(g_Processes[DebugEvent.dwProcessId].first, pAddress, itBP->second)) {
								*pbContinue = false;
								break;
							}

							FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, pAddress, 1);

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Rip = reinterpret_cast<DWORD64>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Eip = reinterpret_cast<DWORD>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#endif

							g_TLSReArm[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = pAddress;

							ContinueStatus = DBG_EXCEPTION_HANDLED;
							bHandledException = true;
							OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
							break;
						}
					}

					auto itDLLOriginalByte = g_DLLEntryPointOriginalByte.find(DebugEvent.dwProcessId);
					if ((itDLLOriginalByte != g_DLLEntryPointOriginalByte.end()) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)) {

						LPVOID pAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
						auto itBP = itDLLOriginalByte->second.find(pAddress);
						if (itBP != itDLLOriginalByte->second.end()) {

							DWORD unReason = 0xFFFFFFFF;
							CONTEXT ctx {};

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							unReason = static_cast<DWORD>(ctx.Rdx & 0xFFFFFFFFull);
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							// [RET][DllHandle][Reason][Reserved]
							SIZE_T unReadden = 0;
							if (!ReadProcessMemory(g_Processes[DebugEvent.dwProcessId].first, reinterpret_cast<LPCVOID>(ctx.Esp + 8), &unReason, sizeof(unReason), &unReadden) || (unReadden != sizeof(unReason))) {
								*pbContinue = false;
								break;
							}
#endif

							LPVOID pOwnerBase = nullptr;
							auto itOwner = g_DLLEntryPointOwner[DebugEvent.dwProcessId].find(pAddress);
							if (itOwner != g_DLLEntryPointOwner[DebugEvent.dwProcessId].end()) {
								pOwnerBase = itOwner->second;
							}

							if (OnDLLEntryPoint(DebugEvent.dwProcessId, DebugEvent.dwThreadId, pAddress, pOwnerBase, unReason)) {
								ContinueStatus = DBG_EXCEPTION_HANDLED;
								bHandledException = true;
								OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
								break;
							}

							if (!WriteByte(g_Processes[DebugEvent.dwProcessId].first, pAddress, itBP->second)) {
								*pbContinue = false;
								break;
							}

							FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, pAddress, 1);

#ifdef _WIN64
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Rip = reinterpret_cast<DWORD64>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#else
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}

							ctx.Eip = reinterpret_cast<DWORD>(pAddress);
							ctx.EFlags |= 0x100; // Trap Flag

							if (!SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
								*pbContinue = false;
								break;
							}
#endif

							g_DLLEntryPointReArm[DebugEvent.dwProcessId][DebugEvent.dwThreadId] = pAddress;

							ContinueStatus = DBG_EXCEPTION_HANDLED;
							bHandledException = true;
							OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, false, &bHandledException);
							break;
						}
					}

					OnExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.Exception, !bSeenInitialBreakPoint, &bHandledException);

					ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

					if (bSeenInitialBreakPoint && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) && (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == g_Processes[DebugEvent.dwProcessId].second) && (g_ProcessesOriginalEntryPointByte.find(DebugEvent.dwProcessId) != g_ProcessesOriginalEntryPointByte.end())) {
						if (!WriteProcessMemory(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, &g_ProcessesOriginalEntryPointByte[DebugEvent.dwProcessId], 1, nullptr)) {
							break;
						}

						FlushInstructionCache(g_Processes[DebugEvent.dwProcessId].first, g_Processes[DebugEvent.dwProcessId].second, 1);

						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (!GetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx)) {
							break;
						}

#ifdef _WIN64
						ctx.Rip = reinterpret_cast<DWORD64>(g_Processes[DebugEvent.dwProcessId].second);
#else
						ctx.Eip = reinterpret_cast<DWORD>(g_Processes[DebugEvent.dwProcessId].second);
#endif

						SetThreadContext(g_Threads[DebugEvent.dwProcessId][DebugEvent.dwThreadId].first, &ctx);

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
	_tprintf_s(_T("Usage:\n"));
	_tprintf_s(_T("  /list\n"));
	_tprintf_s(_T("  /add <File Name> [Flags]\n"));
	_tprintf_s(_T("  /remove <File Name>\n"));
	_tprintf_s(_T("Flags:\n"));
	_tprintf_s(_T("  0x1 - Unload the library immediately after calling DllMain.\n"));
	_tprintf_s(_T("  0x2 - Enable LDR linking.\n"));
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

			DWORD unFlags = 0;
			DWORD unFlagsSize = sizeof(unFlags);

			bool bHasDebugger = false;
			bool bHasFlags = false;

			if ((RegQueryValueEx(hSubKey, _T("Debugger"), nullptr, &unType, reinterpret_cast<LPBYTE>(szDebuggerValue), &unDebuggerValueSize) == ERROR_SUCCESS) && (unType == REG_SZ) && (unDebuggerValueSize > sizeof(TCHAR))) {
				bHasDebugger = true;
			}

			unType = 0;
			if ((RegQueryValueEx(hSubKey, _T("HiJackFlags"), nullptr, &unType, reinterpret_cast<LPBYTE>(&unFlags), &unFlagsSize) == ERROR_SUCCESS) && (unType == REG_DWORD) && (unFlagsSize == sizeof(DWORD))) {
				bHasFlags = unFlags != 0;
			}

			if (bHasDebugger) {
				if (bHasFlags) {
					_tprintf_s(_T("> %s : 0x%08X : %s\n"), szSubKeyName, unFlags, szDebuggerValue);
				} else {
					_tprintf_s(_T("> %s : %s\n"), szSubKeyName, szDebuggerValue);
				}
			}

			RegCloseKey(hSubKey);
		}

		++unIndex;
		unSubKeyNameSize = MAX_PATH;
	}

	RegCloseKey(hKey);
	return true;
}

bool HiJackAdd(const TCHAR* szFileName, DWORD unFlags = 0) {
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
#ifndef _UNICODE
		RtlFreeAnsiString(&as);
#endif
		RegCloseKey(hKey);
		return false;
	}

	DWORD unFlagsDW = unFlags;
	if (RegSetValueEx(hKey, _T("HiJackFlags"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&unFlagsDW), sizeof(unFlagsDW)) != ERROR_SUCCESS) {
		_tprintf_s(_T("ERROR: RegSetValueEx (Error = 0x%08X)\n"), GetLastError());
#ifndef _UNICODE
		RtlFreeAnsiString(&as);
#endif
		RegCloseKey(hKey);
		return false;
	}

#ifndef _UNICODE
	RtlFreeAnsiString(&as);
#endif
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
	RegDeleteValue(hKey, _T("HiJackFlags"));

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

DWORD HiJackQueryFlags(const TCHAR* szPath) {
	if (!szPath) {
		return 0;
	}

	auto StripQuotes = [](const TCHAR* szPath) -> tstring {
		if (!szPath) {
			return {};
		}

		size_t unLength = _tcslen(szPath);
		if ((unLength >= 2) && (szPath[0] == _T('\"')) && (szPath[unLength - 1] == _T('\"'))) {
			return { szPath + 1, szPath + unLength - 1 };
		}

		return { szPath };
	};

	tstring strFull = StripQuotes(szPath);

	const TCHAR* szLastSlash1 = _tcsrchr(strFull.c_str(), _T('\\'));
	const TCHAR* szLastSlash2 = _tcsrchr(strFull.c_str(), _T('/'));
	const TCHAR* szSeparate = (szLastSlash1 && szLastSlash2) ? (std::max(szLastSlash1, szLastSlash2)) : (szLastSlash1 ? szLastSlash1 : szLastSlash2);
	tstring strBaseName = szSeparate ? szSeparate + 1 : strFull.c_str();

	for (auto& ch : strBaseName) {
		ch = static_cast<TCHAR>(_totlower(ch));
	}

	HKEY hIFEO = nullptr;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hIFEO) != ERROR_SUCCESS) {
		return 0;
	}

	for (DWORD unIndex = 0;; ++unIndex) {
		TCHAR szSubName[MAX_PATH] {};
		DWORD unSubLength = _countof(szSubName);
		FILETIME ft {};

		DWORD unError = RegEnumKeyEx(hIFEO, unIndex, szSubName, &unSubLength, nullptr, nullptr, nullptr, &ft);
		if (unError == ERROR_NO_MORE_ITEMS) {
			break;
		}

		if (unError != ERROR_SUCCESS) {
			continue;
		}

		tstring strSubLower = szSubName;
		for (auto& ch : strSubLower) {
			ch = static_cast<TCHAR>(_totlower(ch));
		}

		if (strSubLower == strBaseName) {
			HKEY hSubKey = nullptr;
			if (RegOpenKeyEx(hIFEO, szSubName, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS) {
				DWORD unType = 0;
				DWORD unTypeSize = sizeof(DWORD);
				DWORD unFlags = 0;
				if (RegGetValue(hSubKey, nullptr, _T("HiJackFlags"), RRF_RT_DWORD, &unType, &unFlags, &unTypeSize) == ERROR_SUCCESS) {
					RegCloseKey(hSubKey);
					RegCloseKey(hIFEO);
					return unFlags;
				} 

				RegCloseKey(hSubKey);
				RegCloseKey(hIFEO);
				return 0;
			}
		}
	}

	RegCloseKey(hIFEO);
	return 0;
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
#ifndef _DEBUG
#ifdef _WIN64
		_tprintf_s(_T("HiJack [Version " HIJACK_VERSION "]\n\n"));
#else
		_tprintf_s(_T("HiJack32 [Version " HIJACK_VERSION "]\n\n"));
#endif
#endif // !_DEBUG

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

		DWORD unFlags = 0;

		if (argc == 4) {
			TCHAR* pEnd = nullptr;
			const unsigned long unValue = _tcstoul(argv[3], &pEnd, 0);
			if ((pEnd == nullptr) || (*pEnd != _T('\0'))) {
				_tprintf_s(_T("ERROR: Invalid flags value: `%s`\n"), argv[3]);
				ShowHelp();
				return EXIT_FAILURE;
			}

			unFlags = static_cast<DWORD>(unValue);
		}

		if (!HiJackAdd(argv[2], unFlags)) {
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

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION joli {};
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
#ifndef _UNICODE
			RtlFreeAnsiString(&as);
#endif
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		RtlFreeAnsiString(&as);
#endif

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

		if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
			_tprintf_s(_T("ERROR: AssignProcessToJobObject (Error = 0x%08X)\n"), GetLastError());
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(hJob);
			return EXIT_FAILURE;
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
#ifndef _UNICODE
			RtlFreeAnsiString(&as);
#endif
			_tprintf_s(_T("ERROR: _tsplitpath_s (Error = %i)\n"), err);
			CloseHandle(hJob);
			return EXIT_FAILURE;
		}

#ifndef _UNICODE
		RtlFreeAnsiString(&as);
#endif

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

	g_unHiJackFlags = static_cast<HIJACK_FLAGS>(HiJackQueryFlags(argv[1]));

	tstring CommandLine = _T("");
	for (int i = 1; i < argc; ++i) {

		if ((i == 1) || _tcschr(argv[i], _T(' '))) {
			CommandLine += _T('"');
			CommandLine += argv[i];
			CommandLine += _T('"');
		} else {
			CommandLine += argv[i];
		}

		if ((i + 1) < argc) {
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
		CloseHandle(hJob);
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

	DWORD unSuspendCount = SuspendThread(pi.hThread);
	if ((unSuspendCount != 0) && (unSuspendCount != 1)) { // Allow main thread suspension
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

	unSuspendCount = ResumeThread(pi.hThread);
	if ((unSuspendCount != 1) && (unSuspendCount != 2)) { // Allow main thread suspension
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

	return static_cast<int>(unExitCode);
}
