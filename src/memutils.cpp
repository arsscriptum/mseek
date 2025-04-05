
//==============================================================================
//
//     cmdline.cpp
//
//============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#include "stdafx.h"
#include "targetver.h"
#include "version.h"
#include "log.h"
#include "memutils.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <regex>   
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <algorithm>

extern bool _Suppress;

void CMemUtils::Initialize(bool dumpHex, bool printableOnly,bool suppress, DWORD slipBefore, DWORD slipAfter) {
	_DumpHex = dumpHex;
	_Suppress = suppress;
	_SlipBefore = slipBefore;
	_SlipAfter = slipAfter;
	_PrintableOnly = printableOnly;
}


EMemoryTypeT GetMemoryTypeFromString(const std::string& strInput) {
	std::string str = strInput;
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);

	if (str == "private") return EMEM_PRIVATE;
	if (str == "mapped") return EMEM_MAPPED;
	if (str == "image")  return EMEM_IMAGE;
	if (str == "all")    return EMEM_ALL;

	return EMEM_UNKNOWN;
}

EMemoryType CMemUtils::GetMemType(MEMORY_BASIC_INFORMATION memMeminfo)
{
	switch (memMeminfo.Type) {
	case MEM_IMAGE:
		return EMemoryType::EMEM_IMAGE;
		break;
	case MEM_MAPPED:
		return EMemoryType::EMEM_MAPPED;
		break;
	case MEM_PRIVATE:
		return EMemoryType::EMEM_PRIVATE;
		break;
	default:
		return EMemoryType::EMEM_UNKNOWN;
	}
}

void CMemUtils::PrintMemInfo(MEMORY_BASIC_INFORMATION memMeminfo)
{

	switch (memMeminfo.AllocationProtect)
	{
	case PAGE_EXECUTE:
		fprintf(stdout, "[  x  ]");
		break;
	case PAGE_EXECUTE_READ:
		fprintf(stdout, "[r x  ]");
		break;
	case PAGE_EXECUTE_READWRITE:
		fprintf(stdout, "[rwx  ]");
		break;
	case PAGE_EXECUTE_WRITECOPY:
		fprintf(stdout, "[ wxc ]");
		break;
	case PAGE_NOACCESS:
		fprintf(stdout, "[     ]");
		break;
	case PAGE_READONLY:
		fprintf(stdout, "[r    ]");
		break;
	case PAGE_READWRITE:
		fprintf(stdout, "[rw   ]");
		break;
	case PAGE_WRITECOPY:
		fprintf(stdout, "[ w c ]");
		break;
	}

	switch (memMeminfo.Type) {
	case MEM_IMAGE:
		fprintf(stdout, " - image\n");
		break;
	case MEM_MAPPED:
		fprintf(stdout, " - mapped\n");
		break;
	case MEM_PRIVATE:
		fprintf(stdout, " - private\n");
		break;
	}
}

//
// Function	: ReadAndGrep
// Role		: Reads the process memory into our address space then we search it...
// Notes	: 
//

int CMemUtils::SearchProcessMemory(DWORD pid,FilterParameters filter, bool outputToFile, std::string outputFile)
{
	DWORD dwRet, dwMods;
	int numHits = 0;
	HANDLE hProcess;
	HMODULE hModule[4096];
	char cProcess[MAX_PATH]; // Process name
	SYSTEM_INFO sysnfoSysNFO;
	BOOL bIsWow64 = FALSE;
	BOOL bIsWow64Other = FALSE;
	DWORD dwRES = 0;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
	{
		if (GetLastError() == 5) {
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			if (hProcess == NULL) {
				if (!_Suppress) logerror("Failed to OpenProcess(%d),%d\n", pid, GetLastError());
				return numHits;
			}
		}
		else {
			if (!_Suppress) logerror("Failed to OpenProcess(%d),%d\n", pid, GetLastError());
			return numHits;
		}
	}

	if (EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &dwRet) == 0)
	{
		if (GetLastError() == 299) {
			if (!_Suppress) logerror("64bit process and we're 32bit - sad panda! skipping PID %d\n", pid);
		}
		else {
			if (!_Suppress) logerror("OpenAndGrep(%d),%d\n", pid, GetLastError());
		}
		return numHits;
	}
	dwMods = dwRet / sizeof(HMODULE);

	GetModuleBaseName(hProcess, hModule[0], cProcess, MAX_PATH);

	if (IsWow64Process(GetCurrentProcess(), &bIsWow64)) {
		GetNativeSystemInfo(&sysnfoSysNFO);

		if (bIsWow64)
		{
			//fwprintf(stdout,L"[i] Running under WOW64 - Page Size %d\n",sysnfoSysNFO.dwPageSize);
		}
		else
		{
			//fwprintf(stdout,L"[i] Not running under WOW64 - Page Size %d\n",sysnfoSysNFO.dwPageSize);	
		}
	}
	else {
		fwprintf(stdout, L"[!] Errot\n");
		return numHits;
	}

	if (!_Suppress) logmsg("Searching %s - %d\n", cProcess, pid);
	//
	// Walk the processes address space
	//
	unsigned char* pString = NULL;

	ULONG_PTR addrCurrent = 0;
	ULONG_PTR lastBase = (-1);

	if (outputToFile && outputFile.length() > 0) {
		_DumpFile = fopen(outputFile.c_str(), "w");
		if (!_DumpFile) {
			logerror("Failed to open file '%s' for writing.\n", outputFile.c_str());
			_DumpFile = nullptr;
		}
		else {
			logmsg("Opened file %s for writing\n", outputFile.c_str());
			_FileOpenForWriting = true;
		}
	}
	else {
		_FileOpenForWriting = false;
		_DumpFile = nullptr;
	}

	for (;;)
	{
		MEMORY_BASIC_INFORMATION memMeminfo;
		VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(addrCurrent), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&memMeminfo), sizeof(memMeminfo));

		if (lastBase == (ULONG_PTR)memMeminfo.BaseAddress) {
			break;
		}

		lastBase = (ULONG_PTR)memMeminfo.BaseAddress;

		if (memMeminfo.State == MEM_COMMIT) {
			//fprintf(stdout,"[i] %p\n", memMeminfo.BaseAddress);
			//fprintf(stdout,"[i] %ld\n", memMeminfo.RegionSize);
			numHits += ScanMemory(pid, memMeminfo.RegionSize, (ULONG_PTR)memMeminfo.BaseAddress, hProcess, memMeminfo, filter);
		}

		addrCurrent += memMeminfo.RegionSize;
	}
	if (_DumpFile) {
		logmsg("CLosing file %s\n", filter.strOutFileName);
		fclose(_DumpFile);
	}
	return numHits;

}


int CMemUtils::ScanMemory(DWORD pid, SIZE_T szSize, ULONG_PTR lngAddress, HANDLE hProcess, MEMORY_BASIC_INFORMATION memMeminfo, FilterParameters filter)
{
	SIZE_T szBytesRead = 0;
	int numHits = 0;
	unsigned char* strBuffer = (unsigned char*)VirtualAlloc(0, szSize + 1024, MEM_COMMIT, PAGE_READWRITE);
	if (strBuffer == NULL) return 0;

	if (ReadProcessMemory(hProcess, (LPVOID)lngAddress, strBuffer, szSize, &szBytesRead) == 0) {
		if (GetLastError() != 299)
			fprintf(stderr, "[!] Failed to read process memory %d at %08llx read %llu\n", GetLastError(), lngAddress, szBytesRead);
		VirtualFree(strBuffer, szSize, MEM_RELEASE);
		return numHits;
	}

	if (filter.bIsRegexPattern) {
		fprintf(stderr, "[!] Regex Pattern Not upported Yet\n");
		return numHits;
	}
	else {
		// ORIGINAL ASCII/UNICODE search logic retained
		unsigned char* strBufferNow = strBuffer;
		unsigned char* strBufferEnd = (strBuffer + szSize) - (strlen(filter.strString) + 1);
		unsigned int intCounter = 0;

		while (strBufferNow < strBufferEnd) {
			if (memcmp(filter.strString, strBufferNow, strlen(filter.strString)) == 0) {
				EMemoryType processMemType = GetMemType(memMeminfo);
				bool bMatch = (filter.etypeFilter == EMEM_ALL || processMemType == filter.etypeFilter);

				if (bMatch) {
					numHits++;
					loghighlight("Got ascii hit for %s at %p in PID %d page starts at %p\n", filter.strString, (void*)(lngAddress + intCounter), pid, (void*)lngAddress);
					PrintMemInfo(memMeminfo);

					if (_DumpHex) {
						int length = (int)strlen(filter.strString);
						unsigned char* hexStart = (strBufferNow >= strBuffer + _SlipBefore) ? strBufferNow - _SlipBefore : strBuffer;
						int hexLength = length + _SlipBefore + _SlipAfter;
						if (hexStart + hexLength > strBuffer + szBytesRead) {
							hexLength = (int)((strBuffer + szBytesRead) - hexStart);
						}
						WriteHexOut(hexStart, hexLength, _DumpFile ? _DumpFile : stdout);
					}
				}
			}
			else if (filter.bUNICODE) {
				
				// naive UTF-16LE check
				bool bMatch = true;
				int len = (int)strlen(filter.strString);
				for (int i = 0; i < len * 2; i += 2) {
					if (strBufferNow + i >= strBuffer + szBytesRead ||
						strBufferNow[i] != filter.strString[i / 2] || strBufferNow[i + 1] != 0x00) {
						bMatch = false;
						break;
					}
				}

				if (bMatch) {
					numHits++;
					EMemoryType processMemType = GetMemType(memMeminfo);
					if (filter.etypeFilter == EMEM_ALL || processMemType == filter.etypeFilter) {
						loghighlight("Got unicode hit for %s at %p in PID %d page starts at %p\n", filter.strString, (void*)(lngAddress + intCounter), pid , (void*)lngAddress);
						PrintMemInfo(memMeminfo);

						if (_DumpHex) {
							int length = (int)(strlen(filter.strString) * 2);
							unsigned char* hexStart = (strBufferNow >= strBuffer + _SlipBefore) ? strBufferNow - _SlipBefore : strBuffer;
							int hexLength = length + _SlipBefore + _SlipAfter;
							if (hexStart + hexLength > strBuffer + szBytesRead) {
								hexLength = (int)((strBuffer + szBytesRead) - hexStart);
							}
							WriteHexOut(hexStart, hexLength, _DumpFile ? _DumpFile : stdout);
						}
					}
				}
			}

			strBufferNow++;
			intCounter++;
		}
	}

	VirtualFree(strBuffer, szSize, MEM_RELEASE);
	return numHits;
}


//
// Function	: OpenAndGrep
// Role		: Open a process, enumerate mapped pages of memory and pass to grep routine
// Notes	: 
// 


void CMemUtils::WriteHexOut(unsigned char* buf, int size, FILE* out) {
	int x, y;
	int mult = 8;

	if (_PrintableOnly) {
		// Only print printable characters with optional spacing every 64 chars
		int printableCount = 0;
		for (x = 0; x < size; x++) {
			if (isprint(buf[x])) {
				fprintf(out, "%c", buf[x]);
				printableCount++;
			}

			// Optional: line break after 64 chars
			if (printableCount > 0 && printableCount % 64 == 0) {
				fprintf(out, "\n");
			}
		}
		fprintf(out, "\n");
		return;
	}

	// Regular hex+ASCII view
	for (x = 1; x <= size; x++) {
		if (x == 1) fprintf(out, "%04x  ", x - 1);

		fprintf(out, "%02x ", buf[x - 1]);

		if (x % mult == 0) fprintf(out, " ");

		if (x % 16 == 0) {
			fprintf(out, "   ");
			for (y = x - 15; y <= x; y++) {
				if (isprint(buf[y - 1])) fprintf(out, "%c", buf[y - 1]);
				else fprintf(out, ".");
				if (y % mult == 0) fprintf(out, " ");
			}
			if (x < size) fprintf(out, "\n%04x  ", x);
		}
	}

	x--;

	if (x % 16 != 0) {
		for (y = x + 1; y <= x + (16 - (x % 16)); y++) {
			fprintf(out, "   ");
			if (y % mult == 0) fprintf(out, " ");
		}

		fprintf(out, "   ");
		for (y = (x + 1) - (x % 16); y <= x; y++) {
			if (isprint(buf[y - 1])) fprintf(out, "%c", buf[y - 1]);
			else fprintf(out, ".");
			if (y % mult == 0) fprintf(out, " ");
		}
	}

	fprintf(out, "\n");
}

//
// Function	: EnumerateProcesses
// Role		: Basic processes running
// Notes	: 
// 
void CMemUtils::EnumerateProcesses(bool bUseRegex, bool bReadable, bool bASCII, bool bUNICODE, const char* strString, bool outputToFile, std::string outputFile)
{
	DWORD dwPIDArray[2048], dwRet, dwPIDS, intCount;


	if (EnumProcesses(dwPIDArray, 2048 * sizeof(DWORD), &dwRet) == 0)
	{
		fprintf(stderr, "[!]  EnumProcesses(),%d\n", GetLastError());
		return;
	}

	dwPIDS = dwRet / sizeof(DWORD);

	for (intCount = 0; intCount < dwPIDS; intCount++)
	{
		if (dwPIDArray[intCount] != GetCurrentProcessId()) {
			FilterParameters filter;
			memset(&filter, 0, sizeof(FilterParameters));
			filter.bASCII = bASCII;
			filter.bIsRegexPattern = bUseRegex;
			filter.bUNICODE = bUNICODE;
			filter.strString = strString;
			filter.bReadable = bReadable;
			filter.etypeFilter = EMEM_ALL;
			SearchProcessMemory(dwPIDArray[intCount],filter, outputToFile, outputFile);
		}
		else {
			fprintf(stdout, "[i] Skipping myself\n");
		}
	}
}



bool CMemUtils::GetProcessPidFromName(std::string processName, DWORD& pid)
{
	pid = 0;

	// Snapshot of all processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// Convert search name to lowercase for case-insensitive match
	std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

	if (Process32First(hSnapshot, &pe)) {
		do {
			std::string exeName = pe.szExeFile;
			std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::tolower);

			if (exeName == processName) {
				pid = pe.th32ProcessID;
				CloseHandle(hSnapshot);
				return true;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return false;
}


//
// Function	: SetDebugPrivilege
// Role		: Gets debug privs for our process
// Notes	: 
//
bool CMemUtils::EnableDebugPrivilege(HANDLE hProcess)
{
	LUID luid;
	TOKEN_PRIVILEGES privs;
	HANDLE hToken = NULL;
	DWORD dwBufLen = 0;
	char buf[1024];

	ZeroMemory(&luid, sizeof(luid));

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		return false;

	privs.PrivilegeCount = 1;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	memcpy(&privs.Privileges[0].Luid, &luid, sizeof(privs.Privileges[0].Luid)
	);


	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
		return false;

	if (!AdjustTokenPrivileges(hToken, FALSE, &privs,
		sizeof(buf), (PTOKEN_PRIVILEGES)buf, &dwBufLen))
		return false;

	CloseHandle(hProcess);
	CloseHandle(hToken);

	return true;
}

bool CMemUtils::EnableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	// Open current process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}

	// Get the LUID for SeDebugPrivilege
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	// Check if the privilege was actually enabled
	return GetLastError() == ERROR_SUCCESS;
}


bool CMemUtils::CMemUtils::GetProcessNameFromPID(DWORD pid, TCHAR* buffer, DWORD bufferSize) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == nullptr)
		return false;

	bool success = QueryFullProcessImageName(hProcess, 0, buffer, &bufferSize);
	CloseHandle(hProcess);
	return success;
}


bool CMemUtils::GetProcessNameFromPID(DWORD pid, std::string& processName)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProcess)
		return false;

	std::vector<wchar_t> wideBuffer(MAX_PATH);
	DWORD size = static_cast<DWORD>(wideBuffer.size());

	if (!QueryFullProcessImageNameW(hProcess, 0, wideBuffer.data(), &size)) {
		CloseHandle(hProcess);
		return false;
	}

	CloseHandle(hProcess);

	// Convert wide string to UTF-8 std::string
	int len = WideCharToMultiByte(CP_UTF8, 0, wideBuffer.data(), -1, nullptr, 0, nullptr, nullptr);
	if (len <= 0)
		return false;

	std::vector<char> utf8Buffer(len);
	WideCharToMultiByte(CP_UTF8, 0, wideBuffer.data(), -1, utf8Buffer.data(), len, nullptr, nullptr);

	processName = std::string(utf8Buffer.data());
	return true;
}


bool CMemUtils::HasVMReadAccess(DWORD pid)
{
	// Try to open the process with PROCESS_VM_READ access
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
	if (hProcess == nullptr)
		return false;

	// If we successfully opened it, we have access
	CloseHandle(hProcess);
	return true;
}

bool CMemUtils::HasVMReadAccessElevated(DWORD pid)
{
	// Try to enable SeDebugPrivilege
	EnableDebugPrivilege();

	// Attempt to open the process with PROCESS_VM_READ access
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
	if (hProcess == nullptr)
		return false;

	CloseHandle(hProcess);
	return true;
}



/*

	for (intCount = 0; intCount < dwPIDS; intCount++)
	{
		if (dwPIDArray[intCount] != GetCurrentProcessId()) {
			FilterParameters filter(
				bASCII,                 // bASCII
				bUNICODE,               // bUNICODE
				strString,              // strString
				dwPIDArray[intCount],   // dwPID
				bReadable,              // bReadable
				strProcessName,         // strProcessName
				nullptr,                // strOutFileName (not used in this case)
				false,                  // _FileOpenForWriting (default)
				EMEM_ALL,               // etypeFilter
				bUseRegex               // bIsRegexPattern
			);

			OpenAndGrep(filter);
		}
		else {
			fprintf(stdout, "[i] Skipping myself\n");
		}
	}
	
	*/