//==============================================================================
//
//  memutils.cpp
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
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
#include <string_view>
#include <inttypes.h>  // for PRIxPTR
#include <cstdint>  // for uintptr_t
#include <map>
#include <vector>




extern bool _Suppress;

void CMemUtils::Initialize(bool dumpHex, bool printableOnly,bool suppress, DWORD slipBefore, DWORD slipAfter,bool meminfo) {
	_DumpHex = dumpHex;
	_Suppress = suppress;
	_SlipBefore = slipBefore;
	_SlipAfter = slipAfter;
	_PrintableOnly = printableOnly;
	_PrintMemoryInfo = meminfo;
	_partialMemoryReads = 0;
	_totalMatches = 0;
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

void CMemUtils::PrintMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& mbi) {
	printf("=== Memory Basic Information ===\n");
	printf("Base Address        : %p\n", mbi.BaseAddress);
	printf("Allocation Base     : %p\n", mbi.AllocationBase);
	printf("Region Size         : %zu bytes (%.2f KB)\n", mbi.RegionSize, mbi.RegionSize / 1024.0);

#ifdef _WIN64
	printf("Partition ID        : %hu\n", mbi.PartitionId);
#endif

	// Allocation Protect
	printf("Allocation Protect  : 0x%08X - ", mbi.AllocationProtect);
	switch (mbi.AllocationProtect) {
	case PAGE_READONLY: printf("PAGE_READONLY\n"); break;
	case PAGE_READWRITE: printf("PAGE_READWRITE\n"); break;
	case PAGE_EXECUTE: printf("PAGE_EXECUTE\n"); break;
	case PAGE_EXECUTE_READ: printf("PAGE_EXECUTE_READ\n"); break;
	case PAGE_EXECUTE_READWRITE: printf("PAGE_EXECUTE_READWRITE\n"); break;
	case PAGE_NOACCESS: printf("PAGE_NOACCESS\n"); break;
	default: printf("Unknown\n"); break;
	}

	// State
	printf("State               : 0x%08X - ", mbi.State);
	switch (mbi.State) {
	case MEM_COMMIT: printf("MEM_COMMIT\n"); break;
	case MEM_RESERVE: printf("MEM_RESERVE\n"); break;
	case MEM_FREE: printf("MEM_FREE\n"); break;
	default: printf("Unknown\n"); break;
	}

	// Protection
	printf("Protect             : 0x%08X - ", mbi.Protect);
	switch (mbi.Protect) {
	case PAGE_READONLY: printf("PAGE_READONLY\n"); break;
	case PAGE_READWRITE: printf("PAGE_READWRITE\n"); break;
	case PAGE_EXECUTE: printf("PAGE_EXECUTE\n"); break;
	case PAGE_EXECUTE_READ: printf("PAGE_EXECUTE_READ\n"); break;
	case PAGE_EXECUTE_READWRITE: printf("PAGE_EXECUTE_READWRITE\n"); break;
	case PAGE_NOACCESS: printf("PAGE_NOACCESS\n"); break;
	default: printf("Unknown\n"); break;
	}

	// Type
	printf("Type                : 0x%08X - ", mbi.Type);
	switch (mbi.Type) {
	case MEM_IMAGE: printf("MEM_IMAGE\n"); break;
	case MEM_MAPPED: printf("MEM_MAPPED\n"); break;
	case MEM_PRIVATE: printf("MEM_PRIVATE\n"); break;
	default: printf("Unknown or not defined\n"); break;
	}

	printf("================================\n");
}



void CMemUtils::PrintMemInfo(MEMORY_BASIC_INFORMATION memMeminfo)
{

	switch (memMeminfo.AllocationProtect)
	{
	case PAGE_EXECUTE:
		logmsgext("access: [  x  ]\n");
		break;
	case PAGE_EXECUTE_READ:
		logmsgext("access: [r x  ]\n");
		break;
	case PAGE_EXECUTE_READWRITE:
		logmsgext("access: [rwx  ]\n");
		break;
	case PAGE_EXECUTE_WRITECOPY:
		logmsgext("access: [ wxc ]\n");
		break;
	case PAGE_NOACCESS:
		logmsgext("access: [     ]\n");
		break;
	case PAGE_READONLY:
		logmsgext("access: [r    ]\n");
		break;
	case PAGE_READWRITE:
		logmsgext("access: [rw   ]\n");
		break;
	case PAGE_WRITECOPY:
		logmsgext("access: [ w c ]\n");
		break;
	}

	switch (memMeminfo.Type) {
	case MEM_IMAGE:
		logmsgext("type MEM_IMAGE\n");
		break;
	case MEM_MAPPED:
		logmsgext("type MEM_MAPPED\n");
		break;
	case MEM_PRIVATE:
		logmsgext("type MEM_PRIVATE\n");
		break;
	}
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

void CMemUtils::ResetSearchResults() {
	_totalMatches = 0;
	_partialMemoryReads = 0;
}

bool CMemUtils::SearchProcessMemory(DWORD pid,FilterParameters filter, bool enableOutputToFile, std::string outputFilePath)
{
	DWORD dwRet, dwMods;
	HANDLE hProcess;
	HMODULE hModule[4096];
	char cProcess[MAX_PATH]; // Process name
	SYSTEM_INFO sysnfoSysNFO;
	BOOL bIsWow64 = FALSE;
	BOOL bIsWow64Other = FALSE;
	DWORD dwRES = 0;
	bool scanSuccess = true;
	_totalMatches = 0;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
	{
		if (GetLastError() == 5) {
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			if (hProcess == NULL) {
				if (!_Suppress) logerror("Failed to OpenProcess(%d),%d\n", pid, GetLastError());
				return false;
			}
		}
		else {
			if (!_Suppress) logerror("Failed to OpenProcess(%d),%d\n", pid, GetLastError());
			return false;
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
		return false;
	}
	dwMods = dwRet / sizeof(HMODULE);

	GetModuleBaseName(hProcess, hModule[0], cProcess, MAX_PATH);

	if (IsWow64Process(GetCurrentProcess(), &bIsWow64)) {
		GetNativeSystemInfo(&sysnfoSysNFO);

		if (bIsWow64){
			logmsg("Running under WOW64 - Page Size %d\n",sysnfoSysNFO.dwPageSize);
		}
		else{
			logmsg("Not running under WOW64 - Page Size %d\n",sysnfoSysNFO.dwPageSize);	
		}
	}
	else {
		fwprintf(stdout, L"[!] Errot\n");
		return false;
	}

	if (!_Suppress) logmsg("Searching %s - %d\n", cProcess, pid);
	//
	// Walk the processes address space
	//
	unsigned char* pString = NULL;

	ULONG_PTR addrCurrent = 0;
	ULONG_PTR lastBase = (-1);

	if (enableOutputToFile && outputFilePath.length() > 0) {
		_DumpFile = fopen(outputFilePath.c_str(), "w");
		if (!_DumpFile) {
			logerror("Failed to open file '%s' for writing.\n", outputFilePath.c_str());
			_DumpFile = nullptr;
		}
		else {
			logmsg("Opened file %s for writing\n", outputFilePath.c_str());
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
			scanSuccess = scanSuccess && ScanMemory(pid, memMeminfo.RegionSize, (ULONG_PTR)memMeminfo.BaseAddress, hProcess, memMeminfo, filter);

		}

		addrCurrent += memMeminfo.RegionSize;
	}
	if (_DumpFile) {
		logmsg("flushing...closing \"%s\"\n", filter.strOutFileName);
		fflush(_DumpFile);
		fclose(_DumpFile);
	}
	return scanSuccess;

}

extern bool g_logsDisabled;
bool CMemUtils::ScanMemory(DWORD pid, SIZE_T szSize, ULONG_PTR lngAddress, HANDLE hProcess, MEMORY_BASIC_INFORMATION memMeminfo, FilterParameters filter)
{
	SIZE_T szBytesRead = 0;
	int currentIndex = 0;
	bool scanSuccess = true;
	
	unsigned char* strBuffer = (unsigned char*)VirtualAlloc(0, szSize + 1024, MEM_COMMIT, PAGE_READWRITE);
	if (strBuffer == NULL) return 0;

	if (ReadProcessMemory(hProcess, (LPVOID)lngAddress, strBuffer, szSize, &szBytesRead) == 0) {
		if (GetLastError() == 299) {
			_partialMemoryReads++;
		}else{
			logerror("Failed to read process memory %d at %08llx read %llu\n", GetLastError(), lngAddress, szBytesRead);
			VirtualFree(strBuffer, szSize, MEM_RELEASE);
			return false;
		}	
	}
	std::string actionShow = "show";
	std::string actionSkip = "skip";

#ifdef ENABLE_REGEX_SUPPORT
#pragma message ("=================================")
#pragma message ("*** REGEX SUPPORT COMPILED IN ***")
#pragma message ("=================================")
	if (filter.bIsRegexPattern) {
		try {
			std::string_view bufferView(reinterpret_cast<const char*>(strBuffer), szBytesRead);
			std::regex pattern(filter.strString, std::regex::ECMAScript | std::regex::optimize);

			std::cregex_iterator it(bufferView.data(), bufferView.data() + bufferView.size(), pattern);
			std::cregex_iterator end;

			while (it != end) {
				const std::cmatch& match = *it;
				size_t matchPos = match.position(0);
				const char* matchAddress = reinterpret_cast<const char*>(lngAddress + matchPos);
				currentIndex = _totalMatches++;

				bool resultsFilterShowThisResult = true;
				
				if (!g_logsDisabled) {
					fprintf(_DumpFile ? _DumpFile : stdout, "\n\n==================================================================================\n");
					fprintf(_DumpFile ? _DumpFile : stdout, "%d) found \"%s\" in pid %d at %p\n", currentIndex, filter.strString, pid, (void*)(matchAddress));
					fprintf(_DumpFile ? _DumpFile : stdout, "==================================================================================\n\n");
				}

				uintptr_t matchAddr = (uintptr_t)matchAddress;  // or + intCounter for ASCII
				_searchResults[pid].push_back(matchAddr);

				if (filter.resultsFilterIndex != -1) {
					if (filter.resultsFilterIndex == currentIndex) {
						resultsFilterShowThisResult = true;
					}
					else {
						resultsFilterShowThisResult = false;
					}

					if (filter.resultsFilterMemoryAddress != 0) {
						uintptr_t base = static_cast<uintptr_t>(lngAddress);
						uintptr_t offset = static_cast<uintptr_t>(matchPos);
						uintptr_t target = filter.resultsFilterMemoryAddress;

						uintptr_t rangeEnd = base + offset;

						// Prevent unsigned overflow
						if (rangeEnd >= base) {
							if (target < rangeEnd) {
								uintptr_t deltaAddresses = rangeEnd - target;
								int deltaBytes = static_cast<int>(deltaAddresses / 8);
								_SlipBefore = deltaBytes;

								logmsg("memory address filter 0x%" PRIxPTR
									" calculated delta address 0x%" PRIxPTR
									" delta bytes %d, dumping %d bytes before match\n",
									target, deltaAddresses, deltaBytes, _SlipBefore);
							}
							else {
								uintptr_t deltaAddresses = target - rangeEnd;
								int deltaBytes = static_cast<int>(deltaAddresses / 8);
								_SlipAfter = deltaBytes;

								logmsg("memory address filter 0x%" PRIxPTR
									" calculated delta address 0x%" PRIxPTR
									" delta bytes %d, dumping %d bytes after match\n",
									target, deltaAddresses, deltaBytes, _SlipAfter);
							}
						}
					}
				}

				EMemoryType processMemType = GetMemType(memMeminfo);
				if (filter.etypeFilter != EMEM_ALL && processMemType != filter.etypeFilter) {
					resultsFilterShowThisResult = false;
				}
				loghighlight("[match %3d] \"%-20s\" (regex) | pid %5d | 0x%016" PRIxPTR " | %-4s\n",
					currentIndex,
					filter.strString,
					pid,
					static_cast<uintptr_t>(lngAddress + matchPos),
					resultsFilterShowThisResult?actionShow.c_str() :actionSkip.c_str()
				);


				if (resultsFilterShowThisResult) {

					PrintMemInfo(memMeminfo);
					if (_PrintMemoryInfo) {
						PrintMemoryBasicInformation(memMeminfo);
					}

					if (_DumpHex) {
						unsigned char* hexStart = strBuffer + matchPos >= strBuffer + _SlipBefore
							? strBuffer + matchPos - _SlipBefore
							: strBuffer;

						size_t maxLen = match.length() + _SlipBefore + _SlipAfter;
						if (hexStart + maxLen > strBuffer + szBytesRead) {
							maxLen = (strBuffer + szBytesRead) - hexStart;
						}

						WriteHexOut(hexStart, (int)maxLen, _DumpFile ? _DumpFile : stdout);
					}
				}
				
				++it;
			}
		}
		catch (const std::regex_error& e) {
			fprintf(stderr, "[!] Regex error: %s\n", e.what());
			scanSuccess = false;
		}

		VirtualFree(strBuffer, szSize, MEM_RELEASE);
		return scanSuccess;
	}

#else
	if (filter.bIsRegexPattern) {
		fprintf(stderr, "[!] Regex Pattern Not upported Yet\n");
		return 0;
	}
#endif
	else {
		// ORIGINAL ASCII/UNICODE search logic retained
		unsigned char* strBufferNow = strBuffer;
		unsigned char* strBufferEnd = (strBuffer + szSize) - (strlen(filter.strString) + 1);
		unsigned int intCounter = 0;
		bool resultsFilterShowThisResult = true;
		
		while (strBufferNow < strBufferEnd) {

			if (memcmp(filter.strString, strBufferNow, strlen(filter.strString)) == 0) {
				bool bMatch = true;
				currentIndex = _totalMatches++;

				if (bMatch) {

					if (!g_logsDisabled) {
						fprintf(_DumpFile ? _DumpFile : stdout, "\n\n==================================================================================\n");
						fprintf(_DumpFile ? _DumpFile : stdout, "%d) found \"%s\" in pid %d at %p\n", currentIndex, filter.strString, pid, (void*)(lngAddress + intCounter));
						fprintf(_DumpFile ? _DumpFile : stdout, "==================================================================================\n\n");
					}
					uintptr_t matchAddr = lngAddress + intCounter;  // or + intCounter for ASCII
					_searchResults[pid].push_back(matchAddr);

					if (filter.resultsFilterMemoryAddress != 0) {
						uintptr_t base = static_cast<uintptr_t>(lngAddress);
						uintptr_t offset = static_cast<uintptr_t>(intCounter);
						uintptr_t target = filter.resultsFilterMemoryAddress;

						uintptr_t rangeEnd = base + offset;

						if (filter.resultsFilterIndex != -1) {
							if (filter.resultsFilterIndex == currentIndex) {
								resultsFilterShowThisResult = true;
							}
							else {
								resultsFilterShowThisResult = false;
							}

							// Prevent unsigned overflow
							if (rangeEnd >= base) {
								if (target < rangeEnd) {
									uintptr_t deltaAddresses = rangeEnd - target;
									int deltaBytes = static_cast<int>(deltaAddresses / 8);
									_SlipBefore = deltaBytes;

									logmsg("memory address filter 0x%" PRIxPTR
										" calculated delta address 0x%" PRIxPTR
										" delta bytes %d, dumping %d bytes before match\n",
										target, deltaAddresses, deltaBytes, _SlipBefore);
								}
								else {
									uintptr_t deltaAddresses = target - rangeEnd;
									int deltaBytes = static_cast<int>(deltaAddresses / 8);
									_SlipAfter = deltaBytes;

									logmsg("memory address filter 0x%" PRIxPTR
										" calculated delta address 0x%" PRIxPTR
										" delta bytes %d, dumping %d bytes after match\n",
										target, deltaAddresses, deltaBytes, _SlipAfter);
								}
							}
						}
					}


					EMemoryType processMemType = GetMemType(memMeminfo);
					if (filter.etypeFilter != EMEM_ALL && processMemType != filter.etypeFilter) {
						resultsFilterShowThisResult = false;
					}
					
					loghighlight("[match %3d] \"%-20s\" | pid %5d | 0x%016" PRIxPTR " | %-4s\n",
						currentIndex,
						filter.strString,
						pid,
						static_cast<uintptr_t>(lngAddress + intCounter),
						resultsFilterShowThisResult ? actionShow.c_str() : actionSkip.c_str()
					);

					

					if (resultsFilterShowThisResult) {
						PrintMemInfo(memMeminfo);
						if (_PrintMemoryInfo) {
							PrintMemoryBasicInformation(memMeminfo);
						}

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
			}
			else if (filter.bUNICODE) {
				
				// naive UTF-16LE check
				bool bMatch = true;
				currentIndex = _totalMatches++;
				int len = (int)strlen(filter.strString);
				for (int i = 0; i < len * 2; i += 2) {
					if (strBufferNow + i >= strBuffer + szBytesRead ||
						strBufferNow[i] != filter.strString[i / 2] || strBufferNow[i + 1] != 0x00) {
						bMatch = false;
						break;
					}
				}
				
				if (bMatch) {

					if (!g_logsDisabled) {
						fprintf(_DumpFile ? _DumpFile : stdout, "\n\n==================================================================================\n");
						fprintf(_DumpFile ? _DumpFile : stdout, "%d) found \"%s\" (unicode) in pid %d at %p\n", currentIndex, filter.strString, pid, (void*)(lngAddress + intCounter));
						fprintf(_DumpFile ? _DumpFile : stdout, "==================================================================================\n\n");
					}
					uintptr_t matchAddr = lngAddress + intCounter;  // or + intCounter for ASCII
					_searchResults[pid].push_back(matchAddr);

					if (filter.resultsFilterIndex != -1) {
						if (filter.resultsFilterIndex == currentIndex) {
							resultsFilterShowThisResult = true;
						}
						else {
							resultsFilterShowThisResult = false;
						}

						if (filter.resultsFilterMemoryAddress != 0) {
							uintptr_t base = static_cast<uintptr_t>(lngAddress);
							uintptr_t offset = static_cast<uintptr_t>(intCounter);
							uintptr_t target = filter.resultsFilterMemoryAddress;

							uintptr_t rangeEnd = base + offset;

							// Prevent unsigned overflow
							if (rangeEnd >= base) {
								if (target < rangeEnd) {
									uintptr_t deltaAddresses = rangeEnd - target;
									int deltaBytes = static_cast<int>(deltaAddresses / 8);
									_SlipBefore = deltaBytes;

									logmsg("memory address filter 0x%" PRIxPTR
										" calculated delta address 0x%" PRIxPTR
										" delta bytes %d, dumping %d bytes before match\n",
										target, deltaAddresses, deltaBytes, _SlipBefore);
								}
								else {
									uintptr_t deltaAddresses = target - rangeEnd;
									int deltaBytes = static_cast<int>(deltaAddresses / 8);
									_SlipAfter = deltaBytes;

									logmsg("memory address filter 0x%" PRIxPTR
										" calculated delta address 0x%" PRIxPTR
										" delta bytes %d, dumping %d bytes after match\n",
										target, deltaAddresses, deltaBytes, _SlipAfter);
								}
							}
						}
					}

					EMemoryType processMemType = GetMemType(memMeminfo);
					if (filter.etypeFilter != EMEM_ALL && processMemType != filter.etypeFilter) {
						resultsFilterShowThisResult = false;
					}

					
					loghighlight("[match %3d] \"%-20s\" | pid %5d | 0x%016" PRIxPTR " | %-4s\n",
						currentIndex,
						filter.strString,
						pid,
						static_cast<uintptr_t>(lngAddress + intCounter),
						resultsFilterShowThisResult ? actionShow.c_str() : actionSkip.c_str()
					);
					if (resultsFilterShowThisResult) {
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
	return scanSuccess;
}


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

void CMemUtils::SearchInAllProcess(FilterParameters filter, bool enableOutputToFile, std::string outputFilePath)
{
	DWORD dwPIDArray[2048], dwRet, dwPIDS, intCount;


	if (EnumProcesses(dwPIDArray, 2048 * sizeof(DWORD), &dwRet) == 0)
	{
		logerror("SearchInAllProcess(),%d\n", GetLastError());
		return;
	}

	dwPIDS = dwRet / sizeof(DWORD);
	logmsg("SearchInAllProcess() found %d processes to probe...\n", dwPIDS);
	for (intCount = 0; intCount < dwPIDS; intCount++)
	{
		if (dwPIDArray[intCount] != GetCurrentProcessId()) {
			logmsg("$d) scanning PID %d...\n", (intCount+1),dwPIDArray[intCount]);
			
			int numHits = SearchProcessMemory(dwPIDArray[intCount],filter, enableOutputToFile, outputFilePath);
			if (numHits == -1) {
				logerror("$d) scanning PID %d Error Occured!\n", (intCount + 1), dwPIDArray[intCount]);
			}
			else {
				logmsg("$d) scanning PID %d found %d hits\n", (intCount + 1), dwPIDArray[intCount], numHits);
			}
			
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
