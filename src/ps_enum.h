

//==============================================================================
//
//  ps_enum.h: CEnumProcess class.
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#ifndef ___PROCESSENUMERATION__H__
#define ___PROCESSENUMERATION__H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "psapi.h"
#include "log.h"
#include <vector>
#include "cthread.h"
// #define USE_VDMDBG // Uncomment this if you don´t wat to use vdmdbg at all
#include <string>
#include <fstream>
#ifdef USE_VDMDBG
#include <vdmdbg.h>
#include <afxcoll.h>
#include <afxtempl.h>
#endif // USE_VDMDBG


namespace ENUM_METHOD
{const int NONE    = 0x0;
 const int PSAPI   = 0x1;
 const int TOOLHELP= 0x2;
 const int PROC16  = 0x4;
}

const int MAX_FILENAME = 256;

#ifdef USE_VDMDBG
// 16-bit Enumeration functions
typedef INT (WINAPI *PFVDMEnumTaskWOWEx)(
  DWORD dwProcessId, TASKENUMPROCEX fp, LPARAM lparam
);
#endif // USE_VDMDBG

// Functions loaded from PSAPI
typedef BOOL (WINAPI *PFEnumProcesses)(
    DWORD * lpidProcess, DWORD cb, DWORD * cbNeeded
);

typedef BOOL (WINAPI *PFEnumProcessModules)(
    HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded
);

typedef DWORD (WINAPI *PFGetModuleFileNameEx)(
  HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize	     
);

//Functions loaded from Kernel32
typedef HANDLE (WINAPI *PFCreateToolhelp32Snapshot)(
  DWORD dwFlags,	   
  DWORD th32ProcessID  
);

typedef BOOL (WINAPI *PFProcess32First)(
  HANDLE hSnapshot,	  
  LPPROCESSENTRY32 lppe  
);

typedef BOOL (WINAPI *PFProcess32Next)(
  HANDLE hSnapshot,	  
  LPPROCESSENTRY32 lppe  
);
 
typedef BOOL (WINAPI *PFModule32First)(
  HANDLE hSnapshot,     
  LPMODULEENTRY32 lpme  
);

typedef BOOL (WINAPI *PFModule32Next)(
  HANDLE hSnapshot,     
  LPMODULEENTRY32 lpme  
);

#include <stdio.h>
#include <fstream>      // std::fstream
#include <stdio.h>
#include <string.h>


const char GHeader[0x200] = {};;
const char GPeHeader[20] = {};
const char GElf32Magic[20] = "\x7f\x45\x4c\x46\01";  //7F 45 4C 46  01 // ELF32 
const char GElf64Magic[20] = "\x7f\x45\x4c\x46\02";  //7F 45 4C 46  02 // ELF64
const char GWin32Magic[20] = "\x50\x45\x00\x00\x4C\x01";// PE32
const char GWin64Magic[20] = "\x50\x45\x00\x00\x64\x86";// PE64


 
class CProcessEnumerator  : public CThread
{
public:

	enum PROCESS_TYPE {
		PROCESS_NONE
		, PROCESS_ELF32
		, PROCESS_ELF64
		, PROCESS_WIN32
		, PROCESS_WIN64
		, DLL_WIN32
		, DLL_WIN64
		, PROCESS_MAX
	};

	typedef enum ECurrentState {
		ESTATE_IDLE,
		ESTATE_RUNNING,
		ESTATE_DONE
	} ECurrentStateT;

	struct CThreadEntry
	{
		DWORD th32ThreadID = 0;          // This thread
		DWORD th32OwnerProcessID = 0;    // Process this thread is associated with
		THREADENTRY32 win32ThreadEntry = { 0 };

		// Constructor
		CThreadEntry() {
			Defaults();
		}

		// Copy constructor
		CThreadEntry(const CThreadEntry& e) {
			Defaults();
			memcpy(&win32ThreadEntry, &e.win32ThreadEntry, sizeof(win32ThreadEntry));
		}

		// Destructor
		virtual ~CThreadEntry() = default;

		// Set all members to default (zero) values
		void Defaults() {
			th32ThreadID = 0;
			th32OwnerProcessID = 0;
			memset(&win32ThreadEntry, 0, sizeof(win32ThreadEntry));
		}

		// Backward-compatible alias
		void Reset() {
			Defaults();
		}
	};


	struct CModuleEntry
	{
		LPTSTR lpFilename = nullptr;
		LPTSTR szModuleName = nullptr;
		PVOID pLoadBase = nullptr;
		PVOID pPreferredBase = nullptr;
		MODULEENTRY32 win32ModuleEntry = { 0 };

		// Constructor
		CModuleEntry() {
			Defaults();
		}

		// Copy constructor
		CModuleEntry(const CModuleEntry& e) {
			Defaults();
			if (e.lpFilename) {
				_tcsncpy(lpFilename, e.lpFilename, MAX_FILENAME - 1);
			}
			if (e.szModuleName) {
				_tcsncpy(szModuleName, e.szModuleName, MAX_PATH - 1);
			}
			pLoadBase = e.pLoadBase;
			pPreferredBase = e.pPreferredBase;
			memcpy(&win32ModuleEntry, &e.win32ModuleEntry, sizeof(win32ModuleEntry));
		}

		// Destructor
		virtual ~CModuleEntry() {
			delete[] lpFilename;
			delete[] szModuleName;
		}

		// Initialize all members to empty/zero
		void Defaults() {
			delete[] lpFilename;
			delete[] szModuleName;

			lpFilename = new TCHAR[MAX_FILENAME]{};
			szModuleName = new TCHAR[MAX_PATH]{};
			pLoadBase = nullptr;
			pPreferredBase = nullptr;
			memset(&win32ModuleEntry, 0, sizeof(win32ModuleEntry));
		}
	};


	struct CProcessEntry
	{
		LPTSTR lpFilename;
		
		DWORD  dwPID;
		WORD   hTask16;
		PROCESS_TYPE PsType;
		char PsHeader[0x200];
		char PsPeHeader[20];
		char PsElf32Magic[20];
		char PsElf64Magic[20];
		char PsWin32Magic[20];
		char PsWin64Magic[20];

		WCHAR imagePathW[MAX_FILENAME];
		char imagePath[MAX_FILENAME];

		PIMAGE_DOS_HEADER dosHeader;
		PIMAGE_NT_HEADERS peHeader;

		std::vector<CModuleEntry*> ModulesEntries;
		std::vector<CThreadEntry*> ThreadEntries;
		// Constructors/Destructors
		CProcessEntry() : dwPID(0), hTask16(0)
		{
			LOG_TRACE("CEnumProcess::CProcessEntry", "Constructor");
			Reset();
		}
		CProcessEntry(CProcessEntry &e) : dwPID(e.dwPID), hTask16(e.hTask16)
		{
			LOG_TRACE("CEnumProcess::CProcessEntry", "copy Constructor. Filename: %s", e.lpFilename);
			Reset();
			_STRNCPY(lpFilename, e.lpFilename, MAX_FILENAME);
		}
		virtual ~CProcessEntry() 
		{
			for (auto it = std::begin(ModulesEntries); it != std::end(ModulesEntries); ++it) {
				delete *it;
			}
			ModulesEntries.clear();
			for (auto it = std::begin(ThreadEntries); it != std::end(ThreadEntries); ++it) {
				delete *it;
			}
			ThreadEntries.clear();
			delete[] lpFilename; 
		}
		void CProcessEntry::Reset() 
		{
			for (auto it = std::begin(ModulesEntries); it != std::end(ModulesEntries); ++it) {
				delete *it;
			}
			ModulesEntries.clear();
			for (auto it = std::begin(ThreadEntries); it != std::end(ThreadEntries); ++it) {
				delete *it;
			}
			ThreadEntries.clear();
			lpFilename = new TCHAR[MAX_FILENAME];
			memset(lpFilename, 0, sizeof(lpFilename));

			memcpy(PsHeader, GHeader, sizeof(PsHeader));
			memcpy(PsPeHeader, GPeHeader, sizeof(PsPeHeader));
			memcpy(PsElf32Magic, GElf32Magic, sizeof(PsElf32Magic));
			memcpy(PsElf64Magic, GElf64Magic, sizeof(PsElf64Magic));
			memcpy(PsWin32Magic, GWin32Magic, sizeof(PsWin32Magic));
			memcpy(PsWin64Magic, GWin64Magic, sizeof(PsWin64Magic));

			dosHeader = nullptr;
			peHeader = nullptr;
		}
		void CProcessEntry::CheckWinHeader() {
			int k = 0;
			for (int i = 0; i < 0x200; i++) {
				if (PsHeader[i] == 0x50 && PsHeader[i + 1] == 0x45) {
					
					for (int j = i; j < i + 6; j++) {
						PsPeHeader[k] = PsHeader[j];
						k++;
						//printf("%hhx", Header[j]); 
					}
				}
			}
		}
		void CProcessEntry::GetProcessInformation()
		{
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);

			// Get the process name.
			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;
				
				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),&cbNeeded))
				{
					GetModuleFileNameExW(hProcess, hMod, imagePathW, cbNeeded);
					sprintf(imagePath, "%ws", imagePathW);
					LOG_INFO("CProcessEntry::GetProcessInformation", "process imagePath %s. pid %d", imagePath, dwPID);
				}
			}

			CloseHandle(hProcess);
			//PsType = QueryExeMachineType(imagePath);
			ReadFFileHeader();
			
		}
		#define QUERYPLATFORM_ERROR(e) {LOG_ERROR("CProcessEntry::QueryPlatform", "ERROR: %s. id=%d", e, GetLastError());  break; }
		bool CProcessEntry::ReadFFileHeader()
		{
		
			HANDLE hFile;
			HANDLE hFileMapping = INVALID_HANDLE_VALUE;
			LPVOID lpFileBase = INVALID_HANDLE_VALUE;
			bool fileMapped = false;
			bool ret = false;
			do
			{
				hFile = CreateFileA(imagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

				if (hFile == INVALID_HANDLE_VALUE) {
					QUERYPLATFORM_ERROR("CreateFileA error");
				}

				hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

				if (hFileMapping == 0) {
					QUERYPLATFORM_ERROR("CreateFileMapping failed");
				}

				lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
				if (lpFileBase == 0) {
					QUERYPLATFORM_ERROR("MapViewOfFile failed");
				}
				fileMapped = true;

				//LOG_TRACE("CProcessEntry::QueryPlatform", "SUCESSFULLY RETRIEVED dosHeader struct");
				dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;  //pointer to dos headers

				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					//if it is executable file print different fileds of structure
					//dosHeader->e_lfanew : RVA for PE Header

					//LOG_TRACE("CProcessEntry::QueryPlatform", "DOS Signature (MZ) Matched");
					//pointer to PE/NT header
					//LOG_TRACE("CProcessEntry::QueryPlatform", "SUCESSFULLY RETRIEVED peHeader struct. pointer to PE/NT header");
					peHeader = (PIMAGE_NT_HEADERS)((unsigned char*)dosHeader + dosHeader->e_lfanew);

					if (peHeader->Signature == IMAGE_NT_SIGNATURE)
					{
						ret = true;
						switch (peHeader->FileHeader.Machine) 
						{
						case IMAGE_FILE_MACHINE_I386:
							PsType = PROCESS_WIN32;
							LOG_INFO("CProcessEntry::QueryPlatform", "MACHINE_I386 (%d = %X)", peHeader->FileHeader.Machine, peHeader->FileHeader.Machine);
							break;
						case IMAGE_FILE_MACHINE_IA64:
						case IMAGE_FILE_MACHINE_AMD64:
							LOG_INFO("CProcessEntry::QueryPlatform", "WIN64 (%d = %X)", peHeader->FileHeader.Machine, peHeader->FileHeader.Machine);
							PsType = PROCESS_WIN64;
							break;

						default:
							LOG_INFO("CProcessEntry::QueryPlatform", "Unknown (%d = %X)", peHeader->FileHeader.Machine, peHeader->FileHeader.Machine);
							break;
						}
						
						//LOG_TRACE("CProcessEntry::QueryPlatform", "PE Signature (PE) Matched");
						//important fileds
						//peHeader->FileHeader : Refrence to FileHeader
						//peHeader->OptionalHeader :  Refrence to Optional Header
						// lots of imprtant fileds are present in File header and Optional header to retrive code/data/different sections address of exe
					}
				}
			} while (0);
			
			if (hFileMapping != INVALID_HANDLE_VALUE) {
				CloseHandle(hFileMapping);
			}
			if (hFile != INVALID_HANDLE_VALUE) {
				CloseHandle(hFile);
			}
			if (fileMapped) {
				UnmapViewOfFile(lpFileBase);
			}
			return ret;
		}
		inline bool CProcessEntry::FileExists(const std::string& name) {
			std::ifstream f(name.c_str());
			return f.good();
		}
		void CProcessEntry::DetectPlatform()
		{
			bool exists = FileExists(imagePath);
			if (!exists) {
				PsType = PROCESS_NONE;
				return;
			}
			std::fstream fs;
			fs.open(imagePath, std::fstream::in | std::fstream::out | std::fstream::app);
			fs.read(PsHeader, 0x200);

			if (memcmp(PsHeader, PsElf32Magic, 5) == 0) {
				PsType = PROCESS_ELF32;
			}
			if (memcmp(PsHeader, PsElf64Magic, 5) == 0) {
				PsType = PROCESS_ELF64;
			}

			CheckWinHeader();

			if (memcmp(&PsPeHeader, PsWin32Magic, 6) == 0) {
				PsType = PROCESS_WIN32;
			}

			if (memcmp(&PsPeHeader, PsWin64Magic, 6) == 0) {
				PsType = PROCESS_WIN64;
			}

			fs.close();

			LOG_INFO("CProcessEntry::DetectPlatform", "process type %d",(int)PsType);
		}
		void CProcessEntry::AddModule(CModuleEntry *mod) { ModulesEntries.push_back(mod); };
		void CProcessEntry::AddThread(CThreadEntry *mod) { ThreadEntries.push_back(mod); };
	};
	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID;

	typedef struct _THREAD_BASIC_INFORMATION {
		NTSTATUS    exitStatus;
		PVOID       pTebBaseAddress;
		CLIENT_ID   clientId;
		KAFFINITY	AffinityMask;
		int			Priority;
		int			BasePriority;
		int			v;

	} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

	typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
		ServiceNameFromTagInformation = 1,
		ServiceNameReferencingModuleInformation,
		ServiceNameTagMappingInformation,
	} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

	typedef struct _SC_SERVICE_TAG_QUERY {
		ULONG   processId;
		ULONG   serviceTag;
		ULONG   reserved;
		PVOID   pBuffer;
	} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

	struct SModuleEntry
	{
		std::string imageName;
		std::string moduleName;
		DWORD baseAddress;
		DWORD size;
	};
	struct SThreadEntry
	{
		DWORD threadId;
		DWORD parentPid;
		DWORD baseAddress;
		DWORD size;
		DWORD flags;
	};
	typedef std::vector<SModuleEntry> TModules;
	typedef TModules::iterator ModuleListIter;
	typedef std::vector<SThreadEntry> TThreads;
	typedef TThreads::iterator ThreadsListIter;

	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;
		DWORD SizeOfImage;
		LPVOID EntryPoint;
	} MODULEINFO, * LPMODULEINFO;



    CProcessEnumerator();
    virtual ~CProcessEnumerator();

	bool IsRunning() { return _currentState == ESTATE_RUNNING; }
	bool IsDone() { return _currentState == ESTATE_DONE; }
	
    BOOL GetModuleNext(DWORD dwPID, CModuleEntry* pEntry);
    BOOL GetModuleFirst(DWORD dwPID, CModuleEntry* pEntry);
	BOOL GetThreadFirst(DWORD dwPID, CProcessEnumerator::CThreadEntry *pEntry);
	BOOL GetThreadNext(DWORD dwPID, CProcessEnumerator::CThreadEntry *pEntry);
    BOOL GetProcessNext(CProcessEntry *pEntry);    
    BOOL GetProcessFirst(CProcessEntry* pEntry);
	bool ThreadStarted() { return threadStarted; };
	bool ThreadExited() { return threadExited; };
	bool ThreadStartedAndExited() { return threadStarted && threadExited; };
    int GetAvailableMethods();
    int GetSuggestedMethod();
    int SetMethod(int method);
	CProcessEnumerator::PROCESS_TYPE GetDllType(const char *dll_name);
	static CProcessEnumerator::PROCESS_TYPE QueryExeMachineType(const char *filename);
	bool FillModuleListPSAPI(TModules& mods, DWORD pid, HANDLE hProcess);
	bool FillModuleListTH32(TModules& modules, DWORD pid);
	bool FillThreadsTH32(TThreads& modules, DWORD pid);
protected:

	//overrideable
	unsigned long Process(void* parameter)
	{
		ProcessEntries.clear();
		CProcessEntry psEntry;
		threadStarted = true;
		_currentState = ESTATE_RUNNING;
		BOOL result_process = GetProcessFirst(&psEntry);
		while (result_process == TRUE) {
			psEntry.GetProcessInformation();
			psEntry.DetectPlatform();

			// listing modules
			DWORD pid = psEntry.dwPID;
			CModuleEntry moduleEntry;
			CThreadEntry threadEntry;
			CProcessEntry *newProccessEntry = new CProcessEntry(psEntry);
			BOOL result_module = GetModuleFirst(pid,&moduleEntry);
			while (result_module == TRUE) 
			{		
				LOG_INFO("Process::ModuleEntry", "MODULE NAME:     %s", moduleEntry.win32ModuleEntry.szModule);
				LOG_INFO("Process::ModuleEntry", "Executable       %s", moduleEntry.win32ModuleEntry.szExePath);
				LOG_INFO("Process::ModuleEntry", "Process ID       0x%08X", moduleEntry.win32ModuleEntry.th32ProcessID);
				LOG_INFO("Process::ModuleEntry", "Ref count (g)    0x%04X", moduleEntry.win32ModuleEntry.GlblcntUsage);
				LOG_INFO("Process::ModuleEntry", "Ref count (p)    0x%04X", moduleEntry.win32ModuleEntry.ProccntUsage);
				LOG_INFO("Process::ModuleEntry", "Base address     0x%08X", moduleEntry.win32ModuleEntry.modBaseAddr);
				LOG_INFO("Process::ModuleEntry", "Base size        %d", moduleEntry.win32ModuleEntry.modBaseSize);
				CModuleEntry *newModuleEntry = new CModuleEntry(moduleEntry);
				newProccessEntry->AddModule(newModuleEntry);
				result_module = GetModuleNext(pid, &moduleEntry);
#ifdef LIST_PROCESS_THREADS
				BOOL result_thread = GetThreadFirst(pid, &threadEntry);
				while (result_module == TRUE)
				{
					CThreadEntry *newThreadEntry = new CThreadEntry(threadEntry);
					
					LOG_INFO("Process::ThreadEntry", "dwSize          %d", threadEntry.win32ThreadEntry.dwSize);
					LOG_INFO("Process::ThreadEntry", "cntUsage        0x%08X", threadEntry.win32ThreadEntry.cntUsage);
					LOG_INFO("Process::ThreadEntry", "Ref count (g)   x%04X", threadEntry.win32ThreadEntry.th32ThreadID);
					LOG_INFO("Process::ThreadEntry", "Ref count (p)   0x%04X", threadEntry.win32ThreadEntry.tpBasePri);
					LOG_INFO("Process::ThreadEntry", "Base address    0x%08X", (DWORD)threadEntry.win32ThreadEntry.tpDeltaPri);
					LOG_INFO("Process::ThreadEntry", "Base size       %d", threadEntry.win32ThreadEntry.dwFlags);
					newProccessEntry->AddThread(newThreadEntry);
					result_thread = GetThreadNext(pid,& threadEntry);
				}
#endif // LIST_PROCESS_THREADS
			}

			ProcessEntries.push_back(newProccessEntry);
			result_process = GetProcessNext(&psEntry);
		}

		_currentState = ESTATE_DONE;

		threadExited = true;
		return 0;
	}

protected:


	bool IsThreadRunning() {  }

    PVOID GetModulePreferredBase(DWORD dwPID, PVOID pModBase);
    // General members
    int m_method;
	std::vector<CProcessEntry*> ProcessEntries;
    // PSAPI related members
    HMODULE PSAPI;   //Handle to the module
    int m_MAX_COUNT;
    DWORD* m_pProcesses, *m_pCurrentP; // Process identifiers
    long m_cProcesses, m_cModules;	 // Number of Processes/Modules found
    HMODULE* m_pModules, *m_pCurrentM; // Handles to Modules
    // PSAPI related functions
    PFEnumProcesses	   FEnumProcesses;		   // Pointer to EnumProcess
    PFEnumProcessModules  FEnumProcessModules; // Pointer to EnumProcessModules
    PFGetModuleFileNameEx FGetModuleFileNameEx;// Pointer to GetModuleFileNameEx
    BOOL FillPStructPSAPI(DWORD pid, CProcessEntry* pEntry);
    BOOL FillMStructPSAPI(DWORD dwPID, HMODULE mMod, CModuleEntry* pEntry);

    // ToolHelp related members
    HANDLE m_hProcessSnap, m_hModuleSnap;
    HMODULE TOOLHELP;   //Handle to the module (Kernel32)
    PROCESSENTRY32 m_pe;
    MODULEENTRY32  m_me;
    // ToolHelp related functions
    PFCreateToolhelp32Snapshot FCreateToolhelp32Snapshot;
    PFProcess32First FProcess32First;
    PFProcess32Next  FProcess32Next;
    PFModule32First  FModule32First;
    PFModule32Next   FModule32Next;   
	bool threadStarted;
	bool threadExited;

	ECurrentState _currentState;
#ifdef USE_VDMDBG
    // 16-bit enumeration
    HMODULE VDMDBG;  // Handle to module (vdmdbg.h)
    PFVDMEnumTaskWOWEx FVDMEnumTaskWOWEx;
#endif // USE_VDMDBG


};

#endif // ___PROCESSENUMERATION__H__
 