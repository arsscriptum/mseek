

//==============================================================================
//
//  ps_enum.cpp: implementation of the CEnumProcess class.
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#include "stdafx.h"
#include "ps_enum.h"
#include "log.h"
#include "cdll.h"
#include <stdio.h>
#include <io.h>
#include <stdint.h>
#include <strsafe.h>
using namespace std;

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;



#endif
#define _NOOP_TEXT(x)    x
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////


#ifdef USE_VDMDBG
BOOL CALLBACK Enum16Proc( DWORD dwThreadId, WORD hMod16, WORD hTask16, PSZ pszModName, PSZ pszFileName, LPAR
{AM lpUserDefined ) ;

CTypedPtrArray<CPtrArray, CEnumProcess::CProcessEntry*> g_Processes16;
#endif // USE_VDMDBG

bool CProcessEnumerator::FillThreadsTH32(TThreads& threads, DWORD pid)
{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

		_currentState = ESTATE_IDLE;

		typedef NTSTATUS(WINAPI* _NtQueryInfomationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
		_NtQueryInfomationThread NtQueryInformationThread = (_NtQueryInfomationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");

		// CreateToolhelp32Snapshot()
		typedef HANDLE(__stdcall* FCreateToolhelp32Snapshot)(WORD dwFlags,
														  DWORD th32ProcessID);
		// Module32First()
		typedef BOOL(__stdcall* FThread32First)(HANDLE hSnapshot,
											 LPTHREADENTRY32 lpme);
		// Module32Next()
		typedef BOOL(__stdcall* FThread32Next)(HANDLE hSnapshot,
											LPTHREADENTRY32 lpme);

		// I think the DLL is called tlhelp32.dll on Win9X, so we try both
		FCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
		FThread32First Thread32First;
		FThread32Next Thread32Next;


		const char* dllname[] = {
				"kernel32.dll",
				"tlhelp32.dll",
				NULL
		};

		const char* libname = dllname[0];
		std::unique_ptr<CDll> dll;
		while (libname) {
			dll.reset(new CDll(libname, CDll::eLoadNow, CDll::eAutoUnload));

			CreateToolhelp32Snapshot =
				dll->GetEntryPoint_Func("CreateToolhelp32Snapshot",
										&CreateToolhelp32Snapshot);
			Thread32First =
				dll->GetEntryPoint_Func("Thread32First", &Thread32First);
			Thread32Next =
				dll->GetEntryPoint_Func("Thread32Next", &Thread32Next);

			if (CreateToolhelp32Snapshot && Thread32First && Thread32Next) {
				break;
			}
		}

		if (!CreateToolhelp32Snapshot) {
			return false;
			// "toolhelp32 functions not available");
		}

		HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (handle == (HANDLE)-1) {
			return false;
			//"failed to create toolhelp32 snapshot");
		}
		THREADENTRY32 te32;
		THREAD_BASIC_INFORMATION tbi = { 0 };
		te32.dwSize = sizeof(THREADENTRY32);
		BOOL threadList = Thread32First(handle, &te32);

		HANDLE hEvtProcess = NULL;
		HANDLE hEvtThread = NULL;

		while (threadList) {
			hEvtThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, te32.th32ThreadID);

			NtQueryInformationThread(hEvtThread, (THREAD_INFORMATION_CLASS)0, &tbi, 0x30, NULL);

			hEvtProcess = OpenProcess(PROCESS_VM_READ, FALSE, te32.th32OwnerProcessID);
			typedef ULONG(WINAPI* _I_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);

			_I_QueryTagInformation I_QueryTagInformation = (_I_QueryTagInformation)GetProcAddress(hAdvapi32, "I_QueryTagInformation");

			SC_SERVICE_TAG_QUERY scTagQuery = { 0 };
			ULONG hTag = NULL;

			THREADENTRY32 te32;
			THREAD_BASIC_INFORMATION tbi = { 0 };
			te32.dwSize = sizeof(THREADENTRY32);

			HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

			BOOL threadList = Thread32First(hThreads, &te32);

			HANDLE hEvtProcess = NULL;
			HANDLE hEvtThread = NULL;

			while (threadList) 
			{
				//if (te32.th32ThreadID == 0) { continue;  }
				hEvtThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE,te32.th32ThreadID);

				NtQueryInformationThread(hEvtThread, (THREAD_INFORMATION_CLASS)0, &tbi, 0x30, NULL);

				hEvtProcess = OpenProcess(PROCESS_VM_READ, FALSE,pid);

				if (tbi.pTebBaseAddress != 0) 
				{

					ReadProcessMemory(hEvtProcess, ((PBYTE)tbi.pTebBaseAddress + 0x1720), &hTag, sizeof(HANDLE), NULL);

						scTagQuery.processId = te32.th32OwnerProcessID;
						scTagQuery.serviceTag = hTag;

						I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &scTagQuery);

						char serviceName[MAX_PATH] = { 0 };
						size_t cbDest = MAX_PATH * sizeof(char);

						StringCbPrintfA(serviceName, cbDest, "%ws", (PCWSTR)scTagQuery.pBuffer);
						printf("[!] Thread %d has service name %s\n", te32.th32ThreadID, serviceName);

						/*if (_stricmp(serviceName, "eventlog") == 0) {

							if (TerminateThread(hEvtThread, 0) == 0) {

								printf("[!] Thread %d is detected but kill failed. Error code is: %d\n", te32.th32ThreadID, GetLastError());

							}
							else {

								printf("[+] Thread %d is detected and successfully killed.\n", te32.th32ThreadID);

							}

						}
						*/
						scTagQuery = { 0 }; // Clear array

						CloseHandle(hEvtThread);
						CloseHandle(hEvtProcess);
				}
				threadList = Thread32Next(hThreads, &te32);
			}

			
			CloseHandle(hThreads);
		}

		

	

		/*
		THREADENTRY32 me;
		me.dwSize = sizeof(THREADENTRY32);
		bool done = !Thread32First(handle, &me) ? true : false;
		while (!done) {
			// here, we have a filled-in MODULEENTRY32
			SThreadEntry e;
			e.parentPid = me.th32OwnerProcessID;
			e.threadId = me.th32ThreadID;
			e.size = me.dwSize;
			e.flags = me.dwFlags;

			threads.push_back(e);
			done = !Thread32Next(handle, &me) ? true : false;
		}

		CloseHandle(handle);
		*/

		return threads.size() != 0;
}


bool CProcessEnumerator::FillModuleListTH32(TModules& modules, DWORD pid)
{
		// CreateToolhelp32Snapshot()
		typedef HANDLE(__stdcall* FCreateToolhelp32Snapshot)(WORD dwFlags,
														  DWORD th32ProcessID);
		// Module32First()
		typedef BOOL(__stdcall* FModule32First)(HANDLE hSnapshot,
											 LPMODULEENTRY32 lpme);
		// Module32Next()
		typedef BOOL(__stdcall* FModule32Next)(HANDLE hSnapshot,
											LPMODULEENTRY32 lpme);

		// I think the DLL is called tlhelp32.dll on Win9X, so we try both
		FCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
		FModule32First Module32First;
		FModule32Next Module32Next;


		const char* dllname[] = {
				"kernel32.dll",
				"tlhelp32.dll",
				NULL
		};

		const char* libname = dllname[0];
		std::unique_ptr<CDll> dll;
		while (libname) {
			dll.reset(new CDll(libname, CDll::eLoadNow, CDll::eAutoUnload));

			CreateToolhelp32Snapshot =
				dll->GetEntryPoint_Func("CreateToolhelp32Snapshot",
										&CreateToolhelp32Snapshot);
			Module32First =
				dll->GetEntryPoint_Func("Module32First", &Module32First);
			Module32Next =
				dll->GetEntryPoint_Func("Module32Next", &Module32Next);

			if (CreateToolhelp32Snapshot && Module32First && Module32Next) {
				break;
			}
		}

		if (!CreateToolhelp32Snapshot) {
			return false;
			// "toolhelp32 functions not available");
		}

		HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if (handle == (HANDLE)-1) {
			return false;
			//"failed to create toolhelp32 snapshot");
		}

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);
		bool done = !Module32First(handle, &me) ? true : false;
		while (!done) {
			// here, we have a filled-in MODULEENTRY32
			SModuleEntry e;
			e.imageName = me.szExePath;
			e.moduleName = me.szModule;
			e.baseAddress = (DWORD)me.modBaseAddr;
			e.size = me.modBaseSize;
			modules.push_back(e);

			done = !Module32Next(handle, &me) ? true : false;
		}

		CloseHandle(handle);

		return modules.size() != 0;
}

bool CProcessEnumerator::FillModuleListPSAPI(TModules& mods, DWORD pid, HANDLE hProcess)
{

		// EnumProcessModules()
		typedef BOOL(__stdcall* FEnumProcessModules)(HANDLE hProcess,
													  HMODULE* lphModule,
													  DWORD cb,
													  LPDWORD lpcbNeeded);
		// GetModuleFileNameEx()
		typedef DWORD(__stdcall* FGetModuleFileNameExA)(HANDLE hProcess,
														 HMODULE hModule,
														 LPSTR lpFilename,
														 DWORD nSize);
		// GetModuleBaseName() -- redundant, as GMFNE() has the same prototype, but who cares?
		typedef DWORD(__stdcall* FGetModuleBaseNameA)(HANDLE hProcess,
													   HMODULE hModule,
													   LPSTR lpFilename,
													   DWORD nSize);
		// GetModuleInformation()
		typedef BOOL(__stdcall* FGetModuleInformation)(HANDLE hProcess,
														HMODULE hModule,
														LPMODULEINFO pmi,
														DWORD nSize);

		FEnumProcessModules EnumProcessModules;
		FGetModuleFileNameExA GetModuleFileNameExA;
		FGetModuleBaseNameA GetModuleBaseNameA;
		FGetModuleInformation GetModuleInformation;

		mods.clear();
		CDll dll("psapi.dll", CDll::eLoadNow, CDll::eAutoUnload);

		EnumProcessModules =
			dll.GetEntryPoint_Func("EnumProcessModules",
								   &EnumProcessModules);
		GetModuleFileNameExA =
			dll.GetEntryPoint_Func("GetModuleFileNameExA",
								   &GetModuleFileNameExA);
		GetModuleBaseNameA =
			dll.GetEntryPoint_Func("GetModuleBaseNameA",
								   &GetModuleBaseNameA);
		GetModuleInformation =
			dll.GetEntryPoint_Func("GetModuleInformation",
								   &GetModuleInformation);

		if (!EnumProcessModules ||
			 !GetModuleFileNameExA ||
			 !GetModuleBaseNameA ||
			 !GetModuleInformation) {
			return false;
		}

		vector<HMODULE> modules;
		modules.resize(4096);

		string tmp;
		DWORD needed;
		if (!EnumProcessModules(hProcess,
								 &modules[0],
								 modules.size() * sizeof(HMODULE),
								 &needed)) {
			return false;
		}

		if (needed > modules.size() * sizeof(HMODULE)) {
			return false;
		}


		needed /= sizeof(HMODULE);
		for (size_t i = 0; i < needed; ++i) {
			// for each module, get:
			// base address, size
			MODULEINFO mi;
			GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi));

			SModuleEntry e;
			e.baseAddress = (DWORD)mi.lpBaseOfDll;
			e.size = mi.SizeOfImage;

			// image file name
			char tt[2048];
			tt[0] = '\0';
			GetModuleFileNameExA(hProcess, modules[i], tt, sizeof(tt));
			e.imageName = tt;

			// module name
			tt[0] = '\0';
			GetModuleBaseNameA(hProcess, modules[i], tt, sizeof(tt));
			e.moduleName = tt;

			mods.push_back(e);
		

		return true;
	}


	return false;
}


CProcessEnumerator::CProcessEnumerator() : m_pProcesses(NULL), m_pModules(NULL), m_pCurrentP(NULL), m_pCurrentM(NULL)
{
	SetThreadIdentifier("CEnumProcess Thread");
    m_hProcessSnap = INVALID_HANDLE_VALUE;
    m_hModuleSnap = INVALID_HANDLE_VALUE;
	threadStarted = false;
	threadExited = false;
    PSAPI = ::LoadLibrary(_TEXT("PSAPI"));
    if (PSAPI) 
	    {// Setup variables
		 m_MAX_COUNT = 256;
		 m_cProcesses = 0;
		 m_cModules   = 0;

		 // Find PSAPI functions
		 FEnumProcesses = (PFEnumProcesses)::GetProcAddress(PSAPI, _NOOP_TEXT("EnumProcesses"));
		 FEnumProcessModules = (PFEnumProcessModules)::GetProcAddress(PSAPI, _NOOP_TEXT("EnumProcessModules"));
		 #ifdef UNICODE
		 FGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(PSAPI, _NOOP_TEXT("GetModuleFileNameExW"));
		 #else
		 FGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(PSAPI, _NOOP_TEXT("GetModuleFileNameExA"));
		 #endif
	    }

    TOOLHELP = ::LoadLibrary(_TEXT("Kernel32"));
    if (TOOLHELP) 
	    {// Setup variables
		 m_pe.dwSize = sizeof(m_pe);
		 m_me.dwSize = sizeof(m_me);
		 // Find ToolHelp functions
         
		 FCreateToolhelp32Snapshot = (PFCreateToolhelp32Snapshot)::GetProcAddress(TOOLHELP, _NOOP_TEXT("CreateToolhelp32Snapshot"));
		 FProcess32First		   = (PFProcess32First)::GetProcAddress(TOOLHELP, _NOOP_TEXT("Process32First"));
		 FProcess32Next = (PFProcess32Next)::GetProcAddress(TOOLHELP, _NOOP_TEXT("Process32Next"));
		 FModule32First = (PFModule32First)::GetProcAddress(TOOLHELP, _NOOP_TEXT("Module32First"));
		 FModule32Next = (PFModule32Next)::GetProcAddress(TOOLHELP, _NOOP_TEXT("Module32Next"));
	    }

#ifdef USE_VDMDBG
    VDMDBG = ::LoadLibrary(_TEXT("VDMDBG"));
    if (VDMDBG)
	    {// Setup variables
		 
		 // Find VDMdbg functions
		 FVDMEnumTaskWOWEx = (PFVDMEnumTaskWOWEx)::GetProcAddress(VDMDBG, "VDMEnumTaskWOWEx");
	    }
#endif // USE_VDMDBG
   
    // Find the preferred method of enumeration
    m_method = ENUM_METHOD::NONE;
    int method = GetAvailableMethods();
    if (method == (method|ENUM_METHOD::PSAPI))    m_method = ENUM_METHOD::PSAPI;
    if (method == (method|ENUM_METHOD::TOOLHELP)) m_method += ENUM_METHOD::TOOLHELP;
    if (method == (method|ENUM_METHOD::PROC16))   m_method += ENUM_METHOD::PROC16;

}

CProcessEnumerator::~CProcessEnumerator()
{if (m_pProcesses) {delete[] m_pProcesses;}
 if (m_pModules)   {delete[] m_pModules;}
 if (PSAPI) FreeLibrary(PSAPI);
 if (TOOLHELP) FreeLibrary(TOOLHELP);
 if (INVALID_HANDLE_VALUE != m_hProcessSnap) ::CloseHandle(m_hProcessSnap);
 if (INVALID_HANDLE_VALUE != m_hModuleSnap)  ::CloseHandle(m_hModuleSnap);
 
#ifdef USE_VDMDBG
 if (VDMDBG) FreeLibrary(VDMDBG);
 while (g_Processes16.GetSize()>0)
 {CProcessEntry* tmp = g_Processes16[0];
  g_Processes16.RemoveAt(0);
  delete tmp;
 }
#endif // USE_VDMDBG
}



int CProcessEnumerator::GetAvailableMethods()
{int res = 0;
 // Does all psapi functions exist?
 if (PSAPI&&FEnumProcesses&&FEnumProcessModules&&FGetModuleFileNameEx)
	 res += ENUM_METHOD::PSAPI;
 // How about Toolhelp?
 if (TOOLHELP&&FCreateToolhelp32Snapshot&&FProcess32Next&&FProcess32Next&&FModule32First&&FModule32Next)
	 res += ENUM_METHOD::TOOLHELP;

#ifdef USE_VDMDBG
 // And 16-bit enumeration?
 if (VDMDBG&&FVDMEnumTaskWOWEx && res > ENUM_METHOD::NONE)
	 res += ENUM_METHOD::PROC16;
#endif // USE_VDMDBG

 return res;
}

int CProcessEnumerator::SetMethod(int method)
{int avail = GetAvailableMethods();

 if (method != ENUM_METHOD::PROC16 && avail == (method|avail))
		    m_method = method;

 return m_method;
}

int CProcessEnumerator::GetSuggestedMethod()
{return m_method;
}
// Retrieves the first process in the enumeration. Should obviously be called before
// GetProcessNext
////////////////////////////////////////////////////////////////////////////////////
BOOL CProcessEnumerator::GetProcessFirst(CProcessEnumerator::CProcessEntry *pEntry)
{if (ENUM_METHOD::NONE == m_method) return FALSE;


if ((ENUM_METHOD::TOOLHELP|m_method) == m_method)
// Use ToolHelp functions
// ----------------------
{m_hProcessSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 if (INVALID_HANDLE_VALUE == m_hProcessSnap) return FALSE;

 if (!FProcess32First(m_hProcessSnap, &m_pe)) return FALSE;
 pEntry->dwPID = m_pe.th32ProcessID;
 LOG_INFO("CEnumProcess::GetProcessFirst", "process name %s. pid %d", m_pe.th32ProcessID, m_pe.szExeFile);
 _STRNCPY(pEntry->lpFilename, m_pe.szExeFile, MAX_FILENAME);
}
else
// Use PSAPI functions
// ----------------------
{
 if (m_pProcesses) {delete[] m_pProcesses;}
 m_pProcesses = new DWORD[m_MAX_COUNT];
 m_pCurrentP = m_pProcesses;
 DWORD cbNeeded = 0;
 BOOL OK = FEnumProcesses(m_pProcesses, m_MAX_COUNT*sizeof(DWORD), &cbNeeded);

 // We might need more memory here..
 if (cbNeeded >= m_MAX_COUNT*sizeof(DWORD))
    {m_MAX_COUNT += 256;
	 return GetProcessFirst(pEntry); // Try again.
    }

 if (!OK) return FALSE;
 m_cProcesses = cbNeeded/sizeof(DWORD);
 return FillPStructPSAPI(*m_pProcesses, pEntry);
}

 return TRUE;
}

// Returns the following process
////////////////////////////////////////////////////////////////
BOOL CProcessEnumerator::GetProcessNext(CProcessEnumerator::CProcessEntry *pEntry)
{if (ENUM_METHOD::NONE == m_method) return FALSE;
 pEntry->hTask16 = 0;

#ifdef USE_VDMDBG
 // We have some 16-bit processes to get
 if (g_Processes16.GetSize() > 0)
 {CEnumProcess::CProcessEntry *pTmp = g_Processes16[0];
  g_Processes16.RemoveAt(0);
  strcpy(pEntry->lpFilename, pTmp->lpFilename);
  pEntry->dwPID = pTmp->dwPID;
  pEntry->hTask16 = pTmp->hTask16;
  delete pTmp;
  return TRUE;
 }
#endif // USE_VDMDBG

// Use ToolHelp functions
// ----------------------
if ((ENUM_METHOD::TOOLHELP|m_method) == m_method)
{
 if (!FProcess32Next(m_hProcessSnap, &m_pe)) return FALSE;
 pEntry->dwPID = m_pe.th32ProcessID;
 LOG_INFO("CEnumProcess::GetProcessFirst", "process name %s. pid %d", m_pe.szExeFile, m_pe.th32ProcessID);
 _STRNCPY(pEntry->lpFilename, m_pe.szExeFile, MAX_FILENAME);
}
else
// Use PSAPI functions
// ----------------------
{if (--m_cProcesses <= 0) return FALSE;
 FillPStructPSAPI(*++m_pCurrentP, pEntry);
}

#ifdef USE_VDMDBG
// Check for 16-bit processes?
if ((ENUM_METHOD::PROC16|m_method) == m_method)
   // is this a NTVDM?
   if( 0 == _stricmp( pEntry->lpFilename+(strlen(pEntry->lpFilename)-9), "NTVDM.EXE"))
	 {
	  FVDMEnumTaskWOWEx( pEntry->dwPID, (TASKENUMPROCEX) &Enum16Proc, (LPARAM) pEntry->dwPID);
	 }
#endif // USE_VDMDBG

 return TRUE;
}


BOOL CProcessEnumerator::GetModuleFirst(DWORD dwPID, CProcessEnumerator::CModuleEntry *pEntry)
{
	if (ENUM_METHOD::NONE == m_method) return FALSE;
	// Use ToolHelp functions
	// ----------------------
	if ((ENUM_METHOD::TOOLHELP|m_method) == m_method)
	{
		if (INVALID_HANDLE_VALUE != m_hModuleSnap)  ::CloseHandle(m_hModuleSnap); 
		{
			m_hModuleSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
			if (!FModule32First(m_hModuleSnap, &m_me)) {
				return FALSE;
			}

			pEntry->pLoadBase = m_me.modBaseAddr;
			memcpy(&pEntry->win32ModuleEntry, &m_me, sizeof(m_me));
			_STRNCPY(pEntry->szModuleName, m_me.szModule, _STRNLEN(pEntry->szModuleName, MAX_FILENAME - 1));
			_STRNCPY(pEntry->lpFilename, m_me.szExePath, _STRNLEN(pEntry->lpFilename, MAX_FILENAME - 1));
			pEntry->pPreferredBase = GetModulePreferredBase(dwPID, m_me.modBaseAddr);
			return TRUE;
		}
	}
	else
	{
		// Use PSAPI functions
		// ----------------------
	
		if (m_pModules)
		{
			delete[] m_pModules;
		}
		m_pModules = new HMODULE[m_MAX_COUNT];
		m_pCurrentM = m_pModules;
		DWORD cbNeeded = 0;
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
		if (hProc)
		{
			BOOL OK = FEnumProcessModules(hProc, m_pModules, m_MAX_COUNT * sizeof(HMODULE), &cbNeeded);
			CloseHandle(hProc);

			// We might need more memory here..
			if (cbNeeded >= m_MAX_COUNT * sizeof(HMODULE))
			{
				m_MAX_COUNT += 256;
				return GetModuleFirst(dwPID, pEntry); // Try again.
			}

			if (!OK) return FALSE;
			m_cModules = cbNeeded / sizeof(HMODULE);
			return FillMStructPSAPI(dwPID, *m_pCurrentM, pEntry);
		}	
	}
	return FALSE;
}



BOOL CProcessEnumerator::GetModuleNext(DWORD dwPID, CProcessEnumerator::CModuleEntry *pEntry)
{
	if (ENUM_METHOD::NONE == m_method) return FALSE;

	// Use ToolHelp functions
	// ----------------------
	if ((ENUM_METHOD::TOOLHELP|m_method) == m_method)
	{
		 if(!FModule32Next(m_hModuleSnap, &m_me)) return FALSE;

		 pEntry->pLoadBase = m_me.modBaseAddr;
		 memcpy(&pEntry->win32ModuleEntry, &m_me, sizeof(m_me));
		 
	     _STRNCPY(pEntry->szModuleName, m_me.szModule, _STRNLEN(pEntry->szModuleName, MAX_FILENAME - 1));
		 _STRNCPY(pEntry->lpFilename, m_me.szExePath, _STRNLEN(pEntry->lpFilename,MAX_FILENAME-1));
		 pEntry->pPreferredBase = GetModulePreferredBase(dwPID, m_me.modBaseAddr);
		 return TRUE;
	}
	else
	// Use PSAPI functions
	// ----------------------
	{	
		if (--m_cModules <= 0) return FALSE;
		return FillMStructPSAPI(dwPID, *++m_pCurrentM, pEntry);
	}
	return FALSE;
}


BOOL CProcessEnumerator::FillPStructPSAPI(DWORD dwPID, CProcessEnumerator::CProcessEntry* pEntry)
{
	pEntry->dwPID = dwPID;

	// Open process to get filename
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	if (hProc)
	{
		 HMODULE hMod;
		 DWORD size;
		 // Get the first module (the process itself)
		 if( FEnumProcessModules(hProc, &hMod, sizeof(hMod), &size) ){
			  //Get filename
			  if( !FGetModuleFileNameEx( hProc, hMod, pEntry->lpFilename, MAX_FILENAME) ){
				  _STRNCPY(pEntry->lpFilename, TEXT("N/A (error)"), MAX_FILENAME);
			  }
		 }
		 CloseHandle(hProc);
	}
	else{
		_STRNCPY(pEntry->lpFilename, TEXT("N/A (security restriction)"),MAX_FILENAME);
	}
	 
	return TRUE;
}

BOOL CProcessEnumerator::GetThreadFirst(DWORD dwPID, CProcessEnumerator::CThreadEntry *pEntry)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);
	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		return(FALSE);
	}
	
	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}
	pEntry->th32ThreadID = te32.th32ThreadID;
	pEntry->th32OwnerProcessID = te32.th32OwnerProcessID;;
	memcpy(&pEntry->win32ThreadEntry, &te32, sizeof(te32));
	CloseHandle(hThreadSnap);
	return TRUE;
}
BOOL CProcessEnumerator::GetThreadNext(DWORD dwPID, CProcessEnumerator::CThreadEntry *pEntry)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);
	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		return(FALSE);
	}

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32Next(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}
	pEntry->th32ThreadID = te32.th32ThreadID;
	pEntry->th32OwnerProcessID = te32.th32OwnerProcessID;;
	memcpy(&pEntry->win32ThreadEntry, &te32, sizeof(te32));
	CloseHandle(hThreadSnap);
	return TRUE;
}
BOOL CProcessEnumerator::FillMStructPSAPI(DWORD dwPID, HMODULE mMod, CProcessEnumerator::CModuleEntry *pEntry)
{
	
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	 if (hProc)
	 {
		if( !FGetModuleFileNameEx( hProc, mMod, pEntry->lpFilename, MAX_FILENAME) ){
			_STRNCPY(pEntry->lpFilename, TEXT("N/A (error)"), MAX_FILENAME);
	    } 
		pEntry->pLoadBase = (PVOID) mMod;
		pEntry->pPreferredBase = GetModulePreferredBase(dwPID, (PVOID)mMod);
	    CloseHandle(hProc);
		return TRUE;
	}
	return FALSE;
}



PVOID CProcessEnumerator::GetModulePreferredBase(DWORD dwPID, PVOID pModBase)
{
	if (ENUM_METHOD::NONE == m_method) {
		return NULL;
	}
	HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, dwPID);
	if (hProc){
		IMAGE_DOS_HEADER idh;
		IMAGE_NT_HEADERS inh;
		//Read DOS header
		ReadProcessMemory(hProc, pModBase, &idh, sizeof(idh), NULL);
	  
		if (IMAGE_DOS_SIGNATURE == idh.e_magic) {
			// Read NT headers at offset e_lfanew
			ReadProcessMemory(hProc, (PBYTE)pModBase + idh.e_lfanew, &inh, sizeof(inh), NULL);
		}
		CloseHandle(hProc);
		if (IMAGE_NT_SIGNATURE == inh.Signature) {
			// Get the preferred base...
			return (PVOID)inh.OptionalHeader.ImageBase;
		}
	}

	return NULL;
 }

CProcessEnumerator::PROCESS_TYPE CProcessEnumerator::QueryExeMachineType(const char *filename)
{
	FILE *fp = fopen(filename, "rb");

	if (fp == NULL)
		return PROCESS_NONE;

	// DOS header is 64 bytes
	const uint32_t fsize = filelength(fileno(fp));
	char magic[2] = { 0 };
	uint32_t offset = 0;
	uint16_t machine = 0;

	if (fread(magic, 1, 2, fp) != 2 || magic[0] != 'M' || magic[1] != 'Z')
	{
		LOG_ERROR("CEnumProcess::QueryExeMachineType", "not an executable file");
		fclose(fp);
		return PROCESS_NONE;
	}
	fseek(fp, 60, SEEK_SET);
	fread(&offset, 1, 4, fp);

	if (offset >= fsize)
	{
		LOG_ERROR("CEnumProcess::QueryExeMachineType", "invalid pe offset");
		
		fclose(fp);
		return PROCESS_NONE;
	}
	fseek(fp, offset, SEEK_SET);

	if (fread(magic, 1, 2, fp) != 2 || magic[0] != 'P' || magic[1] != 'E')
	{
		LOG_ERROR("CEnumProcess::QueryExeMachineType", "not a pe executable");

		fclose(fp);
		return PROCESS_NONE;
	}
	fread(magic, 1, 2, fp);
	fread(&machine, 1, 2, fp);
	CProcessEnumerator::PROCESS_TYPE ret = PROCESS_NONE;
	switch (machine)
	{
	case 0x014c:
		ret = PROCESS_WIN32;
		break;

	case 0x8664:
		ret = PROCESS_WIN64;
		break;

	case 0x0200:
		ret = PROCESS_WIN64;
		break;

	default:
		break;
	}
	LOG_TRACE("CEnumProcess::QueryExeMachineType", "file %s. type %d", filename, (int)ret);

	fclose(fp);
	return ret;
}

CProcessEnumerator::PROCESS_TYPE CProcessEnumerator::GetDllType(const char *dll_name) 
{
	const int PE_POINTER_OFFSET = 60;
	const int MACHINE_TYPE_OFFSET = 4;
	FILE *fp;
	size_t ret = 0;
	int peoffset;
	unsigned short machine;

	fp = fopen(dll_name, "rb");
	unsigned char data[4096];
	ret = fread(data, sizeof(char), 4096, fp);
	fclose(fp);
	if (ret == 0) {
		return PROCESS_NONE;
	}
		
	CProcessEnumerator::PROCESS_TYPE rettype = PROCESS_NONE;
	if ((data[0] == 'M') && (data[1] == 'Z')) {
		// Initial magic header is good
		peoffset = data[PE_POINTER_OFFSET + 3];
		peoffset = (peoffset << 8) + data[PE_POINTER_OFFSET + 2];
		peoffset = (peoffset << 8) + data[PE_POINTER_OFFSET + 1];
		peoffset = (peoffset << 8) + data[PE_POINTER_OFFSET];

		// Check second header
		if ((data[peoffset] == 'P') && (data[peoffset + 1] == 'E')) {
			machine = data[peoffset + MACHINE_TYPE_OFFSET];
			machine = (machine)+(data[peoffset + MACHINE_TYPE_OFFSET + 1] << 8);

			if (machine == 0x014c)
			{
				rettype = PROCESS_WIN32;
			}
			if (machine == 0x8664)
			{
				rettype = PROCESS_WIN64;
			}
		}
	}

	return rettype;
}


BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwOwnerPID);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
			_tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
			_tprintf(TEXT("\n"));
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}
	
#ifdef USE_VDMDBG
BOOL CALLBACK Enum16Proc( DWORD dwThreadId, WORD hMod16, WORD hTask16, PSZ pszModName, PSZ pszFileName, LPARAM lpUserDefined )
{CEnumProcess::CProcessEntry* pEntry = new CEnumProcess::CProcessEntry();
 strcpy(pEntry->lpFilename, pszFileName);
 pEntry->dwPID = (DWORD) lpUserDefined;
 pEntry->hTask16 = hTask16;
 g_Processes16.Add(pEntry);
 
 return FALSE;
}
#endif // USE_VDMDBG
