
//==============================================================================
//
//   psinfo.cpp
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#include "stdafx.h"
#include "psinfo.h"

#ifdef _WIN32
#include "psapi.h"
#pragma comment(lib, "psapi.lib")
#include "tlhelp32.h"
#endif

#ifdef linux
#include <sys/sysinfo.h>
#define LINEBUFFLEN 2048
#endif

ProcessInfo::ProcessInfo(unsigned int iProcessId)
{
	mProcessId = iProcessId;

#ifdef _WIN32
	// get number of processors
	SYSTEM_INFO lSysInfo;
	GetSystemInfo(&lSysInfo);
	mNumOfProcessors =  lSysInfo.dwNumberOfProcessors;

	// get system time
	FILETIME lFileTime;
	GetSystemTimeAsFileTime(&lFileTime);
	memcpy(&mPrevSystemTime, &lFileTime, sizeof(FILETIME));

	// get amount of time ran in kernel and user mode
	FILETIME lCreationTime, lExitTime, lKernelTime, lUserTime;
	HANDLE lProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mProcessId);
	if (lProcessHandle != NULL)
	{
		BOOL lSuccess = GetProcessTimes(lProcessHandle, &lCreationTime, &lExitTime, &lKernelTime, &lUserTime);
		if (lSuccess)
		{
			memcpy(&mCreationTime, &lCreationTime, sizeof(FILETIME));
			memcpy(&mPrevKernelTime, &lKernelTime, sizeof(FILETIME));
			memcpy(&mPrevUserTime, &lUserTime, sizeof(FILETIME));
		}

		CloseHandle(lProcessHandle);
	}

#elif defined(linux)
	mJiffiesPerSecond = sysconf(_SC_CLK_TCK);
	mPrevSystemTime = 0;
	mPrevUserTime = 0;
	mPrevKernelTime = 0;

	// calculate total system time from file /proc/stat,
	// the content is like: cpu 7967 550 4155 489328
	FILE* lpFile = fopen("/proc/stat", "r");
	if (lpFile)
	{
		// skip unnecessary content
		fscanf(lpFile, "cpu");
		unsigned long long lTime;
		int lValuesToRead = 4;
		for (int i = 0; i < lValuesToRead; i++)
		{
			fscanf(lpFile, "%llu", &lTime);
			mPrevSystemTime += lTime;
		}
		fclose(lpFile);
	}

	// get user mode time, kernel mode time, start time
	// for current process from file /proc/[pid]/stat
	char lFileName[256];
	sprintf(lFileName, "/proc/%d/stat", mProcessId);
	lpFile = fopen(lFileName, "r");
	if (lpFile)
	{
		// skip unnecessary content
		int lValuesToSkip = 13;
		char lTemp[LINEBUFFLEN];
		for (int i = 0; i < lValuesToSkip; i++)
			fscanf(lpFile, "%s", lTemp);
		fscanf(lpFile, "%llu %llu", &mPrevUserTime, &mPrevKernelTime);

		// skip unnecessary content
		lValuesToSkip = 6;
		for (int i = 0; i < lValuesToSkip; i++)
			fscanf(lpFile, "%s", lTemp);
		unsigned long long lStartTimeSinceBoot;
		fscanf(lpFile, "%llu", &lStartTimeSinceBoot);
		mStartTimeSinceBoot = lStartTimeSinceBoot / mJiffiesPerSecond;

		fclose(lpFile);
	}
#endif
}

ProcessInfo::~ProcessInfo() throw()
{
}

unsigned int ProcessInfo::GetProcessId()
{
	return mProcessId;
}

unsigned long long ProcessInfo::GetProcessUptime()
{
	unsigned long long lUptimeInSec = -1;

#ifdef _WIN32
	FILETIME lCurrTime;
	GetSystemTimeAsFileTime(&lCurrTime);
	
	ULARGE_INTEGER ulCurrTime;
	memcpy(&ulCurrTime, &lCurrTime, sizeof(FILETIME));

	// The FILETIME structure represents the number of 100-nanosecond intervals,
	// so we need to divide by 10 million to get actual seconds
	lUptimeInSec = (ulCurrTime.QuadPart - mCreationTime.QuadPart) / 10000000;

	return lUptimeInSec;

#elif defined(linux)
	struct sysinfo lSysinfo;
	int lReturn = sysinfo(&lSysinfo);

	if (lReturn == 0)
		lUptimeInSec = lSysinfo.uptime - mStartTimeSinceBoot;

#endif
	return lUptimeInSec;
}

double ProcessInfo::GetProcessCPUUsage()
{
	double lCPUUsage = -1;

#ifdef _WIN32
	HANDLE lProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mProcessId);
	if (lProcessHandle != NULL)
	{
		// get current system time
		FILETIME lFileTime;
		GetSystemTimeAsFileTime(&lFileTime);
		ULARGE_INTEGER lCurrSystemTime;
		memcpy(&lCurrSystemTime, &lFileTime, sizeof(FILETIME));

		// get amount of time ran in kernel and user mode
		FILETIME lKernelTime, lUserTime;
		BOOL lSuccess = GetProcessTimes(lProcessHandle, &lFileTime, &lFileTime, &lKernelTime, &lUserTime);
		if (lSuccess)
		{
			ULARGE_INTEGER lCurrKernelTime, lCurrUserTime;
			memcpy(&lCurrKernelTime, &lKernelTime, sizeof(FILETIME));
			memcpy(&lCurrUserTime, &lUserTime, sizeof(FILETIME));

			// calculate process cpu usage
			ULONGLONG lTotalProcess = (lCurrKernelTime.QuadPart - mPrevKernelTime.QuadPart) + (lCurrUserTime.QuadPart - mPrevUserTime.QuadPart);
			ULONGLONG lTotalSystem = lCurrSystemTime.QuadPart - mPrevSystemTime.QuadPart;
			if (lTotalSystem > 0)
				lCPUUsage = (lTotalProcess * 100.0) / (lTotalSystem * mNumOfProcessors);
			
			// store current time info
			mPrevSystemTime = lCurrSystemTime;
			mPrevKernelTime = lCurrKernelTime;
			mPrevUserTime = lCurrUserTime;
		}

		CloseHandle(lProcessHandle);
	}

#elif defined(linux)
	unsigned long long lCurrSystemTime = 0;
	unsigned long long lCurrUserTime = 0;
	unsigned long long lCurrKernelTime = 0;

	// calculate total system time from file /proc/stat,
	// the content is like: cpu 7967 550 4155 489328
	FILE* lpFile = fopen("/proc/stat", "r");
	if (lpFile)
	{
		// skip unnecessary content
		fscanf(lpFile, "cpu");
		unsigned long long lTime;
		int lValuesToRead = 4;
		for (int i = 0; i < lValuesToRead; i++)
		{
			fscanf(lpFile, "%llu", &lTime);
			lCurrSystemTime += lTime;
		}
		fclose(lpFile);
	}

	// get user mode and kernel mode time for current
	// process from file /proc/[pid]/stat
	char lFileName[256];
	sprintf(lFileName, "/proc/%d/stat", mProcessId);
	lpFile = fopen(lFileName, "r");
	if (lpFile)
	{
		// skip unnecessary content
		char lTemp[LINEBUFFLEN];
		int lValuesToSkip = 13;
		for (int i = 0; i < lValuesToSkip; i++)
			fscanf(lpFile, "%s", lTemp);

		fscanf(lpFile, "%llu %llu", &lCurrUserTime, &lCurrKernelTime);
		fclose(lpFile);
	}

	unsigned long long lTotalProcess = (lCurrUserTime - mPrevUserTime) + (lCurrKernelTime - mPrevKernelTime);
	unsigned long long lTotalSystem = lCurrSystemTime - mPrevSystemTime;
	if (lTotalSystem > 0)
		lCPUUsage = (lTotalProcess * 100.0) / lTotalSystem;

	mPrevSystemTime = lCurrSystemTime;
	mPrevUserTime = lCurrUserTime;
	mPrevKernelTime = lCurrKernelTime;

#endif
	return lCPUUsage;
}

double ProcessInfo::GetProcessMemoryUsed()
{
	double lMemUsed = -1;

#ifdef _WIN32
	HANDLE lProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mProcessId);
	if (lProcessHandle != NULL)
	{
		PROCESS_MEMORY_COUNTERS lPMC;
		BOOL lSuccess = GetProcessMemoryInfo(lProcessHandle, &lPMC, sizeof(lPMC));
		if (lSuccess)
		{
			// size in MB
			lMemUsed = lPMC.WorkingSetSize / (1024.0 * 1024.0);
		}

		CloseHandle(lProcessHandle);
	}

#elif defined(linux)
	char lFileName[256];
	sprintf(lFileName, "/proc/%d/status", mProcessId);
	FILE* lpFile = fopen(lFileName, "r");
	char lLineBuf[LINEBUFFLEN];
	if(lpFile)
	{
		while(fgets(lLineBuf, LINEBUFFLEN, lpFile))
		{
			if (0 == strncmp(lLineBuf, "VmRSS:", 6))
			{
				char* cursor = lLineBuf + 6;
				/* Get rid of preceding blanks */
				while (!isdigit(*cursor))
				{
					cursor++;
				}
				/* Get rid of following blanks */
				char* lNumString = cursor;
				while (isdigit(*cursor))
				{
					cursor++;
				}
				*cursor = '\0';
				lMemUsed = MBase::DecimalToInt64(lNumString) / 1024.0;
				break;
			}
		}
		fclose(lpFile);
	}

#endif
	return lMemUsed;
}

unsigned long ProcessInfo::GetProcessThreadCount()
{
	unsigned long lThreadCnt = -1;

#ifdef _WIN32
	// get a process list snapshot
	HANDLE lSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (lSnapshot != NULL)
	{
		// initialize the process entry structure
		PROCESSENTRY32 lEntry;
		lEntry.dwSize = sizeof(PROCESSENTRY32);

		// get the first process info
		BOOL lSuccess = Process32First(lSnapshot, &lEntry);
		while (lSuccess)
		{
			if (lEntry.th32ProcessID == mProcessId)
			{
				lThreadCnt = lEntry.cntThreads;
				break;
			}
			lSuccess = Process32Next(lSnapshot, &lEntry);
		}

		CloseHandle(lSnapshot);
	}

#elif defined(linux)
	// get number of threads from file /proc/[pid]/stat
	char lFileName[256];
	sprintf(lFileName, "/proc/%d/stat", mProcessId);
	FILE* lpFile = fopen(lFileName, "r");
	if (lpFile)
	{
		// skip unnecessary content
		char lTemp[LINEBUFFLEN];
		int lValuesToSkip = 19;
		for (int i = 0; i < lValuesToSkip; i++)
			fscanf(lpFile, "%s", lTemp);
		fscanf(lpFile, "%lu", &lThreadCnt);
		fclose(lpFile);
	}

#endif
	return lThreadCnt;
}