
//==============================================================================
//
//     nowarns.h : remove warnings
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================
 

#include "stdafx.h"
#include "psutils.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wtypes.h>
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <chrono>

#include "win32.h"
#include <Windows.h>
#include <minwindef.h>
#include "ps_enum.h"
#include "log.h"
#include "cdll.h"
#include <stdio.h>
#include <tlhelp32.h>
#include "psapi.h"
#include <stdio.h>
#include <tchar.h>



// #define USE_VDMDBG // Uncomment this if you don´t wat to use vdmdbg at all
#include <string>
#include <fstream>

#include "psapi.h"
#pragma comment(lib, "psapi.lib")
#include "tlhelp32.h"


using namespace std;
#  pragma warning (disable : 4191)

std::string GetPriorityClassString(DWORD priorityClass) {
    switch (priorityClass) {
        case ABOVE_NORMAL_PRIORITY_CLASS: return "Above N";
        case BELOW_NORMAL_PRIORITY_CLASS: return "Below N";
        case HIGH_PRIORITY_CLASS: return "High";
        case IDLE_PRIORITY_CLASS: return "Idle";
        case NORMAL_PRIORITY_CLASS: return "Normal";
        case REALTIME_PRIORITY_CLASS: return "Realtim";
        default: return "Unknown";
    }
}

void PrintProcessPropertiesOneLine(HANDLE processHandle, const std::string& processName, const std::string& processPath, bool showFullPath) {
    DWORD processId = GetProcessId(processHandle);

    // Get process priority
    DWORD priorityClass = GetPriorityClass(processHandle);
    std::string priorityClassStr = GetPriorityClassString(priorityClass);

    // Get number of threads
    DWORD numberOfThreads = 0;
    {
        // Open the snapshot of the process
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 threadEntry;
            threadEntry.dwSize = sizeof(threadEntry);

            // Iterate through threads to count those belonging to the process
            if (Thread32First(snapshot, &threadEntry)) {
                do {
                    if (threadEntry.th32OwnerProcessID == processId) {
                        numberOfThreads++;
                    }
                } while (Thread32Next(snapshot, &threadEntry));
            }
            CloseHandle(snapshot);
        }
    }

    // Get number of handles
    DWORD handleCount;
    GetProcessHandleCount(processHandle, &handleCount);

    // Get memory info
    PROCESS_MEMORY_COUNTERS_EX pmc;
    GetProcessMemoryInfo(processHandle, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc));

    // Get CPU times
    FILETIME creationTime, exitTime, kernelTime, userTime;
    GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime);

    ULARGE_INTEGER kernel, user;
    kernel.LowPart = kernelTime.dwLowDateTime;
    kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;
    user.HighPart = userTime.dwHighDateTime;

    // Convert times to milliseconds
    ULONGLONG totalCpuTime = (kernel.QuadPart + user.QuadPart) / 10000;

    // Get the current time
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER nowTime;
    nowTime.LowPart = now.dwLowDateTime;
    nowTime.HighPart = now.dwHighDateTime;

    // Calculate elapsed time since the process was started
    ULONGLONG startTime = ((ULARGE_INTEGER&)creationTime).QuadPart;
    ULONGLONG elapsedTime = (nowTime.QuadPart - startTime) / 10000;

    // Print the properties
    std::cout << ANSI_TEXT_COLOR_RED << std::right << std::setw(5) << processId << ANSI_TEXT_COLOR_RESET << "   "
        << ANSI_TEXT_COLOR_YELLOW << std::left << std::setw(20) << processName << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(8) << priorityClassStr << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(5) << numberOfThreads << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(6) << handleCount << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(10) << pmc.PrivateUsage / 1024 << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(15) << std::fixed << std::setprecision(3) << (totalCpuTime / 1000.0) << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_CYAN << std::right << std::setw(20) << std::fixed << std::setprecision(3) << (elapsedTime / 1000.0) << ANSI_TEXT_COLOR_RESET;
    if (showFullPath) {
        std::cout << ANSI_TEXT_COLOR_MAGENTA << "   " << processPath << ANSI_TEXT_COLOR_RESET;
    }
    std::cout << std::endl;
}


void PrintProcessPropertiesDetails(HANDLE processHandle) {
    // Get process priority
    DWORD priorityClass = GetPriorityClass(processHandle);
    std::string priorityClassStr = GetPriorityClassString(priorityClass);

    // Get number of threads
    DWORD processId = GetProcessId(processHandle);
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    //NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
   // DWORD numberOfThreads = pbi.NumberOfThreads;

    // Get number of handles
    DWORD handleCount;
    GetProcessHandleCount(processHandle, &handleCount);

    // Get memory info
    PROCESS_MEMORY_COUNTERS_EX pmc;
    GetProcessMemoryInfo(processHandle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

    // Get page faults
    ULONG pageFaultCount = pmc.PageFaultCount;

    // Get non-paged and paged pool usage
   // PROCESS_EXTENDED_BASIC_INFORMATION pebi;
    //NtQueryInformationProcess(processHandle, (PROCESSINFOCLASS)0,, &pebi, sizeof(pebi), &returnLength);
   // SIZE_T nonPagedPoolUsage = pebi.PrivateUsage;

    // Get context switches (using undocumented NtQueryInformationProcess)
    IO_COUNTERS ioCounters;
    GetProcessIoCounters(processHandle, &ioCounters);
    // Get the function pointer
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL) {
        std::cerr << "Failed to get ntdll handle" << std::endl;
        CloseHandle(processHandle);
        return;
    }

    PNT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess =
        (PNT_QUERY_INFORMATION_PROCESS)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        std::cerr << "Failed to get NtQueryInformationProcess address" << std::endl;
        CloseHandle(processHandle);
        return;
    }

    // Query the process information
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;
    pebi.Size = sizeof(pebi);
    NTSTATUS status = NtQueryInformationProcess(
        processHandle,
        (PROCESSINFOCLASS)0,
        &pebi,
        sizeof(pebi),
        NULL
    );

    if (status != 0) {
        std::cerr << "Failed to query process information" << std::endl;
        CloseHandle(processHandle);
        return;
    }


    std::cout << std::setw(20) << "Property" << std::setw(20) << "Value" << std::endl;
    std::cout << std::string(40, '-') << std::endl;
    std::cout << std::setw(20) << "Priority Class:" << std::setw(20) << priorityClassStr << std::endl;
    //std::cout << std::setw(20) << "Threads:" << std::setw(20) << numberOfThreads << std::endl;
    std::cout << std::setw(20) << "Handles:" << std::setw(20) << handleCount << std::endl;
    std::cout << std::setw(20) << "Virtual Memory:" << std::setw(20) << pmc.PagefileUsage << " bytes" << std::endl;
    std::cout << std::setw(20) << "Working Set:" << std::setw(20) << pmc.WorkingSetSize << " bytes" << std::endl;
    std::cout << std::setw(20) << "Private VM:" << std::setw(20) << pmc.PrivateUsage << " bytes" << std::endl;
    std::cout << std::setw(20) << "Peak Private VM:" << std::setw(20) << pmc.PeakPagefileUsage << " bytes" << std::endl;
    std::cout << std::setw(20) << "Page Faults:" << std::setw(20) << pageFaultCount << std::endl;
   // std::cout << std::setw(20) << "Non-Paged Pool:" << std::setw(20) << nonPagedPoolUsage << " bytes" << std::endl;
    std::cout << std::setw(20) << "Paged Pool:" << std::setw(20) << pmc.QuotaPagedPoolUsage << " bytes" << std::endl;
    std::cout << std::setw(20) << "Context Switches:" << std::setw(20) << ioCounters.ReadTransferCount << std::endl; // Placeholder

        // Output the extended basic information
    std::cout << std::setw(20) << "IsProtectedProcess: " << std::setw(20) << pebi.IsProtectedProcess << std::endl;
    std::cout << std::setw(20) << "IsWow64Process: " << std::setw(20) <<pebi.IsWow64Process << std::endl;
    std::cout << std::setw(20) << "IsProcessDeleting: " << std::setw(20) << pebi.IsProcessDeleting << std::endl;
    std::cout << std::setw(20) << "IsCrossSessionCreate: " << std::setw(20) << pebi.IsCrossSessionCreate << std::endl;
    std::cout << std::setw(20) << "IsFrozen: " << std::setw(20) << pebi.IsFrozen << std::endl;
    std::cout << std::setw(20) << "IsBackground: " << std::setw(20) << pebi.IsBackground << std::endl;
    std::cout << std::setw(20) << "IsStronglyNamed: " << std::setw(20) <<  pebi.IsStronglyNamed << std::endl;

}


void PrintProcessListTitle(bool showFullPath) {

    // Print the header
    std::cout << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(5) << "Pid" << "   " << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::left << std::setw(20) << "Name" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(8) << "Pri" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(5) << "Thd" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(6) << "Hnd" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(10) << "Priv" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(15) << "CPU Time" << ANSI_TEXT_COLOR_RESET
        << ANSI_TEXT_COLOR_RED_BKGRND << std::right << std::setw(20) << "Elapsed Time" << ANSI_TEXT_COLOR_RESET;
    if (showFullPath) {
        std::cout << ANSI_TEXT_COLOR_RED_BKGRND << std::left << std::setw(36) << "   Command" << ANSI_TEXT_COLOR_RESET;
    }
    std::cout << std::endl;

}
