//==============================================================================
//
//  memseek.cpp
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
#include "win32.h"
#include "cmdline.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <regex>    // <---- Include this
#include <cstdio>
#include <cstdarg>


bool g_ColoredOutput = false;
bool g_bSuppress = false;
bool g_forceNoColors = false;

typedef enum ESearchInput {
	ESINPUT_NOTSET,
	ESINPUT_STRING,
	ESINPUT_FILE,
	ESINPUT_REGEX,
} ESearchInputT;

typedef enum ESearchMode {
	ESEARCH_NOTSET,
	ESEARCH_PID,
	ESEARCH_PNAME
} ESearchModeT;

void usage(CmdlineParser* inputParser) {
#ifdef PLATFORM_WIN64
	std::string platform_str = "for 64 bits platform";
	std::string name_str = "mseek.exe";
#else
	std::string platform_str = "for 32 bits platform";
	std::string name_str = "mseek32.exe";
#endif
	logmsgn( "%s <-s string> <-p PID | -n PROCESSNAME | -i FILE> [<-x> [-b -a -z -o -t <image|mapped|private>]] [-x] [-q -c -h]\n", name_str.c_str());

	inputParser->DumpAllOptions();

	logmsgn( "\n");
	
}

void banner() {
	std::string verstr = mseek::version::GetAppVersion();
#ifdef PLATFORM_WIN64
	std::string platform_str = "for 64 bits platform";
	std::string name_str = "mseek.exe";
#else
	std::string platform_str = "for 32 bits platform";
	std::string name_str = "mseek32.exe";
#endif
	logmsgn("\n%s v%s - processes memory scan tool\n", name_str.c_str(), verstr.c_str());
#ifdef ENABLE_REGEX_SUPPORT
	logmsgn("regex support: enabled\n");
#else
    logmsgn("regex support: disabled\n");
#endif
	logmsgn("copyright (C) 1999-2023  Guillaume Plante\n");
	logmsgn("built on %s, %s\n\n", __TIMESTAMP__, platform_str.c_str());

}

bool IsRunningAsAdmin()
{
	BOOL isAdmin = FALSE;
	HANDLE hToken = nullptr;

	// Open the current process token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD dwSize = sizeof(TOKEN_ELEVATION);

		// Query elevation status
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
			isAdmin = elevation.TokenIsElevated;
		}

		CloseHandle(hToken);
	}

	return isAdmin == TRUE;
}


bool EnableSeImpersonatePrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	if (!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid)) {
		CloseHandle(hToken);
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return GetLastError() == ERROR_SUCCESS;
}

void exit_error(int errorCode, bool wait=false, const char* message = nullptr)
{
	if (message) {
		logerror("exit_error %d: %s\n", errorCode, message);
	}
	else {
		logerror("exit_error %d\n", errorCode);
	}
	
	if (wait) {
		Sleep(3000);
	}
	exit(errorCode);
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	bool  sleepOnExit = false;
	char	strLine[1024] = { 0 };
	DWORD	dwPID = 0;
	bool    outputToFile = false;
	FILE* fileStrings = NULL;

	DWORD dwSlipBefore = 0;
	DWORD dwSlipAfter = 0;

	ESearchModeT searchMode = ESEARCH_NOTSET;
	ESearchInputT searchInput = ESINPUT_NOTSET;
	EMemoryTypeT eMemoryTypeFilter = EMemoryType::EMEM_ALL;

	std::string afterBytes;
	std::string beforeBytes;
	std::string inputFile;
	std::string procName;
	std::string outputFile;
	std::string procID;
	std::string searchString;
	std::string memoryType;


#ifdef UNICODE
	char** argn = (char**)Convert::allocate_argnw(argc, argv);
#else
	char** argn = argv;
#endif // UNICODE

	CmdLineUtil::get()->initialize(argc, argn);

	CmdlineParser* inputParser = CmdLineUtil::get()->parser();

	
	SCmdlineOptValues optVerbose({ "-v", "--verbose" }, "verbose output", false, cmdlineOptTypes::Verbose);
	
	// Define options
	SCmdlineOptValues optAfter({ "-a", "--after" }, "Print this many bytes after the match in the hex dump (used with -x)", true, cmdlineOptTypes::After);
	SCmdlineOptValues optBefore({ "-b", "--before" }, "Print this many bytes before the match in the hex dump (used with -x)", true, cmdlineOptTypes::Before);
	SCmdlineOptValues optColor({ "-c", "--color" }, "Use colored output for better readability", false, cmdlineOptTypes::Color);
	SCmdlineOptValues optElevate({ "-e", "--elevate" }, "Elevate Privileges if required", false, cmdlineOptTypes::Elevate);
	SCmdlineOptValues optHelp({ "-h", "--help" }, "Show help message", false, cmdlineOptTypes::Help);
	SCmdlineOptValues optInputFile({ "-i", "--input" }, "Input file for search strings", true, cmdlineOptTypes::InputFile);
	SCmdlineOptValues optListAll({ "-l", "--list" }, "Search all processes for the string", false, cmdlineOptTypes::ListAll);
	SCmdlineOptValues optMemoryInfo({ "-m", "--meminfo" }, "Print Extended Memory Info", false, cmdlineOptTypes::MemoryInfo);
	SCmdlineOptValues optProcessName({ "-n", "--name" }, "Search specific process: use process name", true, cmdlineOptTypes::ProcName);
	SCmdlineOptValues optOutputFile({ "-o", "--out" }, "Output matching memory blocks to a file (used with -x)", true, cmdlineOptTypes::OutputFile);
	SCmdlineOptValues optProcessID({ "-p", "--pid" }, "Search specific process: use process ID", true, cmdlineOptTypes::ProcID);
	SCmdlineOptValues optQuiet({ "-q", "--quiet" }, "Quiet mode: suppress all but essential output", false, cmdlineOptTypes::Quiet);
	SCmdlineOptValues optRegex({ "-r", "--regex" }, "Interpret the search string as a regex pattern", false, cmdlineOptTypes::Regex);
	SCmdlineOptValues optSearchString({ "-s", "--string" }, "String to search for", true, cmdlineOptTypes::SearchString);
	SCmdlineOptValues optMemType({ "-t", "--type" }, "Filter memory regions by type: image, mapped, or private", true, cmdlineOptTypes::MemType);
	SCmdlineOptValues optUnicode({ "-u", "--unicode" }, "Unicode", false, cmdlineOptTypes::Unicode);
	SCmdlineOptValues optHexDump({ "-x", "--hexdump" }, "Dump memory as hex when a match is found", false, cmdlineOptTypes::HexDump);
	SCmdlineOptValues optPrintableOnly({ "-z", "--textdump" }, "Output only printable ASCII characters from the matched memory", false, cmdlineOptTypes::PrintableOnly);

	// Add options to the parser
	inputParser->addOption(optAfter);
	inputParser->addOption(optBefore);
	inputParser->addOption(optColor);
	inputParser->addOption(optHelp);
	inputParser->addOption(optElevate);
	inputParser->addOption(optMemoryInfo);
	
	
	inputParser->addOption(optInputFile);
	inputParser->addOption(optListAll);
	inputParser->addOption(optProcessName);
	inputParser->addOption(optOutputFile);
	inputParser->addOption(optProcessID);
	inputParser->addOption(optQuiet);
	inputParser->addOption(optRegex);
	inputParser->addOption(optSearchString);
	inputParser->addOption(optMemType);
	inputParser->addOption(optHexDump);
	inputParser->addOption(optPrintableOnly);
	inputParser->addOption(optUnicode);
	inputParser->addOption(optVerbose);

	// Evaluate options
	bool showHelp = inputParser->isSet(optHelp);

	g_ColoredOutput = inputParser->isSet(optColor);
	g_bSuppress = inputParser->isSet(optQuiet);

	bool listAll = inputParser->isSet(optListAll);
	bool bDumpHex = inputParser->isSet(optHexDump);
	bool printableOnly = inputParser->isSet(optPrintableOnly);
	bool useRegex = inputParser->isSet(optRegex);
	bool isVerboseMode = inputParser->isSet(optVerbose);
	bool isUnicodeMode = inputParser->isSet(optUnicode);
	bool bElevatePrivileges = inputParser->isSet(optElevate);
	bool extMemInfo = inputParser->isSet(optMemoryInfo);

	if (inputParser->get_option_argument(optAfter, afterBytes)) {
		dwSlipAfter = atoi(afterBytes.c_str());
	}
	
	if (inputParser->get_option_argument(optBefore, beforeBytes)) {
		dwSlipBefore = atoi(beforeBytes.c_str());
	}
	
	
	if (inputParser->get_option_argument(optInputFile, inputFile)) {
		searchInput = ESINPUT_FILE;
	}
	
	
	if (inputParser->get_option_argument(optProcessName, procName)) {
		searchMode = ESEARCH_PNAME;
	}
	
	if (inputParser->get_option_argument(optOutputFile, outputFile)) {
		outputToFile = true;
		if (!bDumpHex) {
			logerror(" -o needs to be used with -x!\n");
			return -1;
		}

		// Try to open the file in append mode (creates if it doesn't exist)
		FILE* testFile = fopen(outputFile.c_str(), "a");
		if (testFile == NULL) {
			logerror(" Failed to create output file '%s'\n", outputFile.c_str());
			return -1;
		}
		else {
			fclose(testFile); // Close it, will reopen properly elsewhere
		}
	}
	
	if (inputParser->get_option_argument(optProcessID, procID)) {
		searchMode = ESEARCH_PID;
		dwPID = atoi(procID.c_str());
	}
	
	if (inputParser->get_option_argument(optSearchString, searchString)) {
		searchInput = ESINPUT_STRING;
	}
	
	if (inputParser->get_option_argument(optMemType, memoryType)) {
		eMemoryTypeFilter = GetMemoryTypeFromString(memoryType);
	}


	if (!g_bSuppress) { 
		banner();
	}

	if (showHelp) {
		usage(inputParser);
		return 0;
	}
	
	if (!IsRunningAsAdmin()) {
		if (bElevatePrivileges) {
			EnableSeImpersonatePrivilege();
			char** argn = (char**)C::Convert::allocate_argn(argc, argv);
			C::Process::ElevateNow(argc, argn, NULL);
			//C::Process::LaunchElevatedAndCapture(argc, argn, NULL);
			return 0;
		}
		else {
			logwarn("user doesn't have administrator privileges. some process are not accessible!\n");
		}
		
	}
	else {
		logmsg("execution with administrator privileges!\n");
		// running as admin
		if (bElevatePrivileges) {
			logwarn("execution with administrator privileges, user specified '-e' : automatic elevation detected!\n");
			logmsg("sleeping 5 seconds on program exit\n");
			g_ColoredOutput = false;
			g_forceNoColors = true;
			sleepOnExit = true;
		}
	}

	if (g_bSuppress && isVerboseMode) {
		logmsg("Warning: Quiet and Verbose: Verbose superceed Quiet...\n");
		g_bSuppress = false;
	}
	
	if (searchInput == ESINPUT_NOTSET) {
		logerror("Must use either -s (search string) or -i (file input)\n");
		usage(inputParser);
		exit_error(-1, sleepOnExit);
	}

	CMemUtils::Get().Initialize(bDumpHex, printableOnly,g_bSuppress, dwSlipBefore, dwSlipAfter, extMemInfo);


#ifdef _DEBUG_CMDLINE
	std::ostringstream dbg_output;
	inputParser->dump_tokens(dbg_output);
	std::cout << std::endl << "[DEBUG] dump_tokens " << dbg_output.str() << std::endl << std::endl;

	// Dump each option's state
	optAfter.dump_options(dbg_output);
	optBefore.dump_options(dbg_output);
	optColor.dump_options(dbg_output);
	optHelp.dump_options(dbg_output);
	optInputFile.dump_options(dbg_output);
	optListAll.dump_options(dbg_output);
	optProcessName.dump_options(dbg_output);
	optOutputFile.dump_options(dbg_output);
	optProcessID.dump_options(dbg_output);
	optQuiet.dump_options(dbg_output);
	optRegex.dump_options(dbg_output);
	optSearchString.dump_options(dbg_output);
	optMemType.dump_options(dbg_output);
	optHexDump.dump_options(dbg_output);
	optPrintableOnly.dump_options(dbg_output);

	std::cout << "[DEBUG] " << dbg_output.str() << std::endl;

	// Debug print boolean states (assuming you've parsed these earlier)
	logmsg("quietMode %d", quietMode ? 1 : 0);
	logmsg("showHelp %d", showHelp ? 1 : 0);
	logmsg("isVerboseMode %d", isVerboseMode ? 1 : 0);
	logmsg("g_ColoredOutput %d", g_ColoredOutput ? 1 : 0);
	logmsg("listAll %d", listAll ? 1 : 0);
	logmsg("hexDump %d", hexDump ? 1 : 0);
	logmsg("printableOnly %d", printableOnly ? 1 : 0);
	logmsg("useRegex %d", useRegex ? 1 : 0);

	// For string-valued options, print their value (only if set, if needed)
	if (!afterBytes.empty())       logmsg("afterBytes = %s", afterBytes.c_str());
	if (!beforeBytes.empty())      logmsg("beforeBytes = %s", beforeBytes.c_str());
	if (!inputFile.empty())        logmsg("inputFile = %s", inputFile.c_str());
	if (!procName.empty())         logmsg("procName = %s", procName.c_str());
	if (!outputFile.empty())       logmsg("outputFile = %s", outputFile.c_str());
	if (!procID.empty())           logmsg("procID = %s", procID.c_str());
	if (!searchString.empty())     logmsg("searchString = %s", searchString.c_str());
	if (!memoryType.empty())       logmsg("memoryType = %s", memoryType.c_str());

#endif

	CMemUtils::Get().EnableDebugPrivilege(GetCurrentProcess());


	if (searchMode == ESEARCH_PNAME) {
		logmsg( "validating process name \"%s\"\n", procName.c_str());
		DWORD foundPid = 0;
		bool processFound = CMemUtils::Get().GetProcessPidFromName(procName, foundPid);
		if (!processFound) {
			logerror("cannot find process \"%s\"\n", procName.c_str());
			exit_error(-1, sleepOnExit);
		}
		else {
			logmsg("found process %s: pid %d\n", procName.c_str(), foundPid);
			
			logmsg("checkng VM_READ access on process \"%s\" ( id %d )\n", procName.c_str(), foundPid);
			if (!CMemUtils::Get().HasVMReadAccess(foundPid)) {
				logerror("permission error! no VM_READ access on process \"%s\" ( id %d )\n", procName.c_str(), foundPid);
				logerror("restart as admin, or try - e argument\n");
				exit_error(-1, sleepOnExit);
			}
			else {
				dwPID = foundPid;
				searchMode = ESEARCH_PID;
			}
		}
	}
	else if ( (searchMode == ESEARCH_PID) && (dwPID != 0)) {
		logmsg( "validating process id %d\n", dwPID);
		bool processFound = CMemUtils::Get().GetProcessNameFromPID(dwPID, procName);
		if (!processFound) {
			logerror("cannot find process with id %d\n", dwPID);
			exit_error(-1, sleepOnExit);
		}
		logmsg("checking VM_READ access on process \"%s\" (pid %d) \n", procName.c_str(), dwPID);
		if (!CMemUtils::Get().HasVMReadAccess(dwPID)) {
			logerror("permission error! no VM_READ access on process \"%s\" ( id %d )\n", procName.c_str(), dwPID);
			logerror("restart as admin, or try - e argument\n");
			exit_error(-1, sleepOnExit);
		}
	}
	else {
		logerror( " Must search by process name or process id.\n");
		exit_error(-1, sleepOnExit);// or handle error appropriately
	}



	if ((searchMode == ESEARCH_PID) && (dwPID != 0)) {
		logmsg("scanning process id %d (%s)\n", dwPID, procName.c_str());
	}
	else {
		logerror("ERROR: Not Specified process to search in!\n");
		exit_error(-1, sleepOnExit);// or handle error appropriately
	}


	if (bDumpHex) {
		if (printableOnly) {
			logmsg("dumping readable text in memory\n");
		}else{
			logmsg("dumping hexadecimal memory data\n");
		}
		if (dwSlipBefore > 0) {
			logmsg("Will print %d bytes before hit\n", dwSlipBefore);
		}
		if (dwSlipAfter > 0) {
			logmsg("Will print %d bytes after hit\n", dwSlipAfter);
		}
		if (!dwSlipBefore && !dwSlipAfter) {
			logwarn("using -x to dump data but no byte set with -a or -b\n");
		}
	}
	else {
		if (printableOnly) {
			logerror(" -z needs to be used with -x!\n");
			return -1;
		}
		if (dwSlipBefore > 0) {
			logerror(" -b needs to be used with -x!\n");
			return -1;
		}
		if (dwSlipAfter > 0) {
			logerror(" -a needs to be used with -x!\n");
			return -1;
		}
	}

	FilterParameters filter(
		true,                    // bASCII
		isUnicodeMode,           // bUNICODE
		searchString.c_str(),               // strString
		printableOnly,            // bReadable
		outputFile.c_str(),          // strOutFileName (optional)
		false,                   // bFileOpenForWriting (default, as before)
		eMemoryTypeFilter,       // etypeFilter
		useRegex                // bIsRegexPattern
	);

	int numHits = 0;
	if (searchInput == ESINPUT_STRING){
		logmsg( "searching pattern '%s'\n", searchString.c_str());
		
		numHits = CMemUtils::Get().SearchProcessMemory(dwPID,filter, outputToFile, outputFile);
		logsuccess("found %d hits for %s\n", numHits, filter.strString);
		
	}else if(searchInput == ESINPUT_FILE) {
	
		logmsg("looking in input file \"%s\"\n",inputFile.c_str());
		fileStrings = _tfopen(inputFile.c_str(),"r");
		while ( fgets ( strLine, sizeof strLine, fileStrings ) != NULL ) 
		{
			while ((strLine[strlen(strLine)-1] == '\n') ||  (strLine[strlen(strLine)-1] == '\r'))  {
				logmsg("trailing new line\n");
				strLine[strlen(strLine)-1] = '\0';
			}

			logmsg("searching pattern '%s' from \"%s\"\n",strLine,inputFile.c_str());
			filter.strString = strLine;
			numHits += CMemUtils::Get().SearchProcessMemory(dwPID,filter, outputToFile, outputFile);
			logsuccess("found %d hits for \"%s\"\n", numHits, strLine);
		}
		fclose ( fileStrings );
	}else{
		if(!g_bSuppress) logerror("Unknown error!\n");
		exit_error(-1, sleepOnExit);
	}

	if (sleepOnExit) {
		Sleep(5000);
	}
	
	
	return 0;
}

