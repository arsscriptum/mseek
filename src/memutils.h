//==============================================================================
//
//  memutils.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#ifndef __MEMUTILS_H__
#define __MEMUTILS_H__

#include <map>
#include <vector>


typedef std::map<DWORD, std::vector<uintptr_t>> SearchResultsMap;

typedef enum EMemoryType {
	EMEM_UNKNOWN,
	EMEM_PRIVATE,
	EMEM_MAPPED,
	EMEM_IMAGE,
	EMEM_ALL
} EMemoryTypeT;

EMemoryTypeT GetMemoryTypeFromString(const std::string& strInput);

typedef struct _FilterParameters {
    bool bASCII;
    bool bUNICODE;
    const char* strString;
    bool bReadable;
    const char* strOutFileName;
    bool bFileOpenForWriting;
    EMemoryType etypeFilter;
    bool bIsRegexPattern;
    int resultsFilterIndex;
    ULONG_PTR resultsFilterMemoryAddress;
    // Default constructor
    _FilterParameters() {
        default_();
    }

    // Constructor with parameters
    _FilterParameters(bool ascii, bool unicode, const char* searchStr, bool readable, const char* outFile, bool fileWrite, EMemoryType typeFilter, bool isRegex, int filterIndex, ULONG_PTR filterMemAddress)
        : bASCII(ascii),
        bUNICODE(unicode),
        strString(searchStr),
        bReadable(readable),
        strOutFileName(outFile),
        bFileOpenForWriting(fileWrite),
        etypeFilter(typeFilter),
        resultsFilterIndex(filterIndex),
        resultsFilterMemoryAddress(filterMemAddress),
        bIsRegexPattern(isRegex)
    {}

    // Function to reset to default values
    void default_() {
        bASCII = true;
        bUNICODE = true;
        strString = nullptr;
        bReadable = true;
        strOutFileName = nullptr;
        bFileOpenForWriting = false;
        etypeFilter = EMEM_UNKNOWN;
        resultsFilterIndex = -1;
        resultsFilterMemoryAddress = 0;
        bIsRegexPattern = false;
    }

} FilterParameters;

class CMemUtils {
public:
    


    // Singleton access method
    static CMemUtils& Get() {
        static CMemUtils instance;
        return instance;
    }

    void Initialize(bool dumpHex, bool printableOnly, bool suppress, DWORD slipBefore, DWORD slipAfter,bool memInfo);

    // Public API
    void SearchInAllProcess(FilterParameters filter, bool enableOutputToFile, std::string outputFilePath);
    EMemoryType GetMemType(MEMORY_BASIC_INFORMATION memMeminfo);
    void PrintMemInfo(MEMORY_BASIC_INFORMATION memMeminfo);
    
    bool SearchProcessMemory(DWORD pid, FilterParameters filter, bool enableOutputToFile, std::string outputFilePath);
    void WriteHexOut(unsigned char* buf, int size, FILE* out);
    DWORD FindProcessWithDll(const std::string& dllName);
    int RunTest(std::string dllName);
    std::string GenerateAndCreateUniqueDumpFile(std::string dllName);
    HMODULE GetModuleHandleInRemoteProcess(HANDLE hProcess, const std::string& dllName);
    void ReadMemoryRegion(std::string dllName,HANDLE hProcess, LPCVOID baseAddress, SIZE_T size);
    void ReadDllMemory(const char* processName, const char* dllName);
    DWORD FindProcessId(const char* processName);
    void ListLoadedDlls(DWORD pid);


    bool GetProcessNameFromPID(DWORD pid, TCHAR* buffer, DWORD bufferSize);
    bool GetProcessNameFromPID(DWORD pid, std::string& processName);
    bool HasVMReadAccess(DWORD pid);
    bool EnableDebugPrivilege();
    bool EnableDebugPrivilege(HANDLE hProcess);
    bool HasVMReadAccessElevated(DWORD pid);
    bool GetProcessPidFromName(std::string processName, DWORD& pid);
    void ResetSearchResults();
    int GetTotalMatchesCount() { return _totalMatches;  }
    void ClearSearchResults() { _searchResults.clear(); }
    const SearchResultsMap& GetSearchResults() const {
        return _searchResults;
    }


    

    
private:
    // Private constructor/destructor
    CMemUtils()
        : _DumpFile(nullptr),
        _DumpHex(false),
        _Suppress(false),
        _FileOpenForWriting(false),
        _PrintableOnly(false),
        _PrintMemoryInfo(false),
        _SlipBefore(0),
        _totalMatches(0),
        _partialMemoryReads(0),
        _SlipAfter(0)
    {}
    ~CMemUtils() = default;

    // Delete copy/move constructors and assignments
    CMemUtils(const CMemUtils&) = delete;
    CMemUtils& operator=(const CMemUtils&) = delete;
    CMemUtils(CMemUtils&&) = delete;
    CMemUtils& operator=(CMemUtils&&) = delete;

    void PrintMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& mbi);
    bool ScanMemory(DWORD pid, SIZE_T szSize, ULONG_PTR lngAddress, HANDLE hProcess, MEMORY_BASIC_INFORMATION memMeminfo, FilterParameters filter);

    // Member variables
    FILE*  _DumpFile;
    bool   _DumpHex;
    bool   _Suppress;
    DWORD  _SlipBefore;
    DWORD  _SlipAfter;
    bool _FileOpenForWriting;
    bool _PrintableOnly;
    bool _PrintMemoryInfo;
    unsigned int _totalMatches;
    unsigned int _partialMemoryReads;
    SearchResultsMap _searchResults;
};

#endif