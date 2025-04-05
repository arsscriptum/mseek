//==============================================================================
//
//  memutils.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


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

    // Default constructor
    _FilterParameters() {
        default_();
    }

    // Constructor with parameters
    _FilterParameters(bool ascii, bool unicode, const char* searchStr, bool readable, const char* outFile, bool fileWrite, EMemoryType typeFilter, bool isRegex)
        : bASCII(ascii),
        bUNICODE(unicode),
        strString(searchStr),
        bReadable(readable),
        strOutFileName(outFile),
        bFileOpenForWriting(fileWrite),
        etypeFilter(typeFilter),
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
    void SearchInAllProcess(bool bUseRegex, bool bReadable, bool bASCII, bool bUNICODE, const char* strString, bool outputToFile, std::string outputFile);
    EMemoryType GetMemType(MEMORY_BASIC_INFORMATION memMeminfo);
    void PrintMemInfo(MEMORY_BASIC_INFORMATION memMeminfo);
    
    int SearchProcessMemory(DWORD pid, FilterParameters filter, bool outputToFile, std::string outputFile);
    void WriteHexOut(unsigned char* buf, int size, FILE* out);

    bool GetProcessNameFromPID(DWORD pid, TCHAR* buffer, DWORD bufferSize);
    bool GetProcessNameFromPID(DWORD pid, std::string& processName);
    bool HasVMReadAccess(DWORD pid);
    bool EnableDebugPrivilege();
    bool EnableDebugPrivilege(HANDLE hProcess);
    bool HasVMReadAccessElevated(DWORD pid);
    bool GetProcessPidFromName(std::string processName, DWORD& pid);
    
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
        _SlipAfter(0)
    {}
    ~CMemUtils() = default;

    // Delete copy/move constructors and assignments
    CMemUtils(const CMemUtils&) = delete;
    CMemUtils& operator=(const CMemUtils&) = delete;
    CMemUtils(CMemUtils&&) = delete;
    CMemUtils& operator=(CMemUtils&&) = delete;

    void PrintMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& mbi);
    int ScanMemory(DWORD pid, SIZE_T szSize, ULONG_PTR lngAddress, HANDLE hProcess, MEMORY_BASIC_INFORMATION memMeminfo, FilterParameters filter);

    // Member variables
    FILE*  _DumpFile;
    bool   _DumpHex;
    bool   _Suppress;
    DWORD  _SlipBefore;
    DWORD  _SlipAfter;
    bool _FileOpenForWriting;
    bool _PrintableOnly;
    bool _PrintMemoryInfo;
};
