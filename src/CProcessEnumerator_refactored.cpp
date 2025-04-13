// Refactored CProcessEntry using smart pointers

#include <memory>
#include <vector>
#include <string>
#include <Windows.h>
#include <psapi.h>

class CProcessEnumerator {
public:
    struct CModuleEntry {
        std::unique_ptr<TCHAR[]> lpFilename;
        std::unique_ptr<TCHAR[]> szModuleName;
        PVOID pLoadBase = nullptr;
        PVOID pPreferredBase = nullptr;
        MODULEENTRY32 win32ModuleEntry = { 0 };

        CModuleEntry() {
            lpFilename = std::make_unique<TCHAR[]>(MAX_PATH);
            szModuleName = std::make_unique<TCHAR[]>(MAX_PATH);
        }

        CModuleEntry(const CModuleEntry& e) {
            lpFilename = std::make_unique<TCHAR[]>(MAX_PATH);
            szModuleName = std::make_unique<TCHAR[]>(MAX_PATH);
            _tcsncpy(lpFilename.get(), e.lpFilename.get(), MAX_PATH - 1);
            _tcsncpy(szModuleName.get(), e.szModuleName.get(), MAX_PATH - 1);
            pLoadBase = e.pLoadBase;
            pPreferredBase = e.pPreferredBase;
            memcpy(&win32ModuleEntry, &e.win32ModuleEntry, sizeof(win32ModuleEntry));
        }
    };

    struct CThreadEntry {
        DWORD th32ThreadID = 0;
        DWORD th32OwnerProcessID = 0;
        THREADENTRY32 win32ThreadEntry = { 0 };

        CThreadEntry() = default;
        CThreadEntry(const CThreadEntry& e) {
            th32ThreadID = e.th32ThreadID;
            th32OwnerProcessID = e.th32OwnerProcessID;
            memcpy(&win32ThreadEntry, &e.win32ThreadEntry, sizeof(win32ThreadEntry));
        }
    };

    struct CProcessEntry {
        std::unique_ptr<TCHAR[]> lpFilename;
        DWORD dwPID = 0;
        WORD hTask16 = 0;

        std::vector<std::unique_ptr<CModuleEntry>> ModulesEntries;
        std::vector<std::unique_ptr<CThreadEntry>> ThreadEntries;

        CProcessEntry() {
            lpFilename = std::make_unique<TCHAR[]>(MAX_PATH);
            ZeroMemory(lpFilename.get(), MAX_PATH * sizeof(TCHAR));
        }

        CProcessEntry(const CProcessEntry& e) {
            lpFilename = std::make_unique<TCHAR[]>(MAX_PATH);
            _tcsncpy(lpFilename.get(), e.lpFilename.get(), MAX_PATH - 1);
            dwPID = e.dwPID;
            hTask16 = e.hTask16;

            for (const auto& mod : e.ModulesEntries) {
                ModulesEntries.push_back(std::make_unique<CModuleEntry>(*mod));
            }
            for (const auto& thr : e.ThreadEntries) {
                ThreadEntries.push_back(std::make_unique<CThreadEntry>(*thr));
            }
        }

        void AddModule(std::unique_ptr<CModuleEntry> mod) {
            ModulesEntries.push_back(std::move(mod));
        }

        void AddThread(std::unique_ptr<CThreadEntry> thr) {
            ThreadEntries.push_back(std::move(thr));
        }
    };

    std::vector<std::unique_ptr<CProcessEntry>> ProcessEntries;

    std::vector<std::unique_ptr<CProcessEntry>> GetCopiedProcessEntries() const {
        std::vector<std::unique_ptr<CProcessEntry>> copy;
        for (const auto& entry : ProcessEntries) {
            copy.push_back(std::make_unique<CProcessEntry>(*entry));
        }
        return copy;
    }

    unsigned long Process(void* parameter) {
        ProcessEntries.clear();
        CProcessEntry psEntry;
        threadStarted = true;
        _currentState = ESTATE_RUNNING;
        BOOL result_process = GetProcessFirst(&psEntry);
        while (result_process == TRUE) {
            psEntry.GetProcessInformation();
            psEntry.DetectPlatform();

            DWORD pid = psEntry.dwPID;
            CModuleEntry moduleEntry;
            CThreadEntry threadEntry;
            auto newProccessEntry = std::make_unique<CProcessEntry>(psEntry);

            BOOL result_module = GetModuleFirst(pid, &moduleEntry);
            while (result_module == TRUE) {
                auto newModuleEntry = std::make_unique<CModuleEntry>(moduleEntry);
                newProccessEntry->AddModule(std::move(newModuleEntry));
                result_module = GetModuleNext(pid, &moduleEntry);
            }

#ifdef LIST_PROCESS_THREADS
            BOOL result_thread = GetThreadFirst(pid, &threadEntry);
            while (result_thread == TRUE) {
                auto newThreadEntry = std::make_unique<CThreadEntry>(threadEntry);
                newProccessEntry->AddThread(std::move(newThreadEntry));
                result_thread = GetThreadNext(pid, &threadEntry);
            }
#endif // LIST_PROCESS_THREADS

            ProcessEntries.push_back(std::move(newProccessEntry));
            result_process = GetProcessNext(&psEntry);
        }

        _currentState = ESTATE_DONE;
        threadExited = true;
        return 0;
    }

private:
    bool threadStarted = false;
    bool threadExited = false;
    enum ECurrentState { ESTATE_IDLE, ESTATE_RUNNING, ESTATE_DONE } _currentState = ESTATE_IDLE;
};
