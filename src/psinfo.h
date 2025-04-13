#ifndef ProcessInfo_h
#define ProcessInfo_h

#ifdef _WIN32
#include <windows.h>
#endif

class ProcessInfo
{
public:
	ProcessInfo(unsigned int iProcessId);
	~ProcessInfo() throw();

	unsigned int GetProcessId();
	unsigned long long GetProcessUptime();
	double GetProcessCPUUsage();
	double GetProcessMemoryUsed();
	unsigned long GetProcessThreadCount();

private:
	unsigned int mProcessId;
#ifdef _WIN32
	int mNumOfProcessors; // numbre of processors
	ULARGE_INTEGER mCreationTime; // process creation time
	ULARGE_INTEGER mPrevSystemTime; // previously measured system time
	ULARGE_INTEGER mPrevKernelTime; // amount of time ran in kernel mode
	ULARGE_INTEGER mPrevUserTime; // amount of time ran in user mode
#elif defined(linux)
	long mJiffiesPerSecond;
	unsigned long long mStartTimeSinceBoot;
	unsigned long long mPrevSystemTime;
	unsigned long long mPrevUserTime;
	unsigned long long mPrevKernelTime;
#endif
};

#endif