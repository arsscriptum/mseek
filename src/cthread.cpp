
//==============================================================================
//
//   cthread.cpp
//
//==============================================================================
//  cybercastor - made in quebec 2020 <cybercastor@icloud.com>
//==============================================================================

#include "stdafx.h"
#include "cthread.h"
#include "log.h"



char CThread::threadIdentifier[MAX_PATH];



CThread::CThread ()
{
	LOG_PROFILE("CThread::CThread");
	LOG_TRACE("CThread::CThread", "CThread Instance Creation");
	this->hThread		= NULL;
	this->hThreadId		= 0;
	this->hMainThread	= ::GetCurrentThread ();
	this->hMainThreadId = ::GetCurrentThreadId ();
	this->Timeout		= 2000; //milliseconds
	memset(threadIdentifier, 0, MAX_PATH);

	LOG_TRACE("CThread::CThread", "        0x%.8X", this->hMainThread);
	LOG_TRACE("CThread::CThread", "        0x%.8X", this->hMainThreadId);
	LOG_TRACE("CThread::CThread", "timeout  %d ms", this->Timeout);
}


CThread::CThread(const char *id)
{
	LOG_PROFILE("CThread::CThread");
	LOG_TRACE("CThread::CThread", "CThread Instance Creation");
	this->hThread = NULL;
	this->hThreadId = 0;
	this->hMainThread = ::GetCurrentThread();
	this->hMainThreadId = ::GetCurrentThreadId();
	this->Timeout = 2000; //milliseconds
	memset(threadIdentifier, 0, MAX_PATH);
	strncpy(threadIdentifier, id, MAX_PATH - 1);
	LOG_TRACE("CThread::CThread", "        0x%.8X", this->hMainThread);
	LOG_TRACE("CThread::CThread", "        0x%.8X", this->hMainThreadId);
	LOG_TRACE("CThread::CThread", "timeout  %d ms", this->Timeout);
}


CThread::~CThread ()
{
	//waiting for the thread to terminate
	if (this->hThread) {
		if (::WaitForSingleObject(this->hThread, this->Timeout) == WAIT_TIMEOUT) {
			LOG_TRACE("CThread::~CThread", "WaitForSingleObject: timed out at %d ms", this->Timeout);
		}
		LOG_TRACE("CThread::~CThread", "TerminateThread");
		::TerminateThread (this->hThread, 1);
		LOG_TRACE("CThread::~CThread", "CloseHandle");
		::CloseHandle (this->hThread);
	}
}


unsigned long CThread::Process (void* parameter)
{
	LOG_TRACE("CThread::Process", "[%s]", this->threadIdentifier);
	//a mechanism for terminating thread should be implemented
	//not allowing the method to be run from the main thread
	if (::GetCurrentThreadId () == this->hMainThreadId)
		return 0;
	else {

		return 0;
	}

}


bool CThread::CreateThread ()
{
	LOG_TRACE("CThread::CreateThread", "CreateThread");
	LOG_TRACE("CThread::CreateThread", "[%s]", this->threadIdentifier);
	if (!this->IsCreated ()) {
		param*	this_param = new param;
		this_param->pThread	= this;
		this->hThread = ::CreateThread (NULL, 0, (unsigned long (__stdcall *)(void *))this->runProcess, (void *)(this_param), 0, &this->hThreadId);
		LOG_TRACE("CThread::CreateThread", "Thread created: %s", this->hThread ? "yes" : "no");
		return this->hThread ? true : false;
		
	}
	else {
		LOG_ERROR("CThread::CreateThread", "Thread ALREADY CREATED");
	}
	return false;

}


int CThread::runProcess (void* Param)
{

	LOG_TRACE("CThread::runProcess", "[%s] runProcess", threadIdentifier);
	CThread*	thread;
	thread			= (CThread*)((param*)Param)->pThread;
	delete	((param*)Param);
	return thread->Process (0);
}
