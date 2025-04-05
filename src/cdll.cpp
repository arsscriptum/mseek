
//==============================================================================
//
//     cdll.h : 
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================
 

#include "stdafx.h"
#include "cdll.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wtypes.h>

using namespace std;
#  pragma warning (disable : 4191)

// Platform-dependent DLL handle type definition
struct SDllHandle {
#if defined(PLATFORM_PC)
    HMODULE handle;
#elif defined(PLATFORM_LINUX)
    void* handle;
#endif
};

// Check flag bits
#define F_ISSET(mask) ((m_Flags & (mask)) == (mask))
// Clean up an all non-default bits in group if all bits are set
#define F_CLEAN_REDUNDANT(group) \
    if (F_ISSET(group)) m_Flags &= ~unsigned((group) & ~unsigned(fDefault))


CDll::CDll(const string& name, TFlags flags)
{
    m_Handle = nullptr;
    m_Name = name;
    m_Flags = flags;
}

CDll::CDll(const string& path, const string& name, TFlags flags)
{
    m_Handle = nullptr;
    m_Name = name;
    m_Flags = flags;
}

CDll::CDll(const string& name, ELoad when_to_load, EAutoUnload auto_unload,
    EBasename treate_as)
{
    m_Handle = nullptr;
    m_Name = name;
    m_Flags = TFlags(when_to_load) | TFlags(auto_unload) | TFlags(treate_as);
}

CDll::CDll(const string& path, const string& name, ELoad when_to_load,
    EAutoUnload auto_unload, EBasename treate_as)
{
    m_Handle = nullptr;
    m_Name = name;
    m_Flags = TFlags(when_to_load) | TFlags(auto_unload) | TFlags(treate_as);

}


CDll::~CDll()
{
    if (m_Handle) {
        delete m_Handle;
    }
    m_Handle = nullptr;
    
}


void CDll::Load(void)
{
    // DLL is already loaded
    if (m_Handle) {
        return;
    }

    UINT errMode = SetErrorMode(SEM_FAILCRITICALERRORS);
    HMODULE handle = LoadLibrary(m_Name.c_str());

    if (!handle) {
        return;
    }
    m_Handle = new SDllHandle;
    m_Handle->handle = handle;
}

CDll::TEntryPoint CDll::GetEntryPoint(const string& name)
{
    // If DLL is not yet loaded
    if (!m_Handle) {
        Load();
    }
   
    TEntryPoint entry;

    // Return address of entry (function or data)

    FARPROC ptr = GetProcAddress(m_Handle->handle, name.c_str());


    entry.func = (FEntryPoint)ptr;
    entry.data = ptr;
    return entry;
}
