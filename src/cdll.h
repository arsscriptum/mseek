
//==============================================================================
//
//     cdll.h : Define class for portable Dll handling.
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================
 
#ifndef __CDLL_H__
#define __CDLL_H__

#include "stdafx.h"
#include <iostream>
#include <string>
#include <process.h>

// Forward declaration of struct containing OS-specific DLL handle.
struct SDllHandle;



/////////////////////////////////////////////////////////////////////////////
///
/// CDll --
///
/// Define class for portable Dll handling.
///
/// The DLL name is considered the basename if it does not contain embedded
/// '/', '\', or ':' symbols. Also, in this case, if the DLL name does not
/// start with NCBI_PLUGIN_PREFIX and contain NCBI_PLUGIN_MIN_SUFFIX (and if
/// eExactName flag not passed to the constructor), then it will be
/// automatically transformed according to the following rule:
///   <name>  --->  NCBI_PLUGIN_PREFIX + <name> + NCBI_PLUGIN_SUFFIX
///
///  If the DLL is specified by its basename, then it will be searched
///  (after the transformation described above) in the following locations:
///
///    UNIX:
///      1) the directories that are listed in the LD_LIBRARY_PATH environment
///         variable (analyzed once at the process startup);
///      2) the directory from which the application loaded;
///      3) hard-coded (e.g. with `ldconfig' on Linux) paths.
///
///    MS Windows:
///      1) the directory from which the application is loaded;
///      2) the current directory; 
///      3) the Windows system directory;
///      4) the Windows directory;
///      5) the directories that are listed in the PATH environment variable.
///
/// NOTE: All methods of this class except the destructor throw exception
/// CCoreException::eDll on error.

class CDll
{
public:
    /// General flags.
    ///
    /// Default flag in each group have priority above non-default,
    /// if they are used together.
    enum EFlags {
        /// When to load DLL
        fLoadNow = (1 << 1),  ///< Load DLL immediately in the constructor
        fLoadLater = (1 << 2),  ///< Load DLL later, using method Load()
        /// Whether to unload DLL in the destructor
        fAutoUnload = (1 << 3),  ///< Unload DLL in the destructor
        fNoAutoUnload = (1 << 4),  ///< Unload DLL later, using method Unload()
        /// Whether to transform the DLL basename
        fBaseName = (1 << 5),  ///< Treat the name as DLL basename
        fExactName = (1 << 6),  ///< Use the name "as is"
        /// Specify how to load symbols from DLL.
        /// UNIX specific (see 'man dlopen'), ignored on all other platforms.
        fGlobal = (1 << 7),  ///< Load as RTLD_GLOBAL
        fLocal = (1 << 8),  ///< Load as RTLD_LOCAL
        /// Default flags
        fDefault = fLoadNow | fNoAutoUnload | fBaseName | fGlobal
    };
    typedef unsigned int TFlags;  ///< Binary OR of "EFlags"

    //
    // Enums, retained for backward compatibility
    //

    /// When to load DLL.
    enum ELoad {
        eLoadNow = fLoadNow,
        eLoadLater = fLoadLater
    };

    /// Whether to unload DLL in the destructor.
    enum EAutoUnload {
        eAutoUnload = fAutoUnload,
        eNoAutoUnload = fNoAutoUnload
    };

    /// Whether to transform the DLL basename.
    ///
    /// Transformation is done according to the following:
    ///   <name>  --->  NCBI_PLUGIN_PREFIX + <name> + NCBI_PLUGIN_SUFFIX
    enum EBasename {
        eBasename = fBaseName,
        eExactName = fExactName
    };

    /// Constructor.
    ///
    /// @param name
    ///   Can be either DLL basename or an absolute file path.
    /// @param flags
    ///   Define how to load/unload DLL and interpret passed name.
    /// @sa
    ///   Basename discussion in CDll header, EFlags
    CDll(const std::string& name, TFlags flags);

    /// Constructor (for backward compatibility).
    ///
    /// @param name
    ///   Can be either DLL basename or an absolute file path.
    /// @param when_to_load
    ///   Choice to load now or later using Load().
    /// @param auto_unload
    ///   Choice to unload DLL in destructor.
    /// @param treat_as
    ///   Choice to transform the DLL base name.
    /// @sa
    ///   Basename discussion in CDll header,
    ///   ELoad, EAutoUnload, EBasename definition.

     CDll(const std::string& name,
            ELoad         when_to_load = eLoadNow,
            EAutoUnload   auto_unload = eNoAutoUnload,
            EBasename     treate_as = eBasename);

    /// Constructor.
    ///
    /// The absolute file path to the DLL will be formed using the "path"
    /// and "name" parameters in the following way:
    /// - UNIX:   <path>/PFX<name>SFX ; <path>/<name> if "name" is not basename
    /// - MS-Win: <path>\PFX<name>SFX ; <path>\<name> if "name" is not basename
    /// where PFX is NCBI_PLUGIN_PREFIX and SFX is NCBI_PLUGIN_SUFFIX.
    ///
    /// @param path
    ///   Path to DLL.
    /// @param name
    ///   Name of DLL.
    /// @param flags
    ///   Define how to load/unload DLL and interpret passed name.
    /// @sa
    ///   Basename discussion in CDll header, EFlags
        CDll(const std::string& path, const std::string& name, TFlags flags);

    /// Constructor (for backward compatibility).
    ///
    /// The absolute file path to the DLL will be formed using the "path"
    /// and "name" parameters in the following way:
    /// - UNIX:   <path>/PFX<name>SFX ; <path>/<name> if "name" is not basename
    /// - MS-Win: <path>\PFX<name>SFX ; <path>\<name> if "name" is not basename
    /// where PFX is NCBI_PLUGIN_PREFIX and SFX is NCBI_PLUGIN_SUFFIX.
    ///
    /// @param path
    ///   Path to DLL.
    /// @param name
    ///   Name of DLL.
    /// @param when_to_load
    ///   Choice to load now or later using Load().
    /// @param auto_load
    ///   Choice to unload DLL in destructor.
    /// @param treat_as
    ///   Choice to transform the DLL base name.
    /// @sa
    ///   Basename discussion in CDll header,
    ///   ELoad, EAutoUnload, EBasename definition.

        CDll(const std::string& path, const std::string& name,
            ELoad         when_to_load = eLoadNow,
            EAutoUnload   auto_unload = eNoAutoUnload,
            EBasename     treate_as = eBasename);

    /// Destructor.
    ///
    /// Unload DLL if constructor was passed "eAutoUnload".
    /// Destructor does not throw any exceptions.
    ~CDll(void);

    /// Load DLL.
    ///
    /// Load the DLL using the name specified in the constructor's DLL "name".
    /// If Load() is called more than once without calling Unload() in between,
    /// then it will do nothing.
    ///
    /// @note If the DLL links against the core "xncbi" library, loading it may
    /// result in reinvoking static initializers, with potential consequences
    /// ranging from having to retune diagnostic settings to crashing at exit.
    /// This problem could theoretically also affect other libraries linked
    /// from both sides, but they haven't been an issue in practice.  It can
    /// help for both the program and the DLL to link "xncbi" dynamically, but
    /// in some configurations that change still isn't entirely sufficient.  As
    /// such, on affected platforms, the C++ Toolkit's build system arranges to
    /// filter "xncbi" out of the relevant makefile settings unless
    /// specifically directed otherwise via KEEP_CORELIB = yes (which can be
    /// useful when building plugins for third-party applications such as
    /// scripting languages).
    void Load(void);

    /// Unload DLL.
    ///
    /// Do nothing and do not generate errors if the DLL is not loaded.
    void Unload(void);

    /// Get DLLs entry point (function).
    ///
    /// Get the entry point (a function) with name "name" in the DLL and
    /// return the entry point's address on success, or return NULL on error.
    /// If the DLL is not loaded yet, then this method will call Load(),
    /// which can result in throwing an exception if Load() fails.
    /// @sa
    ///   GetEntryPoint_Data
    template <class TFunc>
    TFunc GetEntryPoint_Func(const std::string& name, TFunc* func)
    {
        TEntryPoint ptr = GetEntryPoint(name);
        if (func) {
            *func = (TFunc)(void*)ptr.func;
        }
        return (TFunc)(void*)ptr.func;
    }

    /// Get DLLs entry point (data).
    ///
    /// Get the entry point (a data) with name "name" in the DLL and
    /// return the entry point's address on success, or return NULL on error.
    /// If the DLL is not loaded yet, then this method will call Load(),
    /// which can result in throwing an exception if Load() fails.
    /// @sa
    ///   GetEntryPoint_Func
    template <class TData>
    TData GetEntryPoint_Data(const std::string& name, TData* data)
    {
        TEntryPoint ptr = GetEntryPoint(name);
        if (data) {
            *data = static_cast<TData> (ptr.data);
        }
        return static_cast<TData> (ptr.data);
    }

    /// Fake, uncallable function pointer
    typedef void (*FEntryPoint)(char**** Do_Not_Call_This);

    /// Entry point -- pointer to either a function or a data
    union TEntryPoint {
        FEntryPoint func;  ///< Do not call this func without type cast!
        void* data;
    };

    /// Helper find method for getting a DLLs entry point.
    ///
    /// Get the entry point (e.g. a function) with name "name" in the DLL.
    /// @param name
    ///   Name of DLL.
    /// @param pointer_size
    ///   Size of pointer.
    /// @return
    ///   The entry point's address on success, or return NULL on error.
    /// @sa
    ///   GetEntryPoint_Func, GetEntryPoint_Data
  
      TEntryPoint GetEntryPoint(const std::string& name);

    /// Get the name of the DLL file 
 
     const std::string& GetName() const { return m_Name; }

private:
    /// Helper method to throw exception with system-specific error message.
    
        void  x_ThrowException(const std::string& what);

    /// Helper method to initialize object.
    ///
    /// Called from constructor.
    /// @param path
    ///   Path to DLL.
    /// @param name
    ///   Name of DLL.
    /// @param when_to_load
    ///   Choice to load now or later using Load().
    /// @param auto_load
    ///   Choice to unload DLL in destructor.
    /// @param treat_as
    ///   Choice to transform the DLL base name.
    /// @sa
    ///   EFlags 
    void  x_Init(const std::string& path, const std::string& name, TFlags flags);

protected:
    /// Private copy constructor to prohibit copy.
    CDll(const CDll&);

    /// Private assignment operator to prohibit assignment.
    CDll& operator= (const CDll&);

private:
    std::string      m_Name;     ///< DLL name
    SDllHandle* m_Handle;   ///< DLL handle
    TFlags      m_Flags;    ///< Flags
};



#endif //__CDLL_H__