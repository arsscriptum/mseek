//==============================================================================
//
//  targetver.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#ifndef __TARGET_VER_H__
#define __TARGET_VER_H__


#include <SDKDDKVer.h>


// platform detection
// from: https://gcc.gnu.org/onlinedocs/cpp/Predefined-Macros.html
#if defined(_WIN32) // for Windows (32-bit and 64-bit, this part is common)
#define PLATFORM_PC
#ifdef _WIN64 // for Windows (64-bit only)
#if !defined PLATFORM_WIN64
#define PLATFORM_WIN64
#endif
#else // _WIN64
#define PLATFORM_WIN32 // for Windows (32-bit only)
//#pragma message("PLATFORM_WIN32 DETECTED")  
#endif // _WIN64
#elif defined(__APPLE__)
#pragma message("PLATFORM_MAC DETECTED")  
#define PLATFORM_MAC
#include "TargetConditionals.h"

#if TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR // for iPhone simulator   
#define PLATFORM_IPHONESIM
#pragma message("PLATFORM_IPHONESIM DETECTED")  
#elif defined(TARGET_OS_IPHONE) // for iPhone
#define PLATFORM_IPHONE
#pragma message("PLATFORM_IPHONE DETECTED")  
#else
#define TARGET_OS_OSX 1
#define PLATFORM_OSX
#pragma message("PLATFORM_OSX DETECTED")  
#endif
#elif defined(__linux)
#define PLATFORM_LINUX
#pragma message("PLATFORM_LINUX DETECTED")   
#else
#pragma message("UNSUPPORTED PLATFORM !")  // this might be Unix or Cygwin... unsupported.
#error Failing compilation because of platform
#endif // _WIN32

#ifdef PLATFORM_PC

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

#endif // PLATFORM_PC

#include <assert.h>
#define ASSERT(x)	assert(x)

#ifdef PLATFORM_PC
#include <conio.h>
#endif // PLATFORM_PC

#ifdef PLATFORM_LINUX
#include <sys/ioctl.h>
#include <termios.h>

bool kbhit();
#endif

#include <string.h>

#endif //__TARGET_VER_H__
