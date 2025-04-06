//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Sunday, April 6, 2025 10:54
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = release;
std::string  mseek::version::sha    = "main";
std::string  mseek::version::branch = "a7ad0230";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 193;
std::string  mseek::version::sha    = "main";
std::string  mseek::version::branch = "a7ad0230";
#endif // _RELEASE
