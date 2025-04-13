//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Sunday, April 13, 2025 17:29
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int mseek::version::major  = 2;
unsigned int mseek::version::minor  = 1;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = release;
std::string  mseek::version::sha    = "ext-dev";
std::string  mseek::version::branch = "67bbac02";
#else
unsigned int mseek::version::major  = 2;
unsigned int mseek::version::minor  = 1;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 1;
std::string  mseek::version::sha    = "ext-dev";
std::string  mseek::version::branch = "67bbac02";
#endif // _RELEASE
