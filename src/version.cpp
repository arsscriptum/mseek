//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Sunday, April 13, 2025 17:39
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
std::string  mseek::version::branch = "a1971d2e";
#else
unsigned int mseek::version::major  = 2;
unsigned int mseek::version::minor  = 1;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 2;
std::string  mseek::version::sha    = "ext-dev";
std::string  mseek::version::branch = "a1971d2e";
#endif // _RELEASE
