//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Saturday, April 5, 2025 0:54
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = release;
std::string  mseek::version::sha    = "master";
std::string  mseek::version::branch = "ac37ca0f";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 111;
std::string  mseek::version::sha    = "master";
std::string  mseek::version::branch = "ac37ca0f";
#endif // _RELEASE
