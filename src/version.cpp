//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Saturday, April 5, 2025 0:24
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
std::string  mseek::version::branch = "287b256f";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 109;
std::string  mseek::version::sha    = "master";
std::string  mseek::version::branch = "287b256f";
#endif // _RELEASE
