//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Saturday, April 12, 2025 21:55
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
std::string  mseek::version::branch = "e9f19ac2";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 205;
std::string  mseek::version::sha    = "main";
std::string  mseek::version::branch = "e9f19ac2";
#endif // _RELEASE
