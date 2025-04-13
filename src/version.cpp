//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Sunday, April 13, 2025 9:06
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int mseek::version::major  = 2;
unsigned int mseek::version::minor  = 1;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = release;
std::string  mseek::version::sha    = "extended_scope_main";
std::string  mseek::version::branch = "bfcdb109";
#else
unsigned int mseek::version::major  = 2;
unsigned int mseek::version::minor  = 1;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 0;
std::string  mseek::version::sha    = "extended_scope_main";
std::string  mseek::version::branch = "bfcdb109";
#endif // _RELEASE
