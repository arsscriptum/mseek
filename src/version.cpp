//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Saturday, April 5, 2025 2:26
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
std::string  mseek::version::branch = "24058082";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 148;
std::string  mseek::version::sha    = "main";
std::string  mseek::version::branch = "24058082";
#endif // _RELEASE
