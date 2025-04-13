//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Sunday, April 13, 2025 0:11
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
std::string  mseek::version::branch = "6bebb3ad";
#else
unsigned int mseek::version::major  = 1;
unsigned int mseek::version::minor  = 2;
unsigned int mseek::version::build  = 0;
unsigned int mseek::version::rev    = 222;
std::string  mseek::version::sha    = "main";
std::string  mseek::version::branch = "6bebb3ad";
#endif // _RELEASE
