//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Friday, April 4, 2025 22:41
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int memgrep::version::major  = 1;
unsigned int memgrep::version::minor  = 2;
unsigned int memgrep::version::build  = 0;
unsigned int memgrep::version::rev    = release;
std::string  memgrep::version::sha    = "master";
std::string  memgrep::version::branch = "57fe4269";
#else
unsigned int memgrep::version::major  = 1;
unsigned int memgrep::version::minor  = 2;
unsigned int memgrep::version::build  = 0;
unsigned int memgrep::version::rev    = 79;
std::string  memgrep::version::sha    = "master";
std::string  memgrep::version::branch = "57fe4269";
#endif // _RELEASE
