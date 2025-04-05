//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on Friday, April 4, 2025 22:44
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
std::string  memgrep::version::branch = "f9a51054";
#else
unsigned int memgrep::version::major  = 1;
unsigned int memgrep::version::minor  = 2;
unsigned int memgrep::version::build  = 0;
unsigned int memgrep::version::rev    = 80;
std::string  memgrep::version::sha    = "master";
std::string  memgrep::version::branch = "f9a51054";
#endif // _RELEASE
