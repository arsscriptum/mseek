//==============================================================================
//
//  cmdline.cpp
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#include "stdafx.h"
#include "cmdline.h"
#include "log.h"

CmdLineUtil* CmdLineUtil::instance = nullptr;


CmdLineUtil* CmdLineUtil::get()
{
    if (instance == nullptr)
    {
        instance = new CmdLineUtil();
    }
    return instance;
}

