//==============================================================================
//
//     cmdline.cpp
//
//============================================================================
// Copyright (C)  Guillaume Plante <codegp@icloud.com>
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

