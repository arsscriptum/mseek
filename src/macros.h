//==============================================================================
//
//  macros.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#ifndef __MACROS_H__
#define __MACROS_H__

//---------------------------------------------------------------------------------------------
// FIXMEs / TODOs / NOTE macros
//---------------------------------------------------------------------------------------------
#define _QUOTE(x) # x
#define QUOTE(x) _QUOTE(x)
#define __FILE__LINE__ __FILE__ "(" QUOTE(__LINE__) ") : "

#define NOTE( x )  message( x )
#define FILE_LINE  message( __FILE__LINE__ )

#define TODO( x )  message( __FILE__LINE__"\n"           \
        " ------------------------------------------------\n" \
        "|  TODO :   " #x "\n" \
        " -------------------------------------------------\n" )
#define FIXME( x )  message(  __FILE__LINE__"\n"           \
        " ------------------------------------------------\n" \
        "|  FIXME :  " #x "\n" \
        " -------------------------------------------------\n" )
#define PLATFORM_FILE( x , y,z)  message( __FILE__LINE__"\n"           \
        " -----------------------------------------------------------------------------\n" \
        "|       PLATFORM-SPECIFIC FILE LOCATION          \n" \
        "|         " #x "   <<<----------\n" \
        "|         " #y "   <<<----------\n" \
        "|" #z " \n" \
        " -----------------------------------------------------------------------------\n" )

#define todo( x )  message( __FILE__LINE__" TODO :   " #x "\n" ) 
#define fixme( x )  message( __FILE__LINE__" FIXME:   " #x "\n" ) 



#endif //__MACROS_H__
