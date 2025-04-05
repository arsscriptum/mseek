//==============================================================================
//
//  log.cpp
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#include "stdafx.h"
#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <wtypes.h>

extern bool g_ColoredOutput;
extern bool g_forceNoColors;
void logmsgn(const char* format, ...)
{
	if (g_ColoredOutput) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stdout, "\033[97m");
	}


	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);

	if (g_ColoredOutput) {
		// Reset console color
		fprintf(stdout, "\033[0m");
	}
}

void logmsg(const char* format, ...)
{
	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stdout, "\033[36m[i] \033[0m");
	}
	else {
		fprintf(stdout, "[i] ");
	}


	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stdout, "\033[97m");
	}


	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);

	if (g_ColoredOutput) {
		// Reset console color
		fprintf(stdout, "\033[0m");
	}
}

void logmsgext(const char* format, ...)
{
	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stdout, "\033[37m[memory] \033[0m");
	}
	else {
		fprintf(stdout, "[memory] ");
	}


	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stdout, "\033[93m");
	}


	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);

	if (g_ColoredOutput) {
		// Reset console color
		fprintf(stdout, "\033[0m");
	}
}
void logsuccess(const char* format, ...)
{
	// Set console text color to red (ANSI escape sequence)
	if (g_forceNoColors) {
		fprintf(stdout, "[done] ");
	}
	else {
		fprintf(stdout, "\033[32m[done] \033[0m");
		fprintf(stdout, "\033[97m");
	}
	
	
	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	if (!g_forceNoColors) {
		fprintf(stdout, "\033[0m");
	}
	
}


void loghighlight(const char* format, ...)
{
	// Set console text color to red (ANSI escape sequence)

	if (g_ColoredOutput && !g_forceNoColors) {
		fprintf(stdout, "\033[5;31;44m[I]\033[0m");
	}
	else {
		fprintf(stdout, "[I] ");
	}



	if (g_ColoredOutput && !g_forceNoColors) {
		fprintf(stdout, " \033[3;33m");
	}

	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	if (!g_forceNoColors) {
		fprintf(stdout, "\033[0m");
	}
	
}




void logwarn(const char* format, ...)
{
	if (g_forceNoColors) {
		fprintf(stderr, "[warn] ");
	}
	else {
		fprintf(stderr, "\033[31m[warn] \033[0m");
		fprintf(stderr, "\033[33m");
	}
	// Set console text color to red (ANSI escape sequence)

	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	if (!g_forceNoColors) {
		fprintf(stdout, "\033[0m");
	}
}


void logerror(const char* format, ...)
{
	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stderr, "\033[31m[!] \033[0m");
	}
	else {
		fprintf(stderr, "[!] ");
	}


	if (g_ColoredOutput && !g_forceNoColors) {
		// Set console text color to red (ANSI escape sequence)
		fprintf(stderr, "\033[33m");
	}

	// Handle the rest of the formatted message
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	if (g_ColoredOutput && !g_forceNoColors) {
		// Reset console color
		fprintf(stderr, "\033[0m");
	}
}



//==============================================================================
// ConsoleOut
// Used by the ServiceTerminal
//==============================================================================
void __cdecl ConsoleOut(std::string color, const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';


	EndOfLineEscapeTag Format{ color, ANSI_TEXT_COLOR_RESET };
	std::clog << Format << buf;
}

void __cdecl ConsoleLog(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	EndOfLineEscapeTag FormatTitle{ CONSOLE_COLOR_GREEN_BRIGHT, ANSI_TEXT_COLOR_RESET };
	EndOfLineEscapeTag FormatText{ CONSOLE_COLOR_GREEN, ANSI_TEXT_COLOR_RESET };
	std::clog << FormatTitle << "[app] ";
	std::clog << FormatText << buf;
}

void __cdecl ConsoleInstaller(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	EndOfLineEscapeTag FormatTitle{ CONSOLE_COLOR_YELLOW_BRIGHT, ANSI_TEXT_COLOR_RESET };
	EndOfLineEscapeTag FormatText{ CONSOLE_COLOR_RED_BRIGHT, ANSI_TEXT_COLOR_RESET };
	std::clog << FormatTitle << "[installer] ";
	std::clog << FormatText << buf;
}
void __cdecl ConsoleNet(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	EndOfLineEscapeTag FormatTitle{ CONSOLE_COLOR_CYAN_BRIGHT, ANSI_TEXT_COLOR_RESET };
	EndOfLineEscapeTag FormatText{ CONSOLE_COLOR_CYAN, ANSI_TEXT_COLOR_RESET };
	std::clog << FormatTitle << "[net] ";
	std::clog << FormatText << buf;
}
void __cdecl ConsoleError(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	EndOfLineEscapeTag FormatTitle{ CONSOLE_COLOR_RED_BRIGHT, ANSI_TEXT_COLOR_RESET };
	EndOfLineEscapeTag FormatText{ CONSOLE_COLOR_YELLOW_BRIGHT, ANSI_TEXT_COLOR_RESET };
	std::clog << FormatTitle << "[error] ";
	std::clog << FormatText << buf;
}
//==============================================================================
// SystemDebugOutput
// Kernel-mode and Win32 debug output
//   - Win32 OutputDebugString
//   - Kernel - mode DbgPrint
// You can monitor this stream using Debugview from SysInternals
// https://docs.microsoft.com/en-us/sysinternals/downloads/debugview
//==============================================================================
void __cdecl SystemDebugOutput(const wchar_t *channel, const char *format, ...)
{
#ifndef FINAL
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	OutputDebugStringA(buf);
#ifdef KERNEL_DEBUG
	DbgPrint(buf);
#endif // KERNEL_DEBUG

#endif // FINAL
}
