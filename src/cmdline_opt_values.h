//==============================================================================
//
//  cmdline_opt_values.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#ifndef __CMDLINE_OPT_VALUES_H__
#define __CMDLINE_OPT_VALUES_H__

#include <vector>
#include <string>
#include "log.h"

#ifndef UINT8_MAX
typedef unsigned char uint8_t;
#endif


enum class cmdlineOptTypes : uint8_t {
    Unknown,
    Help,
    After,          // -a
    Before,         // -b
    Color,          // -c
    Elevate,      // -e
    InputFile,      // -i
    ListAll,        // -l
    MemoryInfo,        // -l
    ProcName,       // -n
    OutputFile,     // -o
    ProcID,         // -p
    Quiet,          // -q
    Regex,          // -r
    SearchString,   // -s
    MemType,        // -t
    Verbose,        // -v
    HexDump,        // -x
    Unicode,        // -u
    PrintableOnly   // -z
};

using cmdOpT = cmdlineOptTypes;

struct SCmdlineOptValues {
    std::vector<std::string> _options;
    std::string _description;
    cmdOpT _type;
    SCmdlineOptValues()
        : _options(), _description(""), _type(cmdOpT::Unknown) {}
    // Constructor to initialize all members.
    SCmdlineOptValues(const std::vector<std::string>& opts,
        const std::string& desc,bool hasArgument,
        cmdOpT id)
        : _options(opts), _description(desc), _type(id) {}

    bool isValid(std::string option) {
        for (auto&& str : _options) {
            if (str == option) { return true; }
        }
        return false;
    }
    bool operator == (const SCmdlineOptValues& other) const
    {
        return _options == other._options;
    }
    void dump_options(std::ostringstream& dbg_output) {
        for (auto&& opt : _options) {
            dbg_output << _description << " : " << opt << std::endl;
            LOG_TRACE("SCmdlineOptValues::dump_options", "%s: option %s", _description.c_str(), opt.c_str());
        }
    }
};

#endif // __CMDLINE_OPT_VALUES_H__
