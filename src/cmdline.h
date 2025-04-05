//==============================================================================
//
//  cmdline.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#include <vector>
#include <string>
#include <memory>
#include <sstream>
#include <map>
#include <algorithm>
#include "log.h"

#include "cmdline_opt_values.h"

// New modern C++ structure with a constructor for easier initialization.

class CmdlineOption
{
public:
    CmdlineOption()
        : _options(), _description(""), _typeId(cmdOpT::Unknown) {}
    CmdlineOption(const std::vector<std::string>& opt, const std::string& desc)
        : _options(opt), _description(desc), _typeId(cmdlineOptTypes::Unknown) {}
    CmdlineOption(const std::vector<std::string>& opt, const std::string& desc,cmdOpT id)
        : _options(opt), _description(desc), _typeId(id) {}

    // New constructor that accepts an SCmdlineOptValues instance.
    CmdlineOption(const SCmdlineOptValues& optValues)
        : _options(optValues._options),
        _description(optValues._description),
        _typeId(optValues._type)
    {}

    bool isValid(std::string option) {
        for (auto&& str : _options) {
            if (str == option) { return true; }
        }
        return false;
    }
    bool operator == (const CmdlineOption& other) const
    {
        return _options == other._options;
    }
    void dump_options(std::ostringstream& dbg_output) const {
        dbg_output << "\t" << _options.at(0).c_str() << ", " << _options.at(1).c_str() << "\t: " << _description.c_str() << std::endl;
    }
  

    std::vector<std::string> _options;
    std::string _description;
    cmdOpT _typeId;
};


// Class to manage program arguments
class CmdlineParser
{
public:
   
    CmdlineParser() {};
    void reset(int& argc, char** argv)
    {
        for (int i = 1; i < argc; ++i) {
            this->tokens.push_back(std::string(argv[i]));
        }
    }

    const std::string& getCmdOption(const std::string& option) const {
        LOG_TRACE("cmdline::getCmdOption", "option %s", option.c_str());
        std::vector<std::string>::const_iterator itr;
        itr = std::find(this->tokens.begin(), this->tokens.end(), option);
        if (itr != this->tokens.end() && ++itr != this->tokens.end())
        {
            std::string tmpstr = *itr;
            LOG_TRACE("cmdline::getCmdOption", "FOUND option %s", tmpstr.c_str());
            return *itr;
        }
        static const std::string empty_string("");
        return empty_string;
    }

    bool get_option_argument(const SCmdlineOptValues& cmdopt, std::string& value) {
        LOG_TRACE("cmdline::get_option_argument", "%s", cmdopt._description.c_str());
        for (auto&& opt : cmdopt._options) {
            LOG_TRACE("cmdline::get_option_argument", "check %s", opt.c_str());
            if (cmdOptionExists(opt) == true) {
                LOG_TRACE("cmdline::get_option_argument", "cmdOptionExists %s == true", opt.c_str());
                std::string retval = getCmdOption(opt);
                LOG_TRACE("cmdline::get_option_argument", "getCmdOption %s == %s", opt.c_str(), retval.c_str());
                if (retval.length() > 0) {
                    value = retval;
                    return true;
                }
            }
        }
        LOG_TRACE("cmdline::get_option_argument", "not found");
        return false;
    }

    bool cmdOptionExists(const std::string& option) const
    {
        return std::find(this->tokens.begin(), this->tokens.end(), option) != this->tokens.end();
    }

    void DumpAllOptions()
    {
        std::ostringstream dbg_output;

        for (const auto& entry : options_map) {
            const CmdlineOption& opt = entry.second;
            opt.dump_options(dbg_output);
        }

        std::cout << dbg_output.str() << std::endl;
    }

    // Updated addOption that takes the new structure type.
    void addOption(const SCmdlineOptValues& optVal)
    {
        CmdlineOption option(optVal._options, optVal._description, optVal._type);
        option._typeId = optVal._type;
        options.push_back(option);
        int type_id = (int)optVal._type;
        options_map[type_id] = option;
    }
    bool getArgument(SCmdlineOptValues& cmdlineOption)
    {
        std::ostringstream dbg_output;

        LOG_TRACE("CmdlineOption::isSet", "%s %s", cmdlineOption._description.c_str(), dbg_output.str().c_str());
        for (auto&& opt : cmdlineOption._options) {
            if (cmdOptionExists(opt) == true) {
                return true;
            }
        }
        return false;
    }
    bool isSet(SCmdlineOptValues& cmdlineOption)
    {
        std::ostringstream dbg_output;
        
        LOG_TRACE("CmdlineOption::isSet", "%s %s", cmdlineOption._description.c_str(), dbg_output.str().c_str());
        for (auto&& opt : cmdlineOption._options) {
            if (cmdOptionExists(opt) == true) {
                return true;
            }
        }
        return false;
    }
    bool invalidToken() {
        for (auto&& token : tokens) {
            if (cmdlineOptionValid(token) == false) {
                return true;
            }
        }
        return false;
    }

    


    void dump_tokens(std::ostringstream& dbg_output) {
        for (auto&& token : tokens) {
            dbg_output << token << std::endl;
        }
    }

    bool get_cmdline_opt(int id, CmdlineOption& retval) {
        auto it = options_map.find(id);
        if (it != options_map.end()) {
            retval = it->second;
            return true;
        }
        return false;  // Not found
    }
private:
    bool cmdlineOptionValid(std::string opt)
    {
        for (auto&& elem : options) {
            if (elem.isValid(opt)) {
                return true;
            }
        }
        return false;
    }
    std::vector <std::string> tokens;
    std::vector<CmdlineOption> options;

    std::map<int, CmdlineOption> options_map;
};

class CmdLineUtil
{
public:
    static CmdLineUtil* get();

    void initialize(int argc, char** argv) {
        inputParser.reset(argc, argv);
    };
    CmdlineParser* parser() { return &inputParser; };

private:
    CmdLineUtil() {};

    CmdlineParser inputParser;
    static CmdLineUtil* instance;
};

#endif //__CMDLINE_H__

