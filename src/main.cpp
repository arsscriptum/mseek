
//==============================================================================
//
//     main.cpp
//
//============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================



#include "stdafx.h"
#include "cmdline.h"
#include "Shlwapi.h"
#include "log.h"
#include "utils.h"
#include "trackers.h"


#include <codecvt>
#include <locale>
#include <vector>
#include <unordered_map>
#include <iterator>
#include <regex>
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include "Shlwapi.h"
#include "log.h"
#include <ctime>
#include <iostream>
#include <string>
#include <algorithm>
#include "test_results.h"
#include "inireader.h"
#include "config.h"

#include "DejaLib.h"

#include <libtorrent/settings_pack.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/error_code.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/torrent_info.hpp>
#include <libtorrent/torrent_status.hpp>
#include <libtorrent/error_code.hpp>

#include "DejaLib.h"

bool g_is_verbose = false;
unsigned  int g_default_num_want = 1;
using namespace std;
using namespace std::chrono_literals;

#pragma message( "Compiling " __FILE__ )
#pragma message( "Last modified on " __TIMESTAMP__ )

unsigned  int g_default_timeout_sec = 5;


int log_config_values() {

	try {
		Config& config = Config::getInstance();

		LOG_TRACE("main::log_config_values", "Version: %d", config.getVersion());
		LOG_TRACE("main::log_config_values", "Tracker Timeout: %d", config.getTimeout());
		LOG_TRACE("main::log_config_values", "Tracker Type: %s", config.getTrackerTypeString().c_str());
		LOG_TRACE("main::log_config_values", "Weight Peers: %.2f", config.getWeightPeers());
		LOG_TRACE("main::log_config_values", "Weight Ping: %.2f", config.getWeightPing());

		LOG_TRACE("main::log_config_values", "Console Logging: %s", config.isConsoleEnabled() ? "Enabled" : "Disabled");
		LOG_TRACE("main::log_config_values", "Log File: %s", config.getLogFile().c_str());

		LOG_TRACE("main::log_config_values", "Debug Mode: %s", config.isDebugEnabled() ? "Enabled" : "Disabled");
		LOG_TRACE("main::log_config_values", "Debug Pause: %d seconds", config.getDebugPause());
		LOG_TRACE("main::log_config_values", "Exit Pause: %d seconds", config.getExitPause());

		if (CONFIG.isDebugEnabled()) {
			COUTDBG("=============================");
			COUTDBG("DEBUG ENABLED");
		}

	}
	catch (const std::exception& e) {
		LOG_TRACE("main", "Exception occurred: %s", e.what());
	}

	return 0;
}

int main(int argc, TCHAR** argv, TCHAR envp)
{

#ifdef UNICODE
	char** argn = (char**)Convert::allocate_argn(argc, argv);
#else
	char** argn = argv;
#endif // UNICODE

	CmdLineUtil::getInstance()->initializeCmdlineParser(argc, argn);

	CmdlineParser* inputParser = CmdLineUtil::getInstance()->getInputParser();

	CmdlineOption cmdlineOptionHelp({		"-h", "--help" },     "display this help");
	CmdlineOption cmdlineOptionVerbose({	"-v", "--verbose" },  "verbose output");
	CmdlineOption cmdlineOptionTimeout({	"-t", "--timeout" },  "timeout in seconds for each tracker requests");
	CmdlineOption cmdlineOptionPath({		"-p", "--path" },     "path");
	CmdlineOption cmdlineOptionConfigFile({ "-c", "--config" },   "config gile");
	CmdlineOption cmdlineOptionJson({		"-j", "--json" },     "json  format");
	CmdlineOption cmdlineOptionIndexer({	"-i", "--indexer" },  "indexer");
	CmdlineOption cmdlineOptionDownload({	"-d", "--download" }, "download latest");
	CmdlineOption cmdlineOptionNoBanner({	"-n", "--nobanner" }, "no banner");
	CmdlineOption cmdlineOptionQuiet({      "-q", "--quiet" },    "quiet");
	CmdlineOption cmdlineOptionChecksum({   "-x", "--xsum" },     "calculate checksum");
	CmdlineOption cmdlineOptionTrackerUrl({ "-u", "--url" },      "tracker url (i.e. udp://mytrack:1337/announce)");
	CmdlineOption cmdlineOptionWhatIf({		"-w", "--whatif" },   "whatif");

	inputParser->addOption(cmdlineOptionHelp);
	inputParser->addOption(cmdlineOptionVerbose);
	inputParser->addOption(cmdlineOptionDownload);
	inputParser->addOption(cmdlineOptionNoBanner);
	inputParser->addOption(cmdlineOptionWhatIf);
	inputParser->addOption(cmdlineOptionTrackerUrl);
	inputParser->addOption(cmdlineOptionPath);
	inputParser->addOption(cmdlineOptionJson);
	inputParser->addOption(cmdlineOptionIndexer);
	inputParser->addOption(cmdlineOptionChecksum);
	inputParser->addOption(cmdlineOptionTimeout);
	inputParser->addOption(cmdlineOptionQuiet);
	inputParser->addOption(cmdlineOptionConfigFile);
	
	bool optNoBanner = inputParser->isSet(cmdlineOptionNoBanner);
	bool optQuiet = inputParser->isSet(cmdlineOptionQuiet);
	bool optHelp = inputParser->isSet(cmdlineOptionHelp);
	bool optVerbose = inputParser->isSet(cmdlineOptionVerbose);
	bool optTracker = inputParser->isSet(cmdlineOptionTrackerUrl);
	bool optDownload = inputParser->isSet(cmdlineOptionDownload);
	bool optPath = inputParser->isSet(cmdlineOptionPath);
	bool optJson = inputParser->isSet(cmdlineOptionJson);
	bool optIndexer = inputParser->isSet(cmdlineOptionIndexer);

	bool optWhatIf = inputParser->isSet(cmdlineOptionWhatIf);
	bool optTimeout = inputParser->isSet(cmdlineOptionTimeout);
	bool optConfig = inputParser->isSet(cmdlineOptionConfigFile);
	bool optChecksum = inputParser->isSet(cmdlineOptionChecksum);

	g_is_verbose = optVerbose;
	if (optQuiet) {
		g_is_verbose = false;
	}
	
#ifdef _DEBUG_CMDLINE
	std::ostringstream dbg_output;
	inputParser->dump_tokens(dbg_output);
	std::cout << std::endl << "[DEBUG] dump_tokens " << dbg_output.str() << std::endl << std::endl;

	cmdlineOptionDownload.dump_options(dbg_output);
	cmdlineOptionHelp.dump_options(dbg_output);
	cmdlineOptionVerbose.dump_options(dbg_output);
	cmdlineOptionDownload.dump_options(dbg_output);
	cmdlineOptionNoBanner.dump_options(dbg_output);
	cmdlineOptionWhatIf.dump_options(dbg_output);
	cmdlineOptionTrackerUrl.dump_options(dbg_output);
	cmdlineOptionPath.dump_options(dbg_output);
	cmdlineOptionJson.dump_options(dbg_output);
	cmdlineOptionIndexer.dump_options(dbg_output);
	cmdlineOptionTimeout.dump_options(dbg_output);
	cmdlineOptionQuiet.dump_options(dbg_output);
	std::cout << "[DEBUG] " << dbg_output.str() << std::endl;

	COUTCS("optQuiet %d", optQuiet ? 1 : 0);
	COUTCS("optHelp %d", optHelp ? 1 : 0);
	COUTCS("optVerbose %d", optVerbose ? 1 : 0);
	COUTCS("optTracker %d", optTracker ? 1 : 0);
	COUTCS("optDownload %d", optDownload ? 1 : 0);
	COUTCS("optPath %d", optPath ? 1 : 0);
	COUTCS("optJson %d", optJson ? 1 : 0);
	COUTCS("optIndexer %d", optIndexer ? 1 : 0);
	COUTCS("optNoBanner %d", optNoBanner ? 1 : 0);
	COUTCS("optWhatIf %d", optWhatIf ? 1 : 0);
	COUTCS("optTimeout %d", optTimeout ? 1 : 0);

	LOG_TRACE("commandline option","optQuiet %d", optQuiet ?1:0);
	LOG_TRACE("commandline option", "optHelp %d", optHelp ? 1 : 0);
	LOG_TRACE("commandline option","optVerbose %d",optVerbose?1:0);
	LOG_TRACE("commandline option","optTracker %d",optTracker?1:0);
	LOG_TRACE("commandline option","optDownload %d",optDownload?1:0);
	LOG_TRACE("commandline option","optPath %d",optPath?1:0);
	LOG_TRACE("commandline option","optJson %d",optJson?1:0);
	LOG_TRACE("commandline option","optIndexer %d",optIndexer?1:0);
	LOG_TRACE("commandline option","optNoBanner %d",optNoBanner?1:0);
	LOG_TRACE("commandline option","optWhatIf %d",optWhatIf?1:0);
	LOG_TRACE("commandline option","optTimeout %d",optTimeout?1:0);
#endif

	if (optQuiet && optVerbose) {
		COUTCS("Warning: Quiet and Verbose: Verbose superceed Quiet...");
	}

	if (optNoBanner == false) {
		banner();
	}
	if (optHelp) {
		usage();
		return 0;
	}
	std::string file_path = "";
	std::string tracker_url = "";
	
	if (optConfig) {

		std::string tmp_config_file = "";
		if (inputParser->get_option_argument(cmdlineOptionConfigFile, tmp_config_file)) {
			LOG_TRACE("main::arguments::optTracker", "tmp_config_file %s", tmp_config_file.c_str());

			bool is_valid = Config::getInstance().ValidateConfigChecksum(tmp_config_file);
			if (is_valid) {
				LOG_TRACE("main::ValidateConfigChecksum", "tmp_config_file %s VALID", tmp_config_file.c_str());
			}else {
				LOG_WARNING("main::ValidateConfigChecksum", "tmp_config_file %s NOT VALID", tmp_config_file.c_str());
#ifdef _RELEASE 
				throw("Error: Invalid config file");
				return -3;
#endif 
			}

			Config::getInstance().Initialize(tmp_config_file);
		}
		else {
			LOG_TRACE("main::arguments::optTracker", "missing url");
			usage_error("missing config Path");
			return -1;
		}
	}
	else {
		Config::getInstance().Initialize();
	}

	log_config_values();

	if (optChecksum) {
		std::string configPath = CONFIG.getFilePath();
		if (Config::getInstance().SetConfigChecksum(configPath)) {
			LOG_DEBUG("main::SetConfigChecksum", "set checksum for configuration file");
		}
		else {
			LOG_ERROR("main::SetConfigChecksum", "failed to update checksum");
		}
	}

	if (optTimeout) {

		std::string str_timeout_sec = "";
		if (inputParser->get_option_argument(cmdlineOptionTimeout, str_timeout_sec)) {
			LOG_DEBUG("main::arguments::cmdlineOptionTimeout", "opt_url %s", str_timeout_sec.c_str());
			if (isNumeric(str_timeout_sec)) {
				g_default_timeout_sec = std::stoi(str_timeout_sec);
				LOG_DEBUG("main::arguments::cmdlineOptionTimeout", "setting default_timeout_sec %d", g_default_timeout_sec);
			}
		}
		else {
			LOG_DEBUG("main::arguments::cmdlineOptionTimeout", "missing timeout value");
			usage_error("missing url");
			return -1;
		}
	}

	if (optDownload) {
		std::string tmp_tracker_list = "";
		if (!get_temp_file_path(tmp_tracker_list)) {
			app_error("cannot create temporary file");
			return -2;
		}
		LOG_DEBUG("main::arguments", "get_temp_file_path %s", tmp_tracker_list.c_str());

		
		string index_url = get_trackers_index_url(CONFIG.getTrackerType());
		LOG_DEBUG("main::arguments", "get_trackers_index_url %s", index_url.c_str());
		string list_url = download_file_content(index_url, optVerbose);
		LOG_DEBUG("main::arguments", "download_file_content(%s) -> %s", index_url.c_str(), list_url.c_str());
		bool ok = download_file_ext(list_url, tmp_tracker_list, optVerbose);
		LOG_DEBUG("main::arguments", "download_file_content(%s,%s) -> %s", list_url.c_str(), tmp_tracker_list.c_str(), ok ? "SUCCESS" : "ERROR");
		COUTRS("DOWNLOADING LATEST VERSION OF TRACKERS FROM URL \"%s\"", list_url.c_str());
		std::vector<std::string> tracker_urls;

		if (!extract_trackers_from_file(tmp_tracker_list, tracker_urls)) {
			app_error("error when extracting trackers from file");
			return -4;
		}
		TrackerTestResults tracker_test_results;
		ok = test_trackers_list_res(tracker_urls, tracker_test_results);
		
		LOG_DEBUG("main::arguments::optTracker", "result: %s, num %d", ok?"SUCCESS":"FAILURE", tracker_test_results.Count());
		rank_trackers(tracker_test_results);
		tracker_test_results.to_json();

		Sleep(1000);
		return 0;
	}

	if (optTracker) {
		
		std::string opt_url = "";
		if (inputParser->get_option_argument(cmdlineOptionTrackerUrl, opt_url)) {
			LOG_TRACE("main::arguments::optTracker", "opt_url %s", opt_url.c_str());
			test_single_tracker_out(opt_url, optJson, g_default_timeout_sec);
		}
		else {
			LOG_TRACE("main::arguments::optTracker", "missing url");
			usage_error("missing url");
			return -1;
		}
	}
	else if (optIndexer) {

		std::string magnet_url = "";
		if (inputParser->get_option_argument(cmdlineOptionIndexer, magnet_url)) {
			LOG_TRACE("main::arguments::cmdlineOptionIndexer", "magnet_url %s", magnet_url.c_str());
			rate_indexer(magnet_url, optJson, g_default_timeout_sec);
		}
		else {
			LOG_TRACE("main::arguments::cmdlineOptionIndexer", "missing url");
			usage_error("missing url");
			return -1;
		}


	}
	else if (optPath) {

		if (inputParser->get_option_argument(cmdlineOptionPath, file_path)) {
			LOG_TRACE("main::arguments::cmdlineOptionPath", "file_path %s", file_path.c_str());
		}
		else {
			LOG_TRACE("main::arguments::cmdlineOptionPath", "missing file path");
			usage_error("missing file path");
			return -1;
		}
		std::vector<std::string> tracker_urls;

		if (!extract_trackers_from_file(file_path, tracker_urls)) {
			app_error("error when extracint trackers from file");
			return -4;
		}
		test_trackers_list_out(tracker_urls, optJson);
	}
	
	if (CONFIG.isDebugEnabled()) {
		DEJA_CONSOLE_WRITE("DO YOU WANT TO SLEEP ?");
		char buf[256];
		DEJA_CONSOLE_READ(buf, 255);
		if (!strcmp(buf, "yes")) {
			DEJA_CONSOLE_ECHO("OK");
		}
		LOG_DEBUG("main", "Sleeping for %d", CONFIG.getExitPause());
		Sleep(CONFIG.getExitPause());
	}
	
	return 0;
}
