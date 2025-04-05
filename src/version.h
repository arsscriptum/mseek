//==============================================================================
//
//  version.h
//
//  this header file must rarely chage. the associated source file version.cpp
//  is automatically generated everytimne the build is started. 
//  on windows, the powershell script "scripts/GenerateAppVersion.ps1" is
//  generating the new version number and the source file.
//  On Linux, the script "scripts/generate_app_version.sh" does the same.
// 
//==============================================================================
//  automatically generated on Feb 14, 2025 9:15:50 PM
//==============================================================================

#include <iostream>
#include <string>
#include <sstream>
namespace memgrep {
	class version {
	public:
		typedef struct sVersionInfo {
			unsigned int major;
			unsigned int minor;
			unsigned int build;
			unsigned int rev;
		} sVersionInfoT;
		static unsigned int major;
		static unsigned int minor;
		static unsigned int build;
		static unsigned int rev;
		static std::string  sha; 
		static std::string  branch;


		// Function to return version as a string
		static std::string version::GetAppVersion(bool include_sha = false) {
			std::ostringstream oss;
			oss << major << "." << minor << "." << build << "." << rev;

			if (include_sha && !sha.empty()) {
				oss << " (" << branch << " - " << sha << ")";
			}

			return oss.str();
		}

		// Function to return version info as a struct
		version::sVersionInfoT version::GetVersionInfo() {
			return { major, minor, build, rev };
		}
	};

}