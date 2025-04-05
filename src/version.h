//==============================================================================
//
//  version.h
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================


#include <iostream>
#include <string>
#include <sstream>
namespace mseek {
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
