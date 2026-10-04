// SPDX-License-Identifier: GPL-2.0
#ifndef KV_SCENARIO_LOADER_HPP
#define KV_SCENARIO_LOADER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "SimUser.hpp"

namespace kvault::sim {

/* Parses a simulation scenario. */
class ScenarioLoader {
public:
	struct Secret {
		std::string name;
		std::string value;
	};

	struct Grant {
		std::string   name;
		std::uint32_t subjectKind;
		std::uint32_t subjectId;
		std::uint32_t perms;
		std::string   subjectSpec;   /* as written, for the report */
	};

	struct UserSteps {
		std::string       user;
		std::vector<Step> steps;
	};

	struct Scenario {
		std::vector<Secret>    secrets;
		std::vector<Grant>     grants;
		std::vector<UserSteps> users;   /* in first-appearance order */
	};

	/* Throws std::runtime_error naming the file and line on any malformed
	 * directive. A partly-applied scenario would run and report results
	 * that mean nothing. */
	static Scenario parse(const std::string &path);

	static Step::Op opFromName(const std::string &name);
};

} // namespace kvault::sim

#endif
