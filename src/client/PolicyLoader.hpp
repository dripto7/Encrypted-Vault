// SPDX-License-Identifier: GPL-2.0
#ifndef KV_POLICY_LOADER_HPP
#define KV_POLICY_LOADER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "kvault_ioctl.h"

namespace kvault {

/* Parses configs/policy.conf: which system users hold which role. */
class PolicyLoader {
public:
	struct Binding {
		std::uint32_t uid    = 0;
		std::uint32_t roleId = KV_ROLE_NONE;
		std::string   user;    /* as written, for diagnostics */
	};

	/* Throws std::runtime_error with the line number on a malformed line:
	 * a policy file that is silently half-applied is worse than one that is
	 * rejected. */
	static std::vector<Binding> parse(const std::string &path);

	static std::uint32_t roleIdFromName(const std::string &name);
	static std::uint32_t permsFromString(const std::string &spec);

	static void subjectFromString(const std::string &spec,
				      std::uint32_t &kind, std::uint32_t &id);
};

} // namespace kvault

#endif
