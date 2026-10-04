// SPDX-License-Identifier: GPL-2.0
#ifndef KV_POLICY_LOADER_HPP
#define KV_POLICY_LOADER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "kvault_ioctl.h"

namespace kvault {

/*
 * Parses configs/policy.conf: which system users hold which role.
 *
 * The file says who holds a role, never what a role may do. Those permissions
 * are compiled into the kernel, so a writable config file cannot widen
 * anybody's access - the worst it can do is name the wrong person, which the
 * audit log then records.
 */
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
};

} // namespace kvault

#endif
