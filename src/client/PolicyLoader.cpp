// SPDX-License-Identifier: GPL-2.0
#include "PolicyLoader.hpp"

#include <pwd.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "kvault_ioctl.h"

namespace kvault {

std::uint32_t PolicyLoader::roleIdFromName(const std::string &name)
{
	if (name == "admin")     return KV_ROLE_ADMIN;
	if (name == "developer") return KV_ROLE_DEVELOPER;
	if (name == "auditor")   return KV_ROLE_AUDITOR;
	if (name == "guest")     return KV_ROLE_GUEST;
	throw std::runtime_error("unknown role '" + name + "'");
}

/* "r", "rw", "rwd", "rwdg" - read, write, delete, grant. */
std::uint32_t PolicyLoader::permsFromString(const std::string &spec)
{
	std::uint32_t perms = 0;

	for (const char c : spec) {
		switch (c) {
		case 'r': perms |= KV_PERM_READ;   break;
		case 'w': perms |= KV_PERM_WRITE;  break;
		case 'd': perms |= KV_PERM_DELETE; break;
		case 'g': perms |= KV_PERM_GRANT;  break;
		case '-': break;
		default:
			throw std::runtime_error(
			    std::string("unknown permission '") + c +
			    "' (expected r, w, d or g)");
		}
	}
	if (perms == 0)
		throw std::runtime_error("empty permission set");
	return perms;
}

void PolicyLoader::subjectFromString(const std::string &spec,
				     std::uint32_t &kind, std::uint32_t &id)
{
	if (spec.rfind("user:", 0) == 0) {
		const std::string who = spec.substr(5);
		kind = KV_SUBJ_UID;
		if (!who.empty() &&
		    who.find_first_not_of("0123456789") == std::string::npos) {
			id = static_cast<std::uint32_t>(std::stoul(who));
			return;
		}
		if (const struct passwd *pw = ::getpwnam(who.c_str())) {
			id = pw->pw_uid;
			return;
		}
		throw std::runtime_error("no such user '" + who + "'");
	}

	kind = KV_SUBJ_ROLE;
	id = roleIdFromName(spec);
}

std::vector<PolicyLoader::Binding> PolicyLoader::parse(const std::string &path)
{
	std::ifstream in(path);
	if (!in)
		throw std::runtime_error("cannot open policy file " + path);

	std::vector<Binding> out;
	std::string line;
	unsigned lineNo = 0;

	while (std::getline(in, line)) {
		++lineNo;

		/* Strip comments and surrounding whitespace before deciding
		 * whether the line is empty, so a line of only a comment is not
		 * a syntax error. */
		const std::size_t hash = line.find('#');
		if (hash != std::string::npos)
			line.erase(hash);

		std::istringstream ls(line);
		std::string keyword, who, role;
		if (!(ls >> keyword))
			continue;

		const auto fail = [&](const std::string &msg) {
			throw std::runtime_error(path + ":" +
						 std::to_string(lineNo) + ": " + msg);
		};

		if (keyword != "user")
			fail("expected 'user', got '" + keyword + "'");
		if (!(ls >> who >> role))
			fail("expected: user <name|uid> <role>");

		Binding b{};
		b.user = who;

		/* A name is resolved through NSS; a bare number is taken as a
		 * UID so a policy can name an account that does not exist yet. */
		if (!who.empty() && who.find_first_not_of("0123456789") ==
				     std::string::npos) {
			b.uid = static_cast<std::uint32_t>(std::stoul(who));
		} else if (const struct passwd *pw = ::getpwnam(who.c_str())) {
			b.uid = pw->pw_uid;
		} else {
			fail("no such user '" + who + "'");
		}

		try {
			b.roleId = roleIdFromName(role);
		} catch (const std::exception &e) {
			fail(e.what());
		}

		out.push_back(b);
	}

	return out;
}

} // namespace kvault
