// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the policy parser and permission notation. */
#include <unistd.h>

#include <cstdio>
#include <fstream>

#include "../kvtest.hpp"
#include "client/PolicyLoader.hpp"

using namespace kvault;

namespace {

/* Writes a temporary policy file and removes it again. Tests must not depend on
 * configs/policy.conf, whose contents are a deployment decision and will change. */
class TempFile {
public:
	explicit TempFile(const std::string &contents)
	    : path_("/tmp/kvtest-policy-" + std::to_string(::getpid()) + ".conf")
	{
		std::ofstream out(path_);
		out << contents;
	}
	~TempFile() { ::remove(path_.c_str()); }
	const std::string &path() const { return path_; }
private:
	std::string path_;
};

} // namespace

KV_TEST(perms_single_letters)
{
	KV_CHECK_EQ(PolicyLoader::permsFromString("r"), KV_PERM_READ);
	KV_CHECK_EQ(PolicyLoader::permsFromString("w"), KV_PERM_WRITE);
	KV_CHECK_EQ(PolicyLoader::permsFromString("d"), KV_PERM_DELETE);
	KV_CHECK_EQ(PolicyLoader::permsFromString("g"), KV_PERM_GRANT);
}

KV_TEST(perms_combinations_are_order_independent)
{
	KV_CHECK_EQ(PolicyLoader::permsFromString("rw"),
		    PolicyLoader::permsFromString("wr"));
	KV_CHECK_EQ(PolicyLoader::permsFromString("rwdg"), KV_PERM_ALL);
}

KV_TEST(perms_rejects_nonsense)
{
	bool threw = false;
	try {
		PolicyLoader::permsFromString("rx");
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);

	/* An empty set is a mistake, not "no permissions": granting nothing is
	 * what revoke is for, and silently accepting it would make a typo in a
	 * grant look like it worked. */
	threw = false;
	try {
		PolicyLoader::permsFromString("");
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
}

KV_TEST(role_names_map_to_ids)
{
	KV_CHECK_EQ(PolicyLoader::roleIdFromName("admin"), KV_ROLE_ADMIN);
	KV_CHECK_EQ(PolicyLoader::roleIdFromName("developer"), KV_ROLE_DEVELOPER);
	KV_CHECK_EQ(PolicyLoader::roleIdFromName("auditor"), KV_ROLE_AUDITOR);
	KV_CHECK_EQ(PolicyLoader::roleIdFromName("guest"), KV_ROLE_GUEST);

	bool threw = false;
	try {
		PolicyLoader::roleIdFromName("superuser");
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
}

KV_TEST(parses_uids_comments_and_blank_lines)
{
	TempFile f("# a comment\n"
		   "\n"
		   "user 1234 developer   # trailing comment\n"
		   "   \n"
		   "user 0 admin\n");

	const auto bindings = PolicyLoader::parse(f.path());
	KV_REQUIRE(bindings.size() == 2);
	KV_CHECK_EQ(bindings[0].uid, 1234u);
	KV_CHECK_EQ(bindings[0].roleId, KV_ROLE_DEVELOPER);
	KV_CHECK_EQ(bindings[1].uid, 0u);
	KV_CHECK_EQ(bindings[1].roleId, KV_ROLE_ADMIN);
}

KV_TEST(reports_the_offending_line_number)
{
	TempFile f("user 0 admin\n"
		   "user 1 wizard\n");

	std::string msg;
	try {
		PolicyLoader::parse(f.path());
	} catch (const std::exception &e) {
		msg = e.what();
	}
	/* The line number is the whole point of the error: a policy file with
	 * one bad line should say which. */
	KV_CHECK(msg.find(":2:") != std::string::npos);
}

KV_TEST(rejects_an_unknown_keyword)
{
	TempFile f("allow 0 admin\n");

	bool threw = false;
	try {
		PolicyLoader::parse(f.path());
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
}

KV_TEST_MAIN("unit/policy")
