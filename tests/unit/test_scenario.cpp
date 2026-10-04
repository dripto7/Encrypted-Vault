// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the simulation scenario parser. */
#include <unistd.h>

#include <cstdio>
#include <fstream>

#include "../kvtest.hpp"
#include "ScenarioLoader.hpp"

using namespace kvault;
using namespace kvault::sim;

namespace {

class TempFile {
public:
	explicit TempFile(const std::string &contents)
	    : path_("/tmp/kvtest-scn-" + std::to_string(::getpid()) + ".conf")
	{
		std::ofstream out(path_);
		out << contents;
	}
	~TempFile() { ::remove(path_.c_str()); }
	const std::string &path() const { return path_; }
private:
	std::string path_;
};

bool throws(const std::string &contents)
{
	TempFile f(contents);
	try {
		ScenarioLoader::parse(f.path());
	} catch (const std::exception &) {
		return true;
	}
	return false;
}

} // namespace

KV_TEST(parses_secrets_grants_and_steps)
{
	TempFile f("# comment\n"
		   "secret db_password  hunter2\n"
		   "grant  db_password  developer  r\n"
		   "\n"
		   "step   kv_alice  get   db_password  allow\n"
		   "step   kv_alice  list  -            allow\n");

	const auto sc = ScenarioLoader::parse(f.path());
	KV_REQUIRE(sc.secrets.size() == 1);
	KV_CHECK_EQ(sc.secrets[0].name, std::string("db_password"));
	KV_CHECK_EQ(sc.secrets[0].value, std::string("hunter2"));

	KV_REQUIRE(sc.grants.size() == 1);
	KV_CHECK_EQ(sc.grants[0].subjectKind, KV_SUBJ_ROLE);
	KV_CHECK_EQ(sc.grants[0].subjectId, KV_ROLE_DEVELOPER);
	KV_CHECK_EQ(sc.grants[0].perms, KV_PERM_READ);

	KV_REQUIRE(sc.users.size() == 1);
	KV_CHECK_EQ(sc.users[0].user, std::string("kv_alice"));
	KV_REQUIRE(sc.users[0].steps.size() == 2);
	KV_CHECK(sc.users[0].steps[0].expectAllowed);
	/* '-' means the operation takes no secret. */
	KV_CHECK_EQ(sc.users[0].steps[1].name, std::string(""));
}

KV_TEST(a_secret_value_may_contain_spaces)
{
	TempFile f("secret motd   hello there, world\n"
		   "step kv_alice get motd allow\n");
	const auto sc = ScenarioLoader::parse(f.path());
	KV_REQUIRE(sc.secrets.size() == 1);
	KV_CHECK_EQ(sc.secrets[0].value, std::string("hello there, world"));
}

KV_TEST(steps_group_by_principal_in_first_appearance_order)
{
	TempFile f("step kv_eve   get a deny\n"
		   "step kv_alice get a allow\n"
		   "step kv_eve   get b deny\n");

	const auto sc = ScenarioLoader::parse(f.path());
	KV_REQUIRE(sc.users.size() == 2);
	/* eve appeared first, so she is first - and both her steps are hers,
	 * not split across two entries. */
	KV_CHECK_EQ(sc.users[0].user, std::string("kv_eve"));
	KV_CHECK_EQ(sc.users[0].steps.size(), 2u);
	KV_CHECK_EQ(sc.users[1].user, std::string("kv_alice"));
	KV_CHECK_EQ(sc.users[1].steps.size(), 1u);
}

KV_TEST(a_put_without_a_value_gets_a_generated_one)
{
	TempFile f("step kv_alice put notes allow\n");
	const auto sc = ScenarioLoader::parse(f.path());
	KV_REQUIRE(sc.users.size() == 1);
	/* An empty value would be rejected by the kernel, so the step would
	 * fail for a reason the scenario did not intend to test. */
	KV_CHECK(!sc.users[0].steps[0].value.empty());
}

KV_TEST(every_operation_name_resolves)
{
	KV_CHECK(ScenarioLoader::opFromName("get")    == Step::Op::Get);
	KV_CHECK(ScenarioLoader::opFromName("put")    == Step::Op::Put);
	KV_CHECK(ScenarioLoader::opFromName("list")   == Step::Op::List);
	KV_CHECK(ScenarioLoader::opFromName("delete") == Step::Op::Delete);
	KV_CHECK(ScenarioLoader::opFromName("rotate") == Step::Op::Rotate);
	KV_CHECK(ScenarioLoader::opFromName("audit")  == Step::Op::ReadAudit);
}

KV_TEST(malformed_directives_are_rejected)
{
	KV_CHECK(throws("wibble kv_alice get a allow\n"));        /* bad directive */
	KV_CHECK(throws("step kv_alice frobnicate a allow\n"));   /* bad op */
	KV_CHECK(throws("step kv_alice get a maybe\n"));          /* bad expectation */
	KV_CHECK(throws("step kv_alice get\n"));                  /* too few fields */
	KV_CHECK(throws("secret lonely\n"));                      /* no value */
	KV_CHECK(throws("grant a developer\n"));                  /* no perms */
	KV_CHECK(throws("grant a wizard r\n"));                   /* unknown role */
	KV_CHECK(throws("grant a developer x\n"));                /* bad perm letter */
	KV_CHECK(throws("# nothing but a comment\n"));            /* no steps */
}

KV_TEST(reports_the_offending_line_number)
{
	TempFile f("step kv_alice get a allow\n"
		   "step kv_alice get a maybe\n");
	std::string msg;
	try {
		ScenarioLoader::parse(f.path());
	} catch (const std::exception &e) {
		msg = e.what();
	}
	KV_CHECK(msg.find(":2:") != std::string::npos);
}

KV_TEST(the_shipped_scenario_parses)
{
	/* The scenario the project ships with must itself be valid - a config
	 * file in the repo that nothing can read is worse than none. */
	const char *path = "../configs/scenario-default.conf";
	std::ifstream probe(path);
	if (!probe) {
		kvtest::Registry::instance().skip(
		    "run from tests/ to check the shipped scenario");
		return;
	}
	const auto sc = ScenarioLoader::parse(path);
	KV_CHECK(sc.secrets.size() >= 2);
	KV_CHECK(sc.grants.size() >= 2);
	KV_CHECK_EQ(sc.users.size(), 4u);
}

KV_TEST_MAIN("unit/scenario")
