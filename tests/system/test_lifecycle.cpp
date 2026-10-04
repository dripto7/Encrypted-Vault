// SPDX-License-Identifier: GPL-2.0
/*
 * System tests: concurrency under the vault mutex, the auto-lock timer, and
 * what survives a module reload.
 */
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "../kvtest.hpp"
#include "client/VaultClient.hpp"

using namespace kvault;

namespace {

constexpr const char *kParamPath = "/sys/module/kvault/parameters/autolock_secs";

bool ready()
{
	try {
		VaultClient c;
		return c.status().state == KV_STATE_UNSEALED;
	} catch (const VaultError &) {
		return false;
	}
}

bool writeParam(const char *path, const std::string &value)
{
	std::ofstream out(path);
	if (!out)
		return false;
	out << value;
	return out.good();
}

std::string readParam(const char *path)
{
	std::ifstream in(path);
	std::string v;
	in >> v;
	return v;
}

} // namespace

KV_TEST(concurrent_readers_all_get_the_right_plaintext)
{
	if (!ready()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}

	constexpr int kChildren = 8;
	constexpr int kReads = 50;
	const std::string value = "concurrent-plaintext-0123456789";

	{
		VaultClient c;
		c.put("kvtest_conc", {value.begin(), value.end()});
	}

	std::vector<pid_t> kids;
	for (int i = 0; i < kChildren; ++i) {
		const pid_t pid = ::fork();
		KV_REQUIRE(pid >= 0);
		if (pid == 0) {
			int bad = 0;
			try {
				VaultClient c;   /* its own fd and session */
				for (int j = 0; j < kReads; ++j) {
					const std::vector<std::uint8_t> got =
					    c.get("kvtest_conc");
					if (got.size() != value.size() ||
					    std::memcmp(got.data(), value.data(),
							value.size()) != 0)
						++bad;
				}
			} catch (const std::exception &) {
				bad = 255;
			}
			::_exit(bad > 255 ? 255 : bad);
		}
		kids.push_back(pid);
	}

	int mismatches = 0;
	for (const pid_t pid : kids) {
		int status = 0;
		::waitpid(pid, &status, 0);
		KV_CHECK(WIFEXITED(status));
		if (WIFEXITED(status))
			mismatches += WEXITSTATUS(status);
	}
	KV_CHECK_EQ(mismatches, 0);

	VaultClient c;
	try { c.remove("kvtest_conc"); } catch (const VaultError &) {}
}

/* Writers and readers interleaved, to put the lock under mixed load rather than
 * read-only load: a missing lock on the store's hash chains would corrupt the
 * list and show up as a crash or a lost entry. */
KV_TEST(concurrent_writers_do_not_corrupt_the_store)
{
	if (!ready()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}

	constexpr int kThreads = 6;
	constexpr int kOps = 40;
	std::atomic<int> errors{0};
	std::vector<std::thread> threads;

	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([t, &errors] {
			try {
				VaultClient c;
				const std::string name =
				    "kvtest_thread_" + std::to_string(t);
				for (int j = 0; j < kOps; ++j) {
					const std::string v =
					    std::to_string(t) + ":" + std::to_string(j);
					c.put(name, {v.begin(), v.end()});
					const std::vector<std::uint8_t> got =
					    c.get(name);
					/* Another thread must never be able to
					 * make this read return someone else's
					 * value: the names are distinct. */
					if (std::string(got.begin(), got.end()) != v)
						++errors;
					c.list();
				}
				c.remove(name);
			} catch (const std::exception &) {
				++errors;
			}
		});
	}
	for (std::thread &th : threads)
		th.join();

	KV_CHECK_EQ(errors.load(), 0);
}

/*
 * A descriptor must not carry the privileges it was opened with.
 *
 * The opener can drop to another user and keep the descriptor, or hand it to an
 * unprivileged process over a unix socket with SCM_RIGHTS. If authorisation
 * used the UID captured at open(), the receiver would inherit the opener's
 * access - precisely the bypass this asserts cannot happen.
 */
KV_TEST(a_descriptor_does_not_carry_the_openers_privileges)
{
	if (!ready()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}

	const struct passwd *pw = ::getpwnam("kv_eve");
	if (!pw) {
		kvtest::Registry::instance().skip(
		    "kv_eve missing; run build/bin/kvsetup");
		return;
	}

	{
		VaultClient c;
		c.put("kvtest_privdrop", {'n', 'o', 't', 'y', 'o', 'u', 'r', 's'});
	}

	const pid_t pid = ::fork();
	KV_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Open while still root, then become a principal with no access
		 * at all, keeping the descriptor. */
		const int fd = ::open("/dev/kvault", O_RDWR | O_CLOEXEC);
		if (fd < 0)
			::_exit(10);
		if (::initgroups("kv_eve", pw->pw_gid) ||
		    ::setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
		    ::setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
			::_exit(11);
		if (::setresuid(0, 0, 0) == 0)
			::_exit(12);          /* the drop was reversible */

		kv_secret_arg arg{};
		std::strncpy(arg.name, "kvtest_privdrop", KV_NAME_MAX - 1);
		arg.len = KV_SECRET_MAX;
		const int rc = ::ioctl(fd, KVAULT_GET, &arg);
		/* 0 means the stale UID was honoured, which is the bug. */
		::_exit(rc == 0 ? 1 : (errno == EACCES ? 0 : 13));
	}

	int status = 0;
	::waitpid(pid, &status, 0);
	KV_REQUIRE(WIFEXITED(status));
	const int rc = WEXITSTATUS(status);

	if (rc == 1)
		kvtest::Registry::instance().noteFailure(
		    "a dropped process read a secret through a descriptor "
		    "opened as root");
	else if (rc >= 10)
		kvtest::Registry::instance().noteFailure(
		    "child setup failed with code " + std::to_string(rc));
	KV_CHECK_EQ(rc, 0);

	VaultClient c;
	try { c.remove("kvtest_privdrop"); } catch (const VaultError &) {}
}

KV_TEST(the_vault_locks_itself_when_idle)
{
	if (!ready()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}

	const std::string saved = readParam(kParamPath);
	if (saved.empty()) {
		kvtest::Registry::instance().skip(
		    "cannot read the autolock_secs parameter");
		return;
	}
	if (!writeParam(kParamPath, "2")) {
		kvtest::Registry::instance().skip(
		    "cannot write the autolock_secs parameter (need root)");
		return;
	}

	{
		VaultClient c;
		c.put("kvtest_autolock", {'t'});   /* re-arms with the new value */
		KV_REQUIRE(c.status().state == KV_STATE_UNSEALED);
	}

	/* Four seconds for a two-second timer: the timer fires on a jiffy
	 * boundary and the handler may re-arm once if it finds the lock held, so
	 * a margin avoids a flaky result. */
	::sleep(4);

	VaultClient c;
	KV_CHECK_EQ(c.status().state, KV_STATE_AUTO_LOCKED);

	writeParam(kParamPath, saved);
}

KV_TEST(a_locked_vault_denies_every_operation)
{
	VaultClient c;
	const kv_status_arg st = c.status();

	if (st.state == KV_STATE_UNSEALED) {
		kvtest::Registry::instance().skip(
		    "vault is still unsealed; the auto-lock case did not run");
		return;
	}

	/* No key means nothing to decrypt with. The entries still exist - which
	 * is the distinction between locking a vault and emptying it. */
	KV_EXPECT_ERRNO(c.get("kvtest_autolock"), EPERM);
	KV_EXPECT_ERRNO(c.put("kvtest_while_locked", {'v'}), EPERM);
	KV_EXPECT_ERRNO(c.list(), EPERM);
	KV_EXPECT_ERRNO(c.exportBlob(), EPERM);
	KV_CHECK(c.status().secret_count > 0);

	std::printf("        note: the vault is left locked; unseal it again "
		    "before further use\n");
}

KV_TEST_MAIN("system/lifecycle")
