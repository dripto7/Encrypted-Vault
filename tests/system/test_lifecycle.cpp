// SPDX-License-Identifier: GPL-2.0
/*
 * System tests: concurrency under the vault mutex, the auto-lock timer, and
 * what survives a module reload.
 *
 * Needs root and an unsealed vault. These cases change global vault state - the
 * last one deliberately leaves it auto-locked - so they run last and say so.
 */
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

/*
 * Many processes reading at once.
 *
 * Every operation serialises on one mutex, so the interesting question is not
 * throughput but whether the plaintext each reader gets back is its own. A
 * shared scratch buffer or a tfm whose key one thread overwrites while another
 * is using it would show up here as a wrong or empty value.
 */
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
 * The auto-lock timer.
 *
 * Driven by writing the module parameter rather than by reloading the module, so
 * the test does not need the passphrase: the timer is re-armed from the current
 * parameter value on the next operation, so shortening it and then touching the
 * vault schedules a lock a couple of seconds out.
 *
 * This and the case after it both leave the vault locked, so they come last.
 */
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

/*
 * A locked vault refuses everything.
 *
 * Deliberately a separate case that runs after the auto-lock one, rather than
 * sealing the vault itself. Any case that seals leaves every later case with
 * nothing to work on, so there is exactly one transition to the locked state in
 * this suite and this case observes the result of it.
 *
 * The explicit SEAL ioctl is exercised in the session log instead
 * (docs/v05-session.log), where the passphrase is known and the vault can be
 * unsealed again afterwards.
 */
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
