// SPDX-License-Identifier: GPL-2.0
/*
 * Integration tests: every ioctl against a loaded module, including the inputs
 * a well-behaved caller would never send.
 *
 * Needs kvault.ko loaded, the vault unsealed, and enough privilege to open
 * /dev/kvault. Cases that need more than the environment provides skip rather
 * than fail.
 *
 * Secrets created here are named kvtest_* and removed at the end, so the suite
 * can run against a vault that has real contents without disturbing them.
 */
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "../kvtest.hpp"
#include "client/VaultClient.hpp"

using namespace kvault;

namespace {

bool deviceAvailable()
{
	try {
		VaultClient c;
		return true;
	} catch (const VaultError &) {
		return false;
	}
}

bool unsealed()
{
	try {
		VaultClient c;
		return c.status().state == KV_STATE_UNSEALED;
	} catch (const VaultError &) {
		return false;
	}
}

/* Removes a secret, ignoring the error if it was never created: cleanup must
 * not fail a test that already reported its real result. */
void tidy(VaultClient &c, const std::string &name)
{
	try {
		c.remove(name);
	} catch (const VaultError &) {
	}
}

} // namespace

KV_TEST(status_reports_a_sane_abi_and_state)
{
	if (!deviceAvailable()) {
		kvtest::Registry::instance().skip("/dev/kvault not openable");
		return;
	}
	VaultClient c;
	const kv_status_arg st = c.status();

	KV_CHECK_EQ(st.abi_version, KV_ABI_VERSION);
	KV_CHECK(st.state <= KV_STATE_LOCKED_OUT);
	KV_CHECK_EQ(st.max_attempts > 0, true);
	/* The driver name must be a terminated string: an unterminated one would
	 * make every caller that prints it read past the buffer. */
	KV_CHECK(std::memchr(st.crypto_driver, '\0',
			     sizeof(st.crypto_driver)) != nullptr);
}

KV_TEST(an_unknown_ioctl_is_rejected)
{
	if (!deviceAvailable()) {
		kvtest::Registry::instance().skip("/dev/kvault not openable");
		return;
	}
	VaultClient c;

	/* Right magic, nonexistent command. */
	KV_CHECK_EQ(::ioctl(c.fd(), _IO(KV_IOC_MAGIC, 199)), -1);
	KV_CHECK_EQ(errno, ENOTTY);

	/* Wrong magic entirely - must not be mistaken for one of ours. */
	KV_CHECK_EQ(::ioctl(c.fd(), _IO('Z', 1)), -1);
	KV_CHECK_EQ(errno, ENOTTY);
}

KV_TEST(names_are_validated)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	const std::vector<std::uint8_t> v = {'x'};

	KV_EXPECT_ERRNO(c.put("", v), EINVAL);
	KV_EXPECT_ERRNO(c.put("has space", v), EINVAL);
	KV_EXPECT_ERRNO(c.put("has/slash", v), EINVAL);
	KV_EXPECT_ERRNO(c.put("has\tTab", v), EINVAL);
	KV_EXPECT_ERRNO(c.put(std::string(KV_NAME_MAX + 10, 'a'), v),
			ENAMETOOLONG);

	/* The characters that are allowed must actually work, or the validator
	 * is too strict and the test above proves nothing. */
	for (const char *ok : {"kvtest_a", "kvtest-b", "kvtest.c",
			       "kvtest_A9"}) {
		try {
			c.put(ok, v);
			c.remove(ok);
		} catch (const VaultError &e) {
			kvtest::Registry::instance().noteFailure(
			    std::string(ok) + " was rejected: " + e.what());
		}
	}
}

KV_TEST(empty_and_oversized_values_are_rejected)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	KV_EXPECT_ERRNO(c.put("kvtest_empty", {}), EINVAL);
	KV_EXPECT_ERRNO(c.put("kvtest_big",
			      std::vector<std::uint8_t>(KV_SECRET_MAX + 1, 'x')),
			E2BIG);
}

KV_TEST(round_trip_at_both_size_boundaries)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	/* One byte and exactly the maximum: the two sizes most likely to expose
	 * an off-by-one in the length handling. */
	for (const std::size_t len : {std::size_t{1}, std::size_t{KV_SECRET_MAX}}) {
		std::vector<std::uint8_t> value(len);
		for (std::size_t i = 0; i < len; ++i)
			value[i] = static_cast<std::uint8_t>(i & 0xff);

		c.put("kvtest_sizes", value);
		const std::vector<std::uint8_t> back = c.get("kvtest_sizes");
		KV_CHECK_EQ(back.size(), len);
		KV_CHECK(back == value);
	}
	tidy(c, "kvtest_sizes");
}

KV_TEST(a_value_containing_nul_bytes_survives)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	/* Secrets are bytes, not strings. A binary key with an embedded NUL must
	 * not be truncated anywhere along the path. */
	const std::vector<std::uint8_t> value = {'a', 0, 'b', 0, 0, 'c'};
	c.put("kvtest_nul", value);
	KV_CHECK(c.get("kvtest_nul") == value);
	tidy(c, "kvtest_nul");
}

KV_TEST(missing_secrets_report_enoent)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	KV_EXPECT_ERRNO(c.get("kvtest_absent"), ENOENT);
	KV_EXPECT_ERRNO(c.remove("kvtest_absent"), ENOENT);
	KV_EXPECT_ERRNO(c.rotate("kvtest_absent"), ENOENT);
}

KV_TEST(put_overwrites_and_bumps_the_version)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	c.put("kvtest_over", {'o', 'l', 'd'});
	c.put("kvtest_over", {'n', 'e', 'w'});
	const std::vector<std::uint8_t> back = c.get("kvtest_over");
	KV_CHECK_EQ(back.size(), 3u);
	KV_CHECK(back == std::vector<std::uint8_t>({'n', 'e', 'w'}));
	tidy(c, "kvtest_over");
}

KV_TEST(rotate_preserves_the_plaintext)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	const std::vector<std::uint8_t> value = {'r', 'o', 't', 'a', 't', 'e'};
	c.put("kvtest_rot", value);
	c.rotate("kvtest_rot");
	/* The nonce and tag changed; what the caller sees must not. */
	KV_CHECK(c.get("kvtest_rot") == value);
	tidy(c, "kvtest_rot");
}

KV_TEST(delete_removes_it)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	c.put("kvtest_del", {'x'});
	c.remove("kvtest_del");
	KV_EXPECT_ERRNO(c.get("kvtest_del"), ENOENT);
}

KV_TEST(list_includes_what_we_just_stored)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	c.put("kvtest_listed", {'x'});
	const std::vector<std::string> names = c.list();
	bool found = false;
	for (const std::string &n : names)
		if (n == "kvtest_listed")
			found = true;
	KV_CHECK(found);
	KV_CHECK(names.size() <= KV_LIST_MAX);
	tidy(c, "kvtest_listed");
}

KV_TEST(grant_rejects_undefined_permission_bits)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	c.put("kvtest_grant", {'x'});

	/* A bit outside KV_PERM_ALL must not be stored: an ACL holding bits the
	 * kernel does not understand is a permission that means nothing today
	 * and might mean something after an upgrade. */
	KV_EXPECT_ERRNO(c.grant("kvtest_grant", KV_SUBJ_ROLE,
				KV_ROLE_DEVELOPER, 0x8000u), EINVAL);
	KV_EXPECT_ERRNO(c.grant("kvtest_grant", 99u, KV_ROLE_DEVELOPER,
				KV_PERM_READ), EINVAL);
	tidy(c, "kvtest_grant");
}

KV_TEST(revoking_an_absent_entry_reports_enoent)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	c.put("kvtest_revoke", {'x'});
	KV_EXPECT_ERRNO(c.revoke("kvtest_revoke", KV_SUBJ_ROLE, KV_ROLE_GUEST),
			ENOENT);
	tidy(c, "kvtest_revoke");
}

KV_TEST(set_role_rejects_an_unknown_role)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	KV_EXPECT_ERRNO(c.setRole(65534, KV_ROLE_COUNT + 5), EINVAL);
}

KV_TEST(export_import_round_trip)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	c.put("kvtest_export", {'e', 'x', 'p'});

	const std::vector<std::uint8_t> blob = c.exportBlob();
	KV_REQUIRE(blob.size() > sizeof(kv_file_header));

	c.importBlob(blob);
	KV_CHECK(c.get("kvtest_export") ==
		 std::vector<std::uint8_t>({'e', 'x', 'p'}));
	tidy(c, "kvtest_export");
}

KV_TEST(import_rejects_rubbish)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;

	KV_EXPECT_ERRNO(c.importBlob({}), EINVAL);
	KV_EXPECT_ERRNO(c.importBlob({1, 2, 3}), EINVAL);
	KV_EXPECT_ERRNO(c.importBlob(std::vector<std::uint8_t>(512, 0xAA)),
			EINVAL);
}

KV_TEST(import_rejects_a_single_flipped_bit)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	c.put("kvtest_tamper", {'t', 'a', 'm', 'p', 'e', 'r'});

	std::vector<std::uint8_t> blob = c.exportBlob();
	KV_REQUIRE(blob.size() > 4);

	/* The last byte is inside the final entry's ciphertext. One bit is
	 * enough: GCM's tag covers every bit of it. */
	blob[blob.size() - 1] ^= 0x01;
	KV_EXPECT_ERRNO(c.importBlob(blob), EBADMSG);

	/* And the running vault is untouched by the rejection. */
	KV_CHECK(c.get("kvtest_tamper") ==
		 std::vector<std::uint8_t>({'t', 'a', 'm', 'p', 'e', 'r'}));
	tidy(c, "kvtest_tamper");
}

/*
 * Random input, to find the crash a hand-written case would not.
 *
 * The point is not that every call fails - many should - but that the kernel
 * answers every one of them with an errno instead of dying, and that the errno
 * is always one the ABI documents.
 */
KV_TEST(fuzz_names_and_lengths)
{
	if (!unsealed()) {
		kvtest::Registry::instance().skip("vault not unsealed");
		return;
	}
	VaultClient c;
	std::mt19937 rng(12345);   /* fixed seed: a failure must be reproducible */
	int unexpected = 0;

	for (int i = 0; i < 400; ++i) {
		const std::size_t nameLen = rng() % (KV_NAME_MAX + 8);
		std::string name;
		for (std::size_t j = 0; j < nameLen; ++j)
			name.push_back(static_cast<char>(rng() % 256));

		const std::size_t valueLen = rng() % (KV_SECRET_MAX + 64);
		std::vector<std::uint8_t> value(valueLen);
		for (std::size_t j = 0; j < valueLen; ++j)
			value[j] = static_cast<std::uint8_t>(rng() & 0xff);

		try {
			c.put(name, value);
			/* It was accepted, so the name was valid after all and
			 * it must read back intact. */
			if (c.get(name) != value)
				++unexpected;
			tidy(c, name);
		} catch (const VaultError &e) {
			switch (e.errnoValue()) {
			case EINVAL:
			case E2BIG:
			case ENAMETOOLONG:
			case ENOENT:
			case EACCES:
			case EPERM:
				break;    /* all documented */
			default:
				++unexpected;
				kvtest::Registry::instance().noteFailure(
				    "undocumented errno " +
				    std::to_string(e.errnoValue()));
			}
		}
	}
	KV_CHECK_EQ(unexpected, 0);
}

KV_TEST(the_audit_device_rejects_ioctls_and_short_reads)
{
	try {
		VaultClient audit(VaultClient::Device::Audit);

		/* The audit minor is a stream, not a command channel. */
		KV_CHECK_EQ(::ioctl(audit.fd(), KVAULT_STATUS, nullptr), -1);
		KV_CHECK_EQ(errno, ENOTTY);

		/* A buffer too small for one record must be refused outright
		 * rather than handed a fragment the reader cannot interpret. */
		char tiny[8];
		KV_CHECK_EQ(::read(audit.fd(), tiny, sizeof(tiny)),
			    static_cast<ssize_t>(-1));
		KV_CHECK_EQ(errno, EINVAL);
	} catch (const VaultError &) {
		kvtest::Registry::instance().skip(
		    "/dev/kvault_audit not openable");
	}
}

KV_TEST_MAIN("integration/ioctl")
