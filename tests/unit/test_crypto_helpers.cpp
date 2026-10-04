// SPDX-License-Identifier: GPL-2.0
/* Unit tests for SecureBuffer and the KDF wrapper. */
#include <cstring>
#include <set>
#include <string>

#include "../kvtest.hpp"
#include "client/KeyDeriver.hpp"
#include "client/SecureBuffer.hpp"

using namespace kvault;

KV_TEST(securebuffer_starts_zeroed)
{
	SecureBuffer<64> b;
	bool allZero = true;
	for (std::size_t i = 0; i < b.size(); ++i)
		if (b.data()[i] != 0)
			allZero = false;
	KV_CHECK(allZero);
}

KV_TEST(securebuffer_wipe_clears_every_byte)
{
	SecureBuffer<32> b;
	std::memset(b.data(), 0xAB, b.size());
	KV_REQUIRE(b.data()[0] == 0xAB);

	b.wipe();
	for (std::size_t i = 0; i < b.size(); ++i)
		KV_CHECK_EQ(b.data()[i], 0u);
}

/*
 * The wipe must survive optimisation.
 *
 * This cannot be asserted from inside the process - the whole problem is that a
 * compiler may remove a store it can prove nobody reads, and any check that
 * reads it stops it being provably dead. What the test can do is confirm the
 * wipe happens at all at -O2 through a pointer the optimiser cannot follow to a
 * known destination; the volatile qualifier in SecureBuffer::wipe is what makes
 * it mandatory, and docs/06-test-report.md records the disassembly check.
 */
KV_TEST(securebuffer_wipe_is_not_elided_at_O2)
{
	SecureBuffer<32> b;
	std::memset(b.data(), 0xCD, b.size());

	unsigned char *escaped = b.data();
	b.wipe();

	int sum = 0;
	for (std::size_t i = 0; i < 32; ++i)
		sum += escaped[i];
	KV_CHECK_EQ(sum, 0);
}

KV_TEST(kdf_is_deterministic_for_the_same_inputs)
{
	const Salt salt{};   /* all zeroes: fine for a determinism check */
	MasterKey a, b;

	KeyDeriver::derive("passphrase", salt, 1000, a);
	KeyDeriver::derive("passphrase", salt, 1000, b);
	KV_CHECK_EQ(std::memcmp(a.data(), b.data(), a.size()), 0);
}

KV_TEST(kdf_output_changes_with_salt_passphrase_and_iterations)
{
	Salt s1{}, s2{};
	s2[0] = 1;

	MasterKey base, otherSalt, otherPass, otherIters;
	KeyDeriver::derive("passphrase", s1, 1000, base);
	KeyDeriver::derive("passphrase", s2, 1000, otherSalt);
	KeyDeriver::derive("passphrasf", s1, 1000, otherPass);
	KeyDeriver::derive("passphrase", s1, 1001, otherIters);

	KV_CHECK(std::memcmp(base.data(), otherSalt.data(), base.size()) != 0);
	KV_CHECK(std::memcmp(base.data(), otherPass.data(), base.size()) != 0);
	KV_CHECK(std::memcmp(base.data(), otherIters.data(), base.size()) != 0);
}

KV_TEST(kdf_rejects_zero_iterations)
{
	const Salt salt{};
	MasterKey k;
	bool threw = false;
	try {
		KeyDeriver::derive("x", salt, 0, k);
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
}

KV_TEST(random_salts_do_not_repeat)
{
	std::set<std::string> seen;
	for (int i = 0; i < 64; ++i) {
		const Salt s = KeyDeriver::randomSalt();
		seen.insert(std::string(reinterpret_cast<const char *>(s.data()),
					s.size()));
	}
	/* A repeat in 64 draws of 128 bits means the CSPRNG is broken. */
	KV_CHECK_EQ(seen.size(), 64u);
}

KV_TEST_MAIN("unit/crypto-helpers")
