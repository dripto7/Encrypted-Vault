// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the sealed-file writer and its header parser. */
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

#include "../kvtest.hpp"
#include "client/SealedStore.hpp"

using namespace kvault;

namespace {

std::string tmpPath(const char *tag)
{
	return "/tmp/kvtest-" + std::string(tag) + "-" +
	       std::to_string(::getpid()) + ".vault";
}

/* Builds a minimal valid header, little-endian, by hand - deliberately not by
 * casting a struct, so the test would catch a parser that assumed host order. */
std::vector<std::uint8_t> makeHeader(std::uint32_t magic, std::uint32_t version,
				     std::uint32_t iters, std::uint32_t entries)
{
	std::vector<std::uint8_t> h(sizeof(kv_file_header), 0);
	const auto put = [&h](std::size_t off, std::uint32_t v) {
		h[off + 0] = static_cast<std::uint8_t>(v & 0xff);
		h[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
		h[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
		h[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
	};
	put(0, magic);
	put(4, version);
	put(8, iters);
	put(12, entries);
	for (std::size_t i = 0; i < KV_SALT_LEN; ++i)
		h[16 + i] = static_cast<std::uint8_t>(0xA0 + i);
	return h;
}

} // namespace

KV_TEST(save_then_load_round_trips)
{
	const std::string p = tmpPath("roundtrip");
	const std::vector<std::uint8_t> blob = {0, 1, 2, 250, 251, 255, 0, 7};

	SealedStore::save(p, blob);
	const std::vector<std::uint8_t> back = SealedStore::load(p);
	KV_CHECK_EQ(back.size(), blob.size());
	KV_CHECK(back == blob);
	::remove(p.c_str());
}

KV_TEST(saved_file_is_private_to_its_owner)
{
	const std::string p = tmpPath("mode");
	SealedStore::save(p, {1, 2, 3});

	struct stat st{};
	KV_REQUIRE(::stat(p.c_str(), &st) == 0);
	/* 0600. The contents are ciphertext, but handing a copy to every local
	 * user invites an unhurried offline attack on the passphrase. */
	KV_CHECK_EQ(st.st_mode & 0777, 0600u);
	::remove(p.c_str());
}

KV_TEST(save_leaves_no_temporary_behind)
{
	const std::string p = tmpPath("notmp");
	SealedStore::save(p, {9, 9, 9});

	struct stat st{};
	KV_CHECK(::stat((p + ".tmp").c_str(), &st) != 0);
	::remove(p.c_str());
}

KV_TEST(save_replaces_the_previous_contents_entirely)
{
	const std::string p = tmpPath("replace");
	SealedStore::save(p, std::vector<std::uint8_t>(500, 0xEE));
	SealedStore::save(p, std::vector<std::uint8_t>(10, 0x11));

	const std::vector<std::uint8_t> back = SealedStore::load(p);
	/* A rename cannot leave a tail of the longer old file behind; an
	 * open-truncate-write could if the truncate were forgotten. */
	KV_CHECK_EQ(back.size(), 10u);
	::remove(p.c_str());
}

KV_TEST(header_parses_magic_version_and_parameters)
{
	const std::string p = tmpPath("header");
	SealedStore::save(p, makeHeader(KV_FILE_MAGIC, KV_FILE_VERSION,
					200000, 7));

	const SealedStore::Header h = SealedStore::readHeader(p);
	KV_CHECK_EQ(h.iterations, 200000u);
	KV_CHECK_EQ(h.entryCount, 7u);
	KV_CHECK_EQ(h.salt[0], 0xA0u);
	KV_CHECK_EQ(h.salt[KV_SALT_LEN - 1],
		    static_cast<std::uint8_t>(0xA0 + KV_SALT_LEN - 1));
	::remove(p.c_str());
}

KV_TEST(header_rejects_a_wrong_magic)
{
	const std::string p = tmpPath("badmagic");
	SealedStore::save(p, makeHeader(0xDEADBEEF, KV_FILE_VERSION, 1000, 0));

	bool threw = false;
	try {
		SealedStore::readHeader(p);
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
	::remove(p.c_str());
}

KV_TEST(header_rejects_a_future_version)
{
	const std::string p = tmpPath("badver");
	SealedStore::save(p, makeHeader(KV_FILE_MAGIC, KV_FILE_VERSION + 1,
					1000, 0));

	bool threw = false;
	try {
		SealedStore::readHeader(p);
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
	::remove(p.c_str());
}

KV_TEST(header_rejects_a_truncated_file)
{
	const std::string p = tmpPath("short");
	SealedStore::save(p, {1, 2, 3, 4});

	KV_CHECK(!SealedStore::exists(p));

	bool threw = false;
	try {
		SealedStore::readHeader(p);
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
	::remove(p.c_str());
}

KV_TEST(header_rejects_zero_iterations)
{
	const std::string p = tmpPath("zeroiters");
	SealedStore::save(p, makeHeader(KV_FILE_MAGIC, KV_FILE_VERSION, 0, 0));

	bool threw = false;
	try {
		SealedStore::readHeader(p);
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
	::remove(p.c_str());
}

KV_TEST(exists_is_false_for_a_missing_file)
{
	KV_CHECK(!SealedStore::exists("/tmp/kvtest-definitely-not-here.vault"));
}

KV_TEST(load_rejects_a_directory)
{
	bool threw = false;
	try {
		SealedStore::load("/tmp");
	} catch (const std::exception &) {
		threw = true;
	}
	KV_CHECK(threw);
}

KV_TEST_MAIN("unit/sealedstore")
