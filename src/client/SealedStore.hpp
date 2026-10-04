// SPDX-License-Identifier: GPL-2.0
#ifndef KV_SEALED_STORE_HPP
#define KV_SEALED_STORE_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "kvault_ioctl.h"

namespace kvault {

/* Reads and writes the sealed vault file. */
class SealedStore {
public:
	/* The public part of the file: everything needed to derive the key, and
	 * nothing that helps anyone who does not know the passphrase. */
	struct Header {
		std::array<std::uint8_t, KV_SALT_LEN> salt;
		std::uint32_t iterations;
		std::uint32_t entryCount;
	};

	/* Throws if the file is missing, too short, or not a KVault vault. */
	static Header readHeader(const std::string &path);

	/* Whether @path looks like a vault file we could unseal against. */
	static bool exists(const std::string &path);

	static void save(const std::string &path,
			 const std::vector<std::uint8_t> &blob);

	static std::vector<std::uint8_t> load(const std::string &path);
};

} // namespace kvault

#endif
