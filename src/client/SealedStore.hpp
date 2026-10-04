// SPDX-License-Identifier: GPL-2.0
#ifndef KV_SEALED_STORE_HPP
#define KV_SEALED_STORE_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "kvault_ioctl.h"

namespace kvault {

/*
 * Reads and writes the sealed vault file.
 *
 * The entries are opaque here, deliberately: the kernel produces them and the
 * kernel authenticates them, so a user-space parser for the entry bodies would
 * be a second implementation of the format and a second chance to get its
 * bounds checks wrong.
 *
 * The header is the exception, and it has to be. Importing a vault requires the
 * right key already loaded, deriving the right key requires the salt, and the
 * salt lives in the file - so something outside the kernel must read the header
 * before the kernel can be given anything. That is not a weakness: the salt and
 * iteration count are public KDF parameters whose job is to make one
 * precomputed table useless against many vaults, not to stay hidden.
 */
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

	/*
	 * Writes @blob to @path durably.
	 *
	 * A plain open-truncate-write loses the old vault if the machine dies
	 * mid-write, leaving neither the old file nor a complete new one. The
	 * sequence here is the standard one: write a temporary file in the same
	 * directory, fsync it so the bytes are really on the medium, rename it
	 * over the target (atomic within a filesystem), then fsync the directory
	 * so the rename itself survives a crash. Skipping the last step is the
	 * usual mistake - the file's contents are durable but the name still
	 * points at the old inode.
	 */
	static void save(const std::string &path,
			 const std::vector<std::uint8_t> &blob);

	static std::vector<std::uint8_t> load(const std::string &path);
};

} // namespace kvault

#endif
