// SPDX-License-Identifier: GPL-2.0
#ifndef KV_KEY_DERIVER_HPP
#define KV_KEY_DERIVER_HPP

#include <array>
#include <cstdint>
#include <string>

#include "SecureBuffer.hpp"
#include "kvault_ioctl.h"

namespace kvault {

using MasterKey = SecureBuffer<KV_KEY_LEN>;
using Salt = std::array<std::uint8_t, KV_SALT_LEN>;

/*
 * PBKDF2-HMAC-SHA256 over OpenSSL. KVault does not invent a KDF: the
 * contribution of this project is the access-control and audit design, and
 * rolling a password hash would only add a way to get it wrong.
 */
class KeyDeriver {
public:
	static constexpr unsigned kDefaultIterations = 200000;

	/* Fill @out with the key derived from @passphrase. */
	static void derive(const std::string &passphrase, const Salt &salt,
			   unsigned iterations, MasterKey &out);

	/* A fresh random salt from the system CSPRNG. */
	static Salt randomSalt();

	/* Random bytes for GCM nonces. A nonce must never repeat under the
	 * same key, which is why rotation generates a new one every time. */
	static void randomBytes(std::uint8_t *out, std::size_t len);
};

} // namespace kvault

#endif
