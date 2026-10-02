// SPDX-License-Identifier: GPL-2.0
#include "KeyDeriver.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace kvault {

void KeyDeriver::derive(const std::string &passphrase, const Salt &salt,
			unsigned iterations, MasterKey &out)
{
	if (iterations == 0)
		throw std::invalid_argument("KeyDeriver: iterations must be > 0");

	if (PKCS5_PBKDF2_HMAC(passphrase.data(),
			      static_cast<int>(passphrase.size()),
			      salt.data(), static_cast<int>(salt.size()),
			      static_cast<int>(iterations), EVP_sha256(),
			      static_cast<int>(out.size()), out.data()) != 1)
		throw std::runtime_error("KeyDeriver: PBKDF2 failed");
}

Salt KeyDeriver::randomSalt()
{
	Salt s{};
	randomBytes(s.data(), s.size());
	return s;
}

void KeyDeriver::randomBytes(std::uint8_t *out, std::size_t len)
{
	if (RAND_bytes(out, static_cast<int>(len)) != 1)
		throw std::runtime_error("KeyDeriver: RAND_bytes failed");
}

} // namespace kvault
