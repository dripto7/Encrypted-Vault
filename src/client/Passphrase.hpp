// SPDX-License-Identifier: GPL-2.0
#ifndef KV_PASSPHRASE_HPP
#define KV_PASSPHRASE_HPP

#include <string>

namespace kvault {

/* Reads a passphrase from the controlling terminal with echo disabled. */
class Passphrase {
public:
	static std::string read(const std::string &prompt);

	/* Reads twice and compares. Used when a passphrase is being set rather
	 * than checked, where a typo would otherwise be unrecoverable. */
	static std::string readConfirmed(const std::string &prompt);
};

} // namespace kvault

#endif
