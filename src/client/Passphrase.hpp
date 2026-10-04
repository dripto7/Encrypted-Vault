// SPDX-License-Identifier: GPL-2.0
#ifndef KV_PASSPHRASE_HPP
#define KV_PASSPHRASE_HPP

#include <string>

namespace kvault {

/*
 * Reads a passphrase from the controlling terminal with echo disabled.
 *
 * The termios flags are restored by a destructor rather than at the end of the
 * function, because an exception thrown while reading - or a signal handled by
 * the standard library - must not leave the user's terminal with echo off.
 */
class Passphrase {
public:
	/* On a terminal, echo is suppressed for the duration of the read. When
	 * stdin is a pipe or a file the passphrase is read as-is: there is no
	 * echo to suppress, and refusing would make the tool unusable from a
	 * test harness. */
	static std::string read(const std::string &prompt);

	/* Reads twice and compares. Used when a passphrase is being set rather
	 * than checked, where a typo would otherwise be unrecoverable. */
	static std::string readConfirmed(const std::string &prompt);
};

} // namespace kvault

#endif
