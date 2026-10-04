// SPDX-License-Identifier: GPL-2.0
#include "Passphrase.hpp"

#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <openssl/crypto.h>

namespace kvault {

namespace {

/* RAII guard over the terminal's echo flag. */
class EchoOff {
public:
	explicit EchoOff(int fd) : fd_(fd), restore_(false)
	{
		if (::tcgetattr(fd_, &saved_) != 0)
			throw std::runtime_error(
			    "passphrase: not a terminal; refusing to read with echo on");

		struct termios quiet = saved_;
		quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
		quiet.c_lflag |= ECHONL;
		if (::tcsetattr(fd_, TCSAFLUSH, &quiet) != 0)
			throw std::runtime_error("passphrase: tcsetattr failed");
		restore_ = true;
	}

	~EchoOff()
	{
		if (restore_)
			::tcsetattr(fd_, TCSAFLUSH, &saved_);
	}

	EchoOff(const EchoOff &) = delete;
	EchoOff &operator=(const EchoOff &) = delete;

private:
	int fd_;
	bool restore_;
	struct termios saved_;
};

} // namespace

std::string Passphrase::read(const std::string &prompt)
{
	/* Echo only needs suppressing on a terminal. When stdin is a pipe or a
	 * file there is nothing to display and nothing to restore, so the guard
	 * is skipped rather than the read being refused - that is what lets the
	 * test suites drive unseal non-interactively. */
	std::unique_ptr<EchoOff> guard;
	const bool interactive = ::isatty(STDIN_FILENO) == 1;

	if (interactive) {
		guard = std::make_unique<EchoOff>(STDIN_FILENO);
		std::cout << prompt << std::flush;
	}
	std::string pass;
	if (!std::getline(std::cin, pass))
		throw std::runtime_error("passphrase: read failed");
	return pass;
}

std::string Passphrase::readConfirmed(const std::string &prompt)
{
	std::string first = Passphrase::read(prompt);
	std::string again = Passphrase::read("Confirm: ");

	const bool same = (first == again);
	/* Wipe the copy we are about to drop regardless of the outcome. */
	OPENSSL_cleanse(again.data(), again.size());
	if (!same) {
		OPENSSL_cleanse(first.data(), first.size());
		throw std::runtime_error("passphrase: entries did not match");
	}
	return first;
}

} // namespace kvault
