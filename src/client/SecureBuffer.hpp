// SPDX-License-Identifier: GPL-2.0
#ifndef KV_SECURE_BUFFER_HPP
#define KV_SECURE_BUFFER_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/mman.h>

namespace kvault {

/*
 * A fixed-size byte buffer that wipes itself on destruction and asks the
 * kernel not to swap its pages out.
 *
 * Two problems it solves:
 *  - a plain std::vector<uint8_t> leaves the key in freed heap memory, and
 *    a std::memset the compiler can prove is unobservable may be removed
 *    entirely, so the wipe goes through a volatile pointer;
 *  - anonymous pages can be written to swap, which would put the derived key
 *    on disk in the clear, so the buffer is mlock()ed.
 *
 * mlock can fail on RLIMIT_MEMLOCK; that is reported through locked() rather
 * than thrown, because failing to lock is a weaker guarantee, not a broken
 * program, and the caller decides whether to warn.
 */
template <std::size_t N>
class SecureBuffer {
public:
	SecureBuffer() : locked_(false)
	{
		std::memset(data_, 0, N);
		locked_ = (::mlock(data_, N) == 0);
	}

	~SecureBuffer()
	{
		wipe();
		if (locked_)
			::munlock(data_, N);
	}

	/* Key material must not be copied around: every copy is another place
	 * that has to be wiped. Moves are not needed either. */
	SecureBuffer(const SecureBuffer &) = delete;
	SecureBuffer &operator=(const SecureBuffer &) = delete;

	void wipe() noexcept
	{
		volatile unsigned char *p = data_;
		for (std::size_t i = 0; i < N; ++i)
			p[i] = 0;
	}

	unsigned char *data() noexcept { return data_; }
	const unsigned char *data() const noexcept { return data_; }
	static constexpr std::size_t size() noexcept { return N; }
	bool locked() const noexcept { return locked_; }

private:
	unsigned char data_[N];
	bool locked_;
};

} // namespace kvault

#endif
