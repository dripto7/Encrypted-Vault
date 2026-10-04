// SPDX-License-Identifier: GPL-2.0
#include "SealedStore.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace kvault {

namespace {

/* Closes its descriptor however the scope is left, including by exception. */
class Fd {
public:
	explicit Fd(int fd) : fd_(fd) {}
	~Fd() { if (fd_ >= 0) ::close(fd_); }
	Fd(const Fd &) = delete;
	Fd &operator=(const Fd &) = delete;
	int get() const noexcept { return fd_; }
	int release() noexcept { const int f = fd_; fd_ = -1; return f; }
private:
	int fd_;
};

std::string dirNameOf(const std::string &path)
{
	const std::size_t slash = path.find_last_of('/');
	if (slash == std::string::npos)
		return ".";
	if (slash == 0)
		return "/";
	return path.substr(0, slash);
}

[[noreturn]] void fail(const std::string &what)
{
	throw std::system_error(errno, std::generic_category(), what);
}

void writeAll(int fd, const std::uint8_t *data, std::size_t len)
{
	std::size_t done = 0;
	while (done < len) {
		/* write() may transfer less than asked even for a regular file;
		 * treating a short write as success silently truncates. */
		const ssize_t n = ::write(fd, data + done, len - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fail("write");
		}
		done += static_cast<std::size_t>(n);
	}
}

std::uint32_t le32(const std::uint8_t *p)
{
	return static_cast<std::uint32_t>(p[0]) |
	       (static_cast<std::uint32_t>(p[1]) << 8) |
	       (static_cast<std::uint32_t>(p[2]) << 16) |
	       (static_cast<std::uint32_t>(p[3]) << 24);
}

} // namespace

bool SealedStore::exists(const std::string &path)
{
	struct stat st{};
	return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
	       static_cast<std::size_t>(st.st_size) >= sizeof(kv_file_header);
}

SealedStore::Header SealedStore::readHeader(const std::string &path)
{
	const std::vector<std::uint8_t> blob = load(path);
	if (blob.size() < sizeof(kv_file_header))
		throw std::runtime_error(path + ": too short to be a vault file");

	/* Field offsets follow struct kv_file_header in kvault_ioctl.h:
	 * magic, version, kdf_iterations, entry_count, salt[16], kcv[32]. */
	if (le32(blob.data()) != KV_FILE_MAGIC)
		throw std::runtime_error(path + ": not a KVault vault file");
	if (le32(blob.data() + 4) != KV_FILE_VERSION)
		throw std::runtime_error(path + ": unsupported vault version");

	Header h{};
	h.iterations = le32(blob.data() + 8);
	h.entryCount = le32(blob.data() + 12);
	std::memcpy(h.salt.data(), blob.data() + 16, KV_SALT_LEN);

	if (h.iterations == 0)
		throw std::runtime_error(path + ": invalid iteration count");
	return h;
}

void SealedStore::save(const std::string &path,
		       const std::vector<std::uint8_t> &blob)
{
	const std::string tmp = path + ".tmp";

	{
		/* 0600: the file is ciphertext, but there is no reason for
		 * anyone else to have a copy to attack offline. */
		Fd fd(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			     0600));
		if (fd.get() < 0)
			fail("open " + tmp);

		writeAll(fd.get(), blob.data(), blob.size());

		if (::fsync(fd.get()) != 0)
			fail("fsync " + tmp);
	}

	if (::rename(tmp.c_str(), path.c_str()) != 0) {
		::unlink(tmp.c_str());
		fail("rename " + tmp + " -> " + path);
	}

	/* Make the rename itself durable. */
	const std::string dir = dirNameOf(path);
	Fd dirfd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if (dirfd.get() < 0)
		fail("open " + dir);
	if (::fsync(dirfd.get()) != 0)
		fail("fsync " + dir);
}

std::vector<std::uint8_t> SealedStore::load(const std::string &path)
{
	Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
	if (fd.get() < 0)
		fail("open " + path);

	struct stat st{};
	if (::fstat(fd.get(), &st) != 0)
		fail("fstat " + path);
	if (!S_ISREG(st.st_mode))
		throw std::runtime_error(path + ": not a regular file");

	std::vector<std::uint8_t> blob(static_cast<std::size_t>(st.st_size));
	std::size_t done = 0;
	while (done < blob.size()) {
		const ssize_t n = ::read(fd.get(), blob.data() + done,
					 blob.size() - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fail("read " + path);
		}
		if (n == 0)
			break;   /* file shrank under us */
		done += static_cast<std::size_t>(n);
	}
	blob.resize(done);
	return blob;
}

} // namespace kvault
