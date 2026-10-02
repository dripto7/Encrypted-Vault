// SPDX-License-Identifier: GPL-2.0
#ifndef KV_VAULT_CLIENT_HPP
#define KV_VAULT_CLIENT_HPP

#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

#include "KeyDeriver.hpp"
#include "kvault_ioctl.h"

namespace kvault {

/* Thrown for anything the kernel rejected. @code carries the errno so callers
 * can distinguish EACCES (the reference monitor said no) from EINVAL (the
 * caller got the request wrong) — the simulator needs that distinction to
 * report "denied" rather than "broken". */
class VaultError : public std::system_error {
public:
	VaultError(int err, const std::string &what)
	    : std::system_error(err, std::generic_category(), what) {}
	int errnoValue() const noexcept { return code().value(); }
};

/*
 * RAII wrapper over /dev/kvault. The file descriptor is owned by the object
 * and closed in the destructor, including when an ioctl throws, so no path
 * through the CLI or the simulator can leak a descriptor to the vault.
 */
class VaultClient {
public:
	enum class Device { Control, Audit };

	explicit VaultClient(Device dev = Device::Control,
			     const std::string &path = "");
	~VaultClient();

	VaultClient(const VaultClient &) = delete;
	VaultClient &operator=(const VaultClient &) = delete;
	VaultClient(VaultClient &&other) noexcept;
	VaultClient &operator=(VaultClient &&other) noexcept;

	int fd() const noexcept { return fd_; }

	kv_status_arg status() const;

	/* Hands the derived key to the kernel once. The caller's copy should be
	 * wiped immediately afterwards; unseal() does not take ownership. */
	void unseal(const MasterKey &key) const;
	void seal() const;

	void put(const std::string &name, const std::vector<std::uint8_t> &plaintext) const;
	std::vector<std::uint8_t> get(const std::string &name) const;
	void remove(const std::string &name) const;
	void rotate(const std::string &name) const;
	std::vector<std::string> list() const;

	void grant(const std::string &name, std::uint32_t subjectKind,
		   std::uint32_t subjectId, std::uint32_t perms) const;
	void revoke(const std::string &name, std::uint32_t subjectKind,
		    std::uint32_t subjectId) const;
	void setRole(std::uint32_t uid, std::uint32_t roleId) const;

	std::vector<std::uint8_t> exportBlob() const;
	void importBlob(const std::vector<std::uint8_t> &blob) const;

	/* Audit device only: one record, blocking until one is available. */
	kv_audit_rec readAudit() const;

	static const char *stateName(std::uint32_t state);
	static const char *opName(std::uint32_t op);
	static const char *roleName(std::uint32_t role);

private:
	void callIoctl(unsigned long request, void *arg, const char *what) const;

	int fd_;
};

} // namespace kvault

#endif
