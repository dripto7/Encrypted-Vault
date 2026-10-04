// SPDX-License-Identifier: GPL-2.0
#include "VaultClient.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <openssl/crypto.h>

namespace kvault {

VaultClient::VaultClient(Device dev, const std::string &path) : fd_(-1)
{
	std::string node = path;
	if (node.empty())
		node = (dev == Device::Audit) ? "/dev/" KV_AUDIT_NAME
					     : "/dev/" KV_DEVICE_NAME;

	/* O_CLOEXEC so a forked-and-exec'd child cannot inherit a descriptor to
	 * the vault that the reference monitor never saw it open. */
	fd_ = ::open(node.c_str(), O_RDWR | O_CLOEXEC);
	if (fd_ < 0 && dev == Device::Audit)
		fd_ = ::open(node.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd_ < 0)
		throw VaultError(errno, "open " + node);
}

VaultClient::~VaultClient()
{
	if (fd_ >= 0)
		::close(fd_);
}

VaultClient::VaultClient(VaultClient &&other) noexcept : fd_(other.fd_)
{
	other.fd_ = -1;
}

VaultClient &VaultClient::operator=(VaultClient &&other) noexcept
{
	if (this != &other) {
		if (fd_ >= 0)
			::close(fd_);
		fd_ = other.fd_;
		other.fd_ = -1;
	}
	return *this;
}

void VaultClient::callIoctl(unsigned long request, void *arg,
			    const char *what) const
{
	if (::ioctl(fd_, request, arg) != 0)
		throw VaultError(errno, what);
}

kv_status_arg VaultClient::status() const
{
	kv_status_arg st{};
	callIoctl(KVAULT_STATUS, &st, "KVAULT_STATUS");
	return st;
}

void VaultClient::unseal(const MasterKey &key, const Salt &salt,
			 unsigned iterations) const
{
	kv_unseal_arg arg{};
	arg.abi_version    = KV_ABI_VERSION;
	arg.kdf_iterations = iterations;
	std::memcpy(arg.salt, salt.data(), KV_SALT_LEN);
	std::memcpy(arg.key, key.data(), KV_KEY_LEN);
	try {
		callIoctl(KVAULT_UNSEAL, &arg, "KVAULT_UNSEAL");
	} catch (...) {
		/* The staging copy must not survive a failed attempt either. */
		OPENSSL_cleanse(arg.key, sizeof(arg.key));
		throw;
	}
	OPENSSL_cleanse(arg.key, sizeof(arg.key));
}

void VaultClient::seal() const
{
	callIoctl(KVAULT_SEAL, nullptr, "KVAULT_SEAL");
}

/* --- secrets ----------------------------------------------------------- */

void VaultClient::put(const std::string &name,
		      const std::vector<std::uint8_t> &plaintext) const
{
	if (name.size() >= KV_NAME_MAX)
		throw VaultError(ENAMETOOLONG, "secret name too long");
	if (plaintext.size() > KV_SECRET_MAX)
		throw VaultError(E2BIG, "secret larger than KV_SECRET_MAX");

	kv_secret_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	arg.len = static_cast<std::uint32_t>(plaintext.size());
	std::memcpy(arg.data, plaintext.data(), plaintext.size());
	try {
		callIoctl(KVAULT_PUT, &arg, "KVAULT_PUT");
	} catch (...) {
		OPENSSL_cleanse(arg.data, sizeof(arg.data));
		throw;
	}
	OPENSSL_cleanse(arg.data, sizeof(arg.data));
}

std::vector<std::uint8_t> VaultClient::get(const std::string &name) const
{
	if (name.size() >= KV_NAME_MAX)
		throw VaultError(ENAMETOOLONG, "secret name too long");

	kv_secret_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	arg.len = KV_SECRET_MAX;   /* capacity in, real length out */
	try {
		callIoctl(KVAULT_GET, &arg, "KVAULT_GET");
	} catch (...) {
		OPENSSL_cleanse(arg.data, sizeof(arg.data));
		throw;
	}

	std::vector<std::uint8_t> out(arg.data, arg.data + arg.len);
	OPENSSL_cleanse(arg.data, sizeof(arg.data));
	return out;
}

void VaultClient::remove(const std::string &name) const
{
	kv_name_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	callIoctl(KVAULT_DELETE, &arg, "KVAULT_DELETE");
}

void VaultClient::rotate(const std::string &name) const
{
	kv_name_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	callIoctl(KVAULT_ROTATE, &arg, "KVAULT_ROTATE");
}

std::vector<std::string> VaultClient::list() const
{
	kv_list_arg arg{};
	callIoctl(KVAULT_LIST, &arg, "KVAULT_LIST");

	std::vector<std::string> names;
	const std::uint32_t n = arg.count > KV_LIST_MAX ? KV_LIST_MAX : arg.count;
	names.reserve(n);
	for (std::uint32_t i = 0; i < n; ++i) {
		arg.names[i][KV_NAME_MAX - 1] = '\0';
		names.emplace_back(arg.names[i]);
	}
	return names;
}

/* --- access control ---------------------------------------------------- */

void VaultClient::grant(const std::string &name, std::uint32_t subjectKind,
			std::uint32_t subjectId, std::uint32_t perms) const
{
	kv_grant_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	arg.subject_kind = subjectKind;
	arg.subject_id   = subjectId;
	arg.perms        = perms;
	callIoctl(KVAULT_GRANT, &arg, "KVAULT_GRANT");
}

void VaultClient::revoke(const std::string &name, std::uint32_t subjectKind,
			 std::uint32_t subjectId) const
{
	kv_grant_arg arg{};
	std::strncpy(arg.name, name.c_str(), KV_NAME_MAX - 1);
	arg.subject_kind = subjectKind;
	arg.subject_id   = subjectId;
	callIoctl(KVAULT_REVOKE, &arg, "KVAULT_REVOKE");
}

void VaultClient::setRole(std::uint32_t uid, std::uint32_t roleId) const
{
	kv_setrole_arg arg{};
	arg.uid     = uid;
	arg.role_id = roleId;
	callIoctl(KVAULT_SET_ROLE, &arg, "KVAULT_SET_ROLE");
}

/* --- persistence ------------------------------------------------------- */

std::vector<std::uint8_t> VaultClient::exportBlob() const
{
	std::vector<std::uint8_t> buf(KV_BLOB_MAX);
	kv_blob_arg arg{};
	arg.buf = reinterpret_cast<std::uint64_t>(buf.data());
	arg.len = KV_BLOB_MAX;
	callIoctl(KVAULT_EXPORT, &arg, "KVAULT_EXPORT");
	buf.resize(arg.len);
	return buf;
}

void VaultClient::importBlob(const std::vector<std::uint8_t> &blob) const
{
	if (blob.size() > KV_BLOB_MAX)
		throw VaultError(E2BIG, "sealed vault larger than KV_BLOB_MAX");

	kv_blob_arg arg{};
	arg.buf = reinterpret_cast<std::uint64_t>(blob.data());
	arg.len = static_cast<std::uint32_t>(blob.size());
	callIoctl(KVAULT_IMPORT, &arg, "KVAULT_IMPORT");
}

/* --- audit ------------------------------------------------------------- */

kv_audit_rec VaultClient::readAudit() const
{
	kv_audit_rec rec{};
	ssize_t n = ::read(fd_, &rec, sizeof(rec));
	if (n < 0)
		throw VaultError(errno, "read audit");
	if (n != static_cast<ssize_t>(sizeof(rec)))
		throw VaultError(EIO, "short audit record");
	rec.name[KV_NAME_MAX - 1] = '\0';
	return rec;
}

const char *VaultClient::stateName(std::uint32_t state)
{
	switch (state) {
	case KV_STATE_SEALED:       return "SEALED";
	case KV_STATE_UNSEALED:     return "UNSEALED";
	case KV_STATE_AUTO_LOCKED:  return "AUTO_LOCKED";
	case KV_STATE_LOCKED_OUT:   return "LOCKED_OUT";
	default:                    return "UNKNOWN";
	}
}

const char *VaultClient::roleName(std::uint32_t role)
{
	switch (role) {
	case KV_ROLE_ADMIN:      return "admin";
	case KV_ROLE_DEVELOPER:  return "developer";
	case KV_ROLE_AUDITOR:    return "auditor";
	case KV_ROLE_GUEST:      return "guest";
	default:                 return "none";
	}
}

const char *VaultClient::opName(std::uint32_t op)
{
	switch (op) {
	case KV_OP_UNSEAL:     return "UNSEAL";
	case KV_OP_SEAL:       return "SEAL";
	case KV_OP_PUT:        return "PUT";
	case KV_OP_GET:        return "GET";
	case KV_OP_DELETE:     return "DELETE";
	case KV_OP_LIST:       return "LIST";
	case KV_OP_ROTATE:     return "ROTATE";
	case KV_OP_GRANT:      return "GRANT";
	case KV_OP_REVOKE:     return "REVOKE";
	case KV_OP_SET_ROLE:   return "SET_ROLE";
	case KV_OP_EXPORT:     return "EXPORT";
	case KV_OP_IMPORT:     return "IMPORT";
	case KV_OP_AUTO_LOCK:  return "AUTO_LOCK";
	case KV_OP_LOCKOUT:    return "LOCKOUT";
	default:               return "?";
	}
}

} // namespace kvault
