// SPDX-License-Identifier: GPL-2.0
/*
 * vaultctl - command-line front end to /dev/kvault.
 *
 * The tool is deliberately thin: it parses arguments, derives keys and prints
 * results. Every authorisation decision happens in the kernel, so running
 * vaultctl as a different user is a real change of subject, not a flag.
 *
 * Milestone v0.1: status and the audit watcher. The remaining verbs are
 * wired to the client but the driver answers ENOSYS until the v0.4/v0.5
 * driver milestones land.
 */
#include <iostream>
#include <string>
#include <vector>

#include <openssl/crypto.h>

#include <poll.h>
#include <pwd.h>
#include <unistd.h>

#include "client/Passphrase.hpp"
#include "client/PolicyLoader.hpp"
#include "client/SealedStore.hpp"
#include "client/VaultClient.hpp"

using namespace kvault;

namespace {

int usage(const char *argv0)
{
	std::cerr <<
	    "usage: " << argv0 << " <command> [args]\n"
	    "\n"
	    "  status                       show vault lifecycle state\n"
	    "  watch                        stream the audit log (blocks)\n"
	    "  unseal [vaultfile]           derive a key and unseal; with a file,\n"
	    "                               take its KDF parameters and load it\n"
	    "  seal                         wipe the key from kernel memory\n"
	    "  put <name>                   store a secret read from stdin\n"
	    "  get <name>                   print a secret to stdout\n"
	    "  del <name>                   delete a secret\n"
	    "  list                         list readable secret names\n"
	    "  rotate <name>                re-encrypt under a fresh nonce\n"
	    "  grant <name> <subject> <perms>  grant permissions\n"
	    "  revoke <name> <subject>      drop a subject's ACL entry\n"
	    "  set-role <user|uid> <role>   bind a user to a role (admin)\n"
	    "  policy <file>                apply a policy file (admin)\n"
	    "  export <file>                write the sealed vault to disk\n"
	    "  import <file>                reload a sealed vault\n"
	    "\n"
	    "  <subject> is a role name (admin, developer, auditor, guest)\n"
	    "  or user:<name|uid>.  <perms> is any of r, w, d, g.\n";
	return 2;
}

int cmdStatus()
{
	VaultClient c;
	const kv_status_arg st = c.status();

	std::cout << "state:            " << VaultClient::stateName(st.state) << "\n"
		  << "secrets:          " << st.secret_count << "\n"
		  << "failed attempts:  " << st.failed_attempts << "/"
					  << st.max_attempts << "\n"
		  << "auto-lock:        " << st.auto_lock_secs << "s\n"
		  << "caller:           uid " << st.caller_uid << " ("
					  << VaultClient::roleName(st.caller_role) << ")\n"
		  << "crypto:           " << st.crypto_driver
					  << (st.accelerated ? " (hardware-accelerated)"
							    : " (software)") << "\n"
		  << "ABI:              " << st.abi_version << "\n";
	return 0;
}

/*
 * Unseal, optionally against a vault file.
 *
 * The salt has to come from the same place the vault did, and that is the file
 * header - not the kernel. A freshly loaded module knows no salt, so deriving
 * from a newly generated one produces a key that cannot authenticate anything
 * in an existing file. (That is exactly the bug this grew out of: unseal
 * succeeded, import then failed with EACCES, and the vault looked corrupt when
 * it was fine.)
 *
 * So: a vault file decides the KDF parameters when one exists, the kernel's
 * recorded parameters decide when the vault is already unsealed-and-populated
 * in memory, and only a genuinely fresh vault generates a new salt.
 */
int cmdUnseal(const std::string &vaultPath)
{
	VaultClient c;
	const kv_status_arg st = c.status();

	Salt salt{};
	unsigned iterations;
	bool importAfter = false;
	std::string pass;

	if (!vaultPath.empty() && SealedStore::exists(vaultPath)) {
		const SealedStore::Header h = SealedStore::readHeader(vaultPath);
		salt = h.salt;
		iterations = h.iterations;
		importAfter = true;
		std::cout << "using the KDF parameters from " << vaultPath
			  << " (" << h.entryCount << " secrets, "
			  << iterations << " iterations)\n";
		pass = Passphrase::read("Passphrase: ");
	} else if (st.initialized) {
		std::memcpy(salt.data(), st.salt, salt.size());
		iterations = st.kdf_iterations;
		pass = Passphrase::read("Passphrase: ");
	} else {
		std::cout << "Vault is uninitialized; this passphrase will "
			     "become the vault's.\n";
		salt = KeyDeriver::randomSalt();
		iterations = KeyDeriver::kDefaultIterations;
		pass = Passphrase::readConfirmed("New passphrase: ");
	}

	MasterKey key;
	if (!key.locked())
		std::cerr << "vaultctl: warning: could not mlock the key buffer; "
			     "it may be swapped to disk\n";

	try {
		KeyDeriver::derive(pass, salt, iterations, key);
	} catch (...) {
		OPENSSL_cleanse(pass.data(), pass.size());
		throw;
	}
	/* The passphrase has done its job. Everything after this point works
	 * from the derived key, and the key itself is wiped by ~MasterKey. */
	OPENSSL_cleanse(pass.data(), pass.size());

	c.unseal(key, salt, iterations);

	if (importAfter) {
		/* A wrong passphrase gets this far - the kernel had no key-check
		 * value to reject it against - and fails here instead, when the
		 * file's own KCV does not match. Report that as what it is. */
		try {
			c.importBlob(SealedStore::load(vaultPath));
		} catch (const VaultError &e) {
			if (e.errnoValue() == EACCES) {
				c.seal();
				std::cerr << "vaultctl: wrong passphrase for "
					  << vaultPath << "\n";
				return 1;
			}
			throw;
		}
	}

	const kv_status_arg after = c.status();
	std::cout << "unsealed (" << after.secret_count << " secrets, "
		  << "auto-lock in " << after.auto_lock_secs << "s)\n";
	return 0;
}

int cmdSeal()
{
	VaultClient c;
	c.seal();
	std::cout << "sealed; key wiped from kernel memory\n";
	return 0;
}

/* Reads the secret from stdin so it never appears in the process's argv, where
 * any user on the system could read it out of /proc/<pid>/cmdline. */
int cmdPut(const std::string &name)
{
	std::vector<std::uint8_t> value;
	char buf[1024];

	/* read() sets failbit at EOF even when it delivered bytes, so the loop
	 * is driven by gcount() rather than by the stream's state. */
	for (;;) {
		std::cin.read(buf, sizeof(buf));
		const std::streamsize n = std::cin.gcount();
		if (n <= 0)
			break;
		value.insert(value.end(), buf, buf + n);
		if (value.size() > KV_SECRET_MAX) {
			std::cerr << "vaultctl: secret exceeds "
				  << KV_SECRET_MAX << " bytes\n";
			return 1;
		}
	}

	/* A trailing newline from `echo` is almost never part of the secret. */
	while (!value.empty() && value.back() == '\n')
		value.pop_back();

	if (value.empty()) {
		std::cerr << "vaultctl: refusing to store an empty secret\n";
		return 1;
	}

	VaultClient c;
	c.put(name, value);
	OPENSSL_cleanse(value.data(), value.size());
	std::cout << "stored " << name << "\n";
	return 0;
}

int cmdGet(const std::string &name)
{
	VaultClient c;
	std::vector<std::uint8_t> value = c.get(name);

	std::cout.write(reinterpret_cast<const char *>(value.data()),
			static_cast<std::streamsize>(value.size()));
	std::cout << "\n" << std::flush;
	OPENSSL_cleanse(value.data(), value.size());
	return 0;
}

int cmdExport(const std::string &path)
{
	VaultClient c;
	std::vector<std::uint8_t> blob = c.exportBlob();
	SealedStore::save(path, blob);
	std::cout << "exported " << blob.size() << " bytes of sealed vault to "
		  << path << "\n";
	return 0;
}

int cmdImport(const std::string &path)
{
	VaultClient c;
	const std::vector<std::uint8_t> blob = SealedStore::load(path);
	c.importBlob(blob);
	std::cout << "imported " << blob.size() << " bytes; "
		  << c.status().secret_count << " secrets now loaded\n";
	return 0;
}

/* Resolves a subject written either as a role name or as user:<name|uid>. */
bool parseSubject(const std::string &spec, std::uint32_t &kind,
		  std::uint32_t &id)
{
	if (spec.rfind("user:", 0) == 0) {
		const std::string who = spec.substr(5);
		kind = KV_SUBJ_UID;
		if (who.find_first_not_of("0123456789") == std::string::npos) {
			id = static_cast<std::uint32_t>(std::stoul(who));
			return true;
		}
		if (const struct passwd *pw = ::getpwnam(who.c_str())) {
			id = pw->pw_uid;
			return true;
		}
		std::cerr << "vaultctl: no such user '" << who << "'\n";
		return false;
	}

	kind = KV_SUBJ_ROLE;
	id = PolicyLoader::roleIdFromName(spec);
	return true;
}

int cmdGrant(const std::string &name, const std::string &subject,
	     const std::string &perms)
{
	std::uint32_t kind, id;
	if (!parseSubject(subject, kind, id))
		return 1;

	VaultClient c;
	c.grant(name, kind, id, PolicyLoader::permsFromString(perms));
	std::cout << "granted " << perms << " on " << name << " to " << subject
		  << "\n";
	return 0;
}

int cmdRevoke(const std::string &name, const std::string &subject)
{
	std::uint32_t kind, id;
	if (!parseSubject(subject, kind, id))
		return 1;

	VaultClient c;
	c.revoke(name, kind, id);
	std::cout << "revoked " << subject << "'s access to " << name << "\n";
	return 0;
}

int cmdSetRole(const std::string &who, const std::string &role)
{
	std::uint32_t uid;
	if (who.find_first_not_of("0123456789") == std::string::npos) {
		uid = static_cast<std::uint32_t>(std::stoul(who));
	} else if (const struct passwd *pw = ::getpwnam(who.c_str())) {
		uid = pw->pw_uid;
	} else {
		std::cerr << "vaultctl: no such user '" << who << "'\n";
		return 1;
	}

	VaultClient c;
	c.setRole(uid, PolicyLoader::roleIdFromName(role));
	std::cout << "uid " << uid << " is now " << role << "\n";
	return 0;
}

/* Applies every binding in a policy file. One failure does not abort the rest:
 * a vault with most of its policy applied and a clear report of what failed is
 * more useful than one left in an unknown half-applied state. */
int cmdPolicy(const std::string &path)
{
	const std::vector<PolicyLoader::Binding> bindings =
	    PolicyLoader::parse(path);

	VaultClient c;
	int failures = 0;

	for (const PolicyLoader::Binding &b : bindings) {
		try {
			c.setRole(b.uid, b.roleId);
			std::cout << "  " << b.user << " (uid " << b.uid << ") -> "
				  << VaultClient::roleName(b.roleId) << "\n";
		} catch (const VaultError &e) {
			std::cerr << "  " << b.user << ": " << e.what() << "\n";
			++failures;
		}
	}

	std::cout << bindings.size() - static_cast<std::size_t>(failures) << "/"
		  << bindings.size() << " bindings applied\n";
	return failures ? 1 : 0;
}

/* Blocks in poll() until the kernel wakes us, which is what makes the wait
 * queue in the driver visible in the demo: no polling loop, no sleep. */
int cmdWatch()
{
	VaultClient audit(VaultClient::Device::Audit);
	struct pollfd pfd{audit.fd(), POLLIN, 0};

	std::cout << "watching audit log (Ctrl-C to stop)\n";
	for (;;) {
		int n = ::poll(&pfd, 1, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			std::perror("poll");
			return 1;
		}
		const kv_audit_rec r = audit.readAudit();
		std::cout << "[" << r.seq << "] uid=" << r.uid
			  << " pid=" << r.pid
			  << " role=" << VaultClient::roleName(r.role)
			  << " op=" << VaultClient::opName(r.op)
			  << " name=" << (r.name[0] ? r.name : "-")
			  << " -> " << (r.result == KV_RESULT_ALLOW ? "ALLOW" : "DENY");
		if (r.err)
			std::cout << " (errno " << -r.err << ")";
		std::cout << "\n" << std::flush;
	}
}

} // namespace

int main(int argc, char **argv)
{
	if (argc < 2)
		return usage(argv[0]);

	const std::string cmd = argv[1];
	try {
		if (cmd == "status")
			return cmdStatus();
		if (cmd == "watch")
			return cmdWatch();
		if (cmd == "unseal")
			return cmdUnseal(argc >= 3 ? argv[2] : "");
		if (cmd == "seal")
			return cmdSeal();
		if (cmd == "put" && argc == 3)
			return cmdPut(argv[2]);
		if (cmd == "get" && argc == 3)
			return cmdGet(argv[2]);
		if (cmd == "export" && argc == 3)
			return cmdExport(argv[2]);
		if (cmd == "import" && argc == 3)
			return cmdImport(argv[2]);
		if (cmd == "grant" && argc == 5)
			return cmdGrant(argv[2], argv[3], argv[4]);
		if (cmd == "revoke" && argc == 4)
			return cmdRevoke(argv[2], argv[3]);
		if (cmd == "set-role" && argc == 4)
			return cmdSetRole(argv[2], argv[3]);
		if (cmd == "policy" && argc == 3)
			return cmdPolicy(argv[2]);

		{
			VaultClient c;
			if (cmd == "list") {
				for (const std::string &n : c.list())
					std::cout << n << "\n";
				return 0;
			}
			if (cmd == "del" && argc == 3) {
				c.remove(argv[2]);
				return 0;
			}
			if (cmd == "rotate" && argc == 3) {
				c.rotate(argv[2]);
				return 0;
			}
		}
		return usage(argv[0]);
	} catch (const VaultError &e) {
		std::cerr << "vaultctl: " << e.what() << "\n";
		return 1;
	} catch (const std::exception &e) {
		std::cerr << "vaultctl: " << e.what() << "\n";
		return 1;
	}
}
