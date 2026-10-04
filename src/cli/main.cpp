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
#include <unistd.h>

#include "client/Passphrase.hpp"
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
	    "  unseal                       derive a key from a passphrase and unseal\n"
	    "  seal                         wipe the key from kernel memory\n"
	    "  put <name>                   store a secret read from stdin\n"
	    "  get <name>                   print a secret to stdout\n"
	    "  del <name>                   delete a secret\n"
	    "  list                         list readable secret names\n"
	    "  rotate <name>                re-encrypt under a fresh nonce\n"
	    "  grant <name> <role> <perms>  grant permissions to a role\n"
	    "  revoke <name> <role>         drop a role's ACL entry\n";
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
 * Unseal.
 *
 * The salt and iteration count are the kernel's, not the CLI's: on an
 * initialized vault STATUS hands them back so the same passphrase derives the
 * same key, and only an uninitialized vault generates fresh ones. Keeping that
 * decision on the kernel side means two different user-space tools cannot
 * disagree about which salt belongs to this vault.
 */
int cmdUnseal()
{
	VaultClient c;
	const kv_status_arg st = c.status();

	Salt salt{};
	unsigned iterations;
	std::string pass;

	if (st.initialized) {
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
			return cmdUnseal();
		if (cmd == "seal")
			return cmdSeal();
		if (cmd == "put" && argc == 3)
			return cmdPut(argv[2]);
		if (cmd == "get" && argc == 3)
			return cmdGet(argv[2]);

		/* The remaining verbs reach the driver, which answers ENOSYS
		 * until the v0.5 milestone. Letting them through means the
		 * error the user sees is the kernel's, not a guess. */
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
