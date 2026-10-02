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

#include <poll.h>
#include <unistd.h>

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
		  << "AES-NI:           " << (st.has_aesni ? "yes" : "no") << "\n"
		  << "ABI:              " << st.abi_version << "\n";
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

		std::cerr << "vaultctl: '" << cmd
			  << "' is not implemented yet (driver milestone v0.4)\n";
		return 3;
	} catch (const VaultError &e) {
		std::cerr << "vaultctl: " << e.what() << "\n";
		return 1;
	} catch (const std::exception &e) {
		std::cerr << "vaultctl: " << e.what() << "\n";
		return 1;
	}
}
