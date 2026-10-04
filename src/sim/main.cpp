// SPDX-License-Identifier: GPL-2.0
/*
 * kvsim - the multi-user access simulator.
 *
 * The parent process builds the scenario, then forks one child per simulated
 * user. Each child calls setresuid() to drop irreversibly to that user's real
 * UID before touching the vault, so when the driver calls current_uid() it
 * sees a genuinely different subject: nothing about the identity is asserted
 * by the process itself.
 *
 * Results travel back over a pipe rather than shared memory, because the
 * children have already dropped privileges and must not be able to write into
 * the parent's state.
 *
 * Must be started as root (it needs to drop to several different users), which
 * is also the interesting case: even running as root, each child is subject to
 * the kernel's check once it has dropped.
 */
#include <iostream>
#include <string>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "SimUser.hpp"
#include "client/AuditViewer.hpp"
#include "client/PolicyLoader.hpp"

using namespace kvault;
using namespace kvault::sim;

namespace {

/* Resolve a system user, or report that the setup script has not been run. */
uid_t lookupUid(const std::string &user)
{
	const struct passwd *pw = ::getpwnam(user.c_str());
	if (!pw) {
		std::cerr << "kvsim: no such user '" << user
			  << "' - run build/bin/kvsetup first\n";
		std::exit(2);
	}
	return pw->pw_uid;
}

/*
 * Become @user completely, with no way back.
 *
 * The order matters and is the classic place to get this wrong:
 *
 *  1. initgroups() installs the user's supplementary groups. Without it the
 *     child keeps root's groups, so a device node owned by group kvault would
 *     still be openable for the wrong reason and the simulation would prove
 *     nothing about that user's access.
 *  2. setresgid() before setresuid(). Once the real UID is no longer 0 the
 *     process has lost the privilege needed to change its groups, so a drop
 *     done the other way round silently leaves the group IDs at root's.
 *  3. setresuid() sets the saved-set-uid too, which is what makes the drop
 *     irreversible; seteuid() alone would leave root in the saved slot for the
 *     child to pick back up.
 *
 * The attempt to regain root afterwards is not paranoia for its own sake: it is
 * the only way to be sure the drop actually took, and a simulation whose
 * children are secretly still root measures nothing.
 */
void dropTo(const std::string &user, uid_t uid)
{
	const struct passwd *pw = ::getpwnam(user.c_str());
	if (!pw) {
		std::cerr << "kvsim: " << user << " vanished between lookup and fork\n";
		std::exit(3);
	}

	if (::initgroups(user.c_str(), pw->pw_gid) != 0) {
		std::perror("initgroups");
		std::exit(3);
	}
	if (::setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0) {
		std::perror("setresgid");
		std::exit(3);
	}
	if (::setresuid(uid, uid, uid) != 0) {
		std::perror("setresuid");
		std::exit(3);
	}

	if (::setresuid(0, 0, 0) == 0) {
		std::cerr << "kvsim: privilege drop was reversible - aborting\n";
		std::exit(3);
	}
}

int printTable(const std::vector<StepResult> &rows)
{
	std::printf("\n%-10s %-10s %-7s %-20s %-8s %-8s %s\n",
		    "USER", "ROLE", "OP", "SECRET", "RESULT", "EXPECTED", "VERDICT");
	std::printf("%s\n", std::string(78, '-').c_str());

	int pass = 0;
	for (const StepResult &r : rows) {
		const bool ok = (r.allowed == r.expected);
		pass += ok ? 1 : 0;
		std::printf("%-10s %-10s %-7s %-20s %-8s %-8s %s\n",
			    r.user.c_str(), r.role.c_str(), r.op.c_str(),
			    r.name.empty() ? "-" : r.name.c_str(),
			    r.allowed ? "allow" : "deny",
			    r.expected ? "allow" : "deny",
			    ok ? "PASS" : "FAIL");
	}
	std::printf("\n%d/%zu steps behaved as the policy says they should\n",
		    pass, rows.size());
	return static_cast<int>(rows.size()) - pass;
}

} // namespace

/*
 * Seeds the vault for the scenario.
 *
 * Done by the parent, as root, before any child exists: the whole point is that
 * the children cannot do this for themselves. Returns false if the vault is not
 * ready, rather than trying to unseal it - the passphrase belongs to whoever is
 * running the simulation, not to the simulation.
 */
bool seedVault()
{
	VaultClient c;
	const kv_status_arg st = c.status();

	if (st.state != KV_STATE_UNSEALED) {
		std::cerr << "kvsim: the vault is " 
			  << VaultClient::stateName(st.state)
			  << "; unseal it first:\n"
			     "         sudo vaultctl unseal [vaultfile]\n";
		return false;
	}

	try {
		for (const PolicyLoader::Binding &b :
		     PolicyLoader::parse("configs/policy.conf"))
			c.setRole(b.uid, b.roleId);
	} catch (const std::exception &e) {
		std::cerr << "kvsim: policy: " << e.what() << "\n";
		return false;
	}

	const std::string dbValue  = "s3cr3t-db-pa55word";
	const std::string tlsValue = "tls-private-key-material";
	c.put("db_password", {dbValue.begin(), dbValue.end()});
	c.put("tls_key", {tlsValue.begin(), tlsValue.end()});

	/* The developer role may read db_password and nothing else. tls_key is
	 * granted to bob by UID, so the table below shows role-based and
	 * identity-based ACLs side by side. */
	c.grant("db_password", KV_SUBJ_ROLE, KV_ROLE_DEVELOPER, KV_PERM_READ);
	if (const struct passwd *pw = ::getpwnam("kv_bob"))
		c.grant("tls_key", KV_SUBJ_UID, pw->pw_uid, KV_PERM_READ);

	return true;
}

int main()
{
	if (::geteuid() != 0) {
		std::cerr << "kvsim: must run as root so it can drop to each "
			     "simulated user\n";
		return 2;
	}

	if (!seedVault())
		return 2;

	/* Watch the audit stream for the duration. The kernel wakes this thread
	 * as each decision is recorded, so what it collects is the reference
	 * monitor's own account of the run - not the simulator's. */
	AuditViewer watcher;
	try {
		watcher.start();
	} catch (const VaultError &e) {
		std::cerr << "kvsim: cannot watch the audit log: " << e.what()
			  << "\n";
	}

	/*
	 * The scenario.
	 *
	 * alice is a developer granted READ on db_password; bob is a developer
	 * who was granted tls_key by UID instead; eve is a guest; carol audits.
	 * Each step records what the policy says should happen, so an expected
	 * denial is a pass and an unexpected success is a failure.
	 */
	std::vector<SimUserPtr> users;
	{
		auto alice = std::make_unique<DeveloperUser>("kv_alice",
							    lookupUid("kv_alice"));
		alice->addStep({Step::Op::Get, "db_password", "", true});
		alice->addStep({Step::Op::Put, "db_password", "overwritten", false});
		alice->addStep({Step::Op::Get, "tls_key", "", false});
		alice->addStep({Step::Op::Delete, "db_password", "", false});
		alice->addStep({Step::Op::List, "", "", true});
		/* A developer may create a secret of her own, and owns what she
		 * creates - creation is governed by role, since a secret that
		 * does not exist yet has no ACL to consult. */
		alice->addStep({Step::Op::Put, "alice_notes", "hers", true});
		alice->addStep({Step::Op::Get, "alice_notes", "", true});
		users.push_back(std::move(alice));

		auto bob = std::make_unique<DeveloperUser>("kv_bob",
							  lookupUid("kv_bob"));
		/* Same role as alice, different ACLs: the role is not the
		 * decision, the ACL is. */
		bob->addStep({Step::Op::Get, "tls_key", "", true});
		bob->addStep({Step::Op::Get, "db_password", "", true});
		bob->addStep({Step::Op::Rotate, "tls_key", "", false});
		users.push_back(std::move(bob));

		auto eve = std::make_unique<GuestUser>("kv_eve", lookupUid("kv_eve"));
		eve->addStep({Step::Op::Get, "db_password", "", false});
		eve->addStep({Step::Op::Get, "tls_key", "", false});
		/* A guest may not create either: without this check eve could
		 * squat a name an application expects to own. */
		eve->addStep({Step::Op::Put, "backdoor", "mine", false});
		eve->addStep({Step::Op::List, "", "", true});   /* allowed, but empty */
		users.push_back(std::move(eve));

		auto carol = std::make_unique<AuditorUser>("kv_carol",
							  lookupUid("kv_carol"));
		carol->addStep({Step::Op::ReadAudit, "", "", true});
		carol->addStep({Step::Op::Get, "db_password", "", false});
		users.push_back(std::move(carol));
	}

	std::vector<StepResult> all;

	for (const SimUserPtr &u : users) {
		int pipefd[2];
		if (::pipe(pipefd) != 0) {
			std::perror("pipe");
			return 1;
		}

		const pid_t pid = ::fork();
		if (pid < 0) {
			std::perror("fork");
			return 1;
		}

		if (pid == 0) {
			::close(pipefd[0]);
			dropTo(u->name(), u->uid());

			const std::vector<StepResult> rows = u->run();
			for (const StepResult &r : rows) {
				/* One line per step, parsed by the parent. The
				 * format is deliberately trivial: a child that
				 * has dropped privileges should not be running
				 * a serialiser. */
				const std::string line =
				    r.user + "|" + r.role + "|" + r.op + "|" +
				    r.name + "|" + (r.allowed ? "1" : "0") + "|" +
				    (r.expected ? "1" : "0") + "|" +
				    std::to_string(r.err) + "\n";
				ssize_t unused = ::write(pipefd[1], line.data(),
							 line.size());
				(void)unused;
			}
			::close(pipefd[1]);
			::_exit(0);
		}

		::close(pipefd[1]);
		std::string buf;
		char chunk[256];
		ssize_t n;
		while ((n = ::read(pipefd[0], chunk, sizeof(chunk))) > 0)
			buf.append(chunk, static_cast<size_t>(n));
		::close(pipefd[0]);

		int status = 0;
		::waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			std::cerr << "kvsim: child for " << u->name()
				  << " exited abnormally\n";

		size_t pos = 0;
		while (pos < buf.size()) {
			const size_t nl = buf.find('\n', pos);
			if (nl == std::string::npos)
				break;
			const std::string line = buf.substr(pos, nl - pos);
			pos = nl + 1;

			std::vector<std::string> f;
			size_t p = 0;
			while (f.size() < 7) {
				const size_t bar = line.find('|', p);
				if (bar == std::string::npos) {
					f.push_back(line.substr(p));
					break;
				}
				f.push_back(line.substr(p, bar - p));
				p = bar + 1;
			}
			if (f.size() == 7)
				all.push_back({f[0], f[1], f[2], f[3],
					       f[4] == "1", f[5] == "1",
					       std::stoi(f[6])});
		}
	}

	const int failures = printTable(all);

	/* Give the watcher a moment to drain the last wake-up, then report what
	 * the kernel logged. Every denial above should appear here: an access
	 * that was refused but not recorded would be the worst outcome of all. */
	::usleep(300000);
	watcher.stop();
	const std::vector<kv_audit_rec> records = watcher.take();

	std::printf("\n--- the kernel's own audit log for this run (%zu records)\n",
		    records.size());
	int denials = 0;
	for (const kv_audit_rec &r : records) {
		if (r.result == KV_RESULT_DENY)
			++denials;
		std::printf("  %s\n", AuditViewer::format(r).c_str());
	}
	std::printf("  %d of %zu records are denials\n", denials, records.size());

	return failures ? 1 : 0;
}
