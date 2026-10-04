// SPDX-License-Identifier: GPL-2.0
/* kvsim - the multi-user access simulator. */
#include <iostream>
#include <string>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ScenarioLoader.hpp"
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

bool seedVault(const ScenarioLoader::Scenario &sc,
	       std::vector<PolicyLoader::Binding> &bindings)
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

	for (const PolicyLoader::Binding &b : bindings)
		c.setRole(b.uid, b.roleId);

	for (const ScenarioLoader::Secret &sec : sc.secrets)
		c.put(sec.name, {sec.value.begin(), sec.value.end()});

	for (const ScenarioLoader::Grant &g : sc.grants)
		c.grant(g.name, g.subjectKind, g.subjectId, g.perms);

	return true;
}

/* The role a principal holds, from the policy file. It decides which SimUser
 * subclass represents them - the scenario file says what they attempt, the
 * policy file says who they are. */
std::uint32_t roleOf(const std::string &user,
		     const std::vector<PolicyLoader::Binding> &bindings)
{
	for (const PolicyLoader::Binding &b : bindings)
		if (b.user == user)
			return b.roleId;
	return KV_ROLE_GUEST;
}

SimUserPtr makeUser(const std::string &name, uid_t uid, std::uint32_t role)
{
	switch (role) {
	case KV_ROLE_ADMIN:     return std::make_unique<AdminUser>(name, uid);
	case KV_ROLE_DEVELOPER: return std::make_unique<DeveloperUser>(name, uid);
	case KV_ROLE_AUDITOR:   return std::make_unique<AuditorUser>(name, uid);
	default:                return std::make_unique<GuestUser>(name, uid);
	}
}

int main(int argc, char **argv)
{
	if (::geteuid() != 0) {
		std::cerr << "kvsim: must run as root so it can drop to each "
			     "simulated user\n";
		return 2;
	}

	const std::string policyPath   = (argc >= 2) ? argv[1]
						     : "configs/policy.conf";
	const std::string scenarioPath = (argc >= 3) ? argv[2]
						     : "configs/scenario-default.conf";

	std::vector<PolicyLoader::Binding> bindings;
	ScenarioLoader::Scenario scenario;
	try {
		bindings = PolicyLoader::parse(policyPath);
		scenario = ScenarioLoader::parse(scenarioPath);
	} catch (const std::exception &e) {
		std::cerr << "kvsim: " << e.what() << "\n";
		return 2;
	}

	std::cout << "policy:   " << policyPath << " (" << bindings.size()
		  << " bindings)\n"
		  << "scenario: " << scenarioPath << " ("
		  << scenario.secrets.size() << " secrets, "
		  << scenario.grants.size() << " grants, "
		  << scenario.users.size() << " principals)\n";

	try {
		if (!seedVault(scenario, bindings))
			return 2;
	} catch (const VaultError &e) {
		std::cerr << "kvsim: seeding failed: " << e.what() << "\n";
		return 2;
	}

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

	std::vector<SimUserPtr> users;
	for (const ScenarioLoader::UserSteps &us : scenario.users) {
		SimUserPtr u = makeUser(us.user, lookupUid(us.user),
					roleOf(us.user, bindings));
		for (const Step &st : us.steps)
			u->addStep(st);
		users.push_back(std::move(u));
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
