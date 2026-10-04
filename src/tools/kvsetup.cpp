// SPDX-License-Identifier: GPL-2.0
/* kvsetup - create the system users the simulator drives. */
#include <grp.h>
#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

const std::array<const char *, 4> kUsers = {
    "kv_alice", "kv_bob", "kv_eve", "kv_carol"
};

struct GroupSpec {
	const char *group;
	std::array<const char *, 3> members;   /* nullptr-terminated */
};

const std::array<GroupSpec, 2> kGroups = {{
    {"kvault",  {"kv_alice", "kv_bob", "kv_eve"}},
    {"kvaudit", {"kv_carol", nullptr, nullptr}},
}};

/* A name that reaches execvp must not be able to turn into an option or a
 * second argument. Restricting to [a-z0-9_] and requiring a letter first is
 * stricter than useradd's own rules, which is the right direction. */
bool validName(const std::string &name)
{
	if (name.empty() || name.size() > 32)
		return false;
	if (!(name[0] >= 'a' && name[0] <= 'z'))
		return false;
	for (const char c : name) {
		const bool ok = (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '_';
		if (!ok)
			return false;
	}
	return true;
}

int runTool(const std::string &prog, const std::vector<std::string> &args)
{
	const pid_t pid = ::fork();
	if (pid < 0) {
		std::perror("fork");
		return -1;
	}

	if (pid == 0) {
		std::vector<char *> argv;
		argv.push_back(const_cast<char *>(prog.c_str()));
		for (const std::string &a : args)
			argv.push_back(const_cast<char *>(a.c_str()));
		argv.push_back(nullptr);

		::execvp(prog.c_str(), argv.data());
		/* Only reached if exec failed; _exit rather than exit so the
		 * parent's stdio buffers are not flushed twice. */
		std::perror(("execvp " + prog).c_str());
		::_exit(127);
	}

	int status = 0;
	if (::waitpid(pid, &status, 0) < 0) {
		std::perror("waitpid");
		return -1;
	}
	if (!WIFEXITED(status)) {
		std::cerr << "kvsetup: " << prog << " did not exit normally\n";
		return -1;
	}
	return WEXITSTATUS(status);
}

/* --system: these are service accounts, not login accounts. nologin and no
 * home directory because nobody should be able to log in as a principal. */
int runUseradd(const std::string &name)
{
	return runTool("useradd", {"--system", "--no-create-home",
				   "--shell", "/usr/sbin/nologin", name});
}

} // namespace

int main()
{
	if (::geteuid() != 0) {
		std::cerr << "kvsetup: must run as root to create users\n";
		return 2;
	}

	int failures = 0;

	for (const char *u : kUsers) {
		const std::string name = u;
		if (!validName(name)) {
			std::cerr << "kvsetup: rejecting invalid user name '"
				  << name << "'\n";
			++failures;
			continue;
		}

		/* getpwnam rather than parsing /etc/passwd: the account may come
		 * from LDAP or any other NSS source, and either way it exists. */
		if (const struct passwd *pw = ::getpwnam(name.c_str())) {
			std::cout << "exists:  " << name << " (uid "
				  << pw->pw_uid << ")\n";
			continue;
		}

		const int rc = runUseradd(name);
		if (rc != 0) {
			std::cerr << "kvsetup: useradd " << name
				  << " failed (status " << rc << ")\n";
			++failures;
			continue;
		}

		const struct passwd *pw = ::getpwnam(name.c_str());
		std::cout << "created: " << name << " (uid "
			  << (pw ? std::to_string(pw->pw_uid) : "?") << ")\n";
	}

	for (const GroupSpec &g : kGroups) {
		if (::getgrnam(g.group)) {
			std::cout << "exists:  group " << g.group << "\n";
		} else if (runTool("groupadd", {"--system", g.group}) != 0) {
			std::cerr << "kvsetup: groupadd " << g.group
				  << " failed\n";
			++failures;
			continue;
		} else {
			std::cout << "created: group " << g.group << "\n";
		}

		for (const char *m : g.members) {
			if (!m)
				break;
			if (runTool("usermod", {"-aG", g.group, m}) != 0) {
				std::cerr << "kvsetup: adding " << m << " to "
					  << g.group << " failed\n";
				++failures;
			} else {
				std::cout << "         " << m << " in "
					  << g.group << "\n";
			}
		}
	}

	std::cout <<
	    "\nRoles are not a property of the account: they are bound inside the\n"
	    "vault with `vaultctl set-role <uid> <role>`, or loaded from\n"
	    "configs/policy.conf. Deleting these users does not remove the\n"
	    "bindings, so a useradd/userdel cycle can hand a recycled UID an\n"
	    "inherited role - see docs/06-test-report.md.\n";

	return failures ? 1 : 0;
}
