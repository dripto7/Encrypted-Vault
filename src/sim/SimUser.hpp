// SPDX-License-Identifier: GPL-2.0
#ifndef KV_SIM_USER_HPP
#define KV_SIM_USER_HPP

#include <memory>
#include <string>
#include <vector>

#include "client/VaultClient.hpp"

namespace kvault::sim {

/* One scripted operation and what the scenario expects to happen. Recording
 * the expectation is what turns the simulator from a demo into a test: a
 * denial that was supposed to be a denial is a pass, not a failure. */
struct Step {
	enum class Op { Get, Put, List, Delete, Rotate, ReadAudit };

	Op          op;
	std::string name;
	std::string value;
	bool        expectAllowed;
};

struct StepResult {
	std::string user;
	std::string role;
	std::string op;
	std::string name;
	bool        allowed;
	bool        expected;
	int         err;
};

class SimUser {
public:
	SimUser(std::string name, uid_t uid, std::uint32_t role);
	virtual ~SimUser() = default;

	const std::string &name() const noexcept { return name_; }
	uid_t uid() const noexcept { return uid_; }
	std::uint32_t role() const noexcept { return role_; }
	const char *roleName() const { return VaultClient::roleName(role_); }

	void addStep(Step s) { steps_.push_back(std::move(s)); }

	/* Runs the scripted steps in this process, which is expected to have
	 * already dropped privileges. Returns one result per step. */
	virtual std::vector<StepResult> run();

protected:
	StepResult execute(VaultClient *client, const Step &step, int openErr);

	std::string       name_;
	uid_t             uid_;
	std::uint32_t     role_;
	std::vector<Step> steps_;
};

/* Administrator: holds the passphrase, may seal and unseal, and is the only
 * principal permitted to grant. */
class AdminUser : public SimUser {
public:
	AdminUser(std::string name, uid_t uid)
	    : SimUser(std::move(name), uid, KV_ROLE_ADMIN) {}
	std::vector<StepResult> run() override;
};

/* Developer: reads the secrets that have been granted to the developer role
 * and nothing else. */
class DeveloperUser : public SimUser {
public:
	DeveloperUser(std::string name, uid_t uid)
	    : SimUser(std::move(name), uid, KV_ROLE_DEVELOPER) {}
};

/* Auditor: may read the audit stream but must never read a secret. The
 * scenario asserts both halves of that. */
class AuditorUser : public SimUser {
public:
	AuditorUser(std::string name, uid_t uid)
	    : SimUser(std::move(name), uid, KV_ROLE_AUDITOR) {}
	std::vector<StepResult> run() override;
};

/* Guest: the unprivileged attacker in the scenario. Every step is expected
 * to be denied. */
class GuestUser : public SimUser {
public:
	GuestUser(std::string name, uid_t uid)
	    : SimUser(std::move(name), uid, KV_ROLE_GUEST) {}
};

using SimUserPtr = std::unique_ptr<SimUser>;

} // namespace kvault::sim

#endif
