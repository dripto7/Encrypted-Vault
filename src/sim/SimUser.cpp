// SPDX-License-Identifier: GPL-2.0
#include "SimUser.hpp"

#include <unistd.h>

#include <cerrno>

namespace kvault::sim {

namespace {

const char *opLabel(Step::Op op)
{
	switch (op) {
	case Step::Op::Get:       return "GET";
	case Step::Op::Put:       return "PUT";
	case Step::Op::List:      return "LIST";
	case Step::Op::Delete:    return "DELETE";
	case Step::Op::Rotate:    return "ROTATE";
	case Step::Op::ReadAudit: return "AUDIT";
	}
	return "?";
}

} // namespace

SimUser::SimUser(std::string name, uid_t uid, std::uint32_t role)
    : name_(std::move(name)), uid_(uid), role_(role)
{
}

StepResult SimUser::execute(VaultClient &client, const Step &step)
{
	StepResult r{name_, roleName(), opLabel(step.op), step.name,
		     false, step.expectAllowed, 0};

	try {
		switch (step.op) {
		case Step::Op::Get:
			client.get(step.name);
			break;
		case Step::Op::Put:
			client.put(step.name,
				   {step.value.begin(), step.value.end()});
			break;
		case Step::Op::List:
			client.list();
			break;
		case Step::Op::Delete:
			client.remove(step.name);
			break;
		case Step::Op::Rotate:
			client.rotate(step.name);
			break;
		case Step::Op::ReadAudit: {
			VaultClient audit(VaultClient::Device::Audit);
			audit.readAudit();
			break;
		}
		}
		r.allowed = true;
	} catch (const VaultError &e) {
		r.err = e.errnoValue();
	}

	return r;
}

std::vector<StepResult> SimUser::run()
{
	std::vector<StepResult> results;
	VaultClient client;

	results.reserve(steps_.size());
	for (const Step &s : steps_)
		results.push_back(execute(client, s));
	return results;
}

/* The admin's script is the same shape, but it runs with the vault already
 * unsealed by the parent and is the only script allowed to contain grants. */
std::vector<StepResult> AdminUser::run()
{
	return SimUser::run();
}

/* The auditor opens the audit device rather than the control device, so a
 * failure to open the control device is itself the expected outcome. */
std::vector<StepResult> AuditorUser::run()
{
	return SimUser::run();
}

} // namespace kvault::sim
