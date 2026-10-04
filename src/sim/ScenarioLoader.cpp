// SPDX-License-Identifier: GPL-2.0
#include "ScenarioLoader.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "client/PolicyLoader.hpp"

namespace kvault::sim {

Step::Op ScenarioLoader::opFromName(const std::string &name)
{
	if (name == "get")    return Step::Op::Get;
	if (name == "put")    return Step::Op::Put;
	if (name == "list")   return Step::Op::List;
	if (name == "delete") return Step::Op::Delete;
	if (name == "rotate") return Step::Op::Rotate;
	if (name == "audit")  return Step::Op::ReadAudit;
	throw std::runtime_error("unknown operation '" + name + "'");
}

ScenarioLoader::Scenario ScenarioLoader::parse(const std::string &path)
{
	std::ifstream in(path);
	if (!in)
		throw std::runtime_error("cannot open scenario file " + path);

	Scenario sc;
	std::string line;
	unsigned lineNo = 0;

	while (std::getline(in, line)) {
		++lineNo;

		const std::size_t hash = line.find('#');
		if (hash != std::string::npos)
			line.erase(hash);

		std::istringstream ls(line);
		std::string directive;
		if (!(ls >> directive))
			continue;

		const auto fail = [&](const std::string &msg) {
			throw std::runtime_error(path + ":" +
						 std::to_string(lineNo) + ": " + msg);
		};

		if (directive == "secret") {
			Secret s;
			if (!(ls >> s.name))
				fail("expected: secret <name> <value>");
			/* The value is the rest of the line, so a secret may
			 * contain spaces. */
			std::getline(ls, s.value);
			const std::size_t b = s.value.find_first_not_of(" \t");
			const std::size_t e = s.value.find_last_not_of(" \t");
			if (b == std::string::npos)
				fail("secret '" + s.name + "' has no value");
			s.value = s.value.substr(b, e - b + 1);
			sc.secrets.push_back(s);

		} else if (directive == "grant") {
			Grant g;
			std::string subject, perms;
			if (!(ls >> g.name >> subject >> perms))
				fail("expected: grant <name> <subject> <perms>");
			g.subjectSpec = subject;
			try {
				PolicyLoader::subjectFromString(subject,
								g.subjectKind,
								g.subjectId);
				g.perms = PolicyLoader::permsFromString(perms);
			} catch (const std::exception &e) {
				fail(e.what());
			}
			sc.grants.push_back(g);

		} else if (directive == "step") {
			std::string user, op, secret, expect;
			if (!(ls >> user >> op >> secret >> expect))
				fail("expected: step <user> <op> <secret> <expect> [value]");

			Step st{};
			try {
				st.op = opFromName(op);
			} catch (const std::exception &e) {
				fail(e.what());
			}
			st.name = (secret == "-") ? "" : secret;

			if (expect == "allow")
				st.expectAllowed = true;
			else if (expect == "deny")
				st.expectAllowed = false;
			else
				fail("expected allow or deny, got '" + expect + "'");

			std::getline(ls, st.value);
			const std::size_t b = st.value.find_first_not_of(" \t");
			st.value = (b == std::string::npos)
				       ? std::string()
				       : st.value.substr(b);
			if (st.op == Step::Op::Put && st.value.empty())
				st.value = "written-by-" + user;

			/* Steps are grouped by principal, in the order the
			 * principals first appear, so one child per user runs
			 * that user's steps in file order. */
			auto it = sc.users.begin();
			for (; it != sc.users.end(); ++it)
				if (it->user == user)
					break;
			if (it == sc.users.end()) {
				sc.users.push_back({user, {}});
				it = sc.users.end() - 1;
			}
			it->steps.push_back(st);

		} else {
			fail("unknown directive '" + directive + "'");
		}
	}

	if (sc.users.empty())
		throw std::runtime_error(path + ": no steps defined");
	return sc;
}

} // namespace kvault::sim
