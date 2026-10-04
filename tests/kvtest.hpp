// SPDX-License-Identifier: GPL-2.0
#ifndef KV_TEST_HPP
#define KV_TEST_HPP

/*
 * A deliberately tiny test harness.
 *
 * No external framework: the project's constraint is C and C++ only, and
 * pulling in a dependency to compare two integers would be a poor trade. What
 * is needed is a way to run named cases, report the first failure in each with
 * a file and line, and exit non-zero if any failed.
 *
 * KV_CHECK records a failure and keeps going; KV_REQUIRE abandons the case,
 * because a case whose precondition failed will otherwise report a cascade of
 * consequences that hide the actual cause.
 */
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace kvtest {

struct Failure : std::exception {
	std::string msg;
	explicit Failure(std::string m) : msg(std::move(m)) {}
	const char *what() const noexcept override { return msg.c_str(); }
};

class Registry {
public:
	struct Case {
		std::string name;
		std::function<void()> fn;
	};

	static Registry &instance()
	{
		static Registry r;
		return r;
	}

	void add(const std::string &name, std::function<void()> fn)
	{
		cases_.push_back({name, std::move(fn)});
	}

	/* Returns the number of failed cases. */
	int run(const std::string &suite)
	{
		int failed = 0;
		int skipped = 0;

		std::cout << "== " << suite << " (" << cases_.size()
			  << " cases)\n";
		for (const Case &c : cases_) {
			softFailures_ = 0;
			skipped_ = false;
			try {
				c.fn();
			} catch (const Failure &f) {
				std::cout << "  FAIL  " << c.name << "\n        "
					  << f.what() << "\n";
				++failed;
				continue;
			} catch (const std::exception &e) {
				std::cout << "  FAIL  " << c.name
					  << "\n        unexpected exception: "
					  << e.what() << "\n";
				++failed;
				continue;
			}
			if (softFailures_) {
				std::cout << "  FAIL  " << c.name << " ("
					  << softFailures_ << " checks)\n";
				++failed;
			} else if (skipped_) {
				/* Reported as skipped, never as a pass: a case
				 * that did not run has proved nothing, and
				 * counting it as green is how a suite comes to
				 * be trusted for coverage it does not have. */
				std::cout << "  SKIP  " << c.name << "\n";
				++skipped;
			} else {
				std::cout << "  ok    " << c.name << "\n";
			}
		}
		std::cout << "-- " << suite << ": "
			  << cases_.size() - failed - skipped << " passed, "
			  << skipped << " skipped, " << failed << " failed\n";
		return failed;
	}

	void noteFailure(const std::string &msg)
	{
		++softFailures_;
		std::cout << "        " << msg << "\n";
	}

	/* Cases that need something the environment may not provide (the module
	 * loaded, root) say so rather than failing: a skipped case is honest,
	 * a case that cannot run and reports success is not. */
	void skip(const std::string &why)
	{
		skipped_ = true;
		std::cout << "        " << why << "\n";
	}

private:
	std::vector<Case> cases_;
	int softFailures_ = 0;
	bool skipped_ = false;
};

struct Registrar {
	Registrar(const std::string &name, std::function<void()> fn)
	{
		Registry::instance().add(name, std::move(fn));
	}
};

} // namespace kvtest

#define KV_TEST(name)                                                         \
	static void name();                                                   \
	static ::kvtest::Registrar kv_reg_##name(#name, name);                \
	static void name()

#define KV_CHECK(cond)                                                        \
	do {                                                                  \
		if (!(cond))                                                  \
			::kvtest::Registry::instance().noteFailure(            \
			    std::string(__FILE__ ":") +                        \
			    std::to_string(__LINE__) + ": check failed: " #cond); \
	} while (0)

#define KV_CHECK_EQ(a, b)                                                     \
	do {                                                                  \
		const auto kv_a = (a);                                        \
		const auto kv_b = (b);                                        \
		if (!(kv_a == kv_b))                                          \
			::kvtest::Registry::instance().noteFailure(            \
			    std::string(__FILE__ ":") +                        \
			    std::to_string(__LINE__) + ": " #a " != " #b);     \
	} while (0)

#define KV_REQUIRE(cond)                                                      \
	do {                                                                  \
		if (!(cond))                                                  \
			throw ::kvtest::Failure(                              \
			    std::string(__FILE__ ":") +                       \
			    std::to_string(__LINE__) +                        \
			    ": requirement failed: " #cond);                  \
	} while (0)

/* Asserts that @expr throws a VaultError carrying @err. The usual mistake is to
 * assert only that it threw, which passes when the kernel returns the wrong
 * error for the right reason. */
#define KV_EXPECT_ERRNO(expr, err)                                            \
	do {                                                                  \
		bool kv_threw = false;                                        \
		try {                                                         \
			(void)(expr);                                         \
		} catch (const ::kvault::VaultError &e) {                     \
			kv_threw = true;                                      \
			if (e.errnoValue() != (err))                          \
				::kvtest::Registry::instance().noteFailure(    \
				    std::string(__FILE__ ":") +               \
				    std::to_string(__LINE__) + ": " #expr     \
				    " gave errno " +                          \
				    std::to_string(e.errnoValue()) +          \
				    ", expected " + std::to_string(err));     \
		}                                                             \
		if (!kv_threw)                                                \
			::kvtest::Registry::instance().noteFailure(            \
			    std::string(__FILE__ ":") +                       \
			    std::to_string(__LINE__) + ": " #expr             \
			    " did not throw");                                \
	} while (0)

#define KV_TEST_MAIN(suite)                                                   \
	int main()                                                            \
	{                                                                     \
		return ::kvtest::Registry::instance().run(suite) ? 1 : 0;     \
	}

#endif
