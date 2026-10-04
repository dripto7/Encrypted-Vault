// SPDX-License-Identifier: GPL-2.0
/* Throughput of the full GET path, and which crypto implementation produced it. */
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "client/VaultClient.hpp"

using namespace kvault;
using Clock = std::chrono::steady_clock;

namespace {

double megabytesPerSecond(std::size_t bytes, double seconds)
{
	if (seconds <= 0.0)
		return 0.0;
	return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / seconds;
}

} // namespace

int main()
{
	try {
		VaultClient c;
		const kv_status_arg st = c.status();

		if (st.state != KV_STATE_UNSEALED) {
			std::printf("bench: vault is %s; unseal it first\n",
				    VaultClient::stateName(st.state));
			return 0;
		}

		std::printf("crypto driver: %s (%s)\n", st.crypto_driver,
			    st.accelerated ? "hardware-accelerated" : "software");
		std::printf("%10s %10s %12s %12s\n", "size", "ops", "us/op",
			    "MB/s");

		for (const std::size_t size : {std::size_t{16}, std::size_t{256},
					       std::size_t{1024},
					       std::size_t{KV_SECRET_MAX}}) {
			const std::vector<std::uint8_t> value(size, 0x5A);
			c.put("kvbench", value);

			/* Warm up so the first measured iteration is not paying
			 * for the page faults and cache misses of setup. */
			for (int i = 0; i < 100; ++i)
				(void)c.get("kvbench");

			const int ops = 3000;
			const auto start = Clock::now();
			for (int i = 0; i < ops; ++i)
				(void)c.get("kvbench");
			const auto end = Clock::now();

			const double secs =
			    std::chrono::duration<double>(end - start).count();
			std::printf("%10zu %10d %12.2f %12.1f\n", size, ops,
				    secs * 1e6 / ops,
				    megabytesPerSecond(size * ops, secs));
		}

		try { c.remove("kvbench"); } catch (const VaultError &) {}
		return 0;
	} catch (const std::exception &e) {
		std::printf("bench: %s\n", e.what());
		return 0;
	}
}
