// SPDX-License-Identifier: GPL-2.0
#ifndef KV_AUDIT_VIEWER_HPP
#define KV_AUDIT_VIEWER_HPP

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "VaultClient.hpp"

namespace kvault {

/*
 * Follows the audit stream on a background thread.
 *
 * The driver's reader blocks in a wait queue, which is what makes the stream
 * live rather than polled - but a blocking read cannot be interrupted by
 * setting a flag, because nothing wakes it. So the thread waits in poll() with
 * a timeout instead: the timeout is not a polling interval, it is only how long
 * stop() may take to be noticed.
 *
 * Records are accumulated under a mutex and handed over by take(). The callback
 * form is for live display; the accumulator is for a test that wants to assert
 * on what was logged after the fact.
 */
class AuditViewer {
public:
	using Callback = std::function<void(const kv_audit_rec &)>;

	/* @onRecord may be empty. It runs on the watcher thread, so it must not
	 * touch anything the main thread owns without synchronising. */
	explicit AuditViewer(Callback onRecord = {});
	~AuditViewer();

	AuditViewer(const AuditViewer &) = delete;
	AuditViewer &operator=(const AuditViewer &) = delete;

	/* Throws VaultError if the audit device cannot be opened. */
	void start();

	/* Idempotent, and called by the destructor: an exception on the main
	 * path must not leave a thread running after the object is gone. */
	void stop();

	std::vector<kv_audit_rec> take();
	std::size_t count() const;

	static std::string format(const kv_audit_rec &r);

private:
	void loop();

	Callback                  onRecord_;
	std::atomic<bool>         stop_{false};
	std::thread               thread_;
	mutable std::mutex        mutex_;
	std::vector<kv_audit_rec> records_;
};

} // namespace kvault

#endif
