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

/* Follows the audit stream on a background thread. */
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
