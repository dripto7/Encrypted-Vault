// SPDX-License-Identifier: GPL-2.0
#include "AuditViewer.hpp"

#include <poll.h>

#include <cerrno>
#include <sstream>

namespace kvault {

AuditViewer::AuditViewer(Callback onRecord) : onRecord_(std::move(onRecord))
{
}

AuditViewer::~AuditViewer()
{
	stop();
}

void AuditViewer::start()
{
	if (thread_.joinable())
		return;

	/* Open on the caller's thread so a permission failure is reported to
	 * whoever asked, rather than thrown on a thread nobody is watching. */
	VaultClient probe(VaultClient::Device::Audit);
	const int fd = probe.fd();
	(void)fd;

	stop_ = false;
	thread_ = std::thread(&AuditViewer::loop, this);
}

void AuditViewer::stop()
{
	stop_ = true;
	if (thread_.joinable())
		thread_.join();
}

void AuditViewer::loop()
{
	try {
		VaultClient audit(VaultClient::Device::Audit);
		struct pollfd pfd{audit.fd(), POLLIN, 0};

		while (!stop_) {
			/* 200 ms is how long stop() may take to be seen, not a
			 * polling interval: when records arrive, poll returns
			 * immediately because the driver wakes its wait queue. */
			const int n = ::poll(&pfd, 1, 200);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				return;
			}
			if (n == 0)
				continue;

			const kv_audit_rec rec = audit.readAudit();
			{
				std::lock_guard<std::mutex> guard(mutex_);
				records_.push_back(rec);
			}
			if (onRecord_)
				onRecord_(rec);
		}
	} catch (const std::exception &) {
		/* The watcher is an observer: if the device goes away - the
		 * module was unloaded - it stops, and the program it was
		 * watching carries on. */
	}
}

std::vector<kv_audit_rec> AuditViewer::take()
{
	std::lock_guard<std::mutex> guard(mutex_);
	std::vector<kv_audit_rec> out;
	out.swap(records_);
	return out;
}

std::size_t AuditViewer::count() const
{
	std::lock_guard<std::mutex> guard(mutex_);
	return records_.size();
}

std::string AuditViewer::format(const kv_audit_rec &r)
{
	std::ostringstream os;

	os << "[" << r.seq << "] uid=" << r.uid << " pid=" << r.pid
	   << " role=" << VaultClient::roleName(r.role)
	   << " op=" << VaultClient::opName(r.op)
	   << " name=" << (r.name[0] ? r.name : "-") << " -> "
	   << (r.result == KV_RESULT_ALLOW ? "ALLOW" : "DENY");
	if (r.err)
		os << " (errno " << -r.err << ")";
	return os.str();
}

} // namespace kvault
