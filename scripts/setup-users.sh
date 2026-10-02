#!/bin/sh
# Create the test principals the simulator drives.
#
# These are real system users because the whole point of the exercise is that
# the kernel resolves the subject from the process credentials; faking the UID
# in user space would test nothing.
#
# Run as root. Safe to re-run: existing users are left alone.
set -eu

for u in kv_alice kv_bob kv_eve kv_carol; do
	if id "$u" >/dev/null 2>&1; then
		echo "exists:  $u (uid $(id -u "$u"))"
	else
		useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
		echo "created: $u (uid $(id -u "$u"))"
	fi
done

cat <<'NOTE'

Roles are not a property of the account: they are bound inside the vault with
  vaultctl set-role <uid> <role>
or loaded from configs/policy.conf. Deleting these users does not remove the
bindings, so re-running setup after a useradd/userdel cycle can hand a recycled
UID an inherited role - see docs/06-test-report.md.
NOTE
