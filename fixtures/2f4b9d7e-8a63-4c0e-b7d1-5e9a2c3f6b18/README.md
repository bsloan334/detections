Needs auditd fixtures (match: a PATH record for /etc/sudoers.d/x from vim; no match: the same
from an Ansible run). Capture them from a lab host with the audit rule
`-w /etc/sudoers -p wa -k sudoers` and `-w /etc/sudoers.d/ -p wa -k sudoers`.
