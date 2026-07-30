# Shared mount library

This archive contains the initial skeleton for the shared mount library.

Planned responsibilities:
- mount_check_partition
- mount_check_option
- mount_apply_option
- mount_validate
- mount_rollback

It is intended to support CIS controls:
- 1.1.2 (/tmp)
- 1.1.3 (/var)
- 1.1.4 (/var/tmp)
- 1.1.5 (/var/log)
- 1.1.6 (/var/log/audit)
- 1.1.7 (/home)
