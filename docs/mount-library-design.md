# Shared mount library

## Purpose

`lib/mount.sh` provides the shared implementation used by CIS controls that
validate or harden filesystem mount points on Rocky Linux 10.

The library keeps CIS modules small and declarative while centralizing:

- runtime mount inspection through `findmnt`;
- persistent configuration inspection through `/etc/fstab`;
- exact mount-option matching;
- atomic `/etc/fstab` updates;
- live remount operations;
- backup creation and rollback;
- framework result-code handling.

## Public API

### Partition checks

```bash
mount_check_partition MOUNT_POINT [FSTAB_FILE]
mount_validate_partition MOUNT_POINT [FSTAB_FILE]
mount_apply_partition CONTROL_ID MOUNT_POINT FSTAB_FILE EFFECTIVE_UID
```

A mount point is compliant when it has an exact persistent `/etc/fstab` entry
and the runtime mount target returned by `findmnt` exactly matches the requested
mount point.

The framework does not create partitions, logical volumes, or filesystems
automatically. `mount_apply_partition` therefore succeeds when the target is
already compliant and returns an error when storage provisioning is required.

### Mount-option checks and remediation

```bash
mount_check_option MOUNT_POINT OPTION [FSTAB_FILE]
mount_validate_option MOUNT_POINT OPTION [FSTAB_FILE]
mount_apply_option CONTROL_ID MOUNT_POINT OPTION FSTAB_FILE BACKUP_FILE EFFECTIVE_UID
mount_rollback CONTROL_ID MOUNT_POINT FSTAB_FILE BACKUP_FILE EFFECTIVE_UID
```

An option is compliant only when it is present in both:

1. the exact mount point entry in `/etc/fstab`;
2. the active runtime options for the exact mount point.

Remediation creates one preserved backup, updates `/etc/fstab` atomically, and
applies the option with a live remount. Rollback restores the preserved backup,
remounts the target from the restored configuration, and removes the backup.

## Safety principles

- No automatic storage provisioning.
- No implicit creation of missing `/etc/fstab` entries.
- Exact option matching; partial matches are rejected.
- Exact mount-point matching; parent mounts are not accepted.
- Root checks before every modifying operation.
- Atomic persistent configuration updates.
- Idempotent apply and rollback operations.

## Intended CIS coverage

The API is designed for mount-related controls covering:

- `/tmp`;
- `/var`;
- `/var/tmp`;
- `/var/log`;
- `/var/log/audit`;
- `/home`;
- `/dev/shm`.
