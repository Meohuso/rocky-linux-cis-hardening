# ADR-0002: Mount Library

- Status: Accepted
- Date: 2026-07-30
- Decision owners: Project maintainers
- Scope: Persistent and runtime mount validation and remediation
- Supersedes: `docs/mount-library-design.md`
- Superseded by: None

## Context

Several CIS controls require filesystem mount points to:

- exist as separate mounts;
- be declared persistently;
- contain specific mount options;
- expose the same required options at runtime.

Typical targets include:

- `/tmp`;
- `/var`;
- `/var/tmp`;
- `/var/log`;
- `/var/log/audit`;
- `/home`;
- `/dev/shm`.

Mount handling is more complex than matching a string in `/etc/fstab`.

The implementation must account for:

- exact target matching;
- inherited parent mounts;
- escaped fields in `/etc/fstab`;
- comments and blank lines;
- runtime state from `findmnt`;
- exact comma-separated option matching;
- atomic configuration updates;
- live remount behavior;
- persistent and runtime consistency;
- idempotence;
- rollback after partial failure.

A shared mount library is therefore required before mount-related CIS modules
are implemented.

## Decision

The project will provide `lib/mount.sh` as the public mount-management API.

The first stable implementation remains a single library file. The code may be
split into internal files later only when size or cohesion demonstrates a real
need. Such a split must not alter the public API.

The mount library is a generic framework service. It contains no CIS control
identifiers, benchmark-specific behavior, or Rocky Linux policy decisions.

## Scope

### Included

The mount library is responsible for:

- validating mount-point arguments;
- reading exact persistent entries from an fstab-compatible file;
- reading exact runtime mount information through `findmnt`;
- determining whether a target is a separate mount;
- checking exact mount options;
- adding an option to an existing persistent entry;
- removing a framework-added option when supported by rollback state;
- creating a preserved backup before modification;
- atomically replacing an fstab-compatible file;
- remounting an existing target;
- validating state after remediation;
- restoring the preserved backup;
- providing idempotent apply and rollback operations.

### Excluded

The mount library does not:

- create a missing fstab entry;
- create a mount unit;
- create partitions;
- create logical volumes;
- create RAID arrays;
- create filesystems;
- resize filesystems;
- move data;
- encrypt storage;
- choose storage devices;
- modify storage topology;
- unmount a target solely to satisfy a control;
- automatically reboot the system.

When a separate mount is required but does not exist, the library reports that
automatic remediation is unavailable.

## Design principles

### Exact target matching

A target is considered a separate mount only when both conditions hold:

1. an active runtime mount exists whose target exactly equals the requested
   target;
2. a persistent fstab entry exists whose mount-point field exactly equals the
   requested target.

A parent mount does not satisfy a child target.

For example, an active `/var` mount does not prove that `/var/log` is a
separate mount.

### Exact option matching

Mount options are comma-separated tokens.

An option matches only when a complete token equals the required option.

Examples:

- `nodev` matches `nodev`;
- `nodev` does not match `nonodev`;
- `noexec` does not match `exec`;
- `nosuid` does not match `suid`.

Option order is not significant.

Duplicate options must not be introduced.

### Persistent and runtime state

A mount option is compliant only when it is present:

- in the exact persistent fstab entry;
- in the exact active runtime mount options.

Persistent compliance without runtime compliance is non-compliant.

Runtime compliance without persistent compliance is non-compliant.

### No implicit entry creation

The library does not infer a source, filesystem type, dump value, or fsck
ordering for a missing target.

If an exact target entry is absent from the selected fstab file, option
remediation returns an error or unavailable-remediation result.

### Preserved backup

Before the first persistent change, the library creates a backup at the path
provided by the caller.

The backup represents the pre-framework state.

The default behavior is:

- create the backup only when it does not already exist;
- never overwrite an existing backup during repeated apply;
- restore that backup during rollback;
- remove the backup only after successful restoration and runtime recovery.

A caller must use a deterministic backup path associated with the control or
managed target.

### Atomic persistent update

The library updates an fstab-compatible file by:

1. creating a temporary file in the same directory;
2. writing the complete transformed content;
3. preserving relevant ownership and mode;
4. validating that transformation succeeded;
5. replacing the original file atomically with `mv`.

The implementation must clean up temporary files on failure.

The original file must remain intact when transformation fails.

### Runtime remediation

After persistent configuration has been updated, the library remounts the exact
target.

The default runtime operation is equivalent to:

```bash
mount -o remount,target-option TARGET
```

The implementation may select a safer command form when required by the active
mount and platform behavior.

After remount, the library validates the exact runtime option through
`findmnt`.

A successful command without the expected effective state is a remediation
failure.

### Failure after persistent change

When the persistent update succeeds but runtime remediation or validation
fails, the apply operation must not silently return success.

The library must attempt to restore the preserved persistent state and recover
the previous runtime configuration when safe.

If automatic recovery also fails, the operation returns an error and preserves
the backup for manual recovery.

### Idempotence

Apply is idempotent.

When persistent and runtime state are already compliant:

- no backup is created;
- no file is rewritten;
- no remount is performed;
- the framework compliant result is returned.

Rollback is idempotent.

When no backup exists:

- no file is changed;
- no remount is performed;
- the framework compliant result is returned.

## Public API

The following functions form the initial public API.

### Option parsing

```bash
mount_option_list_contains OPTION_LIST REQUIRED_OPTION
```

Purpose:

- test whether a comma-separated option list contains an exact token.

Arguments:

1. option list;
2. required option.

Output:

- none.

Return:

- `0` when the exact option is present;
- non-zero otherwise.

Side effects:

- none.

### Separate mount check

```bash
mount_check_partition MOUNT_POINT [FSTAB_FILE]
```

Purpose:

- determine whether a target is an exact active and persistent mount.

Arguments:

1. absolute mount point;
2. optional fstab-compatible file, defaulting to `/etc/fstab`.

Output:

- diagnostics through the framework logging mechanism or standard error.

Return:

- framework compliant result when exact persistent and runtime entries exist;
- framework non-compliant result otherwise;
- framework error result for invalid input or command failure.

Side effects:

- none.

### Separate mount validation

```bash
mount_validate_partition MOUNT_POINT [FSTAB_FILE]
```

Purpose:

- validate separate-mount compliance after an external or manual change.

Behavior:

- delegates to the same effective checks as `mount_check_partition`.

Side effects:

- none.

### Separate mount apply

```bash
mount_apply_partition CONTROL_ID MOUNT_POINT FSTAB_FILE EFFECTIVE_UID
```

Purpose:

- provide a consistent apply interface for controls requiring a separate mount.

Behavior:

- returns compliant when the target is already an exact persistent and runtime
  mount;
- rejects non-root modification attempts;
- does not provision storage;
- returns an unavailable-remediation or error result when the target is not a
  separate mount.

Side effects:

- none, because storage provisioning is excluded.

### Mount option check

```bash
mount_check_option MOUNT_POINT OPTION [FSTAB_FILE]
```

Purpose:

- determine whether an exact option exists persistently and at runtime for an
  exact target.

Arguments:

1. absolute mount point;
2. required option;
3. optional fstab-compatible file, defaulting to `/etc/fstab`.

Output:

- diagnostics through the framework logging mechanism or standard error.

Return:

- framework compliant result when both states contain the option;
- framework non-compliant result when either state is missing it;
- framework error result for invalid input or command failure.

Side effects:

- none.

### Mount option validation

```bash
mount_validate_option MOUNT_POINT OPTION [FSTAB_FILE]
```

Purpose:

- validate effective state after remediation.

Behavior:

- delegates to the same effective checks as `mount_check_option`.

Side effects:

- none.

### Persistent option write

```bash
mount_write_fstab_option MOUNT_POINT OPTION [FSTAB_FILE]
```

Purpose:

- add an exact option to the existing exact target entry in an fstab-compatible
  file.

Behavior:

- does not create a missing entry;
- preserves comments and unrelated lines;
- updates only the selected exact target;
- avoids duplicate options;
- performs atomic replacement;
- returns success without rewriting when the option is already present.

Privilege:

- the caller is responsible for privilege validation when operating on system
  files;
- tests may use a temporary file without root.

Side effects:

- may modify the selected fstab-compatible file.

### Runtime remount

```bash
mount_remount MOUNT_POINT [OPTION]
```

Purpose:

- remount the exact active target, optionally enforcing an option.

Behavior:

- invokes the configured mount command;
- validates command availability;
- returns failure when remount fails.

Side effects:

- changes active mount state.

### Mount option apply

```bash
mount_apply_option \
    CONTROL_ID \
    MOUNT_POINT \
    OPTION \
    FSTAB_FILE \
    BACKUP_FILE \
    EFFECTIVE_UID
```

Purpose:

- safely enforce a persistent and runtime mount option.

Arguments:

1. control identifier;
2. absolute mount point;
3. required option;
4. fstab-compatible file;
5. backup file;
6. effective user identifier.

Behavior:

1. validate arguments;
2. check current persistent and runtime state;
3. return compliant when already compliant;
4. require root privileges;
5. verify an exact persistent target entry exists;
6. verify an exact active target exists;
7. create the preserved backup;
8. add the persistent option atomically when missing;
9. remount when runtime state is missing the option;
10. validate persistent and runtime state;
11. return changed only when state was modified.

Failure behavior:

- attempt recovery when failure occurs after modification;
- preserve backup when complete recovery cannot be confirmed.

### Rollback

```bash
mount_rollback \
    CONTROL_ID \
    MOUNT_POINT \
    FSTAB_FILE \
    BACKUP_FILE \
    EFFECTIVE_UID
```

Purpose:

- restore the pre-framework persistent state and recover active mount state.

Behavior:

1. validate arguments;
2. return compliant when no backup exists;
3. require root privileges;
4. restore the backup atomically;
5. remount the exact target from restored configuration;
6. validate that the target remains active;
7. remove the backup after successful restoration;
8. return changed.

Failure behavior:

- retain the backup when restoration or runtime recovery cannot be confirmed.

## Internal API

Internal functions use a leading underscore.

Expected internal responsibilities include:

```bash
_mount_validate_target
_mount_validate_option
_mount_fstab_entry_exists
_mount_fstab_options
_mount_runtime_target_exists
_mount_runtime_options
_mount_create_temporary_file
_mount_transform_fstab_option
_mount_restore_after_failed_apply
```

These names are illustrative and are not public compatibility commitments.

## Fstab parsing rules

The implementation must:

- ignore blank lines;
- ignore lines whose first non-whitespace character is `#`;
- interpret fields using whitespace separation;
- require at least the source, target, type, and options fields;
- match the target field exactly;
- preserve the source, target, filesystem type, dump, and pass fields;
- preserve unrelated lines byte-for-byte where practical;
- preserve trailing newline behavior where practical;
- avoid unsafe evaluation of file content.

The implementation must support standard fstab field escapes needed for mount
targets, including at minimum escaped spaces.

The first implementation may reject ambiguous duplicate exact target entries
rather than modifying more than one entry.

Duplicate exact target entries are treated as an error because selecting one
silently could modify unintended configuration.

## Runtime inspection rules

Runtime inspection uses `findmnt`.

The library must request machine-consumable output and exact target selection.

It must not parse the human-formatted default table.

The implementation must distinguish:

- exact target present;
- only a parent target present;
- command failure;
- target absent.

Tests replace `findmnt` with a mock executable.

## Command abstraction

The implementation uses configurable command variables or PATH-based mocks so
tests do not alter the host mount table.

At minimum, tests must be able to replace:

- `findmnt`;
- `mount`;
- file metadata commands used by atomic updates.

Production defaults resolve to standard Rocky Linux command names.

## Result semantics

The library uses framework result constants already defined by the project.

Expected outcomes include:

- compliant: requested state already exists or rollback has nothing to do;
- changed: apply or rollback modified state successfully;
- non-compliant: check or validate found missing policy state;
- error: invalid input, command failure, unsafe ambiguity, or failed recovery.

The library must not define a second incompatible result model.

## Security requirements

The implementation must:

- quote all caller-provided paths and values;
- reject empty targets and options;
- require absolute mount targets;
- reject option values containing commas or whitespace when one exact option is
  expected;
- avoid `eval`;
- avoid shell interpretation of fstab content;
- create temporary files securely;
- keep temporary files in the destination directory;
- preserve restrictive permissions;
- prevent symlink-based replacement where supported by existing filesystem
  helpers;
- never follow an untrusted backup path without validation.

## Testing strategy

The mount library receives a dedicated Bats suite.

Required test categories follow.

### Option parsing

- exact option matches;
- partial option does not match;
- first option matches;
- middle option matches;
- last option matches;
- empty option list;
- duplicate option input;
- malformed required option rejection.

### Persistent entry inspection

- exact target exists;
- target missing;
- parent target does not match;
- commented entry ignored;
- blank lines ignored;
- escaped target parsed;
- duplicate exact target rejected;
- custom fstab path supported.

### Runtime inspection

- exact target exists;
- target absent;
- parent target rejected;
- runtime options returned;
- `findmnt` failure propagated.

### Partition checks

- exact persistent and runtime mount is compliant;
- persistent entry missing;
- runtime target missing;
- inherited parent mount rejected;
- invalid target rejected.

### Option checks

- option present persistently and at runtime;
- persistent option missing;
- runtime option missing;
- both missing;
- partial option rejected;
- target missing;
- command failure propagated.

### Persistent updates

- option added atomically;
- existing option is idempotent;
- option order remains valid;
- duplicate option is not introduced;
- unrelated entries remain unchanged;
- comments remain unchanged;
- missing target rejected;
- duplicate target rejected;
- transformation failure preserves original;
- file mode and ownership preservation are tested where portable.

### Apply

- already-compliant state returns compliant;
- persistent-only change returns changed;
- runtime-only change returns changed;
- persistent and runtime change returns changed;
- non-root execution rejected;
- backup created before first change;
- existing backup preserved;
- missing target rejected;
- remount failure triggers recovery;
- post-remount validation failure triggers recovery;
- failed recovery preserves backup;
- successful repeated apply is idempotent.

### Rollback

- backup restored;
- target remounted;
- backup removed after success;
- missing backup is idempotent;
- non-root execution rejected;
- restore failure preserves backup;
- remount failure preserves backup;
- repeated rollback is idempotent.

## Implementation constraints

The implementation must be ShellCheck clean.

Complex inline awk programs should be avoided when an equivalent readable Bash
implementation is available.

When awk is used:

- variable names must not conflict with awk keywords or implementation-specific
  names;
- the program must be independently testable;
- syntax must work with the awk implementation provided by Rocky Linux 10;
- tests must execute the exact transformation path.

The library must not be committed until all dedicated mount tests pass locally
and in GitHub Actions.

## Consequences

### Positive consequences

- All mount-related controls use one consistent implementation.
- Exact matching prevents false compliance.
- Persistent and runtime state are treated separately.
- Atomic updates reduce configuration-corruption risk.
- Rollback behavior is predictable.
- Tests can mock system commands safely.
- Storage provisioning remains an explicit operator responsibility.

### Costs

- The mount library is larger than a control-specific script.
- Safe rollback requires backup management.
- Mount behavior varies by filesystem and target, requiring extensive tests.
- Some non-compliant partition controls cannot be automatically remediated.

These costs are accepted.

## Alternatives considered

### Direct fstab editing in each CIS module

Rejected because it duplicates unsafe parsing and update logic.

### Automatically creating missing entries

Rejected because source device, filesystem type, storage layout, and boot
semantics cannot be inferred safely.

### Automatically provisioning LVM or partitions

Rejected because storage topology changes are high risk and outside framework
scope.

### Checking only `/etc/fstab`

Rejected because persistent configuration does not prove current enforcement.

### Checking only runtime state

Rejected because runtime state may disappear after reboot.

### Using regular-expression substring matching for options

Rejected because it creates false positives such as matching `nodev` inside
another token.

### Splitting the implementation into several files immediately

Rejected for the initial implementation because responsibility can remain
cohesive in one library. Internal splitting remains possible later without
changing the public API.

## Rationale

Mount hardening is safe only when the framework distinguishes policy,
persistent configuration, and active runtime state.

A dedicated library centralizes the difficult parts: exact parsing, atomic
updates, remount validation, recovery, and rollback. CIS modules can then remain
thin policy wrappers without embedding fragile system logic.
