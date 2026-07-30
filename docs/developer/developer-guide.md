# Developer Guide

## Purpose

This guide defines the standard development workflow for the Rocky Linux CIS
Hardening Framework.

It applies to:

- framework libraries;
- CIS control modules;
- test helpers;
- Bats tests;
- documentation;
- CI changes.

Architecture decisions in `docs/architecture/` are normative and take
precedence over this guide.

## Development target

The current production target is Rocky Linux 10.

Development uses:

- Bash;
- Bats;
- ShellCheck;
- Git;
- GitHub Actions.

The framework does not require Ansible.

## Working branch

Rocky Linux 10 development is performed directly on `main`.

Before starting work:

```bash
git switch main
git pull --ff-only
git status
```

The working tree must be understood before files are changed.

Do not discard unrelated local changes.

## Unit of work

The normal unit of work is one CIS control per commit.

A shared library may be introduced or extended in a dedicated framework commit
before the first control that consumes it.

Examples:

```text
feat(lib): implement shared mount library
feat(1.1.2.1): ensure /tmp is a separate partition
fix(lib): preserve fstab entry formatting during option update
test(mount): cover failed remount recovery
docs(adr): define mount library architecture
```

Do not combine unrelated controls in one commit.

## Architecture-first workflow

Before implementing a new control family:

1. read the relevant benchmark controls;
2. identify shared operating-system behavior;
3. verify whether an existing library already owns that behavior;
4. create or update an ADR when a new architectural decision is required;
5. implement the shared library API;
6. add dedicated library tests;
7. validate the library;
8. implement thin control modules one at a time.

Do not add complex reusable logic directly to a CIS module.

## Creating a library

A new library must:

- have one domain responsibility;
- use a multiple-sourcing guard;
- expose documented public functions;
- keep internal helpers private by naming convention;
- validate public arguments;
- use framework result semantics;
- avoid terminating the parent process;
- support mocks in tests;
- have dedicated Bats coverage;
- pass ShellCheck.

Recommended header pattern:

```bash
#!/usr/bin/env bash

if [[ -n "${RLCH_LIBRARY_EXAMPLE_LOADED:-}" ]]; then
    return 0
fi

readonly RLCH_LIBRARY_EXAMPLE_LOADED=1
```

Use the project’s established guard convention when it differs.

## Public and internal functions

Public functions are stable framework API.

Example:

```bash
mount_check_option
mount_apply_option
```

Internal functions begin with an underscore.

Example:

```bash
_mount_runtime_options
```

Modules must not call internal functions.

A public function must document:

- parameters;
- output;
- return behavior;
- side effects;
- privilege requirements;
- idempotence;
- rollback behavior.

## Creating a CIS control module

Follow the repository’s existing namespace and directory conventions.

A module must provide complete metadata, including:

- CIS identifier;
- title;
- level;
- enabled state;
- reboot requirement.

A module must implement the required action functions.

The module should primarily:

- pass policy parameters to a library;
- translate framework results when needed;
- provide control-specific diagnostics;
- avoid duplicating system logic.

Typical shape:

```bash
check() {
    library_check_policy "${CONTROL_PARAMETER}"
}

apply() {
    library_apply_policy \
        "${MODULE_ID}" \
        "${CONTROL_PARAMETER}" \
        "${EUID}"
}

validate() {
    check
}

rollback() {
    library_rollback_policy \
        "${MODULE_ID}" \
        "${CONTROL_PARAMETER}" \
        "${EUID}"
}
```

Use the exact action names and metadata format already established by the
repository.

## Result handling

Use framework result constants.

Do not return arbitrary integers when a framework result exists.

A check normally returns:

- compliant when the required state exists;
- non-compliant when the required state is missing;
- error when the check cannot be performed reliably.

An apply normally returns:

- compliant when no change was needed;
- changed when remediation completed and validated;
- error when remediation failed or could not be completed safely.

A rollback normally returns:

- compliant when there is no managed state to restore;
- changed when previous state was restored;
- error when restoration failed.

## Idempotence

Every apply and rollback path must be tested for repeated execution.

Apply is idempotent when the second execution:

- performs no unnecessary file rewrite;
- performs no unnecessary service restart or remount;
- creates no duplicate configuration;
- returns the compliant result.

Rollback is idempotent when the second execution:

- performs no destructive action;
- returns the compliant result.

## Rollback

A modifying control must define rollback behavior.

Rollback may restore only state that the framework can identify safely.

Do not guess the previous state.

When a preserved backup exists:

- do not overwrite it during repeated apply;
- restore it atomically;
- remove it only after successful recovery;
- preserve it when recovery fails.

A control that cannot safely roll back must document that limitation explicitly
in its ADR and module documentation.

## Error messages

Diagnostics must be:

- actionable;
- concise;
- specific to the failed operation;
- written to standard error unless they are intentional command output.

Prefer:

```text
mount: exact /tmp entry is missing from /etc/fstab
```

Avoid:

```text
error
```

Do not expose secrets.

## Testing workflow

Run the relevant test file while developing:

```bash
bats tests/mount.bats
```

Run the complete suite before commit:

```bash
bats tests
```

Run ShellCheck against all tracked shell files using the repository’s normal
command or workflow.

Example:

```bash
find . -type f \
    \( -name '*.sh' -o -name '*.bash' -o -name '*.bats' \) \
    -print0 |
    xargs -0 shellcheck
```

Use the exact CI command when the repository defines a different invocation.

A change is not ready until:

- targeted Bats tests pass;
- the full Bats suite passes;
- ShellCheck passes;
- GitHub Actions passes.

## Test isolation

Tests must not modify the developer or CI host.

Use:

- temporary directories;
- fixture files;
- PATH-based command mocks;
- configurable file paths;
- configurable effective UID values when supported by the API.

Do not:

- modify `/etc/fstab`;
- remount real filesystems;
- unload real kernel modules;
- change real services;
- install or remove packages.

## ShellCheck suppressions

A ShellCheck suppression is exceptional.

Before adding one:

1. confirm the warning cannot be removed safely;
2. limit the suppression to the smallest possible scope;
3. add a comment explaining why the construct is intentional;
4. cover the behavior with a test.

Do not disable a ShellCheck rule globally to avoid fixing code.

## Documentation

Documentation changes are part of implementation.

Update documentation when a change affects:

- public API;
- behavior;
- arguments;
- return semantics;
- rollback;
- dependencies;
- operator actions;
- compatibility.

Do not describe planned behavior as already implemented.

## Commit procedure

Before commit:

```bash
git status
git diff --check
git diff
bats tests
```

Run ShellCheck using the repository command.

Review the exact staged content:

```bash
git add path/to/complete-file
git diff --cached --check
git diff --cached
```

Commit only validated source files.

Do not commit:

- generated ZIP archives;
- temporary files;
- test output;
- editor swap files;
- local secrets;
- local environment configuration.

## Commit messages

Use a concise conventional form.

Examples:

```text
feat(lib): implement shared mount library
feat(1.1.1.8): disable usb-storage kernel module
fix(mount): avoid awk reserved identifier
test(mount): cover duplicate fstab targets
docs(adr): accept mount library design
```

The subject should describe the completed change, not the activity performed.

## CI failures

When CI fails:

1. read the first failing test or validation step;
2. reproduce it locally;
3. identify the root cause;
4. fix the implementation or test;
5. rerun the targeted validation;
6. rerun the complete suite;
7. push only after local validation succeeds.

Do not weaken a test merely to make CI green.

A test may change when:

- the specification changed deliberately;
- the previous expectation was incorrect;
- the ADR was updated and accepted.

## Review checklist

Before considering work complete, verify:

- the change follows accepted ADRs;
- public API is documented;
- reusable logic is in a library;
- no host system is modified by tests;
- invalid input is tested;
- command failures are tested;
- idempotence is tested;
- rollback is tested;
- ShellCheck passes;
- full Bats suite passes;
- CI passes;
- the commit contains one coherent change.
