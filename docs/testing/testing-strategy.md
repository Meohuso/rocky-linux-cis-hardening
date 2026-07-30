# Testing Strategy

## Purpose

The testing strategy ensures that framework behavior is:

- correct;
- repeatable;
- isolated from the test host;
- safe under failure;
- resistant to regression;
- compatible with the project’s public API guarantees.

Testing is part of implementation, not a later validation phase.

## Test layers

The project uses three primary layers.

### Library unit tests

Library unit tests validate public and important internal behavior in isolation.

Examples:

```text
tests/filesystem.bats
tests/kernel_module.bats
tests/mount.bats
tests/system.bats
```

They use temporary fixtures and command mocks.

They must not modify the host system.

### Module tests

Module tests validate each CIS control as a policy wrapper.

They verify:

- metadata;
- library invocation;
- check behavior;
- apply behavior;
- validate behavior;
- rollback behavior;
- enabled or disabled behavior where applicable.

Module tests should not duplicate every library edge case.

### End-to-end validation

End-to-end validation executes selected framework workflows on disposable Rocky
Linux 10 systems or CI environments designed for privileged integration tests.

This layer may validate:

- real system commands;
- actual service behavior;
- actual remount behavior;
- reboot persistence;
- OpenSCAP results.

End-to-end tests are complementary. They do not replace unit tests.

## Test framework

Bats is the standard shell test framework.

All committed tests must run non-interactively.

The suite must produce a non-zero status when any test fails.

## Test organization

Recommended structure:

```text
tests/
├── fixtures/
│   ├── filesystem/
│   ├── kernel_module/
│   └── mount/
├── helpers/
│   ├── common_helper.bash
│   ├── kernel_module_helper.bash
│   └── mount_helper.bash
├── modules/
│   └── control-specific tests
├── filesystem.bats
├── kernel_module.bats
├── mount.bats
└── system.bats
```

Use the repository’s existing structure as authoritative.

## Test naming

A test name describes behavior and expected outcome.

Good:

```bash
@test "mount_option_list_contains rejects partial option matches"
@test "mount_apply_option preserves an existing backup"
@test "rollback is idempotent without managed state"
```

Avoid:

```bash
@test "test mount function"
@test "case 7"
```

## Isolation

Every test must be independent.

A test must not rely on:

- execution order;
- state created by a previous test;
- host configuration;
- network access;
- root privileges unless it belongs to an explicit privileged test job.

Use `setup` to create isolated state.

Use `teardown` to remove state that Bats temporary directories do not clean
automatically.

## Temporary directories

Use a test-owned temporary directory for:

- configuration files;
- backups;
- mock commands;
- state files;
- generated output.

Prefer Bats-provided temporary directories when available.

Example:

```bash
setup() {
    RLCH_TEST_ROOT="${BATS_TEST_TMPDIR}/case"
    mkdir -p "${RLCH_TEST_ROOT}/bin"
}
```

Do not write to fixed locations such as `/tmp/test-file`.

## Command mocks

System commands that could inspect or alter the host are mocked.

Typical commands include:

- `findmnt`;
- `mount`;
- `modprobe`;
- `rmmod`;
- `systemctl`;
- `sysctl`;
- `rpm`;
- `dnf`;
- `hostnamectl`.

Mocks are normally executable files placed at the start of `PATH`.

Example:

```bash
export PATH="${RLCH_TEST_ROOT}/bin:${PATH}"
```

A mock should:

- accept the production argument shape;
- record invocations when assertions require it;
- produce controlled output;
- support controlled exit statuses;
- fail on unexpected arguments when practical.

Do not create a mock that always succeeds regardless of arguments. Such mocks
hide integration defects.

## Fixtures

Fixtures represent realistic input state.

Fixtures should be:

- minimal;
- readable;
- immutable during a test;
- copied into the test temporary directory before modification;
- named by scenario.

Example:

```text
tests/fixtures/mount/fstab-compliant
tests/fixtures/mount/fstab-missing-nodev
tests/fixtures/mount/fstab-duplicate-target
```

Do not make a test modify the canonical fixture in the repository.

## Assertions

Assert observable outcomes.

Depending on the test, verify:

- return status;
- stdout;
- stderr;
- file content;
- file metadata;
- backup existence;
- command invocation count;
- command arguments;
- preserved unrelated configuration;
- absence of unintended changes.

Do not assert only that a command ran when effective state is the real contract.

## Return-code tests

Every public function must have return-code coverage.

At minimum, test:

- expected success;
- expected non-compliance;
- expected changed result;
- invalid input;
- dependency failure;
- operation failure.

Use framework result constants rather than duplicated numeric literals.

## Idempotence tests

Every modifying public function must have an idempotence test.

The test should execute the function twice and verify that the second execution:

- returns compliant;
- does not rewrite the file;
- does not invoke the modifying system command;
- does not create additional backup files;
- does not duplicate content.

Where timestamps are unreliable, compare checksums, mock call logs, or file
content.

## Rollback tests

Rollback tests must cover:

- successful restoration;
- restored content;
- runtime recovery where applicable;
- backup removal after success;
- backup preservation after failure;
- missing backup;
- repeated rollback;
- privilege failure.

Rollback tests must start from realistic framework-managed state.

## Failure injection

Libraries must be tested under controlled failures.

Examples:

- command not found;
- command exits non-zero;
- temporary-file creation fails;
- transformed file cannot be installed;
- remount succeeds but validation still fails;
- rollback restore succeeds but runtime recovery fails;
- duplicate configuration makes the operation ambiguous.

Failure tests verify both status and residual state.

A failed operation must not leave the fixture silently corrupted.

## Exact matching tests

Structured configuration requires positive and negative exact-match tests.

For mount options:

- `nodev` matches `nodev`;
- `nodev` does not match `nonodev`.

For mount targets:

- `/var` matches `/var`;
- `/var` does not match `/var/log`;
- a parent mount does not satisfy a child target.

For module identifiers:

- valid dotted identifiers match;
- incomplete or wildcard-invalid identifiers are rejected.

## Root privilege tests

Tests do not require actual root when a public API accepts an effective UID
argument.

Test at least:

- UID `0` accepted for a modifying path;
- non-zero UID rejected before modification.

When production code uses `EUID` directly, isolate privilege logic in a helper
that can be tested without privileged host changes.

## ShellCheck

ShellCheck is a required static-analysis gate.

It applies to:

- libraries;
- entry points;
- module implementations;
- metadata shell files when applicable;
- test helpers;
- Bats files where supported by the repository command.

Suppressions must be narrowly scoped and justified.

## Local execution

During development, run the targeted suite:

```bash
bats tests/mount.bats
```

Before commit, run all tests:

```bash
bats tests
```

Run ShellCheck using the repository’s CI-equivalent command.

Run:

```bash
git diff --check
```

before staging and again against staged changes.

## Continuous integration

Every push affecting framework code must run:

- the complete Bats suite;
- ShellCheck;
- repository-specific validation jobs.

A failing job blocks progression to the next control.

CI output must identify the failing test or file clearly.

Do not configure CI to ignore test failures.

## Test-count growth

The total number of tests is informative but is not a quality metric by itself.

The project prioritizes coverage of behavior and failure modes over a target
test count.

Every newly discovered regression should receive a test that fails before the
fix and passes after it.

## Test review checklist

For each new or changed public function, verify coverage for:

- valid input;
- invalid input;
- compliant state;
- non-compliant state;
- change path;
- idempotence;
- privilege requirements;
- dependency failure;
- command failure;
- rollback;
- cleanup after failure;
- exact matching;
- preservation of unrelated state.

Not every item applies to every read-only function, but omissions should be
deliberate.

## Mount-library minimum matrix

Before `lib/mount.sh` is accepted, its test suite must cover:

- library multiple-sourcing guard;
- exact option matching;
- exact fstab target matching;
- comments and blank lines;
- escaped targets;
- duplicate exact targets;
- exact runtime target matching;
- separate partition checks;
- persistent option checks;
- runtime option checks;
- atomic option addition;
- unchanged unrelated lines;
- idempotent write;
- backup creation;
- existing backup preservation;
- root validation;
- remount invocation;
- remount failure recovery;
- post-remount validation failure;
- successful rollback;
- rollback failure;
- backup preservation after failed recovery;
- idempotent rollback.

## Completion criteria

Testing for a change is complete only when:

- targeted tests pass;
- full Bats suite passes;
- ShellCheck passes;
- no test modifies the host;
- failure paths are covered;
- idempotence is covered where applicable;
- rollback is covered where applicable;
- CI passes.
