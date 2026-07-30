# ADR-0001: Framework Architecture

- Status: Accepted
- Date: 2026-07-30
- Decision owners: Project maintainers
- Scope: Rocky Linux CIS Hardening Framework
- Supersedes: None
- Superseded by: None

## Context

The project implements security-hardening controls for Rocky Linux through a
Bash-based framework.

The codebase is expected to grow from a small set of controls into a
long-lived project containing:

- domain libraries;
- control modules;
- command-line entry points;
- rollback mechanisms;
- unit and integration tests;
- continuous-integration workflows;
- developer and user documentation.

A collection of independent scripts would create duplicated system logic,
inconsistent behavior, weak rollback guarantees, and expensive maintenance.
The project therefore requires an explicit architecture before additional CIS
control families are implemented.

## Decision

The project will use a layered architecture in which CIS control modules
declare policy and framework libraries implement reusable operating-system
operations.

```text
+------------------------------------------------------+
|                 Command-line interface               |
+------------------------------------------------------+
|                    CIS control modules               |
|        Metadata, orchestration, policy parameters    |
+------------------------------------------------------+
|                  Framework public API                |
| Domain libraries: mount, sysctl, service, package... |
+------------------------------------------------------+
|                 Shared framework services            |
| Filesystem, logging, validation, execution context   |
+------------------------------------------------------+
|              Operating-system command layer          |
| findmnt, mount, systemctl, modprobe, sysctl, rpm...  |
+------------------------------------------------------+
|                    Rocky Linux 10                    |
+------------------------------------------------------+
```

## Architectural principles

### Policy and mechanism are separated

A CIS module describes:

- the control identifier;
- the control title;
- whether the control is enabled;
- whether a reboot may be required;
- the policy parameters passed to a library;
- the module actions: check, apply, validate, and rollback.

A CIS module does not implement reusable operating-system manipulation.

Domain libraries implement mechanisms such as:

- disabling a kernel module;
- validating a mount option;
- enabling or disabling a service;
- setting a sysctl value;
- managing a package;
- changing file ownership or permissions.

### Modules consume public APIs

Control modules must call public functions exposed by framework libraries.

Control modules must not directly invoke system commands when equivalent
framework functionality exists.

Examples of commands that belong behind library APIs include:

- `findmnt`;
- `mount`;
- `modprobe`;
- `systemctl`;
- `sysctl`;
- `rpm`;
- `dnf`;
- `chmod`;
- `chown`.

A direct command invocation is permitted only when:

1. no appropriate library exists;
2. the operation is specific to one control;
3. the implementation is reviewed as intentionally non-reusable.

When reusable logic is discovered, it must be moved into a library before
additional modules depend on it.

### Libraries have one domain responsibility

Each library owns one coherent system domain.

Examples:

```text
lib/filesystem.sh
lib/kernel_module.sh
lib/mount.sh
lib/package.sh
lib/service.sh
lib/sysctl.sh
lib/systemd.sh
lib/auditd.sh
lib/sshd.sh
lib/firewalld.sh
```

A library must not become a general-purpose collection of unrelated helpers.

### Public APIs are explicit

Public functions:

- are documented;
- use stable names;
- validate their arguments;
- have defined return semantics;
- are covered by dedicated Bats tests;
- do not rely on undocumented global state.

Internal functions use a leading underscore and are not consumed by modules.

Example:

```bash
mount_check_option
_mount_fstab_entry_for_target
```

Internal functions may change without compatibility guarantees. Public
functions may only change through an accepted architectural decision.

### Modifying operations are safe

Every operation that changes system state must satisfy all applicable
requirements:

- root privilege validation;
- argument validation;
- idempotence;
- deterministic behavior;
- atomic file replacement where possible;
- preservation of recoverable state;
- explicit rollback behavior;
- clear error reporting;
- no silent partial success.

A modifying operation must not claim success when only part of the requested
change was completed.

### Storage topology is not provisioned

The framework may validate storage-related requirements and safely modify
existing mount configuration.

The framework does not automatically:

- create partitions;
- create logical volumes;
- create RAID arrays;
- create filesystems;
- resize filesystems;
- move existing application data;
- enable storage encryption.

Controls requiring a dedicated partition return a non-compliant or
manual-remediation result when the required storage topology does not exist.

### Rocky Linux 10 is the current platform

The supported production target is Rocky Linux 10.

Libraries must avoid unnecessary distribution coupling so that future
adaptation to Rocky Linux 11 or another RHEL-compatible distribution remains
possible.

Platform-specific behavior must be isolated behind:

- system detection;
- library implementation details;
- version-aware functions;
- explicit compatibility checks.

Control modules should remain distribution-neutral whenever the policy itself
is distribution-neutral.

## Repository organization

The repository uses the following logical structure:

```text
.
├── bin/
│   └── framework entry points
├── config/
│   └── framework configuration
├── docs/
│   ├── architecture/
│   │   └── architecture decision records
│   ├── developer/
│   │   └── contributor documentation
│   ├── testing/
│   │   └── testing documentation
│   └── user/
│       └── operator documentation
├── lib/
│   └── public and internal framework libraries
├── modules/
│   └── CIS control modules grouped by benchmark namespace
├── tests/
│   ├── helpers/
│   ├── fixtures/
│   └── Bats test files
└── .github/
    └── workflows/
```

Existing repository names remain authoritative when they differ from this
logical example. Structural changes require a separate accepted decision.

## Module contract

Each module provides metadata and the following actions:

```bash
check
apply
validate
rollback
```

The framework execution layer may use module-specific function names, but every
module must expose equivalent behavior.

### Check

`check` inspects current state without changing it.

It returns a framework result representing one of the supported outcomes, such
as:

- compliant;
- non-compliant;
- error.

### Apply

`apply` attempts safe remediation.

It must:

- require appropriate privileges;
- avoid unnecessary changes;
- return changed only when state was modified;
- preserve rollback information when rollback is supported;
- return error when remediation cannot be completed safely.

### Validate

`validate` confirms the effective post-remediation state.

Validation must not assume that apply succeeded.

### Rollback

`rollback` restores the previous framework-managed state when recoverable state
exists.

Rollback must be idempotent. Calling rollback when no rollback state exists
must not damage the system.

## Library contract

Every public library function must document:

- function name;
- purpose;
- arguments;
- output;
- return semantics;
- side effects;
- privilege requirements;
- idempotence behavior;
- rollback interaction.

Libraries must be safe to source multiple times through a sourcing guard.

Libraries must quote parameter expansions unless intentional word splitting is
documented and tested.

Libraries must not terminate the parent process with `exit`. They return
control to their caller.

## Dependencies

### Runtime dependencies

The framework may rely on utilities normally available on Rocky Linux 10,
including:

- Bash;
- GNU Coreutils;
- util-linux;
- systemd tooling;
- kmod tooling;
- procps-ng tooling;
- rpm and dnf tooling;
- grep;
- sed;
- awk, when a simple and portable implementation is justified.

### Development dependencies

Development and CI may additionally use:

- Bats;
- ShellCheck;
- Git;
- GitHub Actions.

### Dependency policy

New runtime dependencies require explicit justification.

The framework must not require:

- Python;
- Perl;
- Ruby;
- Ansible;
- a configuration-management server;
- a network connection during normal execution.

OpenSCAP may be used as an external validation mechanism, but framework runtime
behavior must not depend on OpenSCAP unless a specific feature explicitly
requires it.

## Error handling

Libraries return status to their caller and report actionable diagnostics
through the framework logging facilities or standard error.

Public functions must distinguish between:

- invalid input;
- non-compliant system state;
- unavailable remediation;
- command execution failure;
- post-change validation failure.

Return values must be compatible with the framework result model.

A library must not reinterpret an execution failure as ordinary
non-compliance.

## Testing requirements

No new public function may enter `lib/` without dedicated Bats coverage.

Tests must cover, where applicable:

- successful behavior;
- invalid arguments;
- missing dependencies;
- compliant state;
- non-compliant state;
- changed state;
- idempotent repeated execution;
- privilege failure;
- command failure;
- rollback;
- repeated rollback;
- exact matching versus partial matching.

Mocks and fixtures must isolate tests from the host operating system.

The CI pipeline must run at least:

- all Bats tests;
- ShellCheck;
- repository validation checks defined by the project.

A change is not complete until CI is green.

## Development workflow

The Rocky Linux 10 implementation is developed directly on `main`.

The current workflow is:

1. analyze the relevant control family;
2. create or update an ADR when a new architectural decision is needed;
3. implement or extend the required library;
4. add or update dedicated library tests;
5. run Bats locally;
6. run ShellCheck locally;
7. commit only when local validation succeeds;
8. require green GitHub Actions before starting the next control;
9. implement one CIS control per commit.

Feature branches are reserved for major evolutions such as:

- Rocky Linux 11 support;
- a new CIS benchmark major version;
- a major architecture change;
- a large incompatible feature.

Generated archives are delivery artifacts and are not committed to the
repository.

## Versioning

The project follows semantic-versioning principles.

### Before 1.0

During `0.x` development:

- public APIs should be treated as intentionally stable;
- incompatible changes are allowed only through an accepted ADR;
- release notes must identify compatibility changes.

### From 1.0

From `1.0.0`:

- public APIs are compatibility commitments;
- backward-incompatible changes require a new major version;
- additive compatible functionality uses a minor version;
- compatible fixes use a patch version.

## ADR lifecycle

Every ADR has one of these statuses:

- `Draft`: proposed and under review;
- `Accepted`: approved and normative;
- `Superseded`: replaced by a later ADR;
- `Deprecated`: retained for historical context but no longer recommended;
- `Rejected`: considered and intentionally not adopted.

An accepted ADR is a project specification.

When implementation and an accepted ADR disagree, one of the following must
happen before merge:

1. the implementation is corrected;
2. the ADR is revised and accepted;
3. a new ADR supersedes the previous decision.

Architectural behavior must not change silently.

## Consequences

### Positive consequences

- CIS modules remain small and readable.
- System behavior is implemented once and tested once.
- Rollback and idempotence become consistent.
- Platform adaptation is localized.
- Future contributors have documented design constraints.
- Large-scale refactoring becomes less likely.
- Public API stability can be managed deliberately.

### Costs

- New control families may require library design before module development.
- Documentation must be maintained with code.
- Small changes may require broader tests.
- Architectural review adds deliberate upfront work.

These costs are accepted because the project prioritizes long-term reliability
over short-term implementation speed.

## Alternatives considered

### Independent scripts for each control

Rejected because it duplicates operating-system logic and produces inconsistent
behavior.

### Ansible roles

Rejected for the current project because the framework is intentionally
standalone, Bash-based, locally executable, and independent of an orchestration
platform.

### Direct command execution in every module

Rejected because it prevents central testing, stable error handling, and
consistent rollback.

### One large general-purpose library

Rejected because it creates excessive coupling and unclear ownership.

## Rationale

The benchmark defines security policy, but it does not define maintainable
software architecture.

A layered framework allows control modules to express what the system should
enforce while domain libraries define how Rocky Linux is inspected and changed.
This separation is the foundation for testability, safe remediation, stable
behavior, and future platform support.
