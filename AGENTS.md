# Rocky Linux CIS Hardening Framework - Agent Instructions

## Scope

This repository implements a CIS Level 1 Server hardening framework for Rocky Linux 10.x, with Rocky Linux 10.2 as the primary golden-image target.

GitHub `main` is the source of truth. Always inspect the current repository before changing code.

## Mandatory development workflow

For CIS controls, preserve this sequence strictly:

1. Select exactly one CIS control.
2. Verify its current CIS RHEL 9 v2.0.0 / ComplianceAsCode mapping and Level 1 Server applicability.
3. Inspect existing repository architecture, libraries, modules, helpers, and tests relevant to the control.
4. Implement the control.
5. Add or update Bats tests.
6. Ensure ShellCheck cleanliness.
7. Commit exactly that CIS control.
8. Wait for and inspect GitHub Actions.
9. If CI fails, fix only the current control and repeat until Bats and ShellCheck are green.
10. Only then start the next CIS control.

Never batch several CIS controls into one commit.

## Engineering requirements

- Bash only for framework implementation.
- Production-quality code.
- ShellCheck clean.
- Bats tests mandatory.
- Idempotence mandatory.
- Rollback mandatory for remediations that change system state.
- Do not perform unrelated refactoring in a CIS-control commit.
- Reusable mechanisms belong in libraries; CIS policy belongs in modules.
- Preserve existing repository conventions unless an explicit architecture change is approved.
- Do not invent result constants, metadata fields, OpenSCAP rule IDs, CIS mappings, or benchmark requirements.
- Verify OpenSCAP/ComplianceAsCode mappings before implementation.
- Use `manual` for `RLCH_MODULE_OPENSCAP_RULE` when the repository metadata schema cannot represent an exact applicable primary rule.
- Controls that are Level 2 Server only are out of scope for the Level 1 Server baseline and must be recorded as SKIPPED rather than artificially remediated.

## Module API

Use the result constants defined by `lib/module_api.sh`. At the time this document was created, the established API is:

```bash
readonly RLCH_MODULE_RESULT_SUCCESS=0
readonly RLCH_MODULE_RESULT_NON_COMPLIANT=1
readonly RLCH_MODULE_RESULT_ERROR=2
readonly RLCH_MODULE_RESULT_NOT_APPLICABLE=3
readonly RLCH_MODULE_RESULT_CHANGED=4
```

Always re-read the actual file before relying on this list. There is no `RLCH_MODULE_RESULT_COMPLIANT` unless the API is explicitly changed in the repository.

## Metadata

Existing module metadata uses:

- `RLCH_MODULE_ID`
- `RLCH_MODULE_TITLE`
- `RLCH_MODULE_DESCRIPTION`
- `RLCH_MODULE_RATIONALE`
- `RLCH_MODULE_LEVEL`
- `RLCH_MODULE_ENABLED`
- `RLCH_MODULE_REQUIRES_REBOOT`
- `RLCH_MODULE_OPENSCAP_RULE`

Follow the validator and existing repository conventions.

## Testing notes

In Bats, a module function returning `RLCH_MODULE_RESULT_CHANGED=4` must not be invoked as an unguarded command when shell state needs to persist. Prefer:

```bash
result=0
apply || result=$?
[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
```

Do not use `run apply` when variable/function state modified by the function must remain in the parent Bats shell. Filesystem changes do survive the Bats `run` subshell.

Do not assign to Bash `EUID`; it is readonly. Use the repository's injectable `id -u` testing pattern where applicable.

Do not assert warning text when the test logging shim intentionally suppresses `log_warn` output. Use the established logging/test behavior in `tests/test_helper.bash`.

Avoid ShellCheck patterns known to fail CI, including ambiguous `A && B || C` constructs when SC2015 applies.

## Source verification

For benchmark mapping, verify the current authoritative project reference used by this repository before implementing a control. The project currently follows the CIS RHEL 9 v2.0.0 organization represented by ComplianceAsCode for the relevant sections while retaining established repository numbering where already implemented.

Do not silently renumber existing controls.

## Final validation

Completion of individual CI checks is not the final production validation. Before declaring the framework production-ready, perform the technical-debt review documented in `docs/DEVELOPMENT_STATUS.md`, followed by real Rocky Linux 10.2 testing, reboot/post-reboot validation, OpenSCAP comparison, rollback testing, a second idempotence run, and golden-image validation.
