# Bash Coding Standards

## Scope

These standards apply to:

- `.sh` files;
- `.bash` files;
- `.bats` files;
- embedded Bash snippets maintained as executable examples.

Accepted ADRs take precedence when a domain requires stricter rules.

## Interpreter

Production shell code uses Bash.

Executable shell files begin with:

```bash
#!/usr/bin/env bash
```

Do not write Bash-specific code under `/bin/sh`.

## Formatting

Use four spaces for indentation.

Do not use tab characters for indentation.

Use one statement per line.

Prefer a maximum practical line length near 100 characters, but prioritize
readability over mechanical wrapping.

Place `then`, `do`, and function opening braces on the same line.

```bash
if condition; then
    command
fi

while condition; do
    command
done

example_function() {
    command
}
```

## Strict mode

Do not add strict-mode flags mechanically to sourced libraries.

The parent application owns shell execution options.

A library must behave correctly when sourced by a shell using options such as:

```bash
set -euo pipefail
```

Tests must cover important behavior under the project’s actual bootstrap
settings.

Executable entry points may enable explicit shell options according to the
project bootstrap design.

## Quoting

Quote parameter expansions unless intentional word splitting or glob expansion
is required and documented.

Correct:

```bash
printf '%s\n' "${value}"
command -- "${path}"
```

Incorrect:

```bash
echo $value
command $path
```

Use `--` before path operands when the command supports it.

## Command substitution

Use:

```bash
value="$(command)"
```

Do not use backticks.

Check command-substitution failures when failure matters.

```bash
if ! value="$(command)"; then
    printf 'unable to read value\n' >&2
    return "${RLCH_MODULE_RESULT_ERROR}"
fi
```

## Variables

Use lower-case names for local variables.

Use upper-case names for:

- exported environment variables;
- readonly framework constants;
- global framework configuration;
- public framework state already defined by architecture.

Declare locals explicitly:

```bash
local target
local option_list
```

Prefer assignment separate from command substitution when exit status must be
preserved:

```bash
local output

if ! output="$(command)"; then
    return 1
fi
```

Use `readonly` for constants.

Do not reuse framework constant names for local variables.

## Arrays

Use arrays when handling lists of shell words.

```bash
local -a arguments=(
    "--target"
    "${target}"
)
```

Do not construct command lines as strings.

Incorrect:

```bash
local command="findmnt --target ${target}"
${command}
```

Correct:

```bash
local -a command=(
    findmnt
    --target "${target}"
)

"${command[@]}"
```

## Functions

Use the declaration form:

```bash
function_name() {
    :
}
```

Do not use the `function` keyword.

A function should have one clear responsibility.

Public functions use the domain prefix:

```bash
filesystem_backup
kernel_module_check
mount_apply_option
```

Internal functions begin with an underscore and retain the domain prefix:

```bash
_mount_fstab_entry_exists
_kernel_module_normalize_name
```

Do not create unprefixed global helper functions.

## Function arguments

Validate required arguments at the public API boundary.

Prefer explicit positional assignments:

```bash
mount_check_option() {
    local mount_point="${1:-}"
    local option="${2:-}"
    local fstab_file="${3:-/etc/fstab}"

    if [[ -z "${mount_point}" || -z "${option}" ]]; then
        printf 'mount: mount point and option are required\n' >&2
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
}
```

Do not access an unset positional parameter directly when the caller may omit
it under `set -u`.

Use `shift` only when it improves clarity.

## Return behavior

Libraries return; they do not exit.

Correct:

```bash
return "${RLCH_MODULE_RESULT_ERROR}"
```

Incorrect in a sourced library:

```bash
exit 1
```

Do not return values larger than the shell status range.

Use stdout only for documented data output.

Use stderr for diagnostics.

Do not mix data output and diagnostics on stdout.

## Boolean values

Use the project’s established boolean representation.

When raw shell predicates are appropriate, return status instead of printing
`true` or `false`.

```bash
mount_option_list_contains "${options}" "${required}"
```

Avoid string booleans unless metadata or configuration requires them.

## Conditionals

Use `[[ ... ]]` for Bash conditionals.

Use arithmetic contexts for numeric comparisons:

```bash
if (( effective_uid != 0 )); then
    ...
fi
```

Use `case` for enumerated values.

```bash
case "${action}" in
    check|apply|validate|rollback)
        ;;
    *)
        return "${RLCH_MODULE_RESULT_ERROR}"
        ;;
esac
```

## Pattern matching

Distinguish deliberately between:

- literal equality;
- shell pattern matching;
- regular-expression matching.

Literal equality:

```bash
[[ "${actual}" == "${expected}" ]]
```

Regular expression:

```bash
[[ "${identifier}" =~ ^[0-9]+(\.[0-9]+)+$ ]]
```

Quote regular-expression data when it must be literal, or avoid regex and use a
token parser.

Do not use substring matching for structured comma-separated options.

## File handling

Use the shared filesystem library when it provides the required operation.

For direct temporary files:

- create them securely with `mktemp`;
- create them in the destination directory when atomic replacement is needed;
- install cleanup traps or explicit cleanup paths;
- preserve ownership and mode where required;
- replace files with `mv` only after successful generation and validation.

Do not truncate a critical configuration file before replacement content is
ready.

Do not use predictable temporary filenames.

## Text processing

Prefer the simplest readable tool.

Use Bash for token operations when it is clearer and adequately safe.

Use `grep`, `sed`, or `awk` only when their semantics are explicit and tested.

When using awk:

- avoid identifiers that may conflict with awk keywords or built-ins;
- pass shell values through `-v`;
- do not concatenate untrusted input into the program text;
- test the exact awk program on Rocky Linux 10;
- keep the program small enough to review.

Do not use `eval`.

## External commands

Validate required commands through the framework system library where
available.

Do not assume a command succeeded because it produced no output.

Capture and propagate meaningful failures.

Use machine-readable output modes.

For example, use explicit `findmnt` columns rather than parsing its default
table.

## Privilege checks

Modifying public APIs validate effective privileges before changing system
state.

Use the explicit effective UID argument when the library API supports test
injection.

Otherwise, use Bash’s numeric effective UID:

```bash
if (( EUID != 0 )); then
    printf 'root privileges are required\n' >&2
    return "${RLCH_MODULE_RESULT_ERROR}"
fi
```

Read-only checks should not require root unless the operating-system command
truly requires it.

## Idempotence

Before changing state, determine whether the requested state already exists.

Do not:

- append duplicate configuration;
- rewrite files unnecessarily;
- restart services unnecessarily;
- remount filesystems unnecessarily;
- overwrite preserved backups during repeated apply.

Return the framework compliant result when no change is needed.

## Rollback

Rollback code must use preserved state rather than reconstructing guessed state.

Remove rollback artifacts only after restoration and validation succeed.

Keep recovery artifacts when rollback fails.

## Error handling

Every error message should identify:

- the domain;
- the operation;
- the relevant target;
- the reason when known.

Example:

```bash
printf 'mount: unable to remount %s with option %s\n' \
    "${mount_point}" \
    "${option}" >&2
```

Do not emit stack traces or secrets.

Do not ignore a failure with `|| true` unless failure is explicitly harmless and
documented.

## Sourcing guards

Libraries must prevent duplicate initialization.

Use the repository’s established convention.

A guard must:

- work when the file is sourced;
- avoid exiting the parent shell;
- avoid redefining readonly variables;
- be covered by a test.

## ShellCheck

All maintained shell files must pass ShellCheck.

Fix warnings rather than suppressing them.

When suppression is necessary:

```bash
# shellcheck disable=SCxxxx  # Reason the construct is safe and required.
```

Limit the suppression to the smallest scope.

Do not add broad file-level suppressions without an accepted justification.

## Bats files

Bats test files follow the same quoting and naming rules.

Test names describe observable behavior:

```bash
@test "mount_write_fstab_option is idempotent" {
    ...
}
```

Avoid test names that describe implementation steps.

Use helpers for repeated setup and assertions.

Every test must be independent.

## Comments

Comments explain why, constraints, or non-obvious safety requirements.

Do not narrate straightforward code.

Useful:

```bash
# Preserve the first backup so rollback always restores pre-framework state.
```

Not useful:

```bash
# Check if backup exists.
if [[ -e "${backup_file}" ]]; then
```

## Documentation comments

Public functions should have a consistent comment block when the project adopts
one.

At minimum, public API documentation must exist in developer documentation or
the relevant ADR.

## Prohibited patterns

The following are prohibited unless explicitly justified and tested:

```bash
eval
source <(untrusted-command)
curl ... | bash
wget ... | bash
rm -rf "${possibly_empty_variable}"
echo ${unquoted_variable}
for item in $(command)
command_as_a_string="cmd --arg value"
${command_as_a_string}
```

Use arrays, validation, and shared helpers instead.

## Completion criteria

Shell code is complete only when:

- formatting follows these standards;
- public arguments are validated;
- return behavior follows framework semantics;
- modifying behavior is idempotent;
- rollback behavior is defined where applicable;
- Bats tests pass;
- ShellCheck passes;
- CI passes.
