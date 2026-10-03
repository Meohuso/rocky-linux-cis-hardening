#!/usr/bin/env bash
# Metadata-only observations of files referenced by systemd configuration.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_config.sh
source "${BASH_SOURCE[0]%/*}/systemd_config.sh"

# Never open, read or hash the referenced object, including private keys.
# Physical canonical paths and regular files only; no permission policy is
# inferred from metadata. Compare identity before/after pathname checks.
rlch_sdconf_reference_stamp() {
    local file="$1" before after
    rlch_journal_path "$file" || return 2
    [[ -f "$file" && ! -L "$file" ]] || return 2
    before="$(/usr/bin/stat -c '%d:%i:%F:%u:%g:%a:%s:%y:%z' -- "$file" 2>/dev/null)" || return 2
    rlch_journal_path "$file" || return 2
    [[ -f "$file" && ! -L "$file" ]] || return 2
    after="$(/usr/bin/stat -c '%d:%i:%F:%u:%g:%a:%s:%y:%z' -- "$file" 2>/dev/null)" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf '%s\n' "$before"
}
