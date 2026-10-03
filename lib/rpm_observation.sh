#!/usr/bin/env bash
# Structured RPM inventory observations; no package transactions.
# SPDX-License-Identifier: MIT

# A complete, nonempty inventory is evidence that RPM can read headers. Empty
# output alone cannot distinguish an empty/misdirected database from absence.
# Reject any stderr, even if RPM exits zero or the text resembles valid rows.
rlch_rpm_inventory() (
    local command="$1"
    local format='RPM1|%{DBINSTANCE}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|END\n'
    set -o pipefail
    {
        {
            LC_ALL=C "$command" -qa --qf "$format" 2>&1 1>&3 |
                /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'
        } 3>&1 || exit 2
        # Also detects a missing newline on the last RPM record.
        printf 'RPM-END\n'
    } | /usr/bin/head -c 4194305 | LC_ALL=C /usr/bin/awk -F '|' '
        {
            total+=length($0)+1
            if (total>4194304 || length($0)>2048 || index($0,sprintf("%c",0)) || /[[:cntrl:]]/) {bad=1; exit 2}
            if ($0=="RPM-END") {if (ended) {bad=1; exit 2}; ended=1; next}
            if (ended || ++rows>65536 || NF!=8 || $1!="RPM1" || $8!="END") {bad=1; exit 2}
            if ($2 !~ /^[1-9][0-9]*$/ || length($2)>10 || $2+0>4294967295 || seen[$2]++) {bad=1; exit 2}
            if ($3 !~ /^[a-zA-Z0-9][a-zA-Z0-9._+-]*$/ || length($3)>255) {bad=1; exit 2}
            if ($4 !~ /^(0|[1-9][0-9]*)$/ || length($4)>10 || $4+0>4294967295) {bad=1; exit 2}
            if ($5 !~ /^[a-zA-Z0-9._+~^-]+$/ || length($5)>255 || $6 !~ /^[a-zA-Z0-9._+~^-]+$/ || length($6)>255) {bad=1; exit 2}
            if (($7 !~ /^[a-zA-Z0-9_]+$/ && $7!="(none)") || length($7)>64) {bad=1; exit 2}
            print
        }
        END {if (bad || !ended || !rows) exit 2}
    ' | LC_ALL=C /usr/bin/sort
)

# 0 installed, 1 determinably absent, 2 unsafe/failed/unstable observation.
# Compare the entire normalized inventory, including DB record identities and
# NEVRA. Multiple records of the same name are valid if their IDs are distinct.
rlch_rpm_package_status() {
    local command="$1" package="$2" before after row name
    [[ "$package" =~ ^[a-zA-Z0-9][a-zA-Z0-9._+-]*$ && ${#package} -le 255 ]] || return 2
    before="$(rlch_rpm_inventory "$command" 2>/dev/null)" || return 2
    after="$(rlch_rpm_inventory "$command" 2>/dev/null)" || return 2
    [[ "$before" == "$after" ]] || return 2
    while IFS= read -r row; do
        name="${row#*|}"; name="${name#*|}"; name="${name%%|*}"
        if [[ "$name" == "$package" ]]; then return 0; fi
    done <<< "$before"
    return 1
}
