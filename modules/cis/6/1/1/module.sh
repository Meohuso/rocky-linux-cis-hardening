#!/usr/bin/env bash
# CIS 6.1.1 - Observe package and operational AIDE database, never regenerate.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/aide_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/aide_observation.sh"
RLCH_CIS_6_1_1_CONFIG="${RLCH_CIS_6_1_1_CONFIG:-/etc/aide.conf}"
RLCH_CIS_6_1_1_RPM="${RLCH_CIS_6_1_1_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"

rlch_6_1_1_check() {
    local package=0 final_package=0 before after rows parsed=0 directory uri actual oval file stamp final status=0 finding=0 index=0
    local -A observed=()
    rlch_aide_package_status "$RLCH_CIS_6_1_1_RPM" || package=$?
    [[ "$package" -ne 2 ]] || return 2
    if [[ "$package" -eq 1 ]]; then
        printf 'CIS 6.1.1: AIDE RPM package is absent\n' >&2
        finding=1
    fi
    before="$(rlch_aide_config_stamp "$RLCH_CIS_6_1_1_CONFIG")" || return 2
    rows="$(rlch_aide_config_rows "$RLCH_CIS_6_1_1_CONFIG")" || parsed=$?
    [[ "$parsed" -ne 2 ]] || return 2
    if [[ "$parsed" -eq 1 ]]; then
        printf 'CIS 6.1.1: required AIDE configuration is absent\n' >&2
        finding=1
    else
        IFS='|' read -r directory uri <<< "$rows"
        if [[ "$directory" == missing || "$uri" == missing ]]; then
            printf 'CIS 6.1.1: a CAS-required DBDIR or operational database directive is missing\n' >&2
            finding=1
        else
            [[ "$(/usr/bin/realpath -m -s -- "$directory")" == "$directory" ]] || return 2
            if [[ "$uri" == '@@{DBDIR}/'* ]]; then actual="$directory/${uri#'@@{DBDIR}/'}"; else actual="$uri"; fi
            [[ "$(/usr/bin/realpath -m -s -- "$actual")" == "$actual" ]] || return 2
            # RHEL OVAL composes DBDIR + basename, even for a literal URI.
            oval="$directory/${uri##*/}"
            if [[ "$actual" != "$oval" ]]; then
                printf 'CIS 6.1.1: configured path and CAS-composed path differ; both artifacts are required by this audit\n' >&2
            fi
            for file in "$actual" "$oval"; do
                [[ -z "${observed[$file]+present}" ]] || continue
                status=0; index=$((index + 1))
                stamp="$(rlch_aide_database_stamp "$file")" || status=$?
                [[ "$status" -ne 2 ]] || return 2
                observed["$file"]="$stamp"
                if [[ "$status" -eq 1 ]]; then
                    printf 'CIS 6.1.1: database artifact %s is absent or empty\n' "$index" >&2
                    finding=1
                fi
            done
        fi
    fi
    after="$(rlch_aide_config_stamp "$RLCH_CIS_6_1_1_CONFIG")" || return 2
    [[ "$before" == "$after" ]] || return 2
    for file in "${!observed[@]}"; do
        status=0
        final="$(rlch_aide_database_stamp "$file")" || status=$?
        [[ "$status" -ne 2 && "$final" == "${observed[$file]}" ]] || return 2
    done
    rlch_aide_package_status "$RLCH_CIS_6_1_1_RPM" || final_package=$?
    [[ "$package" == "$final_package" ]] || return 2
    [[ "$finding" -eq 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_6_1_1_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 6.1.1: unsafe or unsupported configuration/database, RPM query error or concurrent change; manual review required\n' >&2
    fi
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.1.1: manual remediation required; review package filesystem effects and initialise/publish a database from an approved known-good system under administrative serialization; preserve every existing database\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
# No installation, initialisation, publication or transaction state is created.
# Rollback therefore never removes a package or administrator database.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
