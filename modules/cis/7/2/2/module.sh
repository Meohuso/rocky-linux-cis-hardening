#!/usr/bin/env bash
# CIS 7.2.2 - Literal CAS .+ exclusion / none_exist, not awk !$2.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_2_SHADOW="${RLCH_CIS_7_2_2_SHADOW:-/etc/shadow}"
RLCH_CIS_7_2_2_RPM="${RLCH_CIS_7_2_2_RPM:-/usr/bin/rpm}"

rlch_7_2_2_observe() {
    local applicable=0 after_applicable=0 before after first second marker total=0 empty=0
    # Pinned RHEL9 system_with_kernel uses kernel-core, including kernel-bearing
    # bootc cases. A failed query is never evidence of a classic container.
    rlch_rpm_package_status "$RLCH_CIS_7_2_2_RPM" kernel-core 2>/dev/null || applicable=$?
    case "$applicable" in 0|1) :;; *) return 2;; esac
    if [[ "$applicable" -eq 1 ]]; then return "$RLCH_MODULE_RESULT_NOT_APPLICABLE"; fi
    # Outer metadata brackets supplement each API descriptor/path comparison.
    # stat observes metadata only; no raw shadow content enters Bash.
    before="$(LC_ALL=C /usr/bin/stat -c '%u|%g|%a|%d|%i|%s|%y|%z|%h' -- "$RLCH_CIS_7_2_2_SHADOW" 2>/dev/null)" || return 2
    first="$(rlch_identity_shadow_password_presence "$RLCH_CIS_7_2_2_SHADOW" 2>/dev/null)" || return 2
    second="$(rlch_identity_shadow_password_presence "$RLCH_CIS_7_2_2_SHADOW" 2>/dev/null)" || return 2
    after="$(LC_ALL=C /usr/bin/stat -c '%u|%g|%a|%d|%i|%s|%y|%z|%h' -- "$RLCH_CIS_7_2_2_SHADOW" 2>/dev/null)" || return 2
    rlch_rpm_package_status "$RLCH_CIS_7_2_2_RPM" kernel-core 2>/dev/null || after_applicable=$?
    [[ "$after_applicable" -eq 0 && -n "$first" && "$first" == "$second" && "$before" == "$after" ]] || return 2
    while IFS= read -r marker; do
        total=$((total + 1)); (( total <= 65536 )) || return 2
        case "$marker" in
            NONEMPTY) : ;;
            EMPTY) empty=$((empty + 1)) ;;
            *) return 2 ;;
        esac
    done <<< "$first"
    if (( empty > 0 )); then
        printf 'CIS 7.2.2: %s of %s local shadow entries have an empty password field; identities and values withheld\n' "$empty" "$total" >&2
        return 1
    fi
    return 0
}
check() {
    local result=0
    rlch_7_2_2_observe || result=$?
    case "$result" in
        0|1|3) return "$result" ;;
        *) printf 'CIS 7.2.2: cannot reliably evaluate applicability or the local shadow database; evidence unavailable, invalid or unstable\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.2: manual remediation required; review account access and protected restoration before changing authentication fields\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
