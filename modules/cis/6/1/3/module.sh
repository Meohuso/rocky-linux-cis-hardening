#!/usr/bin/env bash
# CIS 6.1.3 - pinned RHEL9 direct-line AIDE audit-tool policy.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/aide_audit_tools.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/aide_audit_tools.sh"
RLCH_CIS_6_1_3_CONFIG="${RLCH_CIS_6_1_3_CONFIG:-/etc/aide.conf}"
RLCH_CIS_6_1_3_RPM="${RLCH_CIS_6_1_3_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"

rlch_6_1_3_check() {
    local package=0 final_package=0 before after result=0
    rlch_aide_package_status "$RLCH_CIS_6_1_3_RPM" || package=$?
    [[ "$package" -ne 2 ]] || return 2
    before="$(rlch_aide_tools_snapshot "$RLCH_CIS_6_1_3_CONFIG")" || return 2
    rlch_aide_tools_rows "$RLCH_CIS_6_1_3_CONFIG" \
        'auditctl auditd ausearch aureport autrace augenrules' \
        'p+i+n+u+g+s+b+acl+xattrs+sha512' \
        'p+i+n+u+g+s+b+acl+selinux+xattrs+sha512' || result=$?
    [[ "$result" -ne 2 ]] || return 2
    after="$(rlch_aide_tools_snapshot "$RLCH_CIS_6_1_3_CONFIG")" || return 2
    [[ "$before" == "$after" ]] || return 2
    rlch_aide_package_status "$RLCH_CIS_6_1_3_RPM" || final_package=$?
    [[ "$package" == "$final_package" ]] || return 2
    if [[ "$package" -eq 1 || "$result" -eq 1 ]]; then
        printf 'CIS 6.1.3: AIDE package or required direct audit-tool configuration is missing/nonconforming\n' >&2
        return 1
    fi
    return 0
}
check() {
    local result=0
    rlch_6_1_3_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 6.1.3: unsafe/ambiguous configuration, RPM query failure or concurrent change; manual review required\n' >&2
    fi
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.1.3: manual remediation required; install AIDE if absent, review rule precedence and add/update the six exact direct requirements under administrative serialization; preserve configuration metadata and integrity baselines\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
# No files, packages or transaction state are mutated; rollback is a no-op.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
