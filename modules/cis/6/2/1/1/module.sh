#!/usr/bin/env bash
# CIS 6.2.1.1 - pinned RHEL9 package/runtime/target-dependency observation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_observation.sh"
RLCH_CIS_6_2_1_1_RPM="${RLCH_CIS_6_2_1_1_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"
RLCH_CIS_6_2_1_1_SYSTEMCTL="${RLCH_CIS_6_2_1_1_SYSTEMCTL:-/usr/bin/systemctl}"

rlch_6_2_1_1_snapshot() {
    local command="$RLCH_CIS_6_2_1_1_SYSTEMCTL" service socket graph
    service="$(rlch_systemd_properties "$command" systemd-journald.service runtime)" || return 2
    socket="$(rlch_systemd_properties "$command" systemd-journald.socket runtime)" || return 2
    graph="$(rlch_systemd_target_graph "$command" multi-user.target)" || return 2
    printf 'service:%s\nsocket:%s\n%s\n' "$service" "$socket" "$graph"
}
rlch_6_2_1_1_check() {
    local package=0 final_package=0 before after line id load active file timestamp running=0 dependency=0
    rlch_systemd_package_status "$RLCH_CIS_6_2_1_1_RPM" systemd || package=$?
    [[ "$package" -ne 2 ]] || return 2
    # Determinable package absence does not depend on a working system manager.
    if [[ "$package" -eq 1 ]]; then
        rlch_systemd_package_status "$RLCH_CIS_6_2_1_1_RPM" systemd || final_package=$?
        [[ "$final_package" -eq 1 ]] || return 2
        return 1
    fi
    before="$(rlch_6_2_1_1_snapshot)" || return 2
    after="$(rlch_6_2_1_1_snapshot)" || return 2
    rlch_systemd_package_status "$RLCH_CIS_6_2_1_1_RPM" systemd || final_package=$?
    [[ "$before" == "$after" && "$final_package" -eq 0 ]] || return 2
    while IFS= read -r line; do
        case "$line" in
            service:*|socket:*)
                IFS='|' read -r id load active file timestamp <<< "${line#*:}"
                [[ "$active" != active ]] || running=1;;
            dependency:systemd-journald.service|dependency:systemd-journald.socket) dependency=1;;
        esac
    done <<< "$before"
    [[ "$running" -eq 1 && "$dependency" -eq 1 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_6_2_1_1_check || result=$?
    case "$result" in
        1) printf 'CIS 6.2.1.1: systemd package, journald service/socket activity or multi-user.target startup dependency is nonconforming\n' >&2;;
        2) printf 'CIS 6.2.1.1: RPM/system manager unavailable, unexpected/ambiguous properties or concurrent state change; manual review required\n' >&2;;
    esac
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.1.1: manual remediation required; review vendor target dependencies, masks and socket activation under administrative serialization; automatic changes cannot provide a safe exact runtime rollback for critical journald\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
# No mask/start/enable/configuration mutation or transaction is created.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
