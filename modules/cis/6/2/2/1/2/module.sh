#!/usr/bin/env bash
# CIS 6.2.2.1.2 - manual authentication policy, technical observation only.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_upload_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../../lib/journal_upload_observation.sh"
RLCH_CIS_6_2_2_1_2_ROOT="${RLCH_CIS_6_2_2_1_2_ROOT:-/}"
RLCH_CIS_6_2_2_1_2_ANALYZE="${RLCH_CIS_6_2_2_1_2_ANALYZE:-/usr/bin/systemd-analyze}"

rlch_6_2_2_1_2_references() {
    local rows="$1" key origin line value file stamp missing=0
    while IFS='|' read -r key origin line value; do
        if [[ -z "$origin" || -z "$value" ]]; then
            printf '%s=explicit-setting-missing\n' "$key"; missing=1; continue
        fi
        [[ -n "$line" && "$value" == /* && "$value" != *'"'* && "$value" != *"'"* && "$value" != *'\'* ]] || return 2
        file="${RLCH_CIS_6_2_2_1_2_ROOT%/}$value"
        stamp="$(rlch_sdconf_reference_stamp "$file")" || return 2
        printf '%s|%s\n' "$key" "$stamp"
    done <<< "$rows"
    return "$missing"
}
rlch_6_2_2_1_2_observe() {
    local before after rows first last result=0 final_result=0
    local names='ServerKeyFile ServerCertificateFile TrustedCertificateFile'
    before="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_1_2_ROOT" "$RLCH_CIS_6_2_2_1_2_ANALYZE" systemd/journal-upload.conf)" || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_1_2_ROOT" systemd/journal-upload.conf Upload "$names" <<< "$before")" || return 2
    first="$(rlch_6_2_2_1_2_references "$rows")" || result=$?
    [[ "$result" -ne 2 ]] || return 2
    after="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_1_2_ROOT" "$RLCH_CIS_6_2_2_1_2_ANALYZE" systemd/journal-upload.conf)" || return 2
    [[ "$before" == "$after" ]] || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_1_2_ROOT" systemd/journal-upload.conf Upload "$names" <<< "$after")" || return 2
    last="$(rlch_6_2_2_1_2_references "$rows")" || final_result=$?
    [[ "$result" == "$final_result" && "$first" == "$last" ]] || return 2
    return "$result"
}
check() {
    local result=0
    rlch_6_2_2_1_2_observe 2>/dev/null || result=$?
    case "$result" in
        0) printf 'CIS 6.2.2.1.2: three explicit technical settings and regular referenced objects present; identity, PKI and organizational policy require manual review\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
        1) printf 'CIS 6.2.2.1.2: explicit authentication setting(s) absent or empty; technical configuration deficit\n' >&2; return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *) printf 'CIS 6.2.2.1.2: unsafe, inaccessible, unsupported or unstable observation; manual review required\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    check || :
    printf 'CIS 6.2.2.1.2: manual remediation required; obtain approved authentication/PKI policy and review effective configuration and referenced objects; no configuration, credential or service changes performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
