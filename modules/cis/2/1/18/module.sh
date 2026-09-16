#!/usr/bin/env bash
# Rocky Linux CIS Hardening Framework
# CIS 2.1.18 - Ensure web server services are not in use.
# SPDX-License-Identifier: MIT
RLCH_CIS_2_1_18_PACKAGES="${RLCH_CIS_2_1_18_PACKAGES:-httpd nginx}"
RLCH_CIS_2_1_18_RPM_COMMAND="${RLCH_CIS_2_1_18_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_18_DNF_COMMAND="${RLCH_CIS_2_1_18_DNF_COMMAND:-dnf}"
RLCH_CIS_2_1_18_ID_COMMAND="${RLCH_CIS_2_1_18_ID_COMMAND:-id}"
RLCH_CIS_2_1_18_STATE_DIR="${RLCH_CIS_2_1_18_STATE_DIR:-/var/lib/rlch/cis/2.1.18}"
RLCH_CIS_2_1_18_STATE_FILE="${RLCH_CIS_2_1_18_STATE_FILE:-${RLCH_CIS_2_1_18_STATE_DIR}/packages-removed}"
cis_2_1_18_package_installed(){ local p="${1:-}"; [[ -n "$p" ]] || return 1; "${RLCH_CIS_2_1_18_RPM_COMMAND}" -q "$p" >/dev/null 2>&1; }
cis_2_1_18_any_package_installed(){ local p; for p in ${RLCH_CIS_2_1_18_PACKAGES}; do cis_2_1_18_package_installed "$p" && return 0; done; return 1; }
cis_2_1_18_require_root(){ local uid; if ! uid="$("${RLCH_CIS_2_1_18_ID_COMMAND}" -u 2>/dev/null)"; then error_message "Unable to determine effective user ID for CIS 2.1.18."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; if [[ "$uid" != 0 ]]; then error_message "CIS 2.1.18 requires root privileges."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; return "${RLCH_MODULE_RESULT_SUCCESS}"; }
cis_2_1_18_prepare_state(){ mkdir -p "${RLCH_CIS_2_1_18_STATE_DIR}" || { error_message "Unable to create CIS 2.1.18 state directory: ${RLCH_CIS_2_1_18_STATE_DIR}"; return "${RLCH_MODULE_RESULT_ERROR}"; }; : >"${RLCH_CIS_2_1_18_STATE_FILE}" || { error_message "Unable to create CIS 2.1.18 rollback state: ${RLCH_CIS_2_1_18_STATE_FILE}"; return "${RLCH_MODULE_RESULT_ERROR}"; }; }
cis_2_1_18_record_package(){ printf '%s\n' "$1" >>"${RLCH_CIS_2_1_18_STATE_FILE}" || { error_message "Unable to update CIS 2.1.18 rollback state."; return "${RLCH_MODULE_RESULT_ERROR}"; }; }
cis_2_1_18_remove_state(){ rm -f "${RLCH_CIS_2_1_18_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"; rmdir "${RLCH_CIS_2_1_18_STATE_DIR}" >/dev/null 2>&1 || true; }
check(){ cis_2_1_18_any_package_installed && return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"; return "${RLCH_MODULE_RESULT_SUCCESS}"; }
apply(){ local p changed=false; cis_2_1_18_any_package_installed || return "${RLCH_MODULE_RESULT_SUCCESS}"; cis_2_1_18_require_root || return "${RLCH_MODULE_RESULT_ERROR}"; cis_2_1_18_prepare_state || return "${RLCH_MODULE_RESULT_ERROR}"; for p in ${RLCH_CIS_2_1_18_PACKAGES}; do cis_2_1_18_package_installed "$p" || continue; if ! "${RLCH_CIS_2_1_18_DNF_COMMAND}" -y remove "$p"; then error_message "Unable to remove package $p."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; if cis_2_1_18_package_installed "$p"; then error_message "Package $p is still installed after remediation."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; cis_2_1_18_record_package "$p" || return "${RLCH_MODULE_RESULT_ERROR}"; changed=true; done; [[ "$changed" == true ]] && return "${RLCH_MODULE_RESULT_CHANGED}"; return "${RLCH_MODULE_RESULT_SUCCESS}"; }
validate(){ check; }
rollback(){ local p changed=false; [[ -e "${RLCH_CIS_2_1_18_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"; cis_2_1_18_require_root || return "${RLCH_MODULE_RESULT_ERROR}"; while IFS= read -r p || [[ -n "$p" ]]; do [[ -n "$p" ]] || continue; if ! cis_2_1_18_package_installed "$p"; then if ! "${RLCH_CIS_2_1_18_DNF_COMMAND}" -y install "$p"; then error_message "Unable to reinstall package $p."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; fi; if ! cis_2_1_18_package_installed "$p"; then error_message "Package $p is not installed after rollback."; return "${RLCH_MODULE_RESULT_ERROR}"; fi; changed=true; done <"${RLCH_CIS_2_1_18_STATE_FILE}"; cis_2_1_18_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"; [[ "$changed" == true ]] && return "${RLCH_MODULE_RESULT_CHANGED}"; return "${RLCH_MODULE_RESULT_SUCCESS}"; }
