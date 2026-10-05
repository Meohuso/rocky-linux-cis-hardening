#!/usr/bin/env bash
# CIS 6.2.3.5 - manual logging-policy review; no mapped automatic predicate.
# SPDX-License-Identifier: MIT

check() {
    printf 'CIS 6.2.3.5: manual review required; reconcile organization-approved logging policy with selected rsyslog configuration, ordered includes, inputs, rulesets, filters, actions, destinations and actual log collection; text matches or parser success alone do not prove compliance\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# Fresh manual-review result, never a cached or fabricated system observation.
validate() { check; }

apply() {
    printf 'CIS 6.2.3.5: manual remediation required; review the approved collection policy and selected legacy/RainerScript configuration including stop and discard rules, validate with the installed parser, then verify actual log delivery and persistence through approved change management; destination changes, reload/restart and processed or lost records have no exact rollback\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# No file read/write, command execution, package/service action, backup or state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
