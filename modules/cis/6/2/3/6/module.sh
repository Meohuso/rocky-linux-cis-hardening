#!/usr/bin/env bash
# CIS 6.2.3.6 - remote loghost manual review; related CAS rule is context only.
# SPDX-License-Identifier: MIT

check() {
    printf 'CIS 6.2.3.6: manual review required; establish the organization-approved remote log host, protocol, port, transport security and required log categories; reconcile selected configuration and ordered rules/includes with actual transmission, remote receipt and retention; forwarding text, parser success or connectivity alone do not prove compliance\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# Reevaluate the manual-review requirement each invocation, without cached data.
validate() { check; }

apply() {
    printf 'CIS 6.2.3.6: manual remediation required; obtain the approved destination and transport/PKI policy, then review legacy/RainerScript forwarding, selectors, conditional actions, stop/discard rules, templates, queues and retries; validate with the installed parser and confirm required records reach and remain on the approved remote host through authorized change management; do not infer approval from a configured target; destination changes, reload/restart and delivered or lost records have no exact rollback\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# No system observation, configuration, network/service action, backup or state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
