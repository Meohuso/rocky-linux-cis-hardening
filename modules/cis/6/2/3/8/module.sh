#!/usr/bin/env bash
# CIS 6.2.3.8 - Manual rsyslog rotation-policy review; no system observation.
# SPDX-License-Identifier: MIT

check() {
    printf 'CIS 6.2.3.8: manual review required; reconcile organization-approved rsyslog log coverage and retention policy with effective logrotate configuration, ordered includes, global/local overrides and actual execution; review frequency, rotate count, size, compression, create owner/group/mode and rotation scripts; installed package, enabled timer, parser success or rotation history alone do not prove compliance; verify rsyslog reopens files and continues writing after rotation\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# A fresh manual-review requirement on every invocation, without cached facts.
validate() { check; }

apply() {
    printf 'CIS 6.2.3.8: manual remediation required; obtain approved coverage, frequency, retention, capacity and file-creation policy; review selected includes/globs, duplicate stanzas, effective directives, timer/cron/custom execution, state path and prerotate/postrotate scripts; validate with the installed native parser in a verified non-mutating debug mode, then test rotation and rsyslog reopen/write continuity in an appropriate validation environment through approved change management; do not invent rotate count, size, compression, ownership or signals; no automatic rotation, state update, reload or restart is performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}

# No reads, external commands, configuration writes, rotation, backup or state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
