#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Bats helper for cron authorization file access tests.
# SPDX-License-Identifier: MIT
#

setup_cron_authorization_commands() {
    local command_dir="${RLCH_TEST_CRON_AUTH_DIR}/bin"

    RLCH_TEST_CRON_AUTH_METADATA="${RLCH_TEST_CRON_AUTH_DIR}/metadata"
    mkdir -p "${command_dir}"

    cat > "${command_dir}/stat" <<'SCRIPT'
#!/usr/bin/env bash
format=""
path=""
arguments=("$@")
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c) format="${2:-}"; shift 2 ;;
        --) shift; path="${1:-}"; shift || true ;;
        *) path="$1"; shift ;;
    esac
done

case "${path}" in
    */cron.allow) label=allow ;;
    */cron.deny) label=deny ;;
    *) exec /usr/bin/stat "${arguments[@]}" ;;
esac

case "${format}" in
    "%u")
        if [[ -f "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.owner" ]]; then
            cat "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.owner"
        else
            /usr/bin/stat -c '%u' -- "${path}"
        fi
        ;;
    "%g")
        if [[ -f "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.group" ]]; then
            cat "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.group"
        else
            /usr/bin/stat -c '%g' -- "${path}"
        fi
        ;;
    *) exec /usr/bin/stat "${arguments[@]}" ;;
esac
SCRIPT

    cat > "${command_dir}/chown" <<'SCRIPT'
#!/usr/bin/env bash
ownership="${1:-}"
path="${!#}"
case "${path}" in
    */cron.allow) label=allow ;;
    */cron.deny) label=deny ;;
    *) exec /usr/bin/chown "$@" ;;
esac
printf '%s\n' "${ownership%%:*}" > "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.owner"
printf '%s\n' "${ownership#*:}" > "${RLCH_TEST_CRON_AUTH_METADATA}.${label}.group"
SCRIPT

    chmod +x "${command_dir}/stat" "${command_dir}/chown"
    export RLCH_TEST_CRON_AUTH_METADATA
    PATH="${command_dir}:${PATH}"
    export PATH
}
