#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/lib/bootstrap.sh"

main "$@"