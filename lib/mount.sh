#!/usr/bin/env bash

# Rocky Linux CIS Hardening Framework
# Mount management library.
#
# This library centralizes persistent and runtime mount inspection and
# remediation. CIS modules must consume the public functions exposed here
# instead of invoking findmnt, mount, or editing /etc/fstab directly.

if [[ -n "${RLCH_MOUNT_LIBRARY_LOADED:-}" ]]; then
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        return 0
    fi
    exit 0
fi
readonly RLCH_MOUNT_LIBRARY_LOADED=1

: "${RLCH_MOUNT_FSTAB:=/etc/fstab}"
: "${RLCH_MOUNT_BACKUP_SUFFIX:=.rlch.bak}"
: "${RLCH_MOUNT_FINDMNT_COMMAND:=findmnt}"
: "${RLCH_MOUNT_COMMAND:=mount}"

# Framework result fallbacks. Existing constants remain authoritative.
: "${RLCH_MODULE_RESULT_COMPLIANT:=0}"
: "${RLCH_MODULE_RESULT_NON_COMPLIANT:=1}"
: "${RLCH_MODULE_RESULT_CHANGED:=2}"
: "${RLCH_MODULE_RESULT_ERROR:=3}"

##
# Print a mount-library error.
#
# Arguments:
#   $1 Error message.
#
# Returns:
#   0.
##
_mount_error() {
    printf 'mount: %s\n' "${1:-Unknown error.}" >&2
}

##
# Validate a mount target.
#
# Arguments:
#   $1 Absolute mount target.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_is_valid_target() {
    local target="${1:-}"

    [[ -n "${target}" ]] || return 1
    [[ "${target}" == /* ]] || return 1
    [[ "${target}" != *$'\n'* ]] || return 1
    [[ "${target}" != *$'\r'* ]] || return 1
    [[ "${target}" != *$'\t'* ]] || return 1

    return 0
}

##
# Validate a single mount option.
#
# Arguments:
#   $1 Mount option.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_is_valid_option() {
    local option="${1:-}"

    [[ -n "${option}" ]] || return 1
    [[ "${option}" != *,* ]] || return 1
    [[ "${option}" != *[[:space:]]* ]] || return 1
    [[ "${option}" =~ ^[A-Za-z0-9._:+@=-]+$ ]] || return 1

    return 0
}

##
# Normalize a mount target for exact comparisons.
#
# Root remains "/". Other trailing slashes are removed.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Normalized target.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_normalize_target() {
    local target="${1:-}"

    mount_is_valid_target "${target}" || return 1

    while [[ "${target}" != "/" && "${target}" == */ ]]; do
        target="${target%/}"
    done

    printf '%s\n' "${target}"
}

##
# Decode fstab escape sequences used in source and target fields.
#
# Arguments:
#   $1 Encoded field.
#
# Outputs:
#   Decoded field.
#
# Returns:
#   0.
##
_mount_decode_fstab_field() {
    local value="${1:-}"

    value="${value//\\040/ }"
    value="${value//\\011/$'\t'}"
    value="${value//\\012/$'\n'}"
    value="${value//\\134/\\}"

    printf '%s\n' "${value}"
}

##
# Encode a field for fstab.
#
# Arguments:
#   $1 Plain field.
#
# Outputs:
#   Encoded field.
#
# Returns:
#   0.
##
_mount_encode_fstab_field() {
    local value="${1:-}"

    value="${value//\\/\\134}"
    value="${value//$'\t'/\\011}"
    value="${value//$'\n'/\\012}"
    value="${value// /\\040}"

    printf '%s\n' "${value}"
}

##
# Test whether a comma-separated option list contains an exact option.
#
# Arguments:
#   $1 Comma-separated option list.
#   $2 Required option.
#
# Returns:
#   0 when present.
#   1 otherwise.
##
mount_option_list_contains() {
    local option_list="${1:-}"
    local required_option="${2:-}"
    local option
    local -a options=()

    mount_is_valid_option "${required_option}" || return 1

    IFS=',' read -r -a options <<< "${option_list}"
    for option in "${options[@]}"; do
        [[ "${option}" == "${required_option}" ]] && return 0
    done

    return 1
}

##
# Add an option to a comma-separated list without duplicates.
#
# Arguments:
#   $1 Existing option list.
#   $2 Required option.
#
# Outputs:
#   Updated option list.
#
# Returns:
#   0 on success.
#   1 for invalid input.
##
mount_option_list_add() {
    local option_list="${1:-}"
    local required_option="${2:-}"

    mount_is_valid_option "${required_option}" || return 1

    if mount_option_list_contains "${option_list}" "${required_option}"; then
        printf '%s\n' "${option_list}"
    elif [[ -z "${option_list}" ]]; then
        printf '%s\n' "${required_option}"
    else
        printf '%s,%s\n' "${option_list}" "${required_option}"
    fi
}

##
# Print the first active fstab entry for an exact target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path. Defaults to RLCH_MOUNT_FSTAB.
#
# Outputs:
#   Six tab-separated fields:
#   source, target, filesystem, options, dump, pass.
#
# Returns:
#   0 when found.
#   1 when absent or invalid.
##
mount_fstab_entry() {
    local requested_target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"
    local normalized_target
    local line
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value
    local decoded_target

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1
    [[ -r "${fstab_path}" ]] || return 1

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue

        source=""
        target=""
        filesystem=""
        options=""
        dump_value=""
        pass_value=""

        read -r \
            source \
            target \
            filesystem \
            options \
            dump_value \
            pass_value <<< "${line}"

        [[ -n "${source}" && -n "${target}" && -n "${filesystem}" && -n "${options}" ]] || continue
        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || continue

        if [[ "${decoded_target}" == "${normalized_target}" ]]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${source}" \
                "${target}" \
                "${filesystem}" \
                "${options}" \
                "${dump_value:-0}" \
                "${pass_value:-0}"
            return 0
        fi
    done < "${fstab_path}"

    return 1
}

##
# Print the persistent option list for an exact target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Outputs:
#   Comma-separated option list.
#
# Returns:
#   0 when the target exists in fstab.
#   1 otherwise.
##
mount_fstab_options() {
    local entry
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value

    entry="$(mount_fstab_entry "${1:-}" "${2:-${RLCH_MOUNT_FSTAB}}")" || return 1
    IFS=$'\t' read -r source target filesystem options dump_value pass_value <<< "${entry}"
    printf '%s\n' "${options}"
}

##
# Print runtime mount data for an exact target.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Four tab-separated fields:
#   source, target, filesystem, options.
#
# Returns:
#   0 when the exact target is mounted.
#   1 otherwise.
##
mount_runtime_entry() {
    local requested_target="${1:-}"
    local normalized_target
    local output
    local source
    local target
    local filesystem
    local options
    local decoded_target

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1

    command -v "${RLCH_MOUNT_FINDMNT_COMMAND}" >/dev/null 2>&1 || return 1

    output="$(
        "${RLCH_MOUNT_FINDMNT_COMMAND}" \
            --raw \
            --noheadings \
            --output SOURCE,TARGET,FSTYPE,OPTIONS \
            --target "${normalized_target}" 2>/dev/null
    )" || return 1

    [[ -n "${output}" ]] || return 1

    while IFS= read -r output; do
        read -r source target filesystem options <<< "${output}"
        [[ -n "${target}" ]] || continue

        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || continue

        if [[ "${decoded_target}" == "${normalized_target}" ]]; then
            printf '%s\t%s\t%s\t%s\n' \
                "${source}" \
                "${target}" \
                "${filesystem}" \
                "${options}"
            return 0
        fi
    done <<< "${output}"

    return 1
}

##
# Print runtime options for an exact mount target.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Comma-separated option list.
#
# Returns:
#   0 when mounted.
#   1 otherwise.
##
mount_runtime_options() {
    local entry
    local source
    local target
    local filesystem
    local options

    entry="$(mount_runtime_entry "${1:-}")" || return 1
    IFS=$'\t' read -r source target filesystem options <<< "${entry}"
    printf '%s\n' "${options}"
}

##
# Check whether a target has its own persistent and runtime mount.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when both exact entries exist.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
##
mount_check_partition() {
    local target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"

    if ! mount_fstab_entry "${target}" "${fstab_path}" >/dev/null; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! mount_runtime_entry "${target}" >/dev/null; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_COMPLIANT}"
}

##
# Check whether a mount option is configured persistently and active.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when persistent and runtime states comply.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
#   RLCH_MODULE_RESULT_ERROR for invalid arguments.
##
mount_check_option() {
    local target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local persistent_options
    local runtime_options

    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_option "${required_option}" || return "${RLCH_MODULE_RESULT_ERROR}"

    persistent_options="$(mount_fstab_options "${target}" "${fstab_path}")" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    mount_option_list_contains "${persistent_options}" "${required_option}" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    runtime_options="$(mount_runtime_options "${target}")" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    mount_option_list_contains "${runtime_options}" "${required_option}" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    return "${RLCH_MODULE_RESULT_COMPLIANT}"
}

##
# Return the backup path associated with an fstab file.
#
# Arguments:
#   $1 Optional fstab path.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0.
##
mount_backup_path() {
    local fstab_path="${1:-${RLCH_MOUNT_FSTAB}}"

    printf '%s%s\n' "${fstab_path}" "${RLCH_MOUNT_BACKUP_SUFFIX}"
}

##
# Create the persistent backup once.
#
# Existing backups are preserved to retain the original pre-remediation state.
#
# Arguments:
#   $1 Optional fstab path.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0 on success.
#   1 on failure.
##
mount_backup_fstab() {
    local fstab_path="${1:-${RLCH_MOUNT_FSTAB}}"
    local backup_path

    [[ -f "${fstab_path}" ]] || return 1
    backup_path="$(mount_backup_path "${fstab_path}")"

    if [[ ! -e "${backup_path}" ]]; then
        cp --preserve=mode,ownership,timestamps -- "${fstab_path}" "${backup_path}" || return 1
    fi

    printf '%s\n' "${backup_path}"
}

##
# Require effective root privileges.
#
# Returns:
#   0 for root.
#   1 otherwise.
##
_mount_require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        _mount_error "Root privileges are required."
        return 1
    fi

    return 0
}

##
# Add an option to the exact target entry using an atomic replacement.
#
# Comments, blank lines, unrelated entries, source, filesystem, dump, and pass
# values are preserved. The matching entry is normalized to tab-separated
# fields when changed.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   0 on success, including idempotent success.
#   1 on failure.
##
mount_write_fstab_option() {
    local requested_target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local normalized_target
    local directory
    local temporary_path
    local line
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value
    local decoded_target
    local updated_options
    local found=0
    local changed=0

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1
    mount_is_valid_option "${required_option}" || return 1
    [[ -f "${fstab_path}" && -r "${fstab_path}" && -w "${fstab_path}" ]] || return 1

    directory="$(dirname -- "${fstab_path}")"
    temporary_path="$(mktemp "${directory}/.rlch-fstab.XXXXXX")" || return 1

    if ! chmod --reference="${fstab_path}" "${temporary_path}" ||
        ! chown --reference="${fstab_path}" "${temporary_path}" 2>/dev/null; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" =~ ^[[:space:]]*$ || "${line}" =~ ^[[:space:]]*# ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        source=""
        target=""
        filesystem=""
        options=""
        dump_value=""
        pass_value=""

        read -r \
            source \
            target \
            filesystem \
            options \
            dump_value \
            pass_value <<< "${line}"

        if [[ -z "${source}" || -z "${target}" || -z "${filesystem}" || -z "${options}" ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || decoded_target=""

        if [[ "${decoded_target}" != "${normalized_target}" ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        found=1
        updated_options="$(mount_option_list_add "${options}" "${required_option}")" || {
            rm -f -- "${temporary_path}"
            return 1
        }

        if [[ "${updated_options}" != "${options}" ]]; then
            changed=1
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${source}" \
            "${target}" \
            "${filesystem}" \
            "${updated_options}" \
            "${dump_value:-0}" \
            "${pass_value:-0}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
    done < "${fstab_path}"

    if [[ "${found}" -eq 0 ]]; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    if [[ "${changed}" -eq 0 ]]; then
        rm -f -- "${temporary_path}"
        return 0
    fi

    sync "${temporary_path}" 2>/dev/null || true

    if ! mv -f -- "${temporary_path}" "${fstab_path}"; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    return 0
}

##
# Remount an exact target using its fstab configuration.
#
# Arguments:
#   $1 Mount target.
#
# Returns:
#   0 on success.
#   1 on failure.
##
mount_remount_target() {
    local target="${1:-}"
    local normalized_target

    normalized_target="$(mount_normalize_target "${target}")" || return 1
    command -v "${RLCH_MOUNT_COMMAND}" >/dev/null 2>&1 || return 1

    "${RLCH_MOUNT_COMMAND}" -o remount "${normalized_target}"
}

##
# Apply a persistent and runtime mount option.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when already compliant.
#   RLCH_MODULE_RESULT_CHANGED when changed successfully.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
mount_apply_option() {
    local target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local check_status
    local backup_path

    _mount_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_option "${required_option}" || return "${RLCH_MODULE_RESULT_ERROR}"

    mount_check_option "${target}" "${required_option}" "${fstab_path}"
    check_status=$?

    if [[ "${check_status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    fi

    backup_path="$(mount_backup_fstab "${fstab_path}")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! mount_write_fstab_option "${target}" "${required_option}" "${fstab_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_remount_target "${target}"; then
        cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}" 2>/dev/null || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_check_option "${target}" "${required_option}" "${fstab_path}"; then
        cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}" 2>/dev/null || true
        mount_remount_target "${target}" >/dev/null 2>&1 || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

##
# Refuse automatic storage provisioning.
#
# The framework validates partition requirements but does not create,
# resize, format, or migrate filesystems automatically.
#
# Returns:
#   RLCH_MODULE_RESULT_ERROR.
##
mount_apply_partition() {
    _mount_error "Automatic partition creation is intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

##
# Restore the original fstab backup and remount the target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_CHANGED when restored.
#   RLCH_MODULE_RESULT_COMPLIANT when no backup exists.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
mount_rollback() {
    local target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"
    local backup_path

    _mount_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"

    backup_path="$(mount_backup_path "${fstab_path}")"

    if [[ ! -e "${backup_path}" ]]; then
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    fi

    [[ -f "${backup_path}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if mount_runtime_entry "${target}" >/dev/null 2>&1; then
        if ! mount_remount_target "${target}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -f -- "${backup_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

# Read-only inventory API, additive: historical mount APIs remain unchanged.
# mount_inventory ARRAY [MOUNTINFO=/proc/self/mountinfo]
# ARRAY must be a caller-owned writable indexed array (not _rlch_mi_*).
# Success=0, error=2 with ARRAY empty; stdout is always empty. Ten fields per
# record, sorted by numeric mount ID: ID PARENT MAJ:MIN ROOT TARGET SOURCE
# FSTYPE VFS_OPTIONS FS_OPTIONS OPTIONAL_FIELDS. Empty OPTIONAL_FIELDS is valid.
# Names are byte strings, not lines; kernel escapes 040/011/012/134 only are
# decoded once. Producer framing uses NUL and an explicit trailer/count.
# Limits: 4096 records, 16384 bytes/line, 4 MiB input. Empty, incomplete graph,
# duplicate/stacked target, cycle, unknown optional field or malformed evidence
# fails closed. Root parent may be outside this namespace (or root itself).
# No mount, findmnt, fstab write, path traversal, content read or NSS query.
_mount_inventory_stream() {
    LC_ALL=C /usr/bin/cat -- "$1"
}
_mount_inventory_frame() (
    set -o pipefail
    { _mount_inventory_stream "$1" && printf '%s\n' RLCH-MOUNTINFO-END; } | LC_ALL=C /usr/bin/awk '
        function bad() {invalid=1;exit 2}
        function uint(s,zero) {return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=4294967294 && (zero || s!="0")}
        function decode(s, i,c,e,out) {
            out=""
            for(i=1;i<=length(s);i++) {
                c=substr(s,i,1)
                if(c=="\\") {
                    e=substr(s,i+1,3)
                    if(e=="040") c=" "
                    else if(e=="011") c="\t"
                    else if(e=="012") c="\n"
                    else if(e=="134") c="\\"
                    else bad()
                    i+=3
                }
                out=out c
            }
            return out
        }
        function path(s) {return substr(s,1,1)=="/" && (s=="/" || (s !~ /\/$/ && s !~ /\/\// && s !~ /\/(\.|\.\.)(\/|$)/))}
        {
            if($0=="RLCH-MOUNTINFO-END") {if(ended) bad();ended=1;next}
            if(ended) bad()
            bytes+=length($0)+1
            if(bytes>4194304 || length($0)>16384 || NR>4096 || index($0,sprintf("%c",0)) || index($0,"\t")) bad()
            if(!uint($1,0) || !uint($2,1) || seen[$1]++ || split($3,dev,":")!=2 || !uint(dev[1],1) || !uint(dev[2],1)) bad()
            sep=0
            for(i=7;i<=NF;i++) if($i=="-") {sep=i;break}
            if(!sep || sep+3!=NF || $6=="" || $(sep+1)=="" || $(sep+2)=="" || $(sep+3)=="") bad()
            if($6 !~ /^(ro|rw)(,|$)/ || $(sep+3) !~ /^(ro|rw)(,|$)/) bad()
            root=decode($4);target=decode($5)
            if(!path(root) || !path(target) || targets[target]++) bad()
            id=$1; ids[++n]=id; parent[id]=$2; targetof[id]=target
            if(target=="/") {rootid=id;roots++}
            optional=""
            for(i=7;i<sep;i++) {
                if($i!="unbindable") {
                    if(split($i,part,":")!=2 || part[1] !~ /^(shared|master|propagate_from)$/ || !uint(part[2],0)) bad()
                }
                key=$i; sub(/:.*/,"",key)
                if(opts[id SUBSEP key]++) bad()
                optional=optional (optional=="" ? "" : " ") $i
            }
            record[id,1]=id;record[id,2]=$2;record[id,3]=$3;record[id,4]=root;record[id,5]=target
            record[id,6]=decode($(sep+2));record[id,7]=$(sep+1);record[id,8]=decode($6)
            record[id,9]=decode($(sep+3));record[id,10]=optional
        }
        END {
            if(invalid || !ended || !n || roots!=1) exit 2
            for(i=1;i<=n;i++) {
                id=ids[i];p=parent[id];t=targetof[id]
                if(id==rootid) {if(p in seen && p!=id) exit 2}
                else {
                    if(!(p in seen) || p==id) exit 2
                    pt=targetof[p]
                    if(pt!="/" && substr(t,1,length(pt)+1)!=pt "/") exit 2
                    for(k=1;k<=n;k++) {
                        candidate=targetof[ids[k]]
                        if(ids[k]!=id && length(candidate)>length(pt) && substr(t,1,length(candidate)+1)==candidate "/") exit 2
                    }
                }
            }
            # Canonical order independent of kernel row order; bounded N^2.
            for(i=1;i<=n;i++) for(j=i+1;j<=n;j++) if(ids[j]+0<ids[i]+0) {v=ids[i];ids[i]=ids[j];ids[j]=v}
            printf "RLCH-MOUNTS-1%c",0
            for(i=1;i<=n;i++) for(j=1;j<=10;j++) printf "%s%c",record[ids[i],j],0
            printf "END%c%d%c",0,n,0
        }
    '
)
mount_inventory() {
    local _rlch_mi_name="${1:-}" _rlch_mi_path="${2:-/proc/self/mountinfo}"
    local _rlch_mi_fd _rlch_mi_pid _rlch_mi_result=0 _rlch_mi_count _rlch_mi_size
    local -a _rlch_mi_frame=()
    [[ "$_rlch_mi_name" =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ && "$_rlch_mi_name" != _rlch_mi_* ]] || return 2
    local -n _rlch_mi_out="$_rlch_mi_name"
    _rlch_mi_out=()
    exec {_rlch_mi_fd}< <(_mount_inventory_frame "$_rlch_mi_path" 2>/dev/null)
    _rlch_mi_pid=$!
    mapfile -d '' -t _rlch_mi_frame <&"$_rlch_mi_fd" || _rlch_mi_result=2
    exec {_rlch_mi_fd}<&-
    wait "$_rlch_mi_pid" || _rlch_mi_result=2
    [[ "$_rlch_mi_result" == 0 ]] || return 2
    _rlch_mi_size=${#_rlch_mi_frame[@]}
    (( _rlch_mi_size>=13 )) || return 2
    _rlch_mi_count="${_rlch_mi_frame[_rlch_mi_size-1]}"
    [[ "${_rlch_mi_frame[0]}" == RLCH-MOUNTS-1 && "${_rlch_mi_frame[_rlch_mi_size-2]}" == END &&
       "$_rlch_mi_count" =~ ^[1-9][0-9]{0,3}$ ]] || return 2
    (( _rlch_mi_count<=4096 && _rlch_mi_size==_rlch_mi_count*10+3 )) || return 2
    _rlch_mi_out=("${_rlch_mi_frame[@]:1:_rlch_mi_size-3}")
}
