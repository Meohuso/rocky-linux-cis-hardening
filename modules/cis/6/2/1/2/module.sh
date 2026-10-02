#!/usr/bin/env bash
# CIS 6.2.1.2 - manual mapping, bounded technical access review.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/journal_access.sh"
RLCH_CIS_6_2_1_2_ROOT="${RLCH_CIS_6_2_1_2_ROOT:-/}"
RLCH_CIS_6_2_1_2_TMPFILES="${RLCH_CIS_6_2_1_2_TMPFILES:-/usr/bin/systemd-tmpfiles}"
RLCH_CIS_6_2_1_2_GETFACL="${RLCH_CIS_6_2_1_2_GETFACL:-/usr/bin/getfacl}"
# Only the literal file rule has a required policy presence. Ancestor directory
# modes are not extra CIS requirements. Recursive mode operations are checked
# for their effect on files; ACL operations require human review.
rlch_journal_policy() {
    local machine="$1"
    LC_ALL=C /usr/bin/awk -v machine="$machine" '
        function mode_number(s, n,i) {n=0; for(i=1;i<=length(s);i++) n=n*8+substr(s,i,1); return n}
        function mode_ok(n, i,bit) {for(i=0;i<12;i++) {bit=2^i; if(int(n/bit)%2 && !(i==5 || i==7 || i==8)) return 0} return 1}
        function file_mode(s, conditional,n) {
            conditional=(substr(s,1,1)=="~"); if(conditional) s=substr(s,2)
            if(s !~ /^[0-7][0-7][0-7]([0-7])?$/) {bad=1; return}
            n=mode_number(s)
            # ~ strips specials on files and execute when native new file has
            # none; this is category masking, not bitwise intersection.
            if(conditional) {n=n%512; n-=int(n/64)%2*64+int(n/8)%2*8+n%2}
            if(!mode_ok(n)) finding=1
        }
        /^machine:/ && !program {mid=$0; sub(/^machine:/,"",mid); sub(/\|.*/,"",mid); if(mid!=machine) bad=1}
        /^===program===$/ {program=1; next}
        !program {next}
        /^[ \t]*(#|$)/ {next}
        {
            path=$2
            # Relevant unsupported escapes/expansion or quoted paths fail
            # closed; broad root rules can also affect journal descendants.
            if(path !~ /^\/(var|run)\/log\/journal([\/]|$)/) {
                if(path ~ /[*?\[]/ && $1 ~ /^(Z|A|z|a)/ && path ~ /^\/(var|run|\*)/) bad=1
                if(path=="/" || path=="/var" || path=="/run" || path=="/var/log" || path=="/run/log") {
                    if($1 ~ /^(Z|A)/) bad=1
                }
                if($0 ~ /journal/ && (path ~ /["\\]/ || path !~ /^\//)) bad=1
                next
            }
            if(NF<3 || NF>7 || path ~ /["\\]/ || path ~ /\/\//) {bad=1; next}
            gsub(/%m/,machine,path)
            if(path ~ /%/ || path ~ /\/\.\.?([\/]|$)/) {bad=1; next}
            type=$1; mode=$3
            if(mode!="-" && mode !~ /^~?[0-7][0-7][0-7]([0-7])?$/) {bad=1; next}
            # Only inert ownership fields and no age/argument interpretation
            # are supported for access operations. Never expand user input.
            if((NF>=4 && $4 !~ /^(-|[A-Za-z0-9_][A-Za-z0-9_-]*)$/) ||
               (NF>=5 && $5 !~ /^(-|[A-Za-z0-9_][A-Za-z0-9_-]*)$/) ||
               (NF>=6 && $6!="-") || (NF>=7 && $7!="-")) {bad=1; next}
            if(type ~ /^[aA]/) {bad=1; next}
            target="/var/log/journal/" machine "/system.journal"
            if(type=="z" && path==target) {
                if(!seen++) {
                    if(mode=="-") finding=1; else file_mode(mode)
                }
                next
            }
            if(type=="z" || type=="Z") {
                if(type=="Z" && path==target) {bad=1; next}
                if(path ~ /[*?\[]/) {bad=1; next}
                if(type=="Z" && mode!="-") file_mode(mode)
                else if(path ~ /\.journal(~)?$/ && mode!="-") file_mode(mode)
                next
            }
            if((type=="d" || type=="D") && path !~ /\.journal/ && mode ~ /^~?[0-7]+$/) next
            # Creation/truncation/removal or modified operation types cannot
            # establish a nonmutating safe file-access policy here.
            bad=1
        }
        END {if(bad || !program) exit 2; if(!seen || finding) exit 1; exit 0}
    '
}

rlch_6_2_1_2_check() {
    local root="$RLCH_CIS_6_2_1_2_ROOT" config final tree next third machine result=0 row mode status=0
    rlch_tmout_directory "$root" >/dev/null || return 2
    config="$(rlch_journal_config_snapshot "$root" "$RLCH_CIS_6_2_1_2_TMPFILES")" || return 2
    machine="$(/usr/bin/awk -F'[:|]' '/^machine:/ {print $2; exit}' <<< "$config")"
    rlch_journal_policy "$machine" <<< "$config" || result=$?
    [[ "$result" -ne 2 ]] || return 2
    tree="$(rlch_journal_tree_snapshot "$root" "$RLCH_CIS_6_2_1_2_GETFACL")" || return 2
    next="$(rlch_journal_tree_snapshot "$root" "$RLCH_CIS_6_2_1_2_GETFACL")" || return 2
    # One bounded stabilization retry permits a completed normal rotation.
    # Config changes are never silently retried or accepted.
    if [[ "$tree" != "$next" ]]; then
        third="$(rlch_journal_tree_snapshot "$root" "$RLCH_CIS_6_2_1_2_GETFACL")" || return 2
        [[ "$next" == "$third" ]] || return 2
        tree="$next"
    fi
    final="$(rlch_journal_config_snapshot "$root" "$RLCH_CIS_6_2_1_2_TMPFILES")" || return 2
    [[ "$config" == "$final" ]] || return 2
    while IFS= read -r row; do
        [[ "$row" == journal:* ]] || continue
        mode="${row##*:}"
        [[ "$mode" =~ ^[0-7]{1,4}$ ]] || return 2
        printf -v mode '%04o' "$((8#$mode))"
        status=0; rlch_journal_mode "$mode" 0640 || status=$?
        [[ "$status" -ne 2 ]] || return 2
        [[ "$status" -ne 1 ]] || result=1
    done <<< "$tree"
    return "$result"
}
check() {
    local result=0
    rlch_6_2_1_2_check || result=$?
    case "$result" in
        0) printf 'CIS 6.2.1.2: technical 0640-or-more-restrictive mode policy and observed journal access pass; manual organizational review remains required\n' >&2;;
        1) printf 'CIS 6.2.1.2: required literal tmpfiles file policy absent or configured/observed file mode exceeds 0640\n' >&2;;
        2) printf 'CIS 6.2.1.2: inaccessible/unsupported policy, effective ACL grant requiring site review, unsafe object or unstable observation; manual review required\n' >&2;;
    esac
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.1.2: manual remediation required; review effective tmpfiles configuration, native journal creation, existing modes and ACL/site policy; preserve administrator/vendor configuration and logging access\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
# No tmpfiles action, chmod, ACL edit, unit operation or transaction is created.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
