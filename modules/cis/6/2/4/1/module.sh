#!/usr/bin/env bash
# CIS 6.2.4.1 - bounded static rsyslog file attributes; no remediation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/journal_access.sh"
RLCH_CIS_6_2_4_1_ROOT="${RLCH_CIS_6_2_4_1_ROOT:-/}"

rlch_6_2_4_1_file() (
    local file="$1" before after fd stamp mode
    before="$(rlch_journal_config_file "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    mode="$(/usr/bin/stat -c '%a' -- "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    (( (8#$mode & 0022) == 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
    { exec {fd}<"$file"; } 2>/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    stamp="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "${before%%|*}" == "$stamp" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'file:%s\n' "$file"
    LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1; clean=$0; gsub(/\t/,"",clean)
         if(bytes>1048576 || length($0)>8192 || index($0,sprintf("%c",0)) ||
            clean ~ /[[:cntrl:]]/ || index($0,"\357\273\277") ||
            $0 ~ /^(file:|stamp:|directory:|main:|identity:)/) exit 2; print}
    ' <&"$fd" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_journal_config_file "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'stamp:%s\n' "$after"
)

# Verify the canonical local root identities, never assume names resolve via
# NSS or turn an unreadable account database into a default UID/GID.
rlch_6_2_4_1_identity() {
    local file="$1" kind="$2" before after mode
    before="$(rlch_journal_config_file "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    mode="$(/usr/bin/stat -c '%a' -- "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    (( (8#$mode & 0022) == 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
    LC_ALL=C /usr/bin/awk -F: -v kind="$kind" '
        $1=="root" {n++; if($3!="0" || (kind=="passwd" && ($4!="0" || NF!=7)) || (kind=="group" && NF!=4)) bad=1}
        END {exit (n!=1 || bad) ? 2 : 0}
    ' "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_journal_config_file "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'identity:%s|%s\n' "$file" "$after"
}

# Private discovery stream; a complete whitelist, not a native parser. Unknown
# selected syntax always fails, including dynamic destinations and control flow.
rlch_6_2_4_1_model() {
    RLCH_6241_MODEL_ROOT="${RLCH_CIS_6_2_4_1_ROOT%/}" LC_ALL=C /usr/bin/awk -v error="$RLCH_MODULE_RESULT_ERROR" '
        BEGIN {root=ENVIRON["RLCH_6241_MODEL_ROOT"]}
        function trim(s) {sub(/^[ \t]+/,"",s);sub(/[ \t]+$/,"",s);return s}
        function uncomment(s,i,c,q,out) {
            for(i=1;i<=length(s);i++) {
                c=substr(s,i,1)
                if(c=="\\") {bad=1;return ""}
                if(c=="\"") q=!q
                if(c=="#" && !q) {if(i>1 && substr(s,i-1,1) !~ /[ \t]/) bad=1;break}
                out=out c
            }
            if(q) bad=1
            return trim(out)
        }
        function selector(s,a,b,n,j,m,k) {
            n=split(s,a,";"); if(!n) return 0
            for(j=1;j<=n;j++) {
                if(split(a[j],b,".")!=2) return 0
                if(b[2] !~ /^(\*|none|[!=]?(emerg|alert|crit|err|warning|warn|notice|info|debug))$/) return 0
                m=split(b[1],fac,",")
                for(k=1;k<=m;k++) if(fac[k] !~ /^(\*|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|security|syslog|user|uucp|local[0-7])$/) return 0
            }
            return 1
        }
        function canonical(p) {
            return length(p)<=4096 && p ~ /^\// && p !~ /[|*?\[\]$`{}]/ && p !~ /\/\// && p !~ /\/(\.\.?)(\/|$)/ && p !~ /\/$/
        }
        function destination(p) {
            if(!canonical(p)) {bad=1;return}
            if(p ~ /^\/dev\//) return
            if(!(p in logs)) {logs[p]=1; order[++nl]=p; if(nl>1024) bad=1}
        }
        function include(p,optional,nested,j,found,physical) {
            if(nested || ++ni>32) {bad=1;return}
            if(p=="/etc/rsyslog.d/*.conf") {
                for(j=1;j<=nf;j++) if(names[j]!=main) {found++;scanfile(names[j],1)}
            } else if(p ~ /^\/etc\/rsyslog.d\/[a-zA-Z0-9_-]+\.conf$/) {
                physical=root p
                if(physical in lines) {found=1;scanfile(physical,1)}
            } else {bad=1;return}
            if(!found && !optional) bad=1
        }
        function object(s,kind,nested,token,k,v,n) {
            delete params
            sub(/^[a-z]+[ \t]*\([ \t]*/,"",s);sub(/[ \t]*\)$/, "",s)
            while(s!="") {
                if(!match(s,/^[a-zA-Z]+[ \t]*=[ \t]*"[^"\\]*"/)) {bad=1;return}
                token=substr(s,1,RLENGTH);s=substr(s,RLENGTH+1)
                if(s!="" && s !~ /^[ \t]/) {bad=1;return}
                s=trim(s);k=tolower(token);sub(/[ \t]*=.*/,"",k)
                v=token;sub(/^[^=]*=[ \t]*"/,"",v);sub(/"$/,"",v)
                if(k in params) {bad=1;return};params[k]=v
            }
            n=0;for(k in params) n++
            if(kind=="include") {
                if(!("file" in params)) {bad=1;return}
                for(k in params) if(k!="file" && k!="mode") {bad=1;return}
                if(("mode" in params) && params["mode"]!="optional" && params["mode"]!="required" && params["mode"]!="abort-if-missing") {bad=1;return}
                include(params["file"],params["mode"]=="optional",nested);return
            }
            if(kind=="module") {
                if(n!=1 || params["load"] !~ /^(imuxsock|imjournal|imklog|immark|builtin:omfile)$/ || loaded[params["load"]]++) bad=1
                return
            }
            if(params["type"]!="omfile" || !("file" in params)) {bad=1;return}
            for(k in params) {
                if(k=="type" || k=="file") continue
                if(k=="filecreatemode" && params[k] ~ /^0?[0-7][0-7][0-7]$/) continue
                if((k=="fileowner" || k=="filegroup") && params[k]=="root") continue
                bad=1
            }
            destination(params["file"])
        }
        function scanfile(f,nested,j,s,a,n,pending,kind,depth,i,c,q,prefix,t) {
            if(visited[f]++) {bad=1;return}
            for(j=1;j<=lines[f];j++) {
                s=uncomment(body[f,j]);if(s=="") continue
                if(pending=="") {
                    if(s ~ /^\$IncludeConfig[ \t]+[^ \t]+$/) {
                        split(s,a,/[ \t]+/);include(a[2],0,nested);continue
                    }
                    # These literal defaults affect future creation, not current
                    # file attributes; never certify the future mode from them.
                    if(s ~ /^\$FileCreateMode[ \t]+0?[0-7][0-7][0-7]$/ || s ~ /^\$File(Owner|Group)[ \t]+root$/) continue
                    if(s ~ /^\$ModLoad[ \t]+(imuxsock|imjournal|imklog|immark)$/) {split(s,a,/[ \t]+/);if(loaded[a[2]]++) bad=1;continue}
                    n=split(s,a,/[ \t]+/)
                    if(selector(a[1])) {
                        prefix=a[1];s=trim(substr(s,length(prefix)+1))
                        if(s !~ /^action[ \t]*\(/) {
                            if(s ~ /^-?\/[^ \t]+$/) {sub(/^-/,"",s);destination(s);continue}
                            # Recognized simple forwarding/user/discard outputs
                            # contribute no regular log file; empty sets fail.
                            if(s=="~" || s=="*" || s ~ /^@@?[a-zA-Z0-9.-]+(:[0-9]+)?$/ || s ~ /^[a-zA-Z_][a-zA-Z0-9_-]*(,[a-zA-Z_][a-zA-Z0-9_-]*)*$/) continue
                            bad=1;continue
                        }
                    }
                    if(s !~ /^(action|include|module)[ \t]*\(/) {bad=1;continue}
                    kind=s;sub(/[ \t]*\(.*/,"",kind)
                    depth=0
                }
                # Parentheses inside quoted scalars are data. Complete objects
                # can span lines, but quotes/escapes cannot span physical lines.
                q=0
                for(i=1;i<=length(s);i++) {
                    c=substr(s,i,1);if(c=="\"") q=!q
                    if(!q && c=="(") depth++
                    if(!q && c==")") depth--
                    if(depth<0) bad=1
                }
                pending=trim(pending " " s)
                if(length(pending)>8192) {bad=1;return}
                if(depth==0) {object(pending,kind,nested);pending=""}
            }
            if(pending!="" || depth!=0) bad=1
        }
        /^main:present$/ {present=1;next}
        /^main:absent$/ {next}
        /^(directory:|identity:)/ {next}
        /^file:/ {file=substr($0,6);if(present && !nf) main=file;names[++nf]=file;lines[file]=0;next}
        /^stamp:/ {file="";next}
        {if(file=="") bad=1;else body[file,++lines[file]]=$0}
        END {
            if(bad || !present || main=="") exit error
            scanfile(main,0)
            if(bad || !nl) exit error
            for(j=1;j<=nl;j++) print order[j]
        }
    '
}

# Private primitive permits deterministic stat evidence fixtures without
# bypassing discovery, canonicality, regular-file checks or policy evaluation.
rlch_6_2_4_1_stat() {
    /usr/bin/stat -c '%d|%i|%h|%u|%g|%a|%f|%z' -- "$1"
}

# Never hash or open a log: even 0000 is a valid subset of 0640. Stat does not
# follow the final component; physical canonicality rejects parent symlinks.
rlch_6_2_4_1_attributes() {
    local logical file stamp dev inode links uid gid mode raw time result="$RLCH_MODULE_RESULT_SUCCESS"
    while IFS= read -r logical; do
        [[ -n "$logical" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        file="${RLCH_CIS_6_2_4_1_ROOT%/}$logical"
        rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
        [[ -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        stamp="$(rlch_6_2_4_1_stat "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
        IFS='|' read -r dev inode links uid gid mode raw time <<< "$stamp"
        [[ "$dev" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && -n "$time" && "$mode" =~ ^[0-7]{1,4}$ && "$raw" =~ ^[0-9a-f]+$ && "$links" == 1 && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
        (( (16#$raw & 0170000) == 0100000 )) || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ "$uid" != 0 || "$gid" != 0 ]]; then result="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
        printf -v mode '%04o' "$((8#$mode))"
        if ! rlch_journal_mode "$mode" 0640; then result="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
        printf '%s|%s\n' "$logical" "$stamp"
    done
    return "$result"
}
rlch_6_2_4_1_observe() {
    local before after paths paths_after attrs attrs_after result="$RLCH_MODULE_RESULT_SUCCESS" second="$RLCH_MODULE_RESULT_SUCCESS"
    before="$(rlch_6_2_4_1_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    paths="$(rlch_6_2_4_1_model <<< "$before")" || return "$RLCH_MODULE_RESULT_ERROR"
    attrs="$(rlch_6_2_4_1_attributes <<< "$paths")" || result=$?
    [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" || "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_6_2_4_1_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    paths_after="$(rlch_6_2_4_1_model <<< "$after")" || return "$RLCH_MODULE_RESULT_ERROR"
    attrs_after="$(rlch_6_2_4_1_attributes <<< "$paths_after")" || second=$?
    [[ "$before" == "$after" && "$paths" == "$paths_after" && "$attrs" == "$attrs_after" && "$result" -eq "$second" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$result"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_6_2_4_1_observe 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") printf 'CIS 6.2.4.1: supported stable on-disk rsyslog configuration identifies regular files owned by root:root with POSIX modes 0640 or more restrictive; runtime routing, future creation, ACL/xattr and SELinux are not assessed\n' >&2 ;;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 6.2.4.1: supported stable on-disk rsyslog scope contains a root ownership/group or forbidden POSIX mode-bit deficit; manual remediation required\n' >&2 ;;
        *) result="$RLCH_MODULE_RESULT_ERROR"; printf 'CIS 6.2.4.1: manual review required; scope absent, empty, unsupported, unsafe, inaccessible or unstable; no complete file attribute conclusion\n' >&2 ;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    printf 'CIS 6.2.4.1: manual remediation required; resolve complete rsyslog output/include scope and native syntax, verify root identities, current root:root ownership and modes without forbidden bits beyond 0640; handle dynamic/missing files, rotation, creation defaults and ACL/SELinux separately; preserve more restrictive modes and exact attributes under approved change management; no chmod/chown/chgrp, file creation, backup, reload or restart\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
rlch_6_2_4_1_snapshot() (
    local root="$RLCH_CIS_6_2_4_1_ROOT" directory file stamp mode count=0 bytes=0 size
    local -a files=()
    export LC_ALL=C
    rlch_tmout_directory "$root" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    directory="${root%/}/etc"
    rlch_tmout_directory "$directory" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    mode="$(/usr/bin/stat -c '%a' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
    (( (8#$mode & 0022) == 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
    stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%y:%z' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'directory:%s|%s\n' "$directory" "$stamp"
    rlch_6_2_4_1_identity "$directory/passwd" passwd || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_4_1_identity "$directory/group" group || return "$RLCH_MODULE_RESULT_ERROR"
    file="$directory/rsyslog.conf"
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$file" ]]; then printf 'main:present\n'; files+=("$file"); else printf 'main:absent\n'; fi
    directory="$directory/rsyslog.d"
    rlch_journal_path "$directory" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$directory" ]]; then
        rlch_tmout_directory "$directory" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
        mode="$(/usr/bin/stat -c '%a' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
        (( (8#$mode & 0022) == 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
        stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%y:%z' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
        printf 'directory:%s|%s\n' "$directory" "$stamp"
        shopt -s nullglob
        shopt -u dotglob
        files+=("$directory"/*.conf)
    else printf 'directory:absent\n'; fi
    [[ "${#files[@]}" -le 1024 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    for file in "${files[@]}"; do
        [[ "$file" != *[[:cntrl:]]* && "$file" != *'|'* ]] || return "$RLCH_MODULE_RESULT_ERROR"
        count=$((count+1)); [[ "$count" -le 1024 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_tmout_file_stamp "$file" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
        size="$(/usr/bin/stat -c '%s' -- "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
        bytes=$((bytes+size)); [[ "$bytes" -le 4194304 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_6_2_4_1_file "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    done
)
