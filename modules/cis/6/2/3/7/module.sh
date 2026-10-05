#!/usr/bin/env bash
# CIS 6.2.3.7 - bounded network input declarations, no daemon actions.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/journal_access.sh"
RLCH_CIS_6_2_3_7_ROOT="${RLCH_CIS_6_2_3_7_ROOT:-/}"

# Snapshot all candidates, including unselected snippets, without exposing them
# publicly. The private stream is never evaluated as shell/RainerScript code.
rlch_6_2_3_7_file() (
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
            $0 ~ /^(file:|stamp:|directory:|main:)/) exit 2; print}
    ' <&"$fd" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_journal_config_file "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'stamp:%s\n' "$after"
)

# This is a bounded declaration model, NOT the native rsyslog parser. It only
# establishes a static deficit. Unknown syntax dominates all known evidence;
# even an entirely favorable model never certifies public SUCCESS.
rlch_6_2_3_7_model() {
    LC_ALL=C /usr/bin/awk -v error="$RLCH_MODULE_RESULT_ERROR" -v deficit="$RLCH_MODULE_RESULT_NON_COMPLIANT" '
        function trim(s) {sub(/^[ \t]+/,"",s);sub(/[ \t]+$/,"",s);return s}
        function uncomment(s,i,c,q,out) {
            for(i=1;i<=length(s);i++) {
                c=substr(s,i,1)
                if(c=="\\") {bad=1;return ""}
                if(c=="\"") q=!q
                if(c=="#" && !q) break
                out=out c
            }
            if(q) bad=1
            return trim(out)
        }
        function network(m) {return m ~ /^(imtcp|imudp|imrelp)$/}
        function load(m) {
            if(m !~ /^(imtcp|imudp|imrelp|imuxsock|imjournal|imklog|immark)$/ || loaded[m]++) bad=1
        }
        function listen(m,p,address) {
            if(!network(m) || !loaded[m] || p !~ /^[0-9]+$/ || length(p)>5 || p+0<1 || p+0>65535) {bad=1;return}
            # Specific addresses (including loopback, names, IPv6 zones and
            # mapped addresses) require native and deployment-specific review.
            if(address!="" && address!="0.0.0.0" && address!="::" && !(address=="*" && m!="imrelp")) {bad=1;return}
            if(ports[m,p+0]++) {bad=1;return}
            remote=1
        }
        function object(s,kind,a,n,k,v,token) {
            delete params
            sub(/^[a-zA-Z]+[ \t]*\([ \t]*/,"",s);sub(/[ \t]*\)$/, "",s)
            # Complete double-quoted scalar assignments, arbitrary order,
            # whitespace and parameter-name case. No escapes or expressions.
            while(s!="") {
                if(!match(s,/^[a-zA-Z]+[ \t]*=[ \t]*"[^"\\]*"/)) {bad=1;return}
                token=substr(s,1,RLENGTH);s=substr(s,RLENGTH+1)
                if(s!="" && s !~ /^[ \t]/) {bad=1;return}
                s=trim(s);k=tolower(token);sub(/[ \t]*=.*/,"",k)
                v=token;sub(/^[^=]*=[ \t]*"/,"",v);sub(/"$/,"",v)
                if(k in params) {bad=1;return};params[k]=v
            }
            n=0;for(k in params) n++
            if(kind=="module") {
                if(n!=1 || !("load" in params)) {bad=1;return};load(params["load"]);return
            }
            if(!("type" in params) || !("port" in params)) {bad=1;return}
            for(k in params) if(k!="type" && k!="port" && k!="address") {bad=1;return}
            if(("address" in params) && params["address"]=="") {bad=1;return}
            listen(params["type"],params["port"],params["address"])
        }
        function scan(s,nested,a,n,t,k,m) {
            s=trim(s);if(s=="" || s ~ /^#/) return
            # Quotes protect #; escapes/continuations are review, never read as
            # a hidden comment or joined into a fabricated valid declaration.
            s=uncomment(s);if(s=="") return;t=tolower(s)
            if(t=="$includeconfig /etc/rsyslog.d/*.conf" ||
               s ~ /^include[ \t]*\([ \t]*file[ \t]*=[ \t]*"\/etc\/rsyslog.d\/\*\.conf"[ \t]+mode[ \t]*=[ \t]*"optional"[ \t]*\)$/) {
                if(nested) {bad=1;return}
                for(k=1;k<=nf;k++) if(names[k]!=main) for(n=1;n<=lines[names[k]];n++) scan(body[names[k],n],1)
                return
            }
            if(t ~ /^\$modload[ \t]+[a-z]+$/) {split(s,a,/[ \t]+/);load(a[2]);return}
            if(t ~ /^\$(inputtcpserverrun|udpserverrun|inputrelpserverrun)[ \t]+[0-9]+$/) {
                split(t,a,/[ \t]+/);m=(a[1]=="$inputtcpserverrun" ? "imtcp" : (a[1]=="$udpserverrun" ? "imudp" : "imrelp"))
                listen(m,a[2],address[m]);return
            }
            if(t ~ /^\$udpserveraddress[ \t]+[^ \t]+$/) {
                split(s,a,/[ \t]+/);m="imudp";address[m]=a[2];if(a[2]!="*" && a[2]!="0.0.0.0" && a[2]!="::") bad=1;return
            }
            if(s ~ /^(module|input)[ \t]*\(.*\)$/) {m=s;sub(/[ \t]*\(.*/,"",m);object(s,m);return}
            # A narrow complete local action supplies the required processing
            # rule, without assessing the separate logging-policy/file-mode CIS.
            if(s ~ /^\*\.\*[ \t]+-?\/[a-zA-Z0-9_./-]+$/) {
                split(s,a,/[ \t]+/)
                if(a[2] ~ /\/\// || a[2] ~ /\/(\.\.?)(\/|$)/ || a[2] ~ /\/$/) {bad=1;return}
                actions++;return
            }
            bad=1
        }
        /^main:present$/ {present=1;next}
        /^main:absent$/ {next}
        /^directory:/ {next}
        /^file:/ {file=substr($0,6);if(present && !nf) main=file;names[++nf]=file;next}
        /^stamp:/ {file="";next}
        {if(file=="") bad=1;else body[file,++lines[file]]=$0}
        END {
            if(bad || !present || main=="") exit error
            for(j=1;j<=lines[main];j++) scan(body[main,j],0)
            if(bad || !actions || !remote) exit error
            exit deficit
        }
    '
}
rlch_6_2_3_7_observe() {
    local before after result="$RLCH_MODULE_RESULT_SUCCESS"
    before="$(rlch_6_2_3_7_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_3_7_model <<< "$before" || result=$?
    after="$(rlch_6_2_3_7_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$result"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_6_2_3_7_observe 2>/dev/null || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 6.2.3.7: selected bounded configuration declares a wildcard network input; this is static configuration evidence, not proof of a running listener or remote message acceptance\n' >&2
        return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    printf 'CIS 6.2.3.7: manual review required; absent known input patterns or a loaded module alone cannot certify conformity; unsupported, invalid, unsafe, inaccessible or unstable observations are errors\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
apply() {
    printf 'CIS 6.2.3.7: manual remediation required; review selected ordered includes, legacy/RainerScript inputs, installed modules and native syntax, bind addresses and actual remote reception; establish applicable CIS/organization policy before disabling reception through approved change management; service and message effects have no exact rollback\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No mutation, daemon/parser/network invocation, backup or persistent state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
rlch_6_2_3_7_snapshot() (
    local root="$RLCH_CIS_6_2_3_7_ROOT" directory file stamp mode count=0 bytes=0 size
    local -a files=()
    export LC_ALL=C
    rlch_tmout_directory "$root" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    directory="${root%/}/etc"
    rlch_tmout_directory "$directory" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    mode="$(/usr/bin/stat -c '%a' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
    (( (8#$mode & 0022) == 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
    stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%y:%z' -- "$directory")" || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'directory:%s|%s\n' "$directory" "$stamp"
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
    for file in "${files[@]}"; do
        [[ "$file" != *[[:cntrl:]]* && "$file" != *'|'* ]] || return "$RLCH_MODULE_RESULT_ERROR"
        count=$((count+1)); [[ "$count" -le 1024 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_tmout_file_stamp "$file" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
        size="$(/usr/bin/stat -c '%s' -- "$file")" || return "$RLCH_MODULE_RESULT_ERROR"
        bytes=$((bytes+size)); [[ "$bytes" -le 4194304 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_6_2_3_7_file "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    done
)
