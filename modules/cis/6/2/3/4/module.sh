#!/usr/bin/env bash
# CIS 6.2.3.4 - bounded file creation mode observation, no daemon actions.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/journal_access.sh"
RLCH_CIS_6_2_3_4_ROOT="${RLCH_CIS_6_2_3_4_ROOT:-/}"

# Snapshot all candidates, including unselected snippets, without exposing them
# publicly. The private stream is never evaluated as shell/RainerScript code.
rlch_6_2_3_4_file() (
    local file="$1" before after fd stamp mode
    before="$(rlch_journal_config_file "$file")" || return 2
    mode="$(/usr/bin/stat -c '%a' -- "$file")" || return 2
    (( (8#$mode & 0022) == 0 )) || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    stamp="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || return 2
    [[ "${before%%|*}" == "$stamp" ]] || return 2
    printf 'file:%s\n' "$file"
    LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1; clean=$0; gsub(/\t/,"",clean)
         if(bytes>1048576 || length($0)>8192 || index($0,sprintf("%c",0)) ||
            clean ~ /[[:cntrl:]]/ || index($0,"\357\273\277") ||
            $0 ~ /^(file:|stamp:|directory:|main:)/) exit 2; print}
    ' <&"$fd" || return 2
    after="$(rlch_journal_config_file "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf 'stamp:%s\n' "$after"
)
rlch_6_2_3_4_snapshot() (
    local root="$RLCH_CIS_6_2_3_4_ROOT" directory file stamp mode count=0 bytes=0 size
    local -a files=()
    export LC_ALL=C
    rlch_tmout_directory "$root" >/dev/null || return 2
    directory="${root%/}/etc"
    rlch_tmout_directory "$directory" >/dev/null || return 2
    mode="$(/usr/bin/stat -c '%a' -- "$directory")" || return 2
    (( (8#$mode & 0022) == 0 )) || return 2
    stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%y:%z' -- "$directory")" || return 2
    printf 'directory:%s|%s\n' "$directory" "$stamp"
    file="$directory/rsyslog.conf"
    rlch_journal_path "$file" || return 2
    if [[ -e "$file" ]]; then printf 'main:present\n'; files+=("$file"); else printf 'main:absent\n'; fi
    directory="$directory/rsyslog.d"
    rlch_journal_path "$directory" || return 2
    if [[ -e "$directory" ]]; then
        rlch_tmout_directory "$directory" >/dev/null || return 2
        mode="$(/usr/bin/stat -c '%a' -- "$directory")" || return 2
        (( (8#$mode & 0022) == 0 )) || return 2
        stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%y:%z' -- "$directory")" || return 2
        printf 'directory:%s|%s\n' "$directory" "$stamp"
        shopt -s nullglob
        shopt -u dotglob
        files+=("$directory"/*.conf)
    else printf 'directory:absent\n'; fi
    for file in "${files[@]}"; do
        [[ "$file" != *[[:cntrl:]]* && "$file" != *'|'* ]] || return 2
        count=$((count+1)); [[ "$count" -le 1024 ]] || return 2
        rlch_tmout_file_stamp "$file" >/dev/null || return 2
        size="$(/usr/bin/stat -c '%s' -- "$file")" || return 2
        bytes=$((bytes+size)); [[ "$bytes" -le 4194304 ]] || return 2
        rlch_6_2_3_4_file "$file" || return 2
    done
)

# Recognize only complete standalone legacy directives and simple file selector
# actions, plus standard literal snippet includes. Everything else is review,
# including valid RainerScript actions/module defaults, templates and umasks.
# Result 0 means favorable STATIC evidence only; public check never certifies it.
rlch_6_2_3_4_model() {
    LC_ALL=C /usr/bin/awk '
        function trim(s) {sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s}
        function permitted(s, i,n,d) {
            n=0;for(i=1;i<=4;i++) n=n*8+substr(s,i,1)
            # The allowed bits are 0640, not an arithmetic <= comparison.
            for(i=0;i<9;i++) {d=int(n/2^i)%2; if(d && i!=8 && i!=7 && i!=5) return 0}
            return 1
        }
        function selector(s, a,b,c,i,j,n,m,p) {
            n=split(s,a,";")
            for(i=1;i<=n;i++) {
                if(split(a[i],b,".")!=2) return 0
                m=split(b[1],c,",")
                for(j=1;j<=m;j++) if(c[j] !~ /^(\*|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|security|syslog|user|uucp|local[0-7])$/) return 0
                p=b[2];sub(/^![=]?|^=/,"",p)
                if(p !~ /^(\*|none|debug|info|notice|warning|warn|err|error|crit|alert|emerg|panic)$/) return 0
            }
            return 1
        }
        function scan(s, nested, a,n,t,k) {
            s=trim(s); if(s=="" || s ~ /^#/) return
            sub(/[ \t]+#.*$/,"",s);s=trim(s);t=tolower(s)
            if(t ~ /^\$filecreatemode[ \t]+0[0-7][0-7][0-7]$/) {
                n=split(s,a,/[ \t]+/);mode=a[n];declared=1;return
            }
            if(t ~ /^\$umask[ \t]+0000$/) return
            # A restrictive umask could make an otherwise broad mode safe.
            # Do not infer its scope/effect, or report a false deficit.
            if(t ~ /^\$umask/) {bad=1;return}
            if(t=="$includeconfig /etc/rsyslog.d/*.conf" ||
               s ~ /^include[ \t]*\([ \t]*file[ \t]*=[ \t]*"\/etc\/rsyslog.d\/\*\.conf"[ \t]+mode[ \t]*=[ \t]*"optional"[ \t]*\)$/) {
                if(nested || !index(s,"/etc/rsyslog.d/*.conf")) {bad=1;return}
                for(k=1;k<=nf;k++) if(names[k]!=main) for(n=1;n<=lines[names[k]];n++) scan(body[names[k],n],1)
                return
            }
            # Only syntactically simple legacy selectors and literal absolute
            # omfile destinations; no dynamic templates, shell pipes or blocks.
            if(s ~ /^[a-zA-Z0-9*.,;!\-=]+[ \t]+-?\/[a-zA-Z0-9_./-]+$/) {
                split(s,a,/[ \t]+/)
                if(!selector(a[1]) || a[2] ~ /\/\// || a[2] ~ /\/(\.\.?)(\/|$)/ || a[2] ~ /\/$/) {bad=1;return}
                actions++;if(!permitted(mode)) deficit=1;return
            }
            bad=1
        }
        /^main:present$/ {present=1;next}
        /^main:absent$/ {next}
        /^directory:/ {next}
        # The snapshot emits the present main first. Read its name literally
        # from the stream: awk -v would interpret backslashes in fixture roots.
        /^file:/ {file=substr($0,6);if(present && !nf) main=file;names[++nf]=file;next}
        /^stamp:/ {file="";next}
        {if(file=="") bad=1;else body[file,++lines[file]]=$0}
        END {
            if(bad || (present && main=="")) exit 2
            if(!present) exit 1
            mode="0644"
            for(j=1;j<=lines[main];j++) scan(body[main,j],0)
            if(bad) exit 2
            if(deficit || !declared) exit 1
            if(!actions) exit 2
        }
    '
}
rlch_6_2_3_4_observe() {
    local before after first=0 last=0
    before="$(rlch_6_2_3_4_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_3_4_model <<< "$before" || first=$?
    after="$(rlch_6_2_3_4_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_3_4_model <<< "$after" || last=$?
    [[ "$first" == "$last" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$first"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_6_2_3_4_observe 2>/dev/null || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 6.2.3.4: selected legacy configuration lacks an explicit creation mode or contains a file action with permissions broader than 0640\n' >&2
        return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    printf 'CIS 6.2.3.4: manual review required; static evidence cannot certify native parsing, all action defaults/overrides, umask or loaded configuration; unsafe or unstable observations are errors\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
validate() { check; }
apply() {
    printf 'CIS 6.2.3.4: manual remediation required; review ordered includes, legacy and RainerScript omfile defaults/action overrides, then configure 0640 or stricter, validate with the installed rsyslog parser and verify real log creation; service activation and log effects cannot be exactly rolled back\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No file/package/service/log mutation, backup or persistent state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
