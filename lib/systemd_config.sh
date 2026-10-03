#!/usr/bin/env bash
# Read-only bounded systemd INI selection, scalar extraction and value parsing.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/journal_access.sh"

rlch_sdconf_file() (
    local file="$1" before after fd stamp
    before="$(rlch_journal_config_file "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    stamp="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || return 2
    [[ "${before%%|*}" == "$stamp" ]] || return 2
    LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1; clean=$0; gsub(/\t/,"",clean)
         if(bytes>1048576 || length($0)>8192 || index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/ ||
            $0 ~ /^[ \t]*# \/.*[.]conf[ \t]*$/ || index($0,"\357\273\277")) exit 2}
    ' <&"$fd" || return 2
    after="$(rlch_journal_config_file "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf '%s\n' "$before"
)
rlch_sdconf_snapshot() (
    local root="$1" command="$2" relative="$3" prefix directory file stamp count=0
    local -a prefixes=(etc run usr/local/lib usr/lib) files=() args=()
    [[ "$relative" =~ ^systemd/[a-zA-Z0-9_.-]+\.conf$ ]] || return 2
    rlch_tmout_directory "$root" >/dev/null || return 2
    [[ "$root" == / ]] || args+=("--root=$root")
    shopt -s nullglob dotglob
    for prefix in "${prefixes[@]}"; do
        directory="${root%/}/$prefix/${relative%/*}"
        rlch_journal_path "$directory" || return 2
        if [[ -e "$directory" ]]; then
            stamp="$(rlch_tmout_directory "$directory")" || return 2
            printf 'directory:%s|%s\n' "$directory" "$stamp"
        else printf 'absent:%s\n' "$directory"; fi
        files=("${root%/}/$prefix/$relative")
        directory="${root%/}/$prefix/$relative.d"
        rlch_journal_path "$directory" || return 2
        if [[ -e "$directory" ]]; then
            stamp="$(rlch_tmout_directory "$directory")" || return 2
            printf 'directory:%s|%s\n' "$directory" "$stamp"
            files+=("$directory"/*.conf)
        else printf 'absent:%s\n' "$directory"; fi
        for file in "${files[@]}"; do
            [[ "$file" != *[[:cntrl:]]* && "$file" != *'|'* ]] || return 2
            if [[ ! -e "$file" && ! -L "$file" ]]; then printf 'absent:%s\n' "$file"; continue; fi
            count=$((count+1)); [[ "$count" -le 1024 ]] || return 2
            if [[ -L "$file" ]]; then
                [[ "$(/usr/bin/readlink -- "$file")" == /dev/null ]] || return 2
                stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%s:%y:%z' -- "$file")" || return 2
            else stamp="$(rlch_sdconf_file "$file")" || return 2; fi
            printf 'file:%s|%s\n' "$file" "$stamp"
        done
    done
    printf '===program===\n'
    set -o pipefail
    LC_ALL=C SYSTEMD_PAGER=cat SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 "$command" --no-pager "${args[@]}" cat-config "$relative" 2>/dev/null |
        LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1; clean=$0; gsub(/\t/,"",clean)
         if(bytes>4194304 || length($0)>8192 || index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) exit 2; print}
    ' || return 2
)
# Native cat-config chooses files. Headers are authenticated against inventory;
# input files cannot contain header-shaped comments. Each file resets section.
rlch_sdconf_scalars() {
    local root="$1" relative="$2" section="$3" names="$4"
    LC_ALL=C /usr/bin/awk -v root="${root%/}" -v relative="$relative" -v wanted_section="$section" -v names="$names" '
        function trim(s) {sub(/^[ \t]+/,"",s);sub(/[ \t]+$/,"",s);return s}
        BEGIN {n=split(names,keys," ");for(i=1;i<=n;i++) wanted[keys[i]]=1}
        /^file:/ && !program {p=$0;sub(/^file:/,"",p);sub(/\|.*/,"",p);files[p]=1;next}
        /^===program===$/ && !program {program=1;next}
        !program {next}
        /^# \// {
            if(pending!="") bad=1
            file=substr($0,3); if(!(file in files) || headers[file]++) bad=1
            # v252 daemon reads its /etc main; generic cat-config may select
            # a different main. Do not infer daemon behavior across versions.
            if(file==root "/run/" relative || file==root "/usr/local/lib/" relative || file==root "/usr/lib/" relative) bad=1
            current="";pending="";line=0;next
        }
        {
            line++;s=$0
            if(s ~ /^[ \t]*[#;]/) next
            if(file=="" && s !~ /^[ \t]*$/) {bad=1;next}
            s=pending s;pending=""
            # Count the trailing run directly, including even escaped pairs.
            k=0;for(j=length(s);j>0 && substr(s,j,1)=="\\";j--) k++
            if(k%2) {pending=substr(s,1,length(s)-1) " ";if(length(pending)>8192) bad=1;next}
            s=trim(s);if(s=="") next
            if(s ~ /^\[/) {
                if(s !~ /^\[[^][]+\]$/) {bad=1;next}
                current=substr(s,2,length(s)-2);next
            }
            if(current=="") {bad=1;next}
            if(current!=wanted_section) next
            eq=index(s,"=");if(!eq) {bad=1;next}
            key=trim(substr(s,1,eq-1));value=trim(substr(s,eq+1))
            if(key in wanted) {
                if(value ~ /\|/ || length(value)>256) {bad=1;next}
                values[key]=value;origins[key]=file;lines[key]=line
            }
        }
        END {
            if(!program || bad || pending!="") exit 2
            for(i=1;i<=n;i++) {key=keys[i];printf "%s|%s|%s|%s\n",key,origins[key],lines[key],values[key]}
        }
    '
}
# Exact uint64 integer subset of parse_size(base=1024). Fractions, signed and
# compound forms are intentionally manual-review; no floating point arithmetic.
rlch_sdconf_size() {
    local LC_ALL=C
    local value="$1" number suffix powers=0 digit carry out index iteration product
    [[ ${#value} -le 256 && "$value" =~ ^([0-9]+)[[:blank:]]*([KMGTPEB]?)$ ]] || return 2
    number="${BASH_REMATCH[1]}"; suffix="${BASH_REMATCH[2]}"
    while [[ ${#number} -gt 1 && "$number" == 0* ]]; do number="${number:1}"; done
    case "$suffix" in K) powers=1;; M) powers=2;; G) powers=3;; T) powers=4;; P) powers=5;; E) powers=6;; esac
    for ((iteration=0;iteration<powers;iteration++)); do
        carry=0; out=""
        for ((index=${#number}-1;index>=0;index--)); do
            digit="${number:index:1}";product=$((digit*1024+carry));out="$((product%10))$out";carry=$((product/10))
        done
        [[ "$carry" -eq 0 ]] || out="$carry$out"
        number="$out"
        [[ ${#number} -le 20 ]] || return 2
    done
    # shellcheck disable=SC2071 # Equal-width decimal strings; uint64 exceeds signed Bash arithmetic.
    [[ ${#number} -lt 20 || ( ${#number} -eq 20 && ! "$number" > 18446744073709551615 ) ]] || return 2
    printf '%s\n' "$number"
}
# Same parse_time(default seconds) primitive used by v252 config_parse_sec.
rlch_sdconf_duration() (
    local command="$1" value="$2" output number
    [[ -n "$value" && ${#value} -le 256 && "$value" != *[[:cntrl:]]* && "$value" != *'|'* ]] || return 2
    set -o pipefail
    output="$(LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 SYSTEMD_PAGER=cat COLUMNS=1024 "$command" --no-pager timespan -- "$value" 2>/dev/null |
        LC_ALL=C /usr/bin/awk '{bytes+=length($0)+1;if(bytes>8192 || index($0,sprintf("%c",0)) || $0 ~ /[[:cntrl:]]/) exit 2;print}')" || return 2
    number="$(LC_ALL=C /usr/bin/awk -v input="$value" '
        /^[ ]*Original:/ {s=$0;sub(/^[ ]*Original:[ ]*/,"",s);if(s!=input || original++) bad=1;next}
        /^[ ]*(μs|µs|us):/ {s=$0;sub(/^[ ]*(μs|µs|us):[ ]*/,"",s);if(s !~ /^[0-9]+$/ || usec++) bad=1;number=s;next}
        /^[ ]*Human:/ {if(human++) bad=1;next}
        /^[ ]*$/ {next}
        {bad=1}
        END {if(bad || original!=1 || usec!=1 || human!=1) exit 2;print number}
    ' <<< "$output")" || return 2
    # Normalize/check uint64 range without signed Bash arithmetic.
    rlch_sdconf_size "$number"
)
