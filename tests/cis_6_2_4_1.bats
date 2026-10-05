#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_4_1_ROOT="$BATS_TEST_TMPDIR/root" ATTR_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_6_2_4_1_ROOT"; MAIN="$R/etc/rsyslog.conf"; LOG="$R/var/log/messages"
    mkdir -p "$R/etc/rsyslog.d" "$R/var/log" "$R/var/lib/logrotate"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$R/etc/passwd"
    printf 'root:x:0:\n' > "$R/etc/group"
    printf '*.* /var/log/messages\n' > "$MAIN"
    printf 'PRIVATE records\n' > "$LOG"; chmod 0640 "$LOG"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/4/1/module.sh"
    # CI is unprivileged and local root has a restricted UID map. Normalize
    # only fixture numeric stat identities; the production observer evaluates
    # every policy, path, type, link, mode and stability check unchanged.
    eval "$(declare -f rlch_6_2_4_1_stat | sed '1s/rlch_6_2_4_1_stat/real_stat/')"
    eval "$(declare -f rlch_6_2_4_1_attributes | sed '1s/rlch_6_2_4_1_attributes/real_attributes/')"
    rlch_6_2_4_1_stat() { real_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }

}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 6.2.4.1:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "6241 exact metadata Automated mapping scalar fallback L1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/4/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.4.1 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure access to all logfiles has been configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    validate_loaded_module_metadata 6.2.4.1; validate_loaded_module_functions
}
@test "6241 framework load isolates previous guidance functions" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/8"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/4/1"
    [ "$RLCH_CURRENT_MODULE_ID" = 6.2.4.1 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    # Loading restores the real observer rather than retaining our fixture shim.
    run check
    if [ "$(id -u)" -eq 0 ] && [ "$(id -g)" -eq 0 ]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "6241 root root 0640 complete stable scope succeeds" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"; }
@test "6241 every subset of 0640 accepted including unreadable 0000" {
    for mode in 0000 0040 0200 0240 0400 0440 0600 0640; do chmod "$mode" "$LOG"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "6241 every forbidden POSIX bit including specials rejected" {
    for mode in 0740 0660 0650 0644 0642 0641 4640 2640 1640; do chmod "$mode" "$LOG"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; done
}
@test "6241 actual numeric ownership observer classifies real fixture" {
    rlch_6_2_4_1_stat() { real_stat "$@"; }
    run check
    if [ "$(stat -c %u "$LOG")" = 0 ] && [ "$(stat -c %g "$LOG")" = 0 ]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "6241 root owner and group deficits independently injected at attribute boundary" {
    for tuple in '1001|0' '0|1001' '1001|1001'; do
        rlch_6_2_4_1_attributes() { printf 'observed|%s\n' "$tuple"; return "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
        expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    done
}
@test "6241 legacy realistic selectors minus prefix tabs and comments" {
    printf '*.info;mail.none;authpriv.none;cron.none\t /var/log/messages # note\nauthpriv.* -/var/log/messages\nmail.* /var/log/messages\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 standalone omfile arbitrary parameter order case and spacing" {
    printf 'action( FiLe = "/var/log/messages" TYPE="omfile" )\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 multiline selector omfile and creation parameters are current attributes only" {
    printf '*.info action(\n fileOwner="root"\n TYPE="omfile"\n File="/var/log/messages" # comment\n fileCreateMode="0666" fileGroup="root"\n)\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    chmod 0666 "$LOG"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
}
@test "6241 legacy creation defaults never certify current insecure modes" {
    printf '$FileCreateMode 0640\n$FileOwner root\n$FileGroup root\n*.* /var/log/messages\n' > "$MAIN"
    chmod 0666 "$LOG"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
}
@test "6241 quoted path spaces hash and parentheses remain literal no execution" {
    path='/var/log/log # (safe).txt'; mv "$LOG" "$R$path"
    printf 'action(type="omfile" file="%s") # outside\n' "$path" > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 deduplicate repeated static file destinations" {
    printf '*.* /var/log/messages\nmail.* -/var/log/messages\naction(type="omfile" file="/var/log/messages")\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 multiple custom files include all attribute deficits" {
    mkdir -p "$R/opt/log"; printf 'private\n' > "$R/opt/log/custom"; chmod 0666 "$R/opt/log/custom"
    printf '*.* /var/log/messages\naction(type="omfile" file="/opt/log/custom")\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
}
@test "6241 unrelated files in var log are outside selected scope" {
    printf 'not rsyslog\n' > "$R/var/log/unrelated"; chmod 0777 "$R/var/log/unrelated"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 glob include main position and lexical selected snippets" {
    printf '$IncludeConfig /etc/rsyslog.d/*.conf\n' > "$MAIN"
    printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"
    printf 'module(load="imuxsock")\n' > "$R/etc/rsyslog.d/10.conf"
    printf 'UNKNOWN SECRET\n' > "$R/etc/rsyslog.d/.hidden.conf"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 exact file include only selects that file" {
    printf 'include(file="/etc/rsyslog.d/20.conf")\n' > "$MAIN"
    printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"
    printf 'UNKNOWN SECRET\n' > "$R/etc/rsyslog.d/30.conf"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 unselected snippet does not supply a destination" {
    printf '# empty main\n' > "$MAIN"; printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"; unknown
}
@test "6241 optional absent include is safe only with other complete output" {
    printf 'include(\n mode="optional"\n file="/etc/rsyslog.d/*.conf"\n)\n*.* /var/log/messages\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 missing required exact and glob include error" {
    for text in '$IncludeConfig /etc/rsyslog.d/*.conf' 'include(file="/etc/rsyslog.d/missing.conf")'; do printf '%s\n*.* /var/log/messages\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 nested loop duplicate arbitrary relative directory and hidden includes error" {
    printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"
    for text in '$IncludeConfig /etc/rsyslog.d' '$IncludeConfig /custom/config' 'include(file="relative.conf")' 'include(file="/etc/rsyslog.d/.hidden.conf")' '$IncludeConfig /etc/rsyslog.d/20.conf\n$IncludeConfig /etc/rsyslog.d/20.conf'; do printf '%b\n' "$text" > "$MAIN"; unknown; done
    printf '$IncludeConfig /etc/rsyslog.d/20.conf\n' > "$MAIN"
    printf '$IncludeConfig /etc/rsyslog.d/20.conf\n*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"; unknown
}
@test "6241 scope unknown dominates known mode deficit" {
    chmod 0666 "$LOG"; printf 'if ($msg contains "SECRET") then { action(type="omfile" file="/dynamic") }\n' >> "$MAIN"; unknown
}
@test "6241 dynamic templates variables expressions custom action and unknown parameters error" {
    for text in 'action(type="omfile" dynaFile="template")' 'action(type="omfile" file="/var/log/$name")' 'action(type="omfile" file="/var/log/messages" template="custom")' 'action(type="omprog" binary="/SECRET")' 'action(type="omfile" file="/var/log/messages" unknown="on")'; do printf '%s\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 unknown syntax never silently disappears" {
    for text in 'stop' 'ruleset(name="custom") {' ':msg, contains, "word" /var/log/messages' '$WorkDirectory /var/lib/rsyslog' 'global(workDirectory="/var/lib/rsyslog")' 'module(load="imjournal" StateFile="state")'; do printf '%s\n' "$text" >> "$MAIN"; unknown; printf '*.* /var/log/messages\n' > "$MAIN"; done
}
@test "6241 complete objects duplicate params escapes continuations unbalanced quotes rejected" {
    for text in 'action(type="omfile" file="/var/log/messages" File="/var/log/other")' 'action(type="omfile" file="/var/log/messages") suffix' 'action(type="omfile" file="/var/log/messages"' 'action(type="omfile" file="/var/log/\\secret")' 'action(type="omfile" file="/var/log/messages)' '*.* /var/log/messages;template'; do printf '%s\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 malformed selector and destination syntax rejected" {
    for text in 'garbage /var/log/messages' '*.invalid /var/log/messages' 'madeup.* /var/log/messages' '*.* /var/log/messages /var/log/other' '*.* /var/log/../messages' '*.* /var/log//messages' '*.* /var/log/*.log'; do printf '%s\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 recognized remote user discard device no-file sets never success" {
    for text in '*.* @@remote.example:514' '*.* root' '*.* ~' '*.* *' '*.* /dev/console'; do printf '%s\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 non-file outputs combined with static output do not gain attribute scope" {
    printf '*.* @@remote.example:514\n*.emerg *\n*.* ~\n*.* /dev/console\n*.* /var/log/messages\n' > "$MAIN"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 pipes sockets relative files and single quotes require review" {
    for text in '*.* |/run/pipe' '*.* :omuxsock:/run/socket' '*.* relative.log' "action(type='omfile' file='/var/log/messages')"; do printf '%s\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 absent empty comments-only configuration is ERROR not NA" {
    for text in '' '# SECRET'; do printf '%s\n' "$text" > "$MAIN"; unknown; done
    rm "$MAIN"; unknown
}
@test "6241 referenced missing file error never creates it" { rm "$LOG"; unknown; [ ! -e "$LOG" ]; }
@test "6241 missing log directory and missing snippet directory handled honestly" {
    rm -r "$R/var/log"; unknown
    mkdir "$R/var/log"; printf 'private\n' > "$LOG"; chmod 0640 "$LOG"
    rmdir "$R/etc/rsyslog.d"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6241 log symlink dangling symlink and linked parent errors preserved" {
    mv "$LOG" "$LOG.real"; ln -s messages.real "$LOG"; unknown
    rm "$LOG"; ln -s absent "$LOG"; unknown
    rm "$LOG"; mv "$R/var/log" "$R/var/real"; ln -s real "$R/var/log"; unknown
}
@test "6241 FIFO directory and hardlinked logs error without opening" {
    rm "$LOG"; mkfifo "$LOG"; unknown; rm "$LOG"
    mkdir "$LOG"; unknown; rmdir "$LOG"
    printf 'private\n' > "$LOG"; ln "$LOG" "$LOG.alias"; unknown
}
@test "6241 unsafe symlink inaccessible and special configuration candidates error" {
    for mode in 0666 0000; do chmod "$mode" "$MAIN"; unknown; done
    chmod 0644 "$MAIN"; mv "$MAIN" "$MAIN.real"; ln -s rsyslog.conf.real "$MAIN"; unknown
    rm "$MAIN"; mkfifo "$MAIN"; unknown
}
@test "6241 even unselected unsafe candidates prevent stable trustworthy snapshot" {
    ln -s /dev/null "$R/etc/rsyslog.d/20.conf"; unknown
    rm "$R/etc/rsyslog.d/20.conf"; chmod 0777 "$R/etc/rsyslog.d"; unknown
}
@test "6241 directory symlink errors" { rmdir "$R/etc/rsyslog.d"; ln -s /tmp "$R/etc/rsyslog.d"; unknown; }
@test "6241 root identity absent ambiguous noncanonical unreadable error" {
    for text in '' 'root:x:1:0:root:/root:/bin/bash' 'root:x:0:1:root:/root:/bin/bash' 'root:x:00:0:root:/root:/bin/bash' 'root:x:0:0:root:/root:/bin/bash\nroot:x:0:0:root:/root:/bin/bash'; do printf '%b\n' "$text" > "$R/etc/passwd"; unknown; done
}
@test "6241 root group database failures are not defaulted" {
    printf 'root:x:1:\n' > "$R/etc/group"; unknown
    printf 'root:x:0:\n' > "$R/etc/group"; chmod 0666 "$R/etc/group"; unknown
    chmod 0644 "$R/etc/group"; rm "$R/etc/group"; unknown
}
@test "6241 NUL CR BOM control and reserved framing rejected" {
    for text in '*.* /var/log/messages\000SECRET' '*.* /var/log/messages\r' '\357\273\277*.* /var/log/messages' 'file:forged' 'identity:forged' '*.* /var/log/messages\001'; do printf '%b\n' "$text" > "$MAIN"; unknown; done
}
@test "6241 oversized line file and candidate count bounded" {
    python3 -c 'print("#"+"x"*8193)' > "$MAIN"; unknown
    python3 -c 'print("#"+"x"*1048576)' > "$MAIN"; unknown
    printf '*.* /var/log/messages\n' > "$MAIN"
    for n in {1..1024}; do : > "$R/etc/rsyslog.d/$n.conf"; done
    unknown
}
@test "6241 validate reevaluates new mode without check cache" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$LOG"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
}
@test "6241 snapshots disagree ERROR even for an otherwise known deficit" {
    eval "$(declare -f rlch_6_2_4_1_snapshot | sed '1s/rlch_6_2_4_1_snapshot/real_snapshot/')"
    rlch_6_2_4_1_snapshot() { real_snapshot; printf 'directory:call:%s\n' "$(wc -l < "$ATTR_CALLS")"; printf 'call\n' >> "$ATTR_CALLS"; }
    : > "$ATTR_CALLS"; chmod 0666 "$LOG"; expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "6241 rotating inode or attributes during observation ERROR" {
    rlch_6_2_4_1_attributes() { real_attributes; printf 'call\n' >> "$ATTR_CALLS"; printf 'epoch|%s\n' "$(wc -l < "$ATTR_CALLS")"; }
    # Append a marker to the private observed tuple, no fixture mutation needed.
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "6241 failed attribute helper dominates known deficit" {
    rlch_6_2_4_1_attributes() { return "$RLCH_MODULE_RESULT_ERROR"; }; chmod 0666 "$LOG"; unknown
}
@test "6241 failed config helper produces ERROR no raw diagnostics" {
    rlch_journal_config_file() { printf 'SECRET raw path\n' >&2; return 2; }; unknown
    [[ "$output" != *SECRET* && "$output" != *"$R"* ]]
}
@test "6241 apply always guidance ERROR never mutates even compliant" {
    for mode in 0640 0666; do chmod "$mode" "$LOG"; before="$(snapshot)"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [ "$before" = "$(snapshot)" ]; done
}
@test "6241 rollback silent repeated SUCCESS no resources needed" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "6241 repeated APIs no CHANGED and stable observations" {
    for n in 1 2; do expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_ERROR"; run rollback; [ "$status" -eq 0 ]; done
}
@test "6241 check guidance does not claim runtime ACL future mode proof" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    for word in 'on-disk' 'root:root' '0640 or more restrictive' 'runtime' 'future creation' 'ACL/xattr' 'SELinux'; do [[ "$output" == *"$word"* ]]; done
}
@test "6241 apply guidance no broad chmod or invented remediation" {
    expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'complete' 'root identities' 'dynamic/missing' 'rotation' 'creation defaults' 'more restrictive' 'exact attributes' 'no chmod/chown/chgrp'; do [[ "$output" == *"$word"* ]]; done
}
@test "6241 absence of packages daemons timers native parser never NA" {
    probe() (
        local cmd api expected result
        for cmd in rpm dnf yum systemctl service rsyslogd logrotate logger kill pkill chmod chown chgrp cp mv rm touch mkdir ln curl ss timeout; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$ATTR_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do
            expected="$RLCH_MODULE_RESULT_SUCCESS"; if [[ "$api" == apply ]]; then expected="$RLCH_MODULE_RESULT_ERROR"; fi
            result=0; "$api" >/dev/null 2>/dev/null || result=$?
            [[ "$result" -eq "$expected" ]] || return 1
        done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$ATTR_CALLS" ]; ! declare -F rm
}
@test "6241 preserve configs logrotate state logs metadata inode links regular hashes" {
    printf 'state\n' > "$R/var/lib/logrotate/logrotate.status"
    printf 'weekly\n' > "$R/etc/logrotate.conf"; ln -s rsyslog.conf "$R/etc/admin-link"
    before="$(snapshot)"
    for n in 1 2; do expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_ERROR"; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "6241 unusual root path quoted literal dollar space does not execute" {
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"'; mv "$R" "$new"; R="$new"; RLCH_CIS_6_2_4_1_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [ "$before" = "$(snapshot)" ]
}
@test "6241 control characters in root paths ERROR preserved" {
    new="$BATS_TEST_TMPDIR/"$'root\nSECRET'; mv "$R" "$new"; R="$new"; RLCH_CIS_6_2_4_1_ROOT="$new"
    before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; [[ "$output" != *SECRET* ]]
}
@test "6241 no stdout bounded fixed redacted stderr for all outcomes" {
    for api in check validate apply; do
        result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
        [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
        ! grep -F PRIVATE "$BATS_TEST_TMPDIR/err"; ! grep -F "$R" "$BATS_TEST_TMPDIR/err"
    done
}

@test "6241 aggregate configuration bytes bounded" {
    python3 - "$R/etc/rsyslog.d" <<'PYFIX'
import pathlib, sys
for n in range(5):
    pathlib.Path(sys.argv[1],f"{n}.conf").write_text(("#"+"x"*7999+"\n")*120)
PYFIX
    unknown
}
@test "6241 actual inode replacement between observations errors" {
    eval "$(declare -f rlch_6_2_4_1_attributes | sed '1s/rlch_6_2_4_1_attributes/fixture_attributes/')"
    rlch_6_2_4_1_attributes() {
        fixture_attributes || return "$?"
        if [[ ! -e "$ATTR_CALLS" ]]; then
            : > "$ATTR_CALLS"; mv "$LOG" "$LOG.old"; printf 'replacement\n' > "$LOG"; chmod 0640 "$LOG"
        fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "6241 actual attribute and config changes between observations errors" {
    eval "$(declare -f rlch_6_2_4_1_attributes | sed '1s/rlch_6_2_4_1_attributes/fixture_attributes/')"
    rlch_6_2_4_1_attributes() { fixture_attributes; chmod 0666 "$LOG"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    chmod 0640 "$LOG"
    rlch_6_2_4_1_attributes() { fixture_attributes; printf '# changed\n' >> "$MAIN"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "6241 root ownership deficits exercise production numeric evaluation" {
    for tuple in 1000:0 0:1000 1000:1000; do
        rlch_6_2_4_1_stat() {
            real_stat "$@" | awk -F'|' -v tuple="$tuple" 'BEGIN{OFS="|";split(tuple,a,":")} {$4=a[1];$5=a[2];print}'
        }
        expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    done
}
@test "6241 include required abort-if-missing supported but invalid mode is ERROR" {
    printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"
    for mode in required abort-if-missing; do printf 'include(file="/etc/rsyslog.d/20.conf" mode="%s")\n' "$mode" > "$MAIN"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
    printf 'include(file="/etc/rsyslog.d/20.conf" mode="abort")\n' > "$MAIN"; unknown
}
@test "6241 unquoted inline hash ambiguous filenames and duplicate modules error" {
    printf '*.* /var/log/messages#suffix\n' > "$MAIN"; unknown
    printf 'module(load="imuxsock")\n$ModLoad imuxsock\n*.* /var/log/messages\n' > "$MAIN"; unknown
}
@test "6241 direct helpers reject unsupported shapes and modes" {
    run rlch_journal_config_file "$MAIN"; [ "$status" -eq 0 ]; [[ "$output" == *'|'* ]]
    run rlch_journal_config_file "$R/etc"; [ "$status" -eq 2 ]
    run rlch_tmout_file_stamp "$MAIN"; [ "$status" -eq 0 ]
    run rlch_tmout_directory "$R/etc"; [ "$status" -eq 0 ]
    run rlch_journal_path "$R/var/../log/messages"; [ "$status" -eq 2 ]
    run rlch_journal_mode 0640 0640; [ "$status" -eq 0 ]
    run rlch_journal_mode 4640 0640; [ "$status" -eq 1 ]
    run rlch_journal_mode invalid 0640; [ "$status" -eq 2 ]
}
@test "6241 include expansion and destination lengths have bounded failure" {
    for n in {1..33}; do printf 'include(file="/etc/rsyslog.d/absent.conf" mode="optional")\n' >> "$MAIN"; done
    unknown
    python3 -c 'print("action(type=\"omfile\" file=\"/"+"x"*4097+"\")")' > "$MAIN"; unknown
}
@test "6241 literal backslash root include observed without evaluating shell" {
    new="$BATS_TEST_TMPDIR/"'root\nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_6_2_4_1_ROOT="$new"
    printf 'include(file="/etc/rsyslog.d/20.conf")\n' > "$R/etc/rsyslog.conf"
    printf '*.* /var/log/messages\n' > "$R/etc/rsyslog.d/20.conf"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}

@test "6241 malformed stat output and failed stat are ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|bad|81a0|time' '1|2|1|0|0|640|a1a0|time'; do
        rlch_6_2_4_1_stat() { printf '%s\n' "$evidence"; }; unknown
    done
    rlch_6_2_4_1_stat() { return 99; }; unknown
}
