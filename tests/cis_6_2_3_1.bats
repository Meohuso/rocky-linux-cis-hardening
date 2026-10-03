#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_3_1_RPM="$BATS_TEST_TMPDIR/rpm"
    export RPM_FIXTURE="$BATS_TEST_TMPDIR/fixture" RPM_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$RPM_FIXTURE"
    cat > "$RLCH_CIS_6_2_3_1_RPM" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RPM_CALLS"
[[ "$#" == 3 && "$1" == -qa && "$2" == --qf && "$3" == 'RPM1|%{DBINSTANCE}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|END\n' && "$LC_ALL" == C ]] || { echo mutation >> "$RPM_FIXTURE/mutations"; exit 3; }
n=0; if [[ -e "$RPM_FIXTURE/count" ]]; then read -r n < "$RPM_FIXTURE/count"; fi
n=$((n+1)); echo "$n" > "$RPM_FIXTURE/count"
f="$RPM_FIXTURE/first"; if [[ "$n" -ge 2 && -e "$RPM_FIXTURE/second" ]]; then f="$RPM_FIXTURE/second"; fi
cat "$f"
if [[ -e "$RPM_FIXTURE/stderr" ]]; then cat "$RPM_FIXTURE/stderr" >&2; fi
r=0; if [[ -e "$RPM_FIXTURE/exit" ]]; then read -r r < "$RPM_FIXTURE/exit"; fi
if [[ "$n" -ge 2 && -e "$RPM_FIXTURE/second-exit" ]]; then read -r r < "$RPM_FIXTURE/second-exit"; fi
exit "$r"
MOCK
    chmod 0755 "$RLCH_CIS_6_2_3_1_RPM"
    base
    add rsyslog
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/1/module.sh"
}
base() { printf 'RPM1|1|systemd|0|252|1.el9|x86_64|END\n' > "$RPM_FIXTURE/first"; }
add() { printf 'RPM1|%s|%s|%s|%s|%s|%s|END\n' "${2:-2}" "$1" "${3:-0}" "${4:-252}" "${5:-1.el9}" "${6:-x86_64}" >> "$RPM_FIXTURE/first"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
helper_expect() { run rlch_rpm_package_status "$RLCH_CIS_6_2_3_1_RPM" rsyslog; [ "$status" -eq "$1" ]; [ -z "$output" ]; }
second() { cp "$RPM_FIXTURE/first" "$RPM_FIXTURE/second"; sed -i "$1" "$RPM_FIXTURE/second"; }

@test "6231 metadata L1 enabled no reboot manual no invented mapping" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.1 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog is installed' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "6231 documented supported no rules related only context CCE" {
    run sed -n '/^## CIS 6.2.3.1 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: supported'* && "$output" == *'no rules:'* && "$output" == *'related_rules: package_rsyslog_installed'* && "$output" == *'CCE-84063-7'* && "$output" == *'context only'* && "$output" == *'package-installed-removed.fail.sh'* ]]
}

@test "6231 upstream package-installed.pass.sh" {
    expect 0
}

@test "6231 upstream package-installed-removed.fail.sh" {
    base; expect 1
}

@test "6231 upstream package-removed.fail.sh" {
    base; add chrony; expect 1
}

@test "6231 only non-exact package rsyslogd" { base; add rsyslogd; expect 1; helper_expect 1; }

@test "6231 only non-exact package rsyslog-libs" { base; add rsyslog-libs; expect 1; helper_expect 1; }

@test "6231 only non-exact package rsyslog-doc" { base; add rsyslog-doc; expect 1; helper_expect 1; }

@test "6231 only non-exact package rsyslog-gnutls" { base; add rsyslog-gnutls; expect 1; helper_expect 1; }

@test "6231 only non-exact package rsyslog-devel" { base; add rsyslog-devel; expect 1; helper_expect 1; }

@test "6231 only non-exact package my-rsyslog" { base; add my-rsyslog; expect 1; helper_expect 1; }

@test "6231 only non-exact package rsyslog2" { base; add rsyslog2; expect 1; helper_expect 1; }

@test "6231 any installed version 1 no EVR threshold" {
    base; add rsyslog 2 0 "1"; expect 0
}

@test "6231 any installed version 999999 no EVR threshold" {
    base; add rsyslog 2 0 "999999"; expect 0
}

@test "6231 any installed version 0.1 no EVR threshold" {
    base; add rsyslog 2 0 "0.1"; expect 0
}

@test "6231 any installed version 252~rc1 no EVR threshold" {
    base; add rsyslog 2 0 "252~rc1"; expect 0
}

@test "6231 any installed version 252^git123 no EVR threshold" {
    base; add rsyslog 2 0 "252^git123"; expect 0
}

@test "6231 any installed version 252+vendor no EVR threshold" {
    base; add rsyslog 2 0 "252+vendor"; expect 0
}

@test "6231 any installed version 252_pre no EVR threshold" {
    base; add rsyslog 2 0 "252_pre"; expect 0
}

@test "6231 architecture unconstrained x86_64" {
    base; add rsyslog 2 0 252 1.el9 x86_64; expect 0
}

@test "6231 architecture unconstrained i686" {
    base; add rsyslog 2 0 252 1.el9 i686; expect 0
}

@test "6231 architecture unconstrained aarch64" {
    base; add rsyslog 2 0 252 1.el9 aarch64; expect 0
}

@test "6231 architecture unconstrained noarch" {
    base; add rsyslog 2 0 252 1.el9 noarch; expect 0
}

@test "6231 architecture unconstrained ppc64le" {
    base; add rsyslog 2 0 252 1.el9 ppc64le; expect 0
}

@test "6231 architecture unconstrained s390x" {
    base; add rsyslog 2 0 252 1.el9 s390x; expect 0
}

@test "6231 architecture unconstrained riscv64" {
    base; add rsyslog 2 0 252 1.el9 riscv64; expect 0
}

@test "6231 multilib multiple versions and identical NEVRA distinct records pass" {
    add rsyslog 3 1 253 2.el9 i686; add rsyslog 4; expect 0; helper_expect 0
}

@test "6231 other RPM pseudo-package none arch accepted" {
    add gpg-pubkey 3 0 abcd 1234 "(none)"; expect 0
}

@test "6231 helper installed direct stable two inventories" {
    helper_expect 0; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "6231 helper absent direct stable two inventories" {
    base; helper_expect 1; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "6231 inventory normalized property record order" {
    second ""; sort -r "$RPM_FIXTURE/second" > "$BATS_TEST_TMPDIR/sorted"; mv "$BATS_TEST_TMPDIR/sorted" "$RPM_FIXTURE/second"; expect 0
}

@test "6231 concurrent package disappears" {
    second "/rsyslog/d"; expect 2
}

@test "6231 concurrent name changes" {
    second "s/rsyslog/systemd-libs/"; expect 2
}

@test "6231 concurrent version changes" {
    second "s/|252|/|253|/"; expect 2
}

@test "6231 concurrent release changes" {
    second "s/|1.el9|/|2.el9|/"; expect 2
}

@test "6231 concurrent epoch changes" {
    second "s/|0|/|1|/"; expect 2
}

@test "6231 concurrent architecture changes" {
    second "s/|x86_64|/|i686|/"; expect 2
}

@test "6231 concurrent identity changes" {
    second "s/RPM1|2|/RPM1|3|/"; expect 2
}

@test "6231 package appears between observations" {
    cp "$RPM_FIXTURE/first" "$RPM_FIXTURE/second"; base; expect 2
}

@test "6231 unrelated package change conservatively ERROR" {
    second "s/|systemd|/|systemd-libs|/"; expect 2
}

@test "6231 new duplicate instance concurrent ERROR" {
    second ""; printf "RPM1|3|rsyslog|0|252|1.el9|i686|END\n" >> "$RPM_FIXTURE/second"; expect 2
}

@test "6231 query exit 1 never absence" {
    echo 1 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 query exit 2 never absence" {
    echo 2 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 query exit 3 never absence" {
    echo 3 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 query exit 127 never absence" {
    echo 127 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 query exit 137 never absence" {
    echo 137 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 query exit 143 never absence" {
    echo 143 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "6231 second query error ERROR" {
    echo 1 > "$RPM_FIXTURE/second-exit"; expect 2
}

@test "6231 missing RPM executable ERROR" {
    RLCH_CIS_6_2_3_1_RPM="$BATS_TEST_TMPDIR/missing"; expect 2
}

@test "6231 non executable RPM ERROR" {
    chmod 0644 "$RLCH_CIS_6_2_3_1_RPM"; expect 2
}

@test "6231 empty inventory cannot prove safe absence" {
    : > "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 truncated final newline rejected" {
    printf "RPM1|2|rsyslog|0|252|1.el9|x86_64|END" > "$RPM_FIXTURE/first"; expect 2
}

@test "6231 malformed bad marker" {
    base; printf "%s\n" "WRONG|2|rsyslog|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed missing end" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|252|1.el9|x86_64" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed bad end" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|252|1.el9|x86_64|BAD" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed empty name" {
    base; printf "%s\n" "RPM1|2||0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed invalid name" {
    base; printf "%s\n" "RPM1|2|bad name|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed identity zero" {
    base; printf "%s\n" "RPM1|0|rsyslog|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed identity negative" {
    base; printf "%s\n" "RPM1|-2|rsyslog|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed identity overflow" {
    base; printf "%s\n" "RPM1|4294967296|rsyslog|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed identity duplicate" {
    base; printf "%s\n" "RPM1|1|rsyslog|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed epoch nonnumeric" {
    base; printf "%s\n" "RPM1|2|rsyslog|bad|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed epoch negative" {
    base; printf "%s\n" "RPM1|2|rsyslog|-1|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed epoch overflow" {
    base; printf "%s\n" "RPM1|2|rsyslog|4294967296|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed empty version" {
    base; printf "%s\n" "RPM1|2|rsyslog|0||1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed none version" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|(none)|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed empty release" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|252||x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed empty arch" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|252|1.el9||END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed unknown extra field" {
    base; printf "%s\n" "RPM1|2|rsyslog|0|252|1.el9|x86_64|END|SECRET" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed end injection" {
    base; printf "%s\n" "RPM-END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed human absent text" {
    base; printf "%s\n" "package rsyslog is not installed" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 malformed human database error" {
    base; printf "%s\n" "SECRET RPM database corrupt" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 raw NUL bytes rejected" {
    printf "\0" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 raw CR bytes rejected" {
    printf "\r" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 raw TAB bytes rejected" {
    printf "\t" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 raw escape bytes rejected" {
    printf "\033" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 raw DEL bytes rejected" {
    printf "\177" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 any stderr database error rejected without disclosure" {
    printf "%s\n" "SECRET RPM corruption" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "6231 any stderr valid looking row rejected without disclosure" {
    printf "%s\n" "RPM1|99|rsyslog|0|252|1.el9|x86_64|END" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "6231 any stderr blank rejected without disclosure" {
    printf "%s\n" "" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "6231 stderr binary byte rejected" {
    printf "\0" > "$RPM_FIXTURE/stderr"; expect 2
}

@test "6231 line output bound" {
    head -c 2049 /dev/zero | tr "\000" x >> "$RPM_FIXTURE/first"; expect 2
}

@test "6231 total output bound" {
    base; awk 'BEGIN {for(i=2;i<=50000;i++) printf "RPM1|%d|%0100d|0|1|1|noarch|END\n",i,i}' >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "6231 row count bound" {
    base; awk 'BEGIN {for(i=2;i<=65538;i++) printf "RPM1|%d|x|0|1|1|noarch|END\n",i}' >> "$RPM_FIXTURE/first"; expect 2
}

@test "6231 field bound name" {
    awk -F '|' -v OFS='|' 'NR==2 {$3=""; for(i=0;i<256;i++) $3=$3 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "6231 field bound version" {
    awk -F '|' -v OFS='|' 'NR==2 {$5=""; for(i=0;i<256;i++) $5=$5 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "6231 field bound release" {
    awk -F '|' -v OFS='|' 'NR==2 {$6=""; for(i=0;i<256;i++) $6=$6 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "6231 field bound arch" {
    awk -F '|' -v OFS='|' 'NR==2 {$7=""; for(i=0;i<65;i++) $7=$7 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "6231 helper invalid requested name fails before query" {
    run rlch_rpm_package_status "$RLCH_CIS_6_2_3_1_RPM" "bad name"; [ "$status" -eq 2 ]; [ ! -e "$RPM_CALLS" ]
}

@test "6231 locale forced machine query format" {
    export LC_ALL=C.UTF-8; expect 0; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "6231 file or copied binary does not replace RPM name" {
    base; mkdir -p "$BATS_TEST_TMPDIR/usr/sbin"; touch "$BATS_TEST_TMPDIR/usr/sbin/rsyslogd"; expect 1
}

@test "6231 repeated API installed" {
    for i in 1 2; do expect 0; run validate; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "6231 repeated API absent" {
    base; for i in 1 2; do expect 1; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "6231 repeated API error" {
    echo 1 > "$RPM_FIXTURE/exit"; for i in 1 2; do expect 2; run validate; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "6231 manual install guidance absent" {
    base; run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* && "$output" == *repository* && "$output" == *dependency* && "$output" == *rollback* ]]
}

@test "6231 rollback without RPM ignores stale administrator state" {
    mkdir "$BATS_TEST_TMPDIR/state"; echo rsyslog > "$BATS_TEST_TMPDIR/state/package-installed"; RLCH_CIS_6_2_3_1_RPM="$BATS_TEST_TMPDIR/missing"; run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; [ ! -e "$RPM_CALLS" ]; [ -f "$BATS_TEST_TMPDIR/state/package-installed" ]
}

@test "6231 only RPM inventory commands no DNF systemctl install erase" {
    for command in dnf systemctl; do printf '#!/usr/bin/env bash\necho mutation >> "$RPM_FIXTURE/mutations"\nexit 3\n' > "$BATS_TEST_TMPDIR/$command"; chmod +x "$BATS_TEST_TMPDIR/$command"; done
    export PATH="$BATS_TEST_TMPDIR:$PATH"
    for action in check validate apply rollback; do run "$action"; [ "$status" -eq 0 ]; done
    [ "$(wc -l < "$RPM_CALLS")" -eq 6 ]; ! grep -Eq '(^| )(-e|-i|--install|--erase|--rebuilddb|--initdb)( |$)' "$RPM_CALLS"; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "6231 preservation all APIs content attributes admin state and previous controls" {
    set -o pipefail
    root="$BATS_TEST_TMPDIR/preserve"
    mkdir -p "$root"/{etc/rsyslog.d,etc/pki/private,var/log/journal,run/log/journal,var/lib/rlch,previous,usr/lib/systemd/system}
    for file in etc/rsyslog.conf etc/rsyslog.d/admin.conf etc/journald.conf etc/journal-upload.conf etc/journal-remote.conf etc/pki/private/key.pem var/log/journal/synthetic.journal run/log/journal/synthetic.journal var/lib/rlch/admin-state usr/lib/systemd/system/rsyslog.service usr/lib/systemd/system/remote.socket previous/6211 previous/6212 previous/6213 previous/6214 previous/62211 previous/62212 previous/62213 previous/62214 previous/6222 previous/6223 previous/6224; do printf 'PRIVATE-SECRET\n' > "$root/$file"; done
    chmod 0600 "$root/etc/pki/private/key.pem"
    ln -s /dev/null "$root/etc/rsyslog.d/admin-mask.conf"
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in dnf yum systemctl service journalctl rsyslogd curl wget openssl chmod chown rm cp ln tee sed; do
        printf '#!/usr/bin/env bash\nprintf mutation >> "$RPM_FIXTURE/mutations"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"
        chmod +x "$BATS_TEST_TMPDIR/bin/$command"
    done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for state in installed absent error; do
        case "$state" in absent) base;; error) printf '1\n' > "$RPM_FIXTURE/exit";; esac
        before=$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)
        inventory=$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
        rpm_before=$(sha256sum "$RPM_FIXTURE/first")
        for repeat in 1 2; do for api in check validate apply rollback; do
            expected=0
            if [[ "$api" != rollback && "$state" != installed ]]; then expected=2; [[ "$api" == apply || "$state" != absent ]] || expected=1; fi
            run "$api"; [ "$status" -eq "$expected" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$root"* ]]
        done; done
        [ "$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
        [ "$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
        [ "$(sha256sum "$RPM_FIXTURE/first")" = "$rpm_before" ]
    done
    export PATH="$saved_path"
    [ ! -e "$RPM_FIXTURE/mutations" ]
}
@test "6231 exact name case sensitive RSYSLOG not substitute" { base; add RSYSLOG; expect 1; helper_expect 1; }
@test "6231 exact package only header accepted complete nonempty inventory" { printf 'RPM1|5|rsyslog|0|8.2510.0|5.el10_2.1|x86_64|END\n' > "$RPM_FIXTURE/first"; expect 0; helper_expect 0; }
@test "6231 journald-only inventory no logging-method exemption" { base; expect 1; }
@test "6231 helper direct inventory normalized framing" { run rlch_rpm_inventory "$RLCH_CIS_6_2_3_1_RPM"; [ "$status" -eq 0 ]; [ "$output" = "$(LC_ALL=C sort "$RPM_FIXTURE/first")" ]; }
@test "6231 validate rereads after administrator removes package" { expect 0; base; run validate; [ "$status" -eq 1 ]; }
@test "6231 package does not require binary config unit socket or runtime observation" {
    for command in systemctl rsyslogd journalctl stat; do printf '#!/usr/bin/env bash\nprintf mutation >> "$RPM_FIXTURE/mutations"\nexit 99\n' > "$BATS_TEST_TMPDIR/$command"; chmod +x "$BATS_TEST_TMPDIR/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR:$PATH"
    expect 0
    export PATH="$saved_path"
    [ ! -e "$RPM_FIXTURE/mutations" ]
}
