#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_1_1_RPM="$BATS_TEST_TMPDIR/rpm"
    export RPM_FIXTURE="$BATS_TEST_TMPDIR/fixture" RPM_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$RPM_FIXTURE"
    cat > "$RLCH_CIS_6_2_2_1_1_RPM" <<'MOCK'
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
    chmod 0755 "$RLCH_CIS_6_2_2_1_1_RPM"
    base
    add systemd-journal-remote
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/1/module.sh"
}
base() { printf 'RPM1|1|systemd|0|252|1.el9|x86_64|END\n' > "$RPM_FIXTURE/first"; }
add() { printf 'RPM1|%s|%s|%s|%s|%s|%s|END\n' "${2:-2}" "$1" "${3:-0}" "${4:-252}" "${5:-1.el9}" "${6:-x86_64}" >> "$RPM_FIXTURE/first"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
helper_expect() { run rlch_rpm_package_status "$RLCH_CIS_6_2_2_1_1_RPM" systemd-journal-remote; [ "$status" -eq "$1" ]; [ -z "$output" ]; }
second() { cp "$RPM_FIXTURE/first" "$RPM_FIXTURE/second"; sed -i "$1" "$RPM_FIXTURE/second"; }

@test "62211 metadata exact L1 enabled no reboot unique mapping" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.1.1 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure systemd-journal-remote is installed' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_package_systemd-journal-remote_installed ]
    [ "$(grep -Rl '^RLCH_MODULE_OPENSCAP_RULE="xccdf_org.ssgproject.content_rule_package_systemd-journal-remote_installed"$' "$BATS_TEST_DIRNAME/../modules" | wc -l)" -eq 1 ]
}

@test "62211 documented pinned automated CCE and templated provenance" {
    doc="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    grep -q 'CCE-86760-6' "$doc"; grep -q '## CIS 6.2.2.1.1' "$doc"
    grep -q 'package-installed-removed.fail.sh' "$doc"; grep -q 'linux:rpminfo_test' "$doc"
}

@test "62211 upstream package-installed.pass.sh" {
    expect 0
}

@test "62211 upstream package-installed-removed.fail.sh" {
    base; expect 1
}

@test "62211 upstream package-removed.fail.sh" {
    base; add chrony; expect 1
}

@test "62211 only non-exact package systemd" {
    base; add systemd; expect 1; helper_expect 1
}

@test "62211 only non-exact package systemd-libs" {
    base; add systemd-libs; expect 1; helper_expect 1
}

@test "62211 only non-exact package systemd-udev" {
    base; add systemd-udev; expect 1; helper_expect 1
}

@test "62211 only non-exact package systemd-journal-gateway" {
    base; add systemd-journal-gateway; expect 1; helper_expect 1
}

@test "62211 only non-exact package systemd-journal-remote-devel" {
    base; add systemd-journal-remote-devel; expect 1; helper_expect 1
}

@test "62211 only non-exact package my-systemd-journal-remote" {
    base; add my-systemd-journal-remote; expect 1; helper_expect 1
}

@test "62211 only non-exact package systemd-journal-remote2" {
    base; add systemd-journal-remote2; expect 1; helper_expect 1
}

@test "62211 any installed version 1 no EVR threshold" {
    base; add systemd-journal-remote 2 0 "1"; expect 0
}

@test "62211 any installed version 999999 no EVR threshold" {
    base; add systemd-journal-remote 2 0 "999999"; expect 0
}

@test "62211 any installed version 0.1 no EVR threshold" {
    base; add systemd-journal-remote 2 0 "0.1"; expect 0
}

@test "62211 any installed version 252~rc1 no EVR threshold" {
    base; add systemd-journal-remote 2 0 "252~rc1"; expect 0
}

@test "62211 any installed version 252^git123 no EVR threshold" {
    base; add systemd-journal-remote 2 0 "252^git123"; expect 0
}

@test "62211 any installed version 252+vendor no EVR threshold" {
    base; add systemd-journal-remote 2 0 "252+vendor"; expect 0
}

@test "62211 any installed version 252_pre no EVR threshold" {
    base; add systemd-journal-remote 2 0 "252_pre"; expect 0
}

@test "62211 architecture unconstrained x86_64" {
    base; add systemd-journal-remote 2 0 252 1.el9 x86_64; expect 0
}

@test "62211 architecture unconstrained i686" {
    base; add systemd-journal-remote 2 0 252 1.el9 i686; expect 0
}

@test "62211 architecture unconstrained aarch64" {
    base; add systemd-journal-remote 2 0 252 1.el9 aarch64; expect 0
}

@test "62211 architecture unconstrained noarch" {
    base; add systemd-journal-remote 2 0 252 1.el9 noarch; expect 0
}

@test "62211 architecture unconstrained ppc64le" {
    base; add systemd-journal-remote 2 0 252 1.el9 ppc64le; expect 0
}

@test "62211 architecture unconstrained s390x" {
    base; add systemd-journal-remote 2 0 252 1.el9 s390x; expect 0
}

@test "62211 architecture unconstrained riscv64" {
    base; add systemd-journal-remote 2 0 252 1.el9 riscv64; expect 0
}

@test "62211 multilib multiple versions and identical NEVRA distinct records pass" {
    add systemd-journal-remote 3 1 253 2.el9 i686; add systemd-journal-remote 4; expect 0; helper_expect 0
}

@test "62211 other RPM pseudo-package none arch accepted" {
    add gpg-pubkey 3 0 abcd 1234 "(none)"; expect 0
}

@test "62211 helper installed direct stable two inventories" {
    helper_expect 0; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "62211 helper absent direct stable two inventories" {
    base; helper_expect 1; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "62211 inventory normalized property record order" {
    second ""; sort -r "$RPM_FIXTURE/second" > "$BATS_TEST_TMPDIR/sorted"; mv "$BATS_TEST_TMPDIR/sorted" "$RPM_FIXTURE/second"; expect 0
}

@test "62211 concurrent package disappears" {
    second "/systemd-journal-remote/d"; expect 2
}

@test "62211 concurrent name changes" {
    second "s/systemd-journal-remote/systemd-libs/"; expect 2
}

@test "62211 concurrent version changes" {
    second "s/|252|/|253|/"; expect 2
}

@test "62211 concurrent release changes" {
    second "s/|1.el9|/|2.el9|/"; expect 2
}

@test "62211 concurrent epoch changes" {
    second "s/|0|/|1|/"; expect 2
}

@test "62211 concurrent architecture changes" {
    second "s/|x86_64|/|i686|/"; expect 2
}

@test "62211 concurrent identity changes" {
    second "s/RPM1|2|/RPM1|3|/"; expect 2
}

@test "62211 package appears between observations" {
    cp "$RPM_FIXTURE/first" "$RPM_FIXTURE/second"; base; expect 2
}

@test "62211 unrelated package change conservatively ERROR" {
    second "s/|systemd|/|systemd-libs|/"; expect 2
}

@test "62211 new duplicate instance concurrent ERROR" {
    second ""; printf "RPM1|3|systemd-journal-remote|0|252|1.el9|i686|END\n" >> "$RPM_FIXTURE/second"; expect 2
}

@test "62211 query exit 1 never absence" {
    echo 1 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 query exit 2 never absence" {
    echo 2 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 query exit 3 never absence" {
    echo 3 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 query exit 127 never absence" {
    echo 127 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 query exit 137 never absence" {
    echo 137 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 query exit 143 never absence" {
    echo 143 > "$RPM_FIXTURE/exit"; expect 2; helper_expect 2
}

@test "62211 second query error ERROR" {
    echo 1 > "$RPM_FIXTURE/second-exit"; expect 2
}

@test "62211 missing RPM executable ERROR" {
    RLCH_CIS_6_2_2_1_1_RPM="$BATS_TEST_TMPDIR/missing"; expect 2
}

@test "62211 non executable RPM ERROR" {
    chmod 0644 "$RLCH_CIS_6_2_2_1_1_RPM"; expect 2
}

@test "62211 empty inventory cannot prove safe absence" {
    : > "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 truncated final newline rejected" {
    printf "RPM1|2|systemd-journal-remote|0|252|1.el9|x86_64|END" > "$RPM_FIXTURE/first"; expect 2
}

@test "62211 malformed bad marker" {
    base; printf "%s\n" "WRONG|2|systemd-journal-remote|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed missing end" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|252|1.el9|x86_64" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed bad end" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|252|1.el9|x86_64|BAD" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed empty name" {
    base; printf "%s\n" "RPM1|2||0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed invalid name" {
    base; printf "%s\n" "RPM1|2|bad name|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed identity zero" {
    base; printf "%s\n" "RPM1|0|systemd-journal-remote|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed identity negative" {
    base; printf "%s\n" "RPM1|-2|systemd-journal-remote|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed identity overflow" {
    base; printf "%s\n" "RPM1|4294967296|systemd-journal-remote|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed identity duplicate" {
    base; printf "%s\n" "RPM1|1|systemd-journal-remote|0|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed epoch nonnumeric" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|bad|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed epoch negative" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|-1|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed epoch overflow" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|4294967296|252|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed empty version" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0||1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed none version" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|(none)|1.el9|x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed empty release" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|252||x86_64|END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed empty arch" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|252|1.el9||END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed unknown extra field" {
    base; printf "%s\n" "RPM1|2|systemd-journal-remote|0|252|1.el9|x86_64|END|SECRET" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed end injection" {
    base; printf "%s\n" "RPM-END" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed human absent text" {
    base; printf "%s\n" "package systemd-journal-remote is not installed" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 malformed human database error" {
    base; printf "%s\n" "SECRET RPM database corrupt" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 raw NUL bytes rejected" {
    printf "\0" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 raw CR bytes rejected" {
    printf "\r" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 raw TAB bytes rejected" {
    printf "\t" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 raw escape bytes rejected" {
    printf "\033" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 raw DEL bytes rejected" {
    printf "\177" >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 any stderr database error rejected without disclosure" {
    printf "%s\n" "SECRET RPM corruption" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "62211 any stderr valid looking row rejected without disclosure" {
    printf "%s\n" "RPM1|99|systemd-journal-remote|0|252|1.el9|x86_64|END" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "62211 any stderr blank rejected without disclosure" {
    printf "%s\n" "" > "$RPM_FIXTURE/stderr"; expect 2; helper_expect 2
}

@test "62211 stderr binary byte rejected" {
    printf "\0" > "$RPM_FIXTURE/stderr"; expect 2
}

@test "62211 line output bound" {
    head -c 2049 /dev/zero | tr "\000" x >> "$RPM_FIXTURE/first"; expect 2
}

@test "62211 total output bound" {
    base; awk 'BEGIN {for(i=2;i<=50000;i++) printf "RPM1|%d|%0100d|0|1|1|noarch|END\n",i,i}' >> "$RPM_FIXTURE/first"; expect 2; helper_expect 2
}

@test "62211 row count bound" {
    base; awk 'BEGIN {for(i=2;i<=65538;i++) printf "RPM1|%d|x|0|1|1|noarch|END\n",i}' >> "$RPM_FIXTURE/first"; expect 2
}

@test "62211 field bound name" {
    awk -F '|' -v OFS='|' 'NR==2 {$3=""; for(i=0;i<256;i++) $3=$3 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "62211 field bound version" {
    awk -F '|' -v OFS='|' 'NR==2 {$5=""; for(i=0;i<256;i++) $5=$5 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "62211 field bound release" {
    awk -F '|' -v OFS='|' 'NR==2 {$6=""; for(i=0;i<256;i++) $6=$6 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "62211 field bound arch" {
    awk -F '|' -v OFS='|' 'NR==2 {$7=""; for(i=0;i<65;i++) $7=$7 "x"} {print}' "$RPM_FIXTURE/first" > "$BATS_TEST_TMPDIR/bounded"; mv "$BATS_TEST_TMPDIR/bounded" "$RPM_FIXTURE/first"; expect 2
}

@test "62211 helper invalid requested name fails before query" {
    run rlch_rpm_package_status "$RLCH_CIS_6_2_2_1_1_RPM" "bad name"; [ "$status" -eq 2 ]; [ ! -e "$RPM_CALLS" ]
}

@test "62211 locale forced machine query format" {
    export LC_ALL=C.UTF-8; expect 0; [ "$(wc -l < "$RPM_CALLS")" -eq 2 ]
}

@test "62211 file or copied binary does not replace RPM name" {
    base; mkdir -p "$BATS_TEST_TMPDIR/usr/lib/systemd"; touch "$BATS_TEST_TMPDIR/usr/lib/systemd/systemd-journal-remote"; expect 1
}

@test "62211 repeated API installed" {
    for i in 1 2; do expect 0; run validate; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "62211 repeated API absent" {
    base; for i in 1 2; do expect 1; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "62211 repeated API error" {
    echo 1 > "$RPM_FIXTURE/exit"; for i in 1 2; do expect 2; run validate; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "62211 manual install guidance absent" {
    base; run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* && "$output" == *repository* && "$output" == *dependency* && "$output" == *rollback* ]]
}

@test "62211 rollback without RPM ignores stale administrator state" {
    mkdir "$BATS_TEST_TMPDIR/state"; echo systemd-journal-remote > "$BATS_TEST_TMPDIR/state/package-installed"; RLCH_CIS_6_2_2_1_1_RPM="$BATS_TEST_TMPDIR/missing"; run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; [ ! -e "$RPM_CALLS" ]; [ -f "$BATS_TEST_TMPDIR/state/package-installed" ]
}

@test "62211 only RPM inventory commands no DNF systemctl install erase" {
    for command in dnf systemctl; do printf '#!/usr/bin/env bash\necho mutation >> "$RPM_FIXTURE/mutations"\nexit 3\n' > "$BATS_TEST_TMPDIR/$command"; chmod +x "$BATS_TEST_TMPDIR/$command"; done
    export PATH="$BATS_TEST_TMPDIR:$PATH"
    for action in check validate apply rollback; do run "$action"; [ "$status" -eq 0 ]; done
    [ "$(wc -l < "$RPM_CALLS")" -eq 6 ]; ! grep -Eq '(^| )(-e|-i|--install|--erase|--rebuilddb|--initdb)( |$)' "$RPM_CALLS"; [ ! -e "$RPM_FIXTURE/mutations" ]
}

@test "62211 preserve service socket configurations prior controls and no state" {
    mkdir -p "$BATS_TEST_TMPDIR/preserve/etc" "$BATS_TEST_TMPDIR/preserve/state"
    for f in aide.conf crontab tmpfiles.conf acl journal.bin journald.conf journal-upload.conf journal-remote.conf ForwardToSyslog rsyslog.conf upload.service remote.service remote.socket 6.2.1.1 6.2.1.2 6.2.1.3 6.2.1.4; do echo sentinel > "$BATS_TEST_TMPDIR/preserve/etc/$f"; done
    before="$(find "$BATS_TEST_TMPDIR/preserve" -printf '%p %m %u %g\n'; sha256sum "$BATS_TEST_TMPDIR/preserve/etc/"*)"
    for state in installed absent error; do case "$state" in absent) base;; error) echo 1 > "$RPM_FIXTURE/exit";; esac; for action in check validate apply rollback; do run "$action"; [ "$status" -ne 4 ]; done; done
    after="$(find "$BATS_TEST_TMPDIR/preserve" -printf '%p %m %u %g\n'; sha256sum "$BATS_TEST_TMPDIR/preserve/etc/"*)"
    [ "$before" = "$after" ]; [ -z "$(ls -A "$BATS_TEST_TMPDIR/preserve/state")" ]; [ ! -e "$RPM_FIXTURE/mutations" ]
}
