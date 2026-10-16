#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2016,SC2317 # Literal names and injected observation boundaries.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_12_ROOT="$BATS_TEST_TMPDIR/root" RLCH_CIS_7_1_12_MOUNTINFO="$BATS_TEST_TMPDIR/mountinfo"
    R="$RLCH_CIS_7_1_12_ROOT"; M="$RLCH_CIS_7_1_12_MOUNTINFO"; CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$R/etc" "$R/usr/lib"; chmod 0755 "$R" "$R/etc" "$R/usr" "$R/usr/lib"
    U="$(id -u)"; G="$(id -g)"
    printf 'fixture:x:%s:%s::/:/bin/sh\n' "$U" "$G" > "$R/etc/passwd"
    printf 'fixture:x:%s:\n' "$G" > "$R/etc/group"
    printf 'passwd: files\ngroup: files\n' > "$R/etc/nsswitch.conf"
    printf 'artificial body\n' > "$R/file"; chmod 0644 "$R/file" "$R/etc/"*
    dev="$(stat -c %d "$R")"; DEVICE="$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) )):$(( (dev & 255) | (dev>>12 & 4294967040) ))"
    printf '10 0 %s / / rw - ext4 /dev/fixture rw\n' "$DEVICE" > "$M"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/12/module.sh"
    eval "$(declare -f rlch_fs_find | sed '1s/rlch_fs_find/real_id_find/')"
    BAD_UID=0; BAD_GID=0; BAD_TYPE=''; BAD_PATH="$R/file"; RPM_RESULT=0
    # Only metadata fault boundaries are mocked; actual traversal remains GNU
    # find over the artificial tree. Never chown real runner identities.
    rlch_fs_find() {
        real_id_find "$@" | LC_ALL=C awk -v RS='\0' -v path="$BAD_PATH" -v bu="$BAD_UID" -v bg="$BAD_GID" -v bt="$BAD_TYPE" '
          {k=(NR-1)%10+1;if(k==1) selected=($0==path)
           if(selected && k==6 && bu) $0="42424242"
           if(selected && k==7 && bg) $0="42424243"
           if(selected && k==2 && bt!="") $0=bt
           printf "%s%c",$0,0}'
    }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.12:'* ]]; }
unknown() { expect check 2; expect validate 2; expect apply 2; }
add_mount() { printf '%s %s %s / %s rw - %s %s rw\n' "$1" "$2" "$DEVICE" "$3" "${5:-ext4}" "$4" >> "$M"; }
altfiles() {
    printf 'passwd: files\ngroup: files altfiles\n' > "$R/etc/nsswitch.conf"
    printf 'extra:x:42424243:\n' > "$R/usr/lib/group"; chmod 0644 "$R/usr/lib/group"
    rlch_rpm_package_status() { [ "$2" = nss-altfiles ] || return 2; return "$RPM_RESULT"; }
}
snapshot() { (find "$R" -printf '%p|%y|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort; find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort); }
@test "7112 metadata explicit partial OVAL two-rule scalar" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/12/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.12 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [[ "$RLCH_MODULE_DESCRIPTION" == *partial* ]]
    validate_loaded_module_metadata 7.1.12; validate_loaded_module_functions
}
@test "7112 framework loads after preceding control" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/11"; load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/12"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.12 ]; expect check 0
}
@test "7112 complete local UID GID success all APIs no mutation" {
    before="$(snapshot)"; expect check 0; expect validate 0; expect apply 0; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; [ "$before" = "$(snapshot)" ]; }
@test "7112 only UID unknown deficit" {
    BAD_UID=1; expect check 1; expect validate 1; expect apply 2; }
@test "7112 only GID unknown deficit" {
    BAD_GID=1; expect check 1; expect validate 1; expect apply 2; }
@test "7112 simultaneous UID GID deficits" {
    BAD_UID=1; BAD_GID=1; expect check 1; expect apply 2; }
@test "7112 directories not evaluated even orphan metadata" {
    mkdir "$R/directory"; BAD_PATH="$R/directory"; BAD_UID=1; BAD_GID=1; expect check 0; }
@test "7112 symlink ownership evaluated without following target" {
    ln -s / "$R/link"; BAD_PATH="$R/link"; BAD_UID=1; expect check 1; }
@test "7112 dangling symlink and cycles valid known ownership" {
    ln -s missing "$R/dangling"; ln -s . "$R/loop"; expect check 0; }
@test "7112 special file FIFO ownership evaluated unopened" {
    mkfifo "$R/pipe"; BAD_PATH="$R/pipe"; BAD_GID=1; expect check 1; }
@test "7112 local alias duplicate UID valid" {
    printf 'alias:x:%s:%s::/:/bin/sh\n' "$U" "$G" >> "$R/etc/passwd"; expect check 0; }
@test "7112 local alias duplicate GID valid" {
    printf 'alias:x:%s:\n' "$G" >> "$R/etc/group"; expect check 0; }
@test "7112 duplicate account names ambiguous ERROR" {
    cat "$R/etc/passwd" >> "$R/etc/group"; unknown; }
@test "7112 orphan known by local base addition fresh evaluation" {
    BAD_UID=1; expect check 1; printf 'new:x:42424242:%s::/:/bin/sh\n' "$G" >> "$R/etc/passwd"; expect validate 0; sed -i '$d' "$R/etc/passwd"; expect apply 2; }
@test "7112 NSS external enum zero cannot prove completeness" {
    printf 'passwd: files sss\ngroup: files\n' > "$R/etc/nsswitch.conf"
    getent() { printf 'remote:x:42424242:0::/:/bin/sh\n'; return 0; }
    BAD_UID=1; unknown
}
@test "7112 NSS external outage conservative ERROR" {
    printf 'passwd: files ldap\ngroup: files\n' > "$R/etc/nsswitch.conf"; getent() { return 2; }; unknown
}
@test "7112 NSS actions unsupported cannot silently reduce scope" {
    printf 'passwd: files [NOTFOUND=return] sss\ngroup: files\n' > "$R/etc/nsswitch.conf"; unknown; }
@test "7112 group external NSS intentionally not substitute for local GID" {
    printf 'passwd: files\ngroup: files sss\n' > "$R/etc/nsswitch.conf"; BAD_GID=1
    getent() { printf 'remote:x:42424243:\n'; }; expect check 1
}
@test "7112 altfiles active installed group accepted" {
    altfiles; BAD_GID=1; expect check 0; }
@test "7112 altfiles active package absent group ignored" {
    altfiles; RPM_RESULT=1; BAD_GID=1; expect check 1; }
@test "7112 altfiles disabled file not read" {
    BAD_GID=1; printf 'extra:x:42424243:\n' > "$R/usr/lib/group"; expect check 1; }
@test "7112 altfiles RPM unreadable ERROR" {
    altfiles; RPM_RESULT=2; unknown; }
@test "7112 altfiles required group missing ERROR" {
    altfiles; rm "$R/usr/lib/group"; unknown; }
@test "7112 altfiles malformed group ERROR" {
    altfiles; printf 'bad\n' > "$R/usr/lib/group"; unknown; }
@test "7112 altfiles substring comment matches literal OVAL macro" {
    altfiles; printf 'passwd: files\ngroup: files # altfiles\n' > "$R/etc/nsswitch.conf"; BAD_GID=1; expect check 0; }
@test "7112 group sysroot exclusion does not exclude orphan owner" {
    mkdir "$R/sysroot"; touch "$R/sysroot/file"; BAD_PATH="$R/sysroot/file"; BAD_GID=1; expect check 0; BAD_UID=1; expect check 1; }
@test "7112 sysroot sibling is not excluded" {
    touch "$R/sysroot-file"; BAD_PATH="$R/sysroot-file"; BAD_GID=1; expect check 1; }
@test "7112 newline exception ambiguity ERROR" {
    mkdir "$R/sysroot"; touch "$R/sysroot/line"$'\n'; unknown; }
@test "7112 arbitrary filename bytes transported without disclosure" {
    for name in 'space name' $'line\nname' $'nonutf\377' '$(touch BAD)' 'glob[*?]'; do
        touch "$R/$name"; BAD_PATH="$R/$name"; BAD_GID=1; expect check 1; BAD_GID=0; expect check 0
    done; [ ! -e BAD ]
}
@test "7112 excluded tmpfs even tmp not imported from SCE" {
    mkdir "$R/tmp"; touch "$R/tmp/file"; add_mount 20 10 /tmp tmpfs tmpfs; BAD_PATH="$R/tmp/file"; BAD_UID=1; expect check 0; }
@test "7112 selected nested mount finds owner deficit" {
    mkdir "$R/data"; touch "$R/data/file"; add_mount 20 10 /data /dev/data; BAD_PATH="$R/data/file"; BAD_UID=1; expect check 1; }
@test "7112 same device bind mount finds group deficit" {
    mkdir "$R/bind"; touch "$R/bind/file"; printf '20 10 %s /original /bind rw - ext4 /dev/fixture rw\n' "$DEVICE" >> "$M"
    BAD_PATH="$R/bind/file"; BAD_GID=1; expect check 1
}
@test "7112 selected descendant below excluded ancestor" {
    mkdir -p "$R/net/local"; touch "$R/net/local/file"; add_mount 20 10 /net host:/share nfs; add_mount 30 20 /net/local /dev/local
    BAD_PATH="$R/net/local/file"; BAD_UID=1; expect check 1
}
@test "7112 dev backed distributed and readonly remain in scope" {
    sed -i 's/ext4/ceph/;s/ rw/ ro/g' "$M"; BAD_UID=1; expect check 1; }
@test "7112 no eligible mounts ERROR" {
    sed -i 's@/dev/fixture@overlay@' "$M"; unknown; }
@test "7112 newline device source ERROR" {
    sed -i 's@/dev/fixture@/dev/fixture\\012tail@' "$M"; unknown; }
@test "7112 find failure overrides observed deficit" {
    BAD_UID=1; rlch_fs_find() { real_id_find "$@"; return 1; }; unknown; }
@test "7112 incomplete stream ERROR" {
    rlch_fs_find() { printf '%s\0f\0' "$R"; }; unknown; }
@test "7112 traversal failure later than deficit ERROR" {
    BAD_UID=1; mkdir "$R/closed"; chmod 0000 "$R/closed"; unknown; chmod 0755 "$R/closed"; }
@test "7112 identity change across scans ERROR" {
    rlch_fs_find() { real_id_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; printf 'new:x:1234:1234::/:/bin/sh\n' >> "$R/etc/passwd"; fi; }; expect check 2
}
@test "7112 mount change across scans ERROR" {
    rlch_fs_find() { real_id_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; mkdir "$R/new"; add_mount 20 10 /new proc proc; fi; }; expect check 2
}
@test "7112 malformed bases and NSS ERROR" {
    printf 'private\n' > "$R/etc/passwd"; unknown; }
@test "7112 missing identity bases ERROR" {
    rm "$R/etc/group"; unknown; }
@test "7112 symlink identity base ERROR" {
    mv "$R/etc/passwd" "$R/etc/p"; ln -s p "$R/etc/passwd"; unknown; }
@test "7112 fresh APIs idempotent and rollback silent repeatedly" {
    expect check 0; BAD_UID=1; expect validate 1; BAD_UID=0; expect apply 0; for n in 1 2; do [ "$n" -gt 0 ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; }
@test "7112 no CHANGED for deficits and preserved bodies" {
    before="$(snapshot)"; BAD_GID=1; expect apply 2; [ "$before" = "$(snapshot)" ]; }
@test "7112 diagnostic bounded redacted and coverage explicit" {
    BAD_UID=1; run check; [ "$status" -eq 1 ]; [ "${#output}" -lt 512 ]; [[ "$output" == *'directories excluded'* ]]; [[ "$output" != *"$R"* ]]; [[ "$output" != *42424242* ]]; }
@test "7112 no account service mutation backup or secret access" {
    for cmd in chown chgrp chmod systemctl service cp mv rm getent; do eval "$cmd() { printf '%s\n' '$cmd' >> '$CALLS'; return 99; }"; done
    expect check 0; expect apply 0; [ ! -e "$CALLS" ]; [ ! -e "$R/etc/shadow" ]; [ ! -e "$R/etc/gshadow" ]
    unset -f chown chgrp chmod systemctl service cp mv rm getent
}
@test "7112 complete real RPM inventory proves altfiles branch" {
    altfiles; unset -f rlch_rpm_package_status
    source "$BATS_TEST_DIRNAME/../lib/rpm_observation.sh"
    fake_rpm() { printf 'RPM1|1|nss-altfiles|0|1|1|x86_64|END\n'; }
    RLCH_CIS_7_1_12_RPM=fake_rpm; BAD_GID=1; expect check 0
}
@test "7112 RPM producer warning fails even exit zero" {
    altfiles; unset -f rlch_rpm_package_status
    source "$BATS_TEST_DIRNAME/../lib/rpm_observation.sh"
    fake_rpm() { printf 'RPM1|1|nss-altfiles|0|1|1|x86_64|END\n'; printf 'warning\n' >&2; }
    RLCH_CIS_7_1_12_RPM=fake_rpm; unknown
}
@test "7112 multiple independent orphan objects and IDs do not become AND" {
    touch "$R/second"; BAD_UID=1; expect check 1; BAD_UID=0; BAD_PATH="$R/second"; BAD_GID=1; expect check 1
}
@test "7112 NSS configuration changes across traversal rejected" {
    rlch_fs_find() { real_id_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; printf 'passwd: files sss\ngroup: files\n' > "$R/etc/nsswitch.conf"; fi; }; expect check 2
}
@test "7112 local identity producer errors dominate deficits" {
    BAD_UID=1; rlch_identity_stream() { /usr/bin/cat; return 99; }; unknown
}
