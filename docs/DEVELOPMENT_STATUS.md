# Development Status

## Target

- Operating system: Rocky Linux 10.x
- Primary validation target: Rocky Linux 10.2 golden image
- Baseline: CIS Level 1 Server
- Development branch: `main`
- CI gates: Bats and ShellCheck

The mandatory per-control workflow is documented in `AGENTS.md`.

## Current CIS progress

### Section 1.1

Completed and CI validated:

- 1.1.1.1 through 1.1.1.8
- 1.1.2.1 through 1.1.2.4
- 1.1.3.1 through 1.1.3.3
- 1.1.4.1 through 1.1.4.4
- 1.1.5.1 through 1.1.5.4
- 1.1.6.1 through 1.1.6.4
- 1.1.7.1 through 1.1.7.3
- 1.1.8.1 through 1.1.8.4

1.1.9 was skipped as a duplicate of the existing USB-storage control 1.1.1.8.

### Section 1.2

Completed and CI validated:

- 1.2.1
- 1.2.2
- 1.2.3

Skipped:

- 1.2.4 - Level 2 Server only for this project baseline.

### Section 1.3

Completed and CI validated:

- 1.3.1
- 1.3.2
- 1.3.3

### Section 1.4

Completed and CI validated:

- 1.4.1
- 1.4.2

### Section 1.5

Completed and CI validated:

- 1.5.1
- 1.5.2
- 1.5.3
- 1.5.4

### Section 1.6

Completed and CI validated:

- 1.6.1
- 1.6.3
- 1.6.4
- 1.6.5
- 1.6.6
- 1.6.7

1.6.2 was treated as not applicable for the Rocky Linux 10 / RHEL 9+ policy model used by the project.

### Section 1.7

Completed and CI validated:

- 1.7.1 through 1.7.6

### Section 1.8

Completed and CI validated where applicable:

- 1.8.2 through 1.8.10

Skipped:

- 1.8.1 - Level 2 Server only.

### Section 2.1

Completed and CI validated:

- 2.1.1 through 2.1.19
- 2.1.21
- 2.1.22

The latest completed implementation commit at the time this document was created is:

```text
f3d86c9 feat(cis): implement CIS 2.1.19 xinetd hardening
```

Next benchmark item:

- 2.1.20 - X Window server services - Level 2 Server, therefore SKIPPED for this Level 1 Server baseline.

The next applicable benchmark item after that skip is 2.1.21. CIS 2.1.21 is implemented with manual OpenSCAP metadata because its ComplianceAsCode mapping contains multiple rules and one tailoring variable while the current metadata schema accepts only one rule.

CIS 2.1.22 is a manual Level 1 Server control. The framework inventories listening services for organizational approval review and intentionally performs no automatic service shutdown or removal.

### Section 2.2

Completed and CI validated:

- 2.2.1
- 2.2.3
- 2.2.4
- 2.2.5

Skipped:

- 2.2.2 - Level 2 Server only for this project baseline.

Section 2.2 is complete for the Level 1 Server baseline.

### Section 2.3

Completed and CI validated:

- 2.3.1
- 2.3.2
- 2.3.3

CIS 2.3.2 uses the exact OpenSCAP rule for remote chrony sources. Its remediation follows the ComplianceAsCode RHEL tailoring value for the four RHEL time pools.

CIS 2.3.3 uses the exact OpenSCAP rule for the chronyd runtime user. On RHEL-compatible systems, chronyd runs as the chrony user by default, so the module removes only explicit user overrides and preserves the remaining service options.

Section 2.3 is complete for the Level 1 Server baseline.

### Section 2.4

Completed and CI validated:

- 2.4.1.1
- 2.4.1.2
- 2.4.1.3
- 2.4.1.4
- 2.4.1.5
- 2.4.1.6
- 2.4.1.7
- 2.4.1.8
- 2.4.2.1

CIS 2.4.1.1 maps to both the ComplianceAsCode package installation and service enablement rules. Its metadata is therefore `manual` because the current schema accepts only one OpenSCAP rule.

CIS 2.4.1.2 maps to separate ComplianceAsCode ownership, group ownership, and permission rules for `/etc/crontab`. Its metadata is therefore `manual`; remediation preserves the exact original numeric owner, group, and mode for rollback.

CIS 2.4.1.3 applies the corresponding ownership and mode requirements to `/etc/cron.hourly`. Its rollback state is isolated from the other cron controls and preserves the exact original numeric owner, group, and mode.

CIS 2.4.1.4 applies the corresponding ownership and mode requirements to `/etc/cron.daily`, with isolated rollback state preserving its exact original access metadata.

CIS 2.4.1.5 applies the corresponding ownership and mode requirements to `/etc/cron.weekly`, with isolated rollback state preserving its exact original access metadata.

CIS 2.4.1.6 applies the corresponding ownership and mode requirements to `/etc/cron.monthly`, with isolated rollback state preserving its exact original access metadata.

CIS 2.4.1.7 applies the corresponding ownership and mode requirements to `/etc/cron.d`, with isolated rollback state preserving its exact original access metadata.

CIS 2.4.1.8 maps to five ComplianceAsCode rules covering `cron.deny` absence and `cron.allow` existence, ownership, group ownership, and permissions. Its metadata is therefore `manual`; rollback preserves the exact original existence, content, numeric ownership, and mode of both files.

Section 2.4.1 is complete for the Level 1 Server baseline.

CIS 2.4.2.1 maps to five ComplianceAsCode rules covering `at.deny` absence and `at.allow` existence, ownership, group ownership, and permissions. Its metadata is therefore `manual`; rollback preserves the exact original existence, content, numeric ownership, and mode of both files.

Section 2.4.2 is complete for the Level 1 Server baseline.

### Section 3.1

Completed and CI validated:

- 3.1.1
- 3.1.2
- 3.1.3

CIS 3.1.1 is an observation-only manual control with no ComplianceAsCode rule mapping. The module identifies and reports the IPv6 status without selecting or changing the organization's IPv6 policy.

CIS 3.1.2 uses the exact ComplianceAsCode wireless-interface rule. Systems without a physical Wi-Fi radio are reported as not applicable; remediation preserves the original Wi-Fi and WWAN radio states independently because the benchmark command disables all NetworkManager radios.

CIS 3.1.3 uses the exact ComplianceAsCode Bluetooth service rule. The module stops, disables, and masks `bluetooth.service` only when the `bluez` package is installed, and preserves the original active, enablement, and masking states for isolated rollback.

Section 3.1 is complete for the Level 1 Server baseline.

### Section 3.2

Skipped:

- 3.2.1 - DCCP kernel module availability is a Level 2 Server control and is outside this project's Level 1 Server baseline.
- 3.2.2 - TIPC kernel module availability is a Level 2 Server control and is outside this project's Level 1 Server baseline.
- 3.2.3 - RDS kernel module availability is a Level 2 Server control and is outside this project's Level 1 Server baseline.
- 3.2.4 - SCTP kernel module availability is a Level 2 Server control and is outside this project's Level 1 Server baseline.

Section 3.2 is complete for the Level 1 Server baseline. All controls in this section are Level 2 Server only; no Level 1 remediation modules were created.

### Section 3.3

Completed and CI validated:

- 3.3.1
- 3.3.2
- 3.3.3
- 3.3.4
- 3.3.5
- 3.3.6
- 3.3.7
- 3.3.8
- 3.3.9
- 3.3.10
- 3.3.11

CIS 3.3.1 maps to separate ComplianceAsCode IPv4 and IPv6 forwarding rules plus an IPv6 tailoring value. Its metadata is therefore `manual`. Runtime and persistent values use a control-specific configuration file and rollback state so other sysctl controls cannot invalidate its rollback.

CIS 3.3.2 maps to separate ComplianceAsCode rules for the IPv4 `all` and `default` packet redirect settings. Its metadata is therefore `manual`; runtime and persistent remediation and rollback remain isolated from CIS 3.3.1.

CIS 3.3.3 uses the exact ComplianceAsCode rule for `net.ipv4.icmp_ignore_bogus_error_responses`. Its control-specific persistent file and rollback state preserve isolation from the other sysctl controls.

CIS 3.3.4 uses the exact ComplianceAsCode rule for `net.ipv4.icmp_echo_ignore_broadcasts`, with isolated persistent and rollback state.

CIS 3.3.5 maps to four ComplianceAsCode rules for IPv4 and IPv6 `accept_redirects` settings. Its metadata is therefore `manual`. IPv6 settings remain required by the benchmark even when IPv6 is disabled; a missing expected parameter is reported as an error rather than not applicable.

CIS 3.3.6 maps to separate ComplianceAsCode rules for IPv4 `all` and `default` secure redirects. Its metadata is therefore `manual`, with control-specific persistent and rollback state.

CIS 3.3.7 maps to separate ComplianceAsCode rules for IPv4 `all` and `default` reverse path filtering, both tailored to the strict value `1`. Its metadata is therefore `manual`.

CIS 3.3.8 maps to four ComplianceAsCode rules for IPv4 and IPv6 source-route acceptance. Its metadata is therefore `manual`; required IPv6 parameters are not treated as not applicable merely because IPv6 is disabled.

CIS 3.3.9 maps to separate ComplianceAsCode rules for IPv4 `all` and `default` martian-packet logging. Its metadata is therefore `manual`, with isolated persistent and rollback state.

CIS 3.3.10 uses the exact ComplianceAsCode rule for `net.ipv4.tcp_syncookies`, with isolated persistent and rollback state.

CIS 3.3.11 maps to separate ComplianceAsCode rules for IPv6 `all` and `default` router-advertisement acceptance. Its metadata is therefore `manual`; disabled IPv6 does not remove this Level 1 requirement, and a missing expected parameter is reported as an error rather than not applicable.

Section 3.3 is complete for the Level 1 Server baseline. All controls in this section are applicable; none are skipped.

### Section 4.1

Completed and CI validated:

- 4.1.1
- 4.1.2

CIS 4.1.1 uses the exact ComplianceAsCode `package_nftables_installed` rule. It installs only the nftables package required by the firewalld backend and does not enable or start the standalone nftables service. Rollback removes the package only when this control installed it.

CIS 4.1.2 maps to the ComplianceAsCode firewalld package-installation and service-enablement rules plus the nftables service-disablement rule. Its metadata is therefore `manual`. Remediation selects firewalld as the sole management utility without configuring the standalone nftables service, and rollback preserves the original package, enablement, masking, and runtime states in control-specific storage.

Section 4.1 is complete for the Level 1 Server baseline. Both controls are applicable; none are skipped.

### Section 4.2

Completed and CI validated:

- 4.2.1
- 4.2.2

CIS 4.2.1 is a manual Level 1 Server control related to the ComplianceAsCode `configure_firewalld_ports` rule. The required services and ports depend on the approved role-specific firewall baseline, so the framework reports the current `firewall-cmd --list-all` inventory for manual comparison and deliberately performs no automatic port or service changes. The control is observation-only and therefore has no rollback state.

CIS 4.2.2 maps to separate ComplianceAsCode rules for trusting the loopback interface and restricting spoofed IPv4 and IPv6 loopback-source traffic. Its metadata is therefore `manual`. Remediation uses firewalld exclusively and preserves the exact pre-existing permanent and runtime state of each loopback element in control-specific rollback storage. IPv6 protection remains required even when NetworkManager does not use IPv6.

Section 4.2 is complete for the Level 1 Server baseline. Both controls are applicable; none are skipped or runtime not applicable.

### Section 4.3

Completed and CI validated:

- 4.3.1
- 4.3.2
- 4.3.3
- 4.3.4

CIS 4.3.1 is a supported Level 1 Server control related to `set_nftables_base_chain` and its firewalld tailoring variables. Because RHEL/Rocky uses firewalld as the sole firewall manager, the module verifies in read-only mode that active firewalld generated `input`, `forward`, and `output` filter base-chain hooks in the `inet firewalld` nftables table. It does not depend on firewalld's internal chain names, does not create nftables chains, and has no rollback state. Metadata is `manual` because the benchmark uses an indirect related rule plus multiple tailoring variables.

CIS 4.3.2 is a manual Level 1 Server control with no ComplianceAsCode rule mapping. The observation-only module verifies that the active firewalld-generated nftables table contains a stateful accept rule covering both `established` and `related` connections. It does not require or create role-specific `new` connection rules, does not modify nftables, and has no rollback state.

CIS 4.3.3 is a supported Level 1 Server control related to `nftables_ensure_default_deny_policy`. That related rule targets a standalone nftables configuration and explicitly excludes systems with active firewalld, so metadata is `manual`. The observation-only implementation verifies the equivalent firewalld policy: effective zones use `default`, `DROP`, or `REJECT` targets. An `ACCEPT` target is rejected except for the non-default `trusted` zone when it is bound only to `lo` with no source bindings, preserving CIS 4.2.2. No zone target or nftables chain policy is changed automatically.

CIS 4.3.4 is a supported Level 1 Server control related to `set_nftables_loopback_traffic`. That related rule targets standalone nftables and explicitly excludes active firewalld, so metadata is `manual`. The observation-only implementation verifies active firewalld, its generated `inet firewalld` nftables table, and the permanent and runtime loopback trust plus IPv4 and IPv6 anti-spoofing rules managed by CIS 4.2.2. It does not write direct nftables rules and has no rollback state.

Section 4.3 is complete for the Level 1 Server baseline. All four controls are applicable and CI validated; none are skipped or runtime not applicable.

### Section 5.1

Completed and CI validated:

- 5.1.1
- 5.1.2
- 5.1.3
- 5.1.4
- 5.1.5
- 5.1.6
- 5.1.7
- 5.1.8
- 5.1.9
- 5.1.12
- 5.1.13
- 5.1.14
- 5.1.15
- 5.1.16
- 5.1.17
- 5.1.18
- 5.1.19
- 5.1.20
- 5.1.21
- 5.1.22

Section 5.1 is complete and CI validated for the Level 1 Server baseline. CIS 5.1.10 and 5.1.11 are the only skipped controls, both because they are Level 2 Server only. No control in section 5.1 is runtime not applicable.

Skipped for the Level 1 Server baseline:

- 5.1.10 (Level 2 Server only)
- 5.1.11 (Level 2 Server only)

CIS 5.1.1 is an automated Level 1 Server control mapped to three ComplianceAsCode rules for owner, group owner, and permissions on `/etc/ssh/sshd_config`. Metadata is `manual` because the project schema stores only one rule. Remediation changes only numeric ownership and mode, preserves the exact original UID, GID, and mode in control-specific rollback state, and never modifies file content.

CIS 5.1.2 is an automated Level 1 Server control mapped to three ComplianceAsCode rules. It dynamically discovers regular `/etc/ssh/*_key` files, requires owner `root`, the RHEL dedicated group `ssh_keys`, and mode `0600` or more restrictive. It never creates missing keys or changes key content. Per-file numeric UID, GID, and mode are stored in a null-delimited, control-specific rollback state.

CIS 5.1.3 is an automated Level 1 Server control mapped to three ComplianceAsCode rules. It dynamically discovers regular `/etc/ssh/*.pub` files, requires owner and group `root`, and mode `0644` or more restrictive. It never creates missing public keys or changes key content. Per-file numeric UID, GID, and mode are stored in a null-delimited, control-specific rollback state.

CIS 5.1.4 is an automated Level 1 Server control using the exact ComplianceAsCode `configure_custom_crypto_policy_cis` rule. It validates the generated system-wide policy and, when required, installs the rule's RHEL 9 `NO-SSHWEAKCIPHERS` subpolicy without writing an `sshd_config` cipher override. Its crypto-policy backup and module state are isolated to this control.

CIS 5.1.5 is an automated Level 1 Server control using the exact ComplianceAsCode `configure_custom_crypto_policy_cis` rule. It validates that the effective system-wide SSH hash policy excludes SHA-1 and adds the benchmark `NO-SHA1` subpolicy only when necessary. It does not write a conflicting `KexAlgorithms` directive, and its rollback policy state is isolated from the other crypto controls.

CIS 5.1.6 is an automated Level 1 Server control using the exact ComplianceAsCode `configure_custom_crypto_policy_cis` rule. It validates the generated SSH MAC policy and installs the RHEL 9 `NO-SSHWEAKMACS` subpolicy only when needed, without writing a conflicting `MACs` directive. Its crypto-policy backup and module state are isolated to this control.

CIS 5.1.7 is an automated Level 1 Server check using the exact ComplianceAsCode `sshd_limit_user_access` rule. Compliance requires at least one non-empty `AllowUsers`, `AllowGroups`, `DenyUsers`, or `DenyGroups` directive. Because the approved identities are organization-specific and ComplianceAsCode provides no generic remediation, the module inventories and validates configured directives but deliberately refuses to invent an access policy. It is observation-only and has no rollback state.

CIS 5.1.8 is an automated Level 1 Server control using the exact primary ComplianceAsCode `sshd_enable_warning_banner_net` rule. It verifies the effective sshd `Banner` value and manages only a control-specific drop-in pointing to `/etc/issue.net`; the banner content remains owned by CIS 1.7.3. Rollback restores or removes only this control's drop-in.

CIS 5.1.9 is an automated Level 1 Server control mapped to the separate ComplianceAsCode `sshd_set_idle_timeout` and `sshd_set_keepalive` rules plus their tailoring values (`300` seconds and `1`). Metadata is therefore `manual`. Both effective settings are validated and managed together in one control-specific drop-in with isolated rollback state.

CIS 5.1.10 and CIS 5.1.11 are excluded from the Level 1 Server profile by the benchmark; both are Level 2 Server controls and are documented only as `SKIPPED`, with no module or remediation.

CIS 5.1.12 is an automated Level 1 Server control using the exact ComplianceAsCode `disable_host_auth` rule. It validates the effective `HostbasedAuthentication no` setting and manages only a control-specific sshd drop-in with isolated rollback state.

CIS 5.1.13 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_disable_rhosts` rule. It validates `IgnoreRhosts yes` and manages only its own sshd drop-in and rollback state.

CIS 5.1.14 is an automated Level 1 Server control mapped to ComplianceAsCode `sshd_set_login_grace_time` and its tailored value of 60 seconds. Metadata is `manual` because the project schema cannot encode both the rule and variable. The module manages only `LoginGraceTime 60` in isolated state.

CIS 5.1.15 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_set_loglevel_verbose` rule. It validates the effective `LogLevel VERBOSE` value and manages only its control-specific drop-in and rollback state.

CIS 5.1.16 is an automated Level 1 Server control mapped to ComplianceAsCode `sshd_set_max_auth_tries` and the tailored value `4`. Metadata is `manual` because the project schema cannot encode both. Its drop-in and rollback state are isolated.

CIS 5.1.17 is an automated Level 1 Server control mapped to ComplianceAsCode `sshd_set_maxstartups` and the tailored value `10:30:60`. Metadata is `manual`; remediation and rollback affect only this directive and control-specific state.

CIS 5.1.18 is an automated Level 1 Server control mapped to ComplianceAsCode `sshd_set_max_sessions` and the tailored value `10`. Metadata is `manual`; the isolated drop-in changes no other SSH limit.

CIS 5.1.19 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_disable_empty_passwords` rule. It enforces `PermitEmptyPasswords no` in an isolated drop-in with exact rollback.

CIS 5.1.20 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_disable_root_login` rule. It enforces `PermitRootLogin no` without modifying SSH access allow/deny policy, using isolated rollback state.

CIS 5.1.21 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_do_not_permit_user_env` rule. It enforces `PermitUserEnvironment no` in its own drop-in and preserves an exact, isolated rollback state.

CIS 5.1.22 is an automated Level 1 Server control using the exact ComplianceAsCode `sshd_enable_pam` rule. It enforces `UsePAM yes` in a control-specific drop-in with exact rollback.

CIS 5.1.22 was validated by GitHub Actions run 205 on commit `715c1b9a684658939711ad49c7c086f8cabcd291`. Development previously stopped before CIS 5.2.

### Section 5.2

Completed and CI validated:

- 5.2.1
- 5.2.2
- 5.2.3
- 5.2.5
- 5.2.6
- 5.2.7

Skipped for the Level 1 Server baseline:

- 5.2.4 (Level 2 Server only)

CIS 5.2.1 is an automated Level 1 Server control using the exact ComplianceAsCode `package_sudo_installed` rule. It installs the `sudo` package only when absent, records control-specific rollback state before installation, and removes sudo during rollback only when this control installed it.

CIS 5.2.2 is an automated Level 1 Server control using the exact ComplianceAsCode `sudo_add_use_pty` rule. It validates sudoers syntax before evaluating global effective policy, rejects active global or scoped `!use_pty` exceptions, and manages a dedicated mode `0440` sudoers drop-in. A failed `visudo` validation restores the prior file immediately; successful rollback affects only this control's file.

CIS 5.2.3 is an automated Level 1 Server control using the exact ComplianceAsCode `sudo_custom_logfile` rule and its default `/var/log/sudo.log` value. It configures only the sudoers `logfile` option; it does not create an empty log file because the rule validates configuration and sudo creates the file when it writes. The dedicated drop-in is validated by `visudo` and has isolated exact rollback state.

CIS 5.2.4 is `SKIPPED` because the benchmark classifies `sudo_remove_nopasswd` as Level 2 Server only. No module is created and Level 1 remediation does not remove approved `NOPASSWD` policy.

CIS 5.2.5 is an automated Level 1 Server control using the exact ComplianceAsCode `sudo_remove_no_authenticate` rule. Because that rule disallows every active `!authenticate` occurrence, remediation removes only that option from affected global or scoped Defaults directives, preserves all other options and comments, validates with `visudo`, and records exact per-file backups in isolated state. Ambiguous continued directives are rejected rather than rewritten destructively.

CIS 5.2.6 is an automated Level 1 Server control mapped to ComplianceAsCode `sudo_require_reauthentication` plus `var_sudo_timestamp_timeout=15_minutes`. Metadata is `manual` because the schema cannot encode both. The rule's equals operator requires exactly `timestamp_timeout=15`; absent, zero, negative, lower, higher, or conflicting scoped values are non-compliant. Remediation uses a dedicated late-sorting drop-in, validates with `visudo`, and removes its own change if it cannot establish compliance.

CIS 5.2.6 was validated by GitHub Actions run 210 on commit `40e9e5c789db6bb5d1e3c97434c501c13e1c221b`.

CIS 5.2.7 maps to ComplianceAsCode `use_pam_wheel_group_for_su`, `ensure_pam_wheel_group_empty`, and the `cis` option of `var_pam_wheel_group_for_su`. This option resolves to the group name `sugroup`, not a group literally named `cis`. Metadata is `manual` because this is a composite mapping. Remediation adds only the required `auth required pam_wheel.so use_uid group=sugroup` PAM line, preserving all existing lines and their order. It creates `sugroup` only if absent, refuses to change a populated group or competing active PAM rule, and does not change administrative group memberships. Isolated rollback restores the exact prior PAM file only when no subsequent edits occurred, and deletes `sugroup` only when this control created it and the group remains empty with the same GID. Local Bats and ShellCheck validation completed; the corresponding GitHub Actions run determines final acceptance.

CIS 5.2 is complete: six Level 1 Server controls have dedicated commits and green CI runs 206–211. CIS 5.2.4 is SKIPPED (Level 2 Server); no controls are NOT_APPLICABLE. CIS 5.2.7 was validated on commit `78056b35c22a0f9759cb1d0e8604a972eeee4072` by GitHub Actions run 211. Development stopped before CIS 5.3.

### Section 5.3

CIS 5.3.1.1 is a Level 1 Server control marked `pending` by ComplianceAsCode, with no exact OpenSCAP rule. Metadata therefore records `manual`. Its check requires an installed `pam` RPM, a refreshed DNF5 repository query finding PAM in enabled repositories, and no available update. An absent package or available update is NON_COMPLIANT; an unavailable repository or missing available package is ERROR because the latest version cannot be established. Automatic installation or upgrade is deliberately disabled: PAM is a core authentication package, and an exact package rollback cannot be guaranteed by DNF history or by the availability of an older RPM. Remediation requires an operator-managed system snapshot and recovery plan. `apply` returns ERROR when remediation is needed and makes no changes; `rollback` is a no-op. This limitation must be resolved or explicitly accepted before declaring the Level 1 image fully remediated.

CIS 5.3.1.1 was validated by GitHub Actions run 212 on commit `e4b8f49f2498e987a509be91bf949cdd178f4b57`.

CIS 5.3.1.2 is Level 1 Server and `pending` in ComplianceAsCode, with no exact rule; metadata is `manual`. It checks that `authselect` is installed, available in refreshed enabled DNF5 repositories, and has no pending upgrade. Absent or outdated packages are NON_COMPLIANT; an unavailable repository or missing available package is ERROR. Automatic installation and upgrade are disabled because a guaranteed rollback of this authentication package cannot be established. An operator-managed snapshot and recovery plan are required when remediation is needed. `apply` returns ERROR without making changes; `rollback` is a no-op. This limitation must be resolved or explicitly accepted before production validation.

CIS 5.3.1.2 was validated by GitHub Actions run 213 on commit `0ffadfb58ae5cb675b06d783ee6d7040dc2bca13`.

CIS 5.3.1.3 is Level 1 Server and `pending` in ComplianceAsCode. Its `package_pam_pwquality_installed` rule checks only that `libpwquality` is installed, while the CIS title requires the latest version. Metadata is therefore `manual`: claiming the package-installation rule as an exact mapping would be misleading. The module checks installation, fresh enabled repository availability and pending upgrades. Absent or outdated is NON_COMPLIANT; unavailable repositories or no available package produce ERROR. Automatic package changes are disabled until a reliable rollback path for the exact prior version exists; `apply` reports ERROR when remediation is needed and `rollback` has no changes to undo. This limitation requires an operator-managed snapshot and recovery plan or explicit acceptance before production validation.

CIS 5.3.1.3 was validated by GitHub Actions run 214 on commit `874ae3cece7d6595f80a2fa995a85992a0713ba4`.

CIS 5.3.2.1 is a Level 1 Server automated benchmark control mapped exactly to `accounts_password_pam_modules_in_authselect_profile`. It reads the selected profile from `authselect.conf`, verifies `authselect check`, then checks the profile's `system-auth` and `password-auth` source files for `pam_pwquality.so`, `pam_pwhistory.so`, `pam_faillock.so` and `pam_unix.so`. Standard profiles are read from the system defaults; custom profiles from their existing source directory. Missing modules are NON_COMPLIANT and inconsistent authselect state is ERROR. `apply` does not invent PAM stack ordering or replace an organizational profile: it returns ERROR when manual profile remediation is needed, without changing files. Rollback has no changes to undo. This is an explicit automated-remediation limitation before production validation.

CIS 5.3.2.1 was validated by GitHub Actions run 215 on commit `eb3d6f09364c000903fdc3034587f29495f01a75`.

CIS 5.3.2.2 is Level 1 Server, with two ComplianceAsCode rules: `account_password_pam_faillock_password_auth` and `account_password_pam_faillock_system_auth`. Metadata is `manual` because the schema cannot encode both. After `authselect check`, the module checks the generated `system-auth` and `password-auth` stacks for ordered `preauth`, `pam_unix`, `authfail`, and the `pam_faillock` account hook. Missing or misordered entries are NON_COMPLIANT; inconsistent authselect is ERROR. Automatic remediation is disabled because generated PAM files must not be edited directly and the correct changes to the selected profile depend on its existing structure and features. `apply` returns ERROR without mutation when correction is needed; rollback is a no-op. This is a documented automated-remediation limitation.

CIS 5.3.2.2 was validated by GitHub Actions run 216 on commit `67fbf7d66561c916abc8058dee233239edfca4d9`.

CIS 5.3.2.3 is Level 1 Server and automated in the CIS mapping, but ComplianceAsCode has no exact primary rule. Its related `package_pam_pwquality_installed` rule checks package presence only. Metadata uses `manual`. After `authselect check`, the module verifies a single active `password` hook for `pam_pwquality.so` in each generated stack. Missing or duplicate hooks are NON_COMPLIANT; authselect inconsistency is ERROR. Changes to the active profile require reviewing its existing PAM stack and features, so automatic apply returns ERROR when correction is needed without changing files. Rollback has no changes to undo. This is an explicit limitation before production validation.

CIS 5.3.2.3 was validated by GitHub Actions run 217 on commit `036ad060103e861076f60fa1bf1eac6458383815`.

CIS 5.3.2.4 is Level 1 Server with no exact primary rule. The `accounts_password_pam_pwhistory_remember_password_auth` and `accounts_password_pam_pwhistory_remember_system_auth` rules are related mappings for a later control; metadata is `manual`. After `authselect check`, the module requires exactly one active `password` hook for `pam_pwhistory.so` in each generated stack. It does not set the history length or other later policy. Missing or duplicate hooks are NON_COMPLIANT; authselect inconsistency is ERROR. Automatic apply refuses to rewrite an existing PAM profile or its generated stacks without a reviewed stack order; rollback is a no-op. This is a documented automated-remediation limitation.

CIS 5.3.2.4 was validated by GitHub Actions run 218 on commit `48e238b03bca95774521f0f643686845777df940`.

CIS 5.3.2.5 is Level 1 Server and `partial` in ComplianceAsCode; `no_empty_passwords` is a related rule, not an exact test of whether pam_unix is enabled. Metadata is `manual`. Following `authselect check`, the module verifies active pam_unix authentication and password hooks in each generated PAM stack. Missing or duplicated hooks are NON_COMPLIANT, and inconsistent authselect state is ERROR. It does not change the active profile or generated files automatically: `apply` returns ERROR if remediation is needed, and rollback is a no-op. This limitation requires review before production validation.

CIS 5.3.2.5 was validated by GitHub Actions run 219 on commit `d60cec64df22e6c2f562bc720749c68e405ef354` (2225 Bats tests and the configured ShellCheck job green).

CIS 5.3.3.1.1 is a Level 1 Server automated control mapped to `accounts_passwords_pam_faillock_deny` with `var_accounts_passwords_pam_faillock_deny=5`. The effective threshold must be greater than zero and no more than five; existing values 1–4 remain untouched. The check validates `authselect check`, active `pam_faillock.so` authentication lines in both generated stacks, their inline `deny=` options, and `/etc/security/faillock.conf` for lines without an inline override. Missing and out-of-range values are NON_COMPLIANT; malformed or ambiguous duplicate settings are ERROR. The normal remediation edits only the active `deny` line in `faillock.conf`, retaining unrelated settings, comments, ownership, and mode. An inline PAM option requiring correction is deliberately not rewritten in generated files: apply returns ERROR and asks for a reviewed authselect profile change. Rollback tracks only the original `deny` line or its absence and removes/replaces its marked line without restoring a whole-file backup, so later `unlock_time` changes remain intact. There is no assumed faillock drop-in directory. The CI ShellCheck job does not currently scan `modules` or `tests`; the module was checked locally with ShellCheck for this control.

CIS 5.3.3.1.1 was validated by GitHub Actions run 220 on commit `0c24002fd705a2d12fcc299a9a9810a49493ca26` (2241 Bats tests and the configured ShellCheck job green).

CIS 5.3.3.1.2 is a Level 1 Server automated control mapped to `accounts_passwords_pam_faillock_unlock_time` with `var_accounts_passwords_pam_faillock_unlock_time=900`. The CIS mapping explicitly also accepts `unlock_time=0` (manual administrator unlock), so effective values of zero or at least 900 seconds are compliant and remain unchanged. The check first validates `authselect check`, then accounts for active inline `unlock_time=` options in both generated PAM stacks and the corresponding value in `/etc/security/faillock.conf` wherever no inline option applies. Missing or values 1–899 are NON_COMPLIANT; malformed and ambiguous duplicate settings are ERROR. Remediation changes only the `unlock_time` line to 900 seconds, preserving comments, file ownership/mode, and the `deny` line managed by CIS 5.3.3.1.1. Inline PAM corrections are refused without modifying generated authselect files; a reviewed profile change is required. Its distinct rollback state restores only the original `unlock_time` line or removes its marked line, retaining `deny` and other later settings. No unsupported faillock drop-in is assumed. The CI ShellCheck job does not directly scan `modules` or `tests`; the module is checked locally.

CIS 5.3.3.1.3 is **SKIPPED** for the Level 1 Server baseline: the CIS RHEL 9 v2.0.0 control is Level 2 Server only. No module or tests are created.

CIS 5.3.3.2.1 is Level 1 Server, mapped to ComplianceAsCode `accounts_password_pam_difok` with `var_password_pam_difok=2`. An effective `difok` of at least two is accepted without weakening a stronger setting. The module validates authselect and both generated password stacks. Inline `difok=` takes precedence; a custom `conf=` path or malformed inline option is an error, while an inline value below two requires a reviewed authselect profile change and cannot be corrected by editing generated PAM files. For hooks using the default configuration, vendor and administrator `.conf.d` files are merged by filename in ASCII order, followed by `/etc/security/pwquality.conf` (or the vendor main file when the administrator main file is absent). The last active `difok` wins. Remediation writes only the `difok` line in the administrator main file, preserving unrelated policy and ownership/mode. Duplicate main-file definitions are assessed by their last value but refused for automated replacement. Per-control rollback restores only its prior line or removes the owned line, preserving other pwquality changes; administrator edits to `difok` block rollback. This does not rewrite an authselect profile or handle custom `conf=` paths automatically. Local Bats and ShellCheck and GitHub Actions are required before this control is considered validated.

CIS 5.3.3.2.2 is an automated Level 1 Server control mapped exactly to ComplianceAsCode `accounts_password_pam_minlen` with `var_password_pam_minlen=14`. Effective values of at least 14 are compliant and stronger values remain unchanged. After `authselect check`, the module reads active `pam_pwquality.so` password hooks in both generated stacks. An inline `minlen=` overrides the default configuration; malformed or duplicated options, inconsistent stacks, and custom `conf=` paths return ERROR. Inline values below 14 require a reviewed authselect profile change; generated PAM files are never edited. The default configuration merges `/usr/lib/security/pwquality.conf.d/*.conf` and `/etc/security/pwquality.conf.d/*.conf` by filename in ASCII order (the administrator file wins a name collision), then reads `/etc/security/pwquality.conf` or falls back to `/usr/lib/security/pwquality.conf` when the administrator main file is absent. The last active `minlen` is effective. Remediation writes only `minlen = 14` to the administrator main file and retains unrelated parameters, comments, ownership, and mode. Duplicate main-file definitions can be checked using the last value, but automated replacement is refused. The separate rollback state restores only the original `minlen` line or removes the marked line, preserving later unrelated settings and the `difok` setting managed by CIS 5.3.3.2.1. Administrator changes to the managed `minlen` block rollback. Cross-control tests exercise both independent rollback orders. Custom `conf=` and inline corrections remain manual remediation limitations. GitHub Actions validation is required before this control is marked complete.

## Known technical debt / mandatory pre-production review

The following items must be resolved or explicitly reviewed before final real-world validation.

### Crypto-policy rollback isolation

The crypto-policy implementation historically uses a shared backup file across several controls. Sequential controls can therefore couple rollback state. Refactor to per-control backup state or another isolation mechanism before production sign-off.

### Warning-banner rollback when original file is absent

The banner helper needs review for the case where a managed banner file did not exist before remediation. Rollback must be able to remove a file created by the framework rather than leaving it behind.

### Metadata schema supports only one OpenSCAP rule

Some CIS controls map to multiple ComplianceAsCode/OpenSCAP rules, while current metadata stores only one `RLCH_MODULE_OPENSCAP_RULE`. Review the schema before final validation so framework/OpenSCAP comparison is not misleading.

### CIS 1.8.7 OpenSCAP mapping

Review the committed metadata for CIS 1.8.7. A previously used mapping ending in `dconf_gnome_disable_automount_user` was identified as likely incorrect. Current ComplianceAsCode mapping should be verified and the repository corrected in a dedicated commit if necessary.

### Shared dconf profile management

Controls 1.8.4, 1.8.6, and 1.8.8 manage shared dconf profile state. Review them to ensure administrator-provided entries are not overwritten and rollback state remains isolated across controls.

### CIS 2.1.8 message-access servers

Review CIS 2.1.8. The benchmark requires message-access server coverage including Dovecot and Cyrus IMAP, while the current implementation was identified as handling only Dovecot. Correct this before final validation.

### Package-removal rollback fidelity and duplication

Several section 2 controls implement very similar package-removal logic. Rollback commonly reinstalls by package name rather than preserving the exact original NEVRA/version. Review whether exact-version restoration is required for production rollback and whether the repeated mechanism should be consolidated into a reusable library. Do not mix this refactor into an unrelated CIS-control commit.

### XDMCP parser semantics

Validate the XDMCP configuration/parser behavior against a real Rocky Linux 10.2 installation before production sign-off.

## Final validation plan

After implementation of the applicable CIS Level 1 Server controls is complete and the technical-debt items above are addressed:

1. Deploy/run on a real Rocky Linux 10.2 test system representative of the golden image.
2. Execute the framework from a known baseline.
3. Reboot.
4. Perform post-reboot framework validation.
5. Run OpenSCAP with the applicable CIS Level 1 Server profile/reference.
6. Compare framework results with OpenSCAP and investigate discrepancies.
7. Exercise rollback for remediated controls.
8. Verify the restored state.
9. Re-apply the framework.
10. Run it a second time and verify idempotence/no unintended changes.
11. Perform final golden-image validation.

## Workflow reminder

Never advance automatically past a failing control:

```text
CONTROL N
  -> implementation
  -> Bats + ShellCheck
  -> one commit
  -> GitHub Actions
  -> fix until CI green
  -> CONTROL N+1
```
