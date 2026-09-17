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

CIS 3.3.1 maps to separate ComplianceAsCode IPv4 and IPv6 forwarding rules plus an IPv6 tailoring value. Its metadata is therefore `manual`. Runtime and persistent values use a control-specific configuration file and rollback state so other sysctl controls cannot invalidate its rollback.

CIS 3.3.2 maps to separate ComplianceAsCode rules for the IPv4 `all` and `default` packet redirect settings. Its metadata is therefore `manual`; runtime and persistent remediation and rollback remain isolated from CIS 3.3.1.

CIS 3.3.3 uses the exact ComplianceAsCode rule for `net.ipv4.icmp_ignore_bogus_error_responses`. Its control-specific persistent file and rollback state preserve isolation from the other sysctl controls.

CIS 3.3.4 uses the exact ComplianceAsCode rule for `net.ipv4.icmp_echo_ignore_broadcasts`, with isolated persistent and rollback state.

CIS 3.3.5 maps to four ComplianceAsCode rules for IPv4 and IPv6 `accept_redirects` settings. Its metadata is therefore `manual`. IPv6 settings remain required by the benchmark even when IPv6 is disabled; a missing expected parameter is reported as an error rather than not applicable.

CIS 3.3.6 maps to separate ComplianceAsCode rules for IPv4 `all` and `default` secure redirects. Its metadata is therefore `manual`, with control-specific persistent and rollback state.

CIS 3.3.7 maps to separate ComplianceAsCode rules for IPv4 `all` and `default` reverse path filtering, both tailored to the strict value `1`. Its metadata is therefore `manual`.

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
