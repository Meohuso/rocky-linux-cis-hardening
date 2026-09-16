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
