# Rocky Linux CIS Hardening Framework

Enterprise-grade CIS Benchmark Level 1 hardening framework for Rocky Linux 10.x.

The goal of this project is to provide a modular, idempotent and reproducible framework to automate the implementation of the CIS Benchmark Level 1 Server profile while validating compliance using OpenSCAP.

> **Project Status:** 🚧 Early Development (v0.1.0-alpha)

---

## Features

- Modular Bash framework
- Rocky Linux 10.x support
- CIS Benchmark Level 1 Server implementation
- OpenSCAP compliance validation
- Idempotent execution
- Automatic execution engine
- Enterprise-oriented logging
- State management
- Rollback-friendly design
- English and French documentation

---

## Design Principles

This project follows a few simple principles.

- Keep it simple.
- One module, one responsibility.
- Idempotency first.
- Security by default.
- Documentation before implementation.
- OpenSCAP validation whenever possible.
- Enterprise-ready architecture.
- Transparent execution.

---

## Project Goals

The framework aims to:

- automate CIS hardening;
- simplify compliance validation;
- reduce manual configuration;
- improve deployment consistency;
- provide reusable hardening modules;
- generate predictable and reproducible results.

---

## Non-Goals

This project intentionally does **not** aim to:

- replace configuration management solutions such as Ansible or Puppet;
- deploy applications;
- configure Kubernetes clusters;
- manage VMware infrastructure;
- replace enterprise vulnerability scanners.

---

## Repository Layout

```text
rocky-linux-cis-hardening/
├── audit/
├── docs/
├── examples/
├── lib/
├── logs/
├── reports/
├── scripts/
├── state/
├── templates/
├── tests/
├── install.sh
├── config.sh
└── README.md
```

---

## Project Architecture

```
Configuration
        │
        ▼
Framework Core
        │
        ▼
Execution Engine
        │
        ▼
Hardening Modules
        │
        ▼
Validation
        │
        ▼
Reports
```

---

## Development Workflow

Each new feature follows the same lifecycle.

```
Study
    ↓
Design
    ↓
Implementation
    ↓
Testing
    ↓
OpenSCAP Validation
    ↓
Documentation
    ↓
Git Commit
```

---

## Roadmap

### Sprint 0

- Repository initialization
- Documentation
- Framework foundation

### Sprint 1

- Framework Core
- Logging
- Configuration loader
- Utilities

### Sprint 2

- Execution Engine
- State management
- Reboot handling

### Sprint 3

- CIS modules

### Sprint 4

- Validation
- Reporting

### v1.0

First production-ready release.

---

## Requirements

- Rocky Linux 10.x
- Bash
- Root privileges
- OpenSCAP
- Internet access (optional)

---

## Documentation

English documentation:

```
docs/en/
```

French documentation:

```
docs/fr/
```

---

## Contributing

Contributions are welcome.

Please read:

- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- SECURITY.md

before opening an issue or pull request.

---

## Versioning

This project follows Semantic Versioning.

```
MAJOR.MINOR.PATCH
```

Example:

```
v1.2.0
```

---

## License

This project is released under the MIT License.

See the LICENSE file for details.